"""Mail providers for ChatGPT registration and login OTP.

OutlookTokenProvider reads Outlook/Hotmail mailboxes through OAuth tokens.
GmailProvider reads a Gmail inbox through IMAP App Passwords and can create
plus-address aliases for registration.

Outlook format: email----password----client_id----refresh_token (one per line)
"""

from __future__ import annotations

import hashlib
import imaplib
import json
import logging
import re
import secrets
import string
import time
from datetime import datetime, timezone
from email import message_from_bytes, policy
from email.header import decode_header, make_header
from email.utils import parsedate_to_datetime
from pathlib import Path
from threading import Lock
from typing import Any, Callable

from curl_cffi import requests

logger = logging.getLogger(__name__)

# ── Data directory (stores pool state) ─────────────────────────────

DATA_DIR = Path("data")
STATE_FILE = DATA_DIR / "outlook_token_state.json"

# ── Outlook constants ───────────────────────────────────────────────

OUTLOOK_TOKEN_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
OUTLOOK_GRAPH_MESSAGES_URL = "https://graph.microsoft.com/v1.0/me/messages"
OUTLOOK_GRAPH_SCOPE = "offline_access https://graph.microsoft.com/Mail.Read"
OUTLOOK_IMAP_SCOPE = "offline_access https://outlook.office.com/IMAP.AccessAsUser.All"
OUTLOOK_DEFAULT_IMAP_HOST = "outlook.office365.com"

# ── Pool state tracking ─────────────────────────────────────────────

_outlook_token_state_lock = Lock()
OUTLOOK_IN_USE_STALE_SECONDS = 3600  # 1 hour stale timeout
OUTLOOK_UNAVAILABLE_STATES = {"used", "token_invalid", "failed"}
_otp_seen_lock = Lock()
_otp_seen_cache: dict[str, dict[str, set[str]]] = {}


def _load_state() -> dict[str, dict[str, Any]]:
    """Load pool state from disk (email_lower → {state, reason, updated_at})."""
    try:
        if not STATE_FILE.exists():
            return {}
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return {}
    state: dict[str, dict[str, Any]] = {}
    if isinstance(data, list):
        for item in data:
            key = str(item).strip().lower()
            if key:
                state[key] = {"state": "used", "reason": "", "updated_at": ""}
    elif isinstance(data, dict):
        for key, value in data.items():
            email = str(key).strip().lower()
            if not email:
                continue
            if isinstance(value, dict):
                state[email] = {
                    "state": str(value.get("state") or "used").strip() or "used",
                    "reason": str(value.get("reason") or ""),
                    "updated_at": str(value.get("updated_at") or ""),
                }
            else:
                state[email] = {
                    "state": str(value or "used").strip() or "used",
                    "reason": "",
                    "updated_at": "",
                }
    return state


def _save_state(state: dict[str, dict[str, Any]]) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    ordered = {key: state[key] for key in sorted(state)}
    STATE_FILE.write_text(
        json.dumps(ordered, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )


def _entry_available(entry: dict[str, Any] | None) -> bool:
    """Check if this email is available for use."""
    if not isinstance(entry, dict):
        return True
    current = str(entry.get("state") or "")
    if current in OUTLOOK_UNAVAILABLE_STATES:
        return False
    if current == "in_use":
        updated_at = str(entry.get("updated_at") or "")
        try:
            ts = datetime.fromisoformat(updated_at)
            age = (
                datetime.now(timezone.utc)
                - (ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc))
            ).total_seconds()
            return age >= OUTLOOK_IN_USE_STALE_SECONDS
        except Exception:
            return True
    return True


def _set_state(address: str, state: str, reason: str = "") -> None:
    target = str(address or "").strip().lower()
    if not target:
        return
    with _outlook_token_state_lock:
        store = _load_state()
        store[target] = {
            "state": str(state),
            "reason": str(reason or ""),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        _save_state(store)


def _release_state(address: str) -> None:
    """Release in_use state back to unused."""
    target = str(address or "").strip().lower()
    if not target:
        return
    with _outlook_token_state_lock:
        store = _load_state()
        entry = store.get(target)
        if isinstance(entry, dict) and str(entry.get("state") or "") == "in_use":
            store.pop(target, None)
            _save_state(store)


# ── Credential parsing ──────────────────────────────────────────────


def parse_outlook_credentials(text: str) -> list[dict[str, str]]:
    """Parse outlook token pool text.

    Format: email----password----client_id----refresh_token (one per line)
    """
    credentials: list[dict[str, str]] = []
    seen: set[str] = set()
    for raw_line in str(text or "").splitlines():
        line = str(raw_line or "").strip()
        if not line or "----" not in line:
            continue
        parts = [str(p).strip() for p in line.split("----", 3)]
        if len(parts) != 4:
            continue
        email, password, client_id, refresh_token = parts
        if "@" not in email or not client_id or not refresh_token:
            continue
        key = email.lower()
        if key in seen:
            continue
        seen.add(key)
        credentials.append(
            {
                "email": email,
                "password": password,
                "client_id": client_id,
                "refresh_token": refresh_token,
            }
        )
    return credentials


# ── Code extraction ─────────────────────────────────────────────────


def _extract_code(message: dict[str, Any]) -> str | None:
    """Extract 6-digit verification code from email content."""
    content = (
        f"{message.get('subject', '')}\n"
        f"{message.get('text_content', '')}\n"
        f"{message.get('html_content', '')}"
    ).strip()
    if not content:
        return None

    # OpenAI styled <p> with background-color: #F3F3F3
    match = re.search(
        r"background-color:\s*#F3F3F3[^>]*>[\s\S]*?(\d{6})[\s\S]*?</p>",
        content,
        re.I,
    )
    if match:
        return match.group(1)

    # Text patterns
    match = re.search(
        r"(?:Verification code|code is|代码为|验证码)[:\s]*(\d{6})",
        content,
        re.I,
    )
    if match and match.group(1) != "177010":
        return match.group(1)

    # Generic 6-digit codes (excluding known false positive 177010)
    for code in re.findall(r">\s*(\d{6})\s*<|(?<![#&])\b(\d{6})\b", content):
        value = code[0] or code[1]
        if value and value != "177010":
            return value

    return None


def _message_tracking_ref(message: dict[str, Any]) -> str:
    """Create a content-based tracking reference for deduplication."""
    provider = str(message.get("provider") or "").strip()
    mailbox = str(message.get("mailbox") or "").strip()
    imap_uid = str(message.get("imap_uid") or "").strip()
    if imap_uid:
        return f"imap:{provider}:{mailbox}:{imap_uid}"
    message_id = str(message.get("message_id") or "").strip()
    if message_id:
        return f"id:{provider}:{mailbox}:{message_id}"

    received_at = message.get("received_at")
    received_value = (
        received_at.isoformat()
        if isinstance(received_at, datetime)
        else str(received_at or "")
    )
    content = "\n".join(
        str(message.get(key) or "")
        for key in ("subject", "sender", "text_content", "html_content")
    )
    digest = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
    return f"content:{provider}:{mailbox}:{received_value}:{digest}"


def _otp_seen_cache_key(mailbox: dict[str, Any]) -> str:
    provider = str(mailbox.get("provider") or "").strip().lower()
    provider_ref = str(mailbox.get("provider_ref") or "").strip().lower()
    address = str(mailbox.get("address") or "").strip().lower()
    return f"{provider}:{provider_ref}:{address}"


def _mailbox_seen_refs(mailbox: dict[str, Any]) -> set[str]:
    seen_value = mailbox.setdefault("_seen_code_message_refs", [])
    if not isinstance(seen_value, list):
        seen_value = []
        mailbox["_seen_code_message_refs"] = seen_value

    refs = {str(item) for item in seen_value if str(item)}
    cache_key = _otp_seen_cache_key(mailbox)
    with _otp_seen_lock:
        cached = _otp_seen_cache.get(cache_key, {})
        refs.update(str(item) for item in cached.get("refs", set()) if str(item))
    return refs


def _remember_seen_code(mailbox: dict[str, Any], ref: str, code: str) -> None:
    ref = str(ref or "").strip()
    if not ref:
        return

    seen_refs = mailbox.setdefault("_seen_code_message_refs", [])
    if not isinstance(seen_refs, list):
        seen_refs = []
        mailbox["_seen_code_message_refs"] = seen_refs
    if ref and ref not in {str(item) for item in seen_refs}:
        seen_refs.append(ref)

    cache_key = _otp_seen_cache_key(mailbox)
    with _otp_seen_lock:
        cached = _otp_seen_cache.setdefault(cache_key, {"refs": set()})
        if ref:
            cached.setdefault("refs", set()).add(ref)


def _message_matches_code_filters(mailbox: dict[str, Any], message: dict[str, Any]) -> bool:
    if str(mailbox.get("provider") or "") == GmailProvider.name:
        if not _message_targets_address(message, str(mailbox.get("address") or "")):
            return False
    subject_include = str(mailbox.get("subject_include") or "").strip().lower()
    return not subject_include or subject_include in str(message.get("subject") or "").lower()


def _message_before_code_boundary(
    mailbox: dict[str, Any], message: dict[str, Any]
) -> bool:
    """Check if message arrived before the code boundary timestamp."""
    boundary = mailbox.get("_code_not_before")
    received_at = message.get("received_at")
    if not isinstance(boundary, datetime) or not isinstance(received_at, datetime):
        return False
    if not received_at.tzinfo:
        received_at = received_at.replace(tzinfo=timezone.utc)
    return received_at < boundary


def _parse_received_at(value: Any) -> datetime | None:
    if isinstance(value, (int, float)):
        try:
            return datetime.fromtimestamp(float(value), tz=timezone.utc)
        except Exception:
            return None
    text = str(value or "").strip()
    if not text:
        return None
    try:
        date = datetime.fromisoformat(
            text[:-1] + "+00:00" if text.endswith("Z") else text
        )
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    try:
        date = parsedate_to_datetime(text)
        return date if date.tzinfo else date.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _safe_alias_tag(value: str) -> str:
    tag = re.sub(r"[^a-z0-9]+", "", str(value or "").lower())
    return tag[:64]


def _gmail_base_address(value: str) -> str:
    email = str(value or "").strip().lower()
    if "@" not in email:
        return ""
    local, domain = email.rsplit("@", 1)
    return f"{local.split('+', 1)[0]}@{domain}"


def _gmail_entry_matches_address(entry: dict, address: str) -> bool:
    user = str(entry.get("user") or entry.get("email") or "").strip().lower()
    target = str(address or "").strip().lower()
    if not user or not target:
        return False
    return _gmail_base_address(user) == _gmail_base_address(target)


def _message_targets_address(message: dict[str, Any], address: str) -> bool:
    target = str(address or "").strip().lower()
    if not target:
        return True
    recipients = message.get("recipients")
    if isinstance(recipients, list):
        haystack = " ".join(str(item or "") for item in recipients).lower()
    else:
        haystack = " ".join(
            str(message.get(key) or "")
            for key in ("to", "recipient", "delivered_to", "headers")
        ).lower()
    if target in haystack:
        return True
    return _gmail_base_address(target) == target and target in haystack


# ── Provider classes ────────────────────────────────────────────────


class OutlookTokenError(RuntimeError):
    """refresh_token exchange failed (invalid/expired credentials)."""


class BaseMailProvider:
    """Abstract base for mail providers."""

    name = "unknown"

    def __init__(self, conf: dict, provider_ref: str = ""):
        self.conf = conf
        self.provider_ref = provider_ref

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        raise NotImplementedError

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        raise NotImplementedError

    def wait_for_code(self, mailbox: dict[str, Any]) -> str | None:
        seen_refs = _mailbox_seen_refs(mailbox)

        deadline = time.monotonic() + self.conf["wait_timeout"]
        while time.monotonic() < deadline:
            message = self.fetch_latest_message(mailbox)
            if message:
                ref = _message_tracking_ref(message)
                if ref not in seen_refs:
                    code = _extract_code(message)
                    if code:
                        _remember_seen_code(mailbox, ref, code)
                        return code
                    seen_refs.add(ref)
            time.sleep(max(0.2, self.conf["wait_interval"]))
        return None

    def close(self) -> None:
        pass


class OutlookTokenProvider(BaseMailProvider):
    """Use Outlook/Hotmail refresh_token to read verification codes.

    Pool entries: email----password----client_id----refresh_token
    Supports Graph API and IMAP modes for reading mail.
    """

    name = "outlook_token"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.label = str(entry.get("label") or self.provider_ref)
        self.pool = parse_outlook_credentials(
            str(entry.get("mailboxes") or entry.get("pool") or "")
        )
        self.mode = str(entry.get("mode") or "graph").strip().lower() or "graph"
        if self.mode not in {"graph", "imap", "auto"}:
            self.mode = "graph"
        self.imap_host = (
            str(entry.get("imap_host") or OUTLOOK_DEFAULT_IMAP_HOST).strip()
            or OUTLOOK_DEFAULT_IMAP_HOST
        )
        self.message_limit = max(1, int(entry.get("message_limit") or 10))
        self.session = self._make_session()

    def _make_session(self):
        proxy = str(self.conf.get("proxy") or "").strip()
        kwargs = {"impersonate": "chrome", "verify": False}
        if proxy:
            kwargs["proxy"] = proxy
        return requests.Session(**kwargs)

    def close(self) -> None:
        self.session.close()

    # ── Token exchange ──────────────────────────────────────────

    def _exchange_refresh_token(
        self, client_id: str, refresh_token: str, scope: str
    ) -> str:
        resp = self.session.post(
            OUTLOOK_TOKEN_URL,
            data={
                "client_id": client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": scope,
            },
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "User-Agent": self.conf["user_agent"],
            },
            timeout=self.conf["request_timeout"],
            verify=False,
        )
        try:
            data = resp.json()
        except Exception:
            data = {}
        if resp.status_code != 200:
            detail = (
                data.get("error_description")
                or data.get("error")
                or resp.text[:300]
            )
            raise OutlookTokenError(
                f"OutlookToken refresh failed: HTTP {resp.status_code}, {detail}"
            )
        access_token = str(data.get("access_token") or "").strip()
        if not access_token:
            raise OutlookTokenError(
                "OutlookToken refresh response missing access_token"
            )
        return access_token

    def _cached_access_token(
        self, mailbox: dict[str, Any], client_id: str, refresh_token: str, scope: str
    ) -> str:
        """Cache access_token for 10 min to avoid rate limits during polling."""
        cache = mailbox.get("_outlook_token_cache")
        if not isinstance(cache, dict):
            cache = {}
            mailbox["_outlook_token_cache"] = cache
        cached = cache.get(scope)
        if (
            isinstance(cached, tuple)
            and len(cached) == 2
            and time.monotonic() < cached[1]
        ):
            return str(cached[0])
        token = self._exchange_refresh_token(client_id, refresh_token, scope)
        cache[scope] = (token, time.monotonic() + 600)
        return token

    # ── Mailbox creation ─────────────────────────────────────────

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        if not self.pool:
            raise RuntimeError(
                "OutlookToken pool is empty. "
                "Import email----password----client_id----refresh_token lines."
            )
        with _outlook_token_state_lock:
            store = _load_state()
            credential = next(
                (
                    item
                    for item in self.pool
                    if _entry_available(store.get(item["email"].strip().lower()))
                ),
                None,
            )
            if credential is None:
                raise RuntimeError(
                    f"[{self.label}] OutlookToken pool exhausted "
                    f"({len(self.pool)} total). "
                    f"All emails used/failed. Import new emails or reset pool state."
                )
            store[credential["email"].strip().lower()] = {
                "state": "in_use",
                "reason": "",
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            _save_state(store)

        return {
            "provider": self.name,
            "provider_ref": self.provider_ref,
            "address": credential["email"],
            "label": self.label,
            "client_id": credential["client_id"],
            "refresh_token": credential["refresh_token"],
        }

    # ── Graph API mail reading ───────────────────────────────────

    def _read_graph(self, access_token: str) -> list[dict[str, Any]]:
        resp = self.session.get(
            OUTLOOK_GRAPH_MESSAGES_URL,
            headers={
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json",
                "User-Agent": self.conf["user_agent"],
            },
            params={
                "$top": self.message_limit,
                "$orderby": "receivedDateTime desc",
                "$select": "subject,receivedDateTime,from,body,bodyPreview",
            },
            timeout=self.conf["request_timeout"],
            verify=False,
        )
        try:
            data = resp.json()
        except Exception:
            data = {}
        if resp.status_code != 200:
            detail = (
                data.get("error", {}).get("message")
                if isinstance(data.get("error"), dict)
                else resp.text[:300]
            )
            raise RuntimeError(
                f"OutlookToken Graph failed: HTTP {resp.status_code}, {detail}"
            )
        items = data.get("value") if isinstance(data, dict) else None
        return [item for item in items if isinstance(item, dict)] if isinstance(items, list) else []

    @staticmethod
    def _graph_sender(message: dict[str, Any]) -> str:
        sender = message.get("from") or {}
        if isinstance(sender, dict):
            address = sender.get("emailAddress") or {}
            if isinstance(address, dict):
                return str(address.get("address") or address.get("name") or "")
        return ""

    def _normalize_graph_item(
        self, mailbox: dict[str, Any], item: dict[str, Any]
    ) -> dict[str, Any]:
        body = item.get("body") if isinstance(item.get("body"), dict) else {}
        content_type = str(body.get("contentType") or "").lower()
        content = str(body.get("content") or "")
        text_content = (
            content if content_type != "html" else str(item.get("bodyPreview") or "")
        )
        html_content = content if content_type == "html" else ""
        return {
            "provider": self.name,
            "mailbox": mailbox["address"],
            "message_id": str(item.get("id") or ""),
            "subject": str(item.get("subject") or ""),
            "sender": self._graph_sender(item),
            "text_content": text_content,
            "html_content": html_content,
            "received_at": _parse_received_at(item.get("receivedDateTime")),
            "raw": item,
        }

    def _graph_messages(
        self, mailbox: dict[str, Any], access_token: str
    ) -> list[dict[str, Any]]:
        return [
            self._normalize_graph_item(mailbox, item)
            for item in self._read_graph(access_token)
        ]

    # ── IMAP mail reading ────────────────────────────────────────

    def _imap_messages(
        self, mailbox: dict[str, Any], access_token: str
    ) -> list[dict[str, Any]]:
        auth_string = (
            f"user={mailbox['address']}\x01auth=Bearer {access_token}\x01\x01"
        )
        imap = imaplib.IMAP4_SSL(self.imap_host)
        try:
            imap.authenticate("XOAUTH2", lambda _: auth_string.encode("utf-8"))
            status, _ = imap.select("INBOX", readonly=True)
            if status != "OK":
                raise RuntimeError("OutlookToken IMAP select INBOX failed")
            status, data = imap.uid("search", None, "ALL")
            if status != "OK" or not data or not data[0]:
                return []
            uids = data[0].split()[-self.message_limit :]
            messages: list[dict[str, Any]] = []
            for uid in reversed(uids):
                status, fetched = imap.uid("fetch", uid, "(RFC822)")
                if status != "OK":
                    continue
                raw_payload = next(
                    (
                        part[1]
                        for part in fetched
                        if isinstance(part, tuple) and isinstance(part[1], bytes)
                    ),
                    b"",
                )
                if raw_payload:
                    message = self._parse_imap_message(mailbox, raw_payload)
                    message["imap_uid"] = uid.decode("utf-8", errors="replace")
                    messages.append(message)
            return messages
        finally:
            try:
                imap.logout()
            except Exception:
                pass

    def _parse_imap_message(self, mailbox: dict[str, Any], raw: bytes) -> dict[str, Any]:
        message = message_from_bytes(raw, policy=policy.default)
        try:
            received = _parse_received_at(
                parsedate_to_datetime(str(message.get("Date") or ""))
            )
        except Exception:
            received = None
        plain: list[str] = []
        html: list[str] = []
        for part in message.walk() if message.is_multipart() else [message]:
            if part.get_content_maintype() == "multipart":
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if not payload:
                continue
            if part.get_content_type() == "text/html":
                html.append(str(payload))
            else:
                plain.append(str(payload))

        def _decode(value: str | None) -> str:
            if not value:
                return ""
            try:
                return str(make_header(decode_header(value)))
            except Exception:
                return value

        return {
            "provider": self.name,
            "mailbox": mailbox["address"],
            "message_id": _decode(str(message.get("Message-ID") or "")),
            "subject": _decode(str(message.get("Subject") or "")),
            "sender": _decode(str(message.get("From") or "")),
            "text_content": "\n".join(plain).strip(),
            "html_content": "\n".join(html).strip(),
            "received_at": received,
            "raw": None,
        }

    # ── Message fetching ─────────────────────────────────────────

    def fetch_recent_messages(self, mailbox: dict[str, Any]) -> list[dict[str, Any]]:
        client_id = str(mailbox.get("client_id") or "").strip()
        refresh_token = str(mailbox.get("refresh_token") or "").strip()
        if not client_id or not refresh_token:
            raise RuntimeError(
                "OutlookToken mailbox missing client_id or refresh_token"
            )
        errors: list[str] = []
        if self.mode in {"graph", "auto"}:
            try:
                access_token = self._cached_access_token(
                    mailbox, client_id, refresh_token, OUTLOOK_GRAPH_SCOPE
                )
                return self._graph_messages(mailbox, access_token)
            except Exception as error:
                if self.mode == "graph":
                    raise
                errors.append(f"graph: {error}")
        if self.mode in {"imap", "auto"}:
            try:
                access_token = self._cached_access_token(
                    mailbox, client_id, refresh_token, OUTLOOK_IMAP_SCOPE
                )
                return self._imap_messages(mailbox, access_token)
            except Exception as error:
                if self.mode == "imap":
                    raise
                errors.append(f"imap: {error}")
        if errors:
            raise RuntimeError("; ".join(errors))
        return []

    def fetch_latest_message(self, mailbox: dict[str, Any]) -> dict[str, Any] | None:
        messages = self.fetch_recent_messages(mailbox)
        return messages[0] if messages else None

    def wait_for_code(self, mailbox: dict[str, Any]) -> str | None:
        """Scan recent N messages for verification code, not just the latest."""
        seen_refs = _mailbox_seen_refs(mailbox)

        deadline = time.monotonic() + self.conf["wait_timeout"]
        while time.monotonic() < deadline:
            for message in self.fetch_recent_messages(mailbox):
                # Skip messages from before the code boundary
                if _message_before_code_boundary(mailbox, message):
                    continue
                subject_include = str(mailbox.get("subject_include") or "").strip().lower()
                if subject_include and subject_include not in str(message.get("subject") or "").lower():
                    continue
                ref = _message_tracking_ref(message)
                if ref in seen_refs:
                    continue
                code = _extract_code(message)
                if code:
                    logger.debug(
                        "Verification code candidate from mailbox=%s "
                        "credential_email=%s subject=%s sender=%s received_at=%s code=%s",
                        mailbox.get("address", ""),
                        mailbox.get("_credential_email", ""),
                        message.get("subject", ""),
                        message.get("sender", ""),
                        message.get("received_at", ""),
                        code,
                    )
                    _remember_seen_code(mailbox, ref, code)
                    return code
                seen_refs.add(ref)
            time.sleep(max(0.2, self.conf["wait_interval"]))
        return None


class GmailProvider(BaseMailProvider):
    """Use a Gmail account and app password to read OpenAI OTP emails.

    Registration creates plus-address aliases from one Gmail inbox:
    user@gmail.com -> user+randomtag@gmail.com.
    """

    name = "gmail"

    def __init__(self, entry: dict, conf: dict):
        super().__init__(conf, str(entry.get("provider_ref") or ""))
        self.label = str(entry.get("label") or self.provider_ref)
        self.user = str(entry.get("user") or entry.get("email") or "").strip()
        self.app_password = str(entry.get("app_password") or "").replace(" ", "")
        self.imap_host = str(entry.get("imap_host") or "imap.gmail.com").strip()
        self.imap_port = int(entry.get("imap_port") or 993)
        self.imap_timeout = max(1.0, float(conf.get("request_timeout") or 30))
        self.message_limit = max(1, int(entry.get("message_limit") or 10))
        self.alias_length = max(4, int(entry.get("alias_length") or 8))
        self.alias_prefix = str(entry.get("alias_prefix") or "").strip()
        if not self.user or "@" not in self.user:
            raise RuntimeError("Gmail provider requires user")
        if not self.app_password:
            raise RuntimeError("Gmail provider requires app_password")

    def create_mailbox(self, username: str | None = None) -> dict[str, Any]:
        address = self._alias_address(username)
        return {
            "provider": self.name,
            "provider_ref": self.provider_ref,
            "address": address,
            "label": self.label,
            "_credential_email": self.user,
        }

    def _alias_address(self, username: str | None = None) -> str:
        local, domain = self.user.rsplit("@", 1)
        base_local = local.split("+", 1)[0]
        tag = _safe_alias_tag(username or "")
        if not tag:
            alphabet = string.ascii_lowercase + string.digits
            tag = "".join(secrets.choice(alphabet) for _ in range(self.alias_length))
        if self.alias_prefix:
            tag = f"{_safe_alias_tag(self.alias_prefix)}{tag}"
        return f"{base_local}+{tag}@{domain}"

    def fetch_recent_messages(self, mailbox: dict[str, Any]) -> list[dict[str, Any]]:
        target_address = str(mailbox.get("address") or "").strip()
        logger.debug(
            "Gmail IMAP connect: host=%s port=%s timeout=%s user=%s target=%s",
            self.imap_host,
            self.imap_port,
            self.imap_timeout,
            self.user,
            target_address,
        )
        imap = imaplib.IMAP4_SSL(
            self.imap_host,
            self.imap_port,
            timeout=self.imap_timeout,
        )
        try:
            imap.login(self.user, self.app_password)
            logger.debug("Gmail IMAP login OK: user=%s", self.user)
            status, _ = imap.select("INBOX", readonly=True)
            if status != "OK":
                raise RuntimeError("Gmail IMAP select INBOX failed")
            logger.debug("Gmail IMAP select INBOX OK: target=%s", target_address)

            search_query = f'(TO "{target_address}")' if target_address else "ALL"
            status, data = imap.uid("search", None, search_query)
            if (status != "OK" or not data or not data[0]) and search_query != "ALL":
                logger.debug(
                    "Gmail IMAP target search returned empty: target=%s; falling back to ALL",
                    target_address,
                )
                status, data = imap.uid("search", None, "ALL")
            if status != "OK" or not data or not data[0]:
                logger.debug("Gmail IMAP search returned no messages: target=%s", target_address)
                return []
            uids = data[0].split()[-self.message_limit :]
            logger.debug(
                "Gmail IMAP search OK: target=%s matched=%s fetching=%s",
                target_address,
                len(data[0].split()),
                len(uids),
            )
            messages: list[dict[str, Any]] = []
            for uid in reversed(uids):
                status, fetched = imap.uid("fetch", uid, "(RFC822)")
                if status != "OK":
                    logger.debug("Gmail IMAP fetch skipped: uid=%s status=%s", uid, status)
                    continue
                raw_payload = next(
                    (
                        part[1]
                        for part in fetched
                        if isinstance(part, tuple) and isinstance(part[1], bytes)
                    ),
                    b"",
                )
                if raw_payload:
                    message = self._parse_imap_message(mailbox, raw_payload)
                    message["imap_uid"] = uid.decode("utf-8", errors="replace")
                    logger.debug(
                        "Gmail IMAP message candidate: target=%s subject=%s sender=%s "
                        "recipients=%s received_at=%s",
                        target_address,
                        message.get("subject", ""),
                        message.get("sender", ""),
                        message.get("recipients", []),
                        message.get("received_at", ""),
                    )
                    messages.append(message)
            return messages
        finally:
            try:
                imap.logout()
            except Exception:
                pass

    def _parse_imap_message(self, mailbox: dict[str, Any], raw: bytes) -> dict[str, Any]:
        message = message_from_bytes(raw, policy=policy.default)
        plain: list[str] = []
        html: list[str] = []
        for part in message.walk() if message.is_multipart() else [message]:
            if part.get_content_maintype() == "multipart":
                continue
            try:
                payload = part.get_content()
            except Exception:
                continue
            if not payload:
                continue
            if part.get_content_type() == "text/html":
                html.append(str(payload))
            else:
                plain.append(str(payload))

        def _decode(value: str | None) -> str:
            if not value:
                return ""
            try:
                return str(make_header(decode_header(value)))
            except Exception:
                return value

        recipients = [
            _decode(str(message.get(header) or ""))
            for header in ("To", "Delivered-To", "X-Original-To", "Envelope-To")
            if str(message.get(header) or "").strip()
        ]

        return {
            "provider": self.name,
            "mailbox": mailbox["address"],
            "message_id": _decode(str(message.get("Message-ID") or "")),
            "subject": _decode(str(message.get("Subject") or "")),
            "sender": _decode(str(message.get("From") or "")),
            "recipients": recipients,
            "text_content": "\n".join(plain).strip(),
            "html_content": "\n".join(html).strip(),
            "received_at": _parse_received_at(str(message.get("Date") or "")),
            "raw": None,
        }

    def wait_for_code(self, mailbox: dict[str, Any]) -> str | None:
        """Scan recent messages for a code addressed to the target alias."""
        seen_refs = _mailbox_seen_refs(mailbox)

        deadline = time.monotonic() + self.conf["wait_timeout"]
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            remaining = max(0.0, deadline - time.monotonic())
            logger.debug(
                "Gmail OTP poll attempt=%s mailbox=%s credential_email=%s remaining=%.1fs",
                attempt,
                mailbox.get("address", ""),
                mailbox.get("_credential_email", ""),
                remaining,
            )
            messages = self.fetch_recent_messages(mailbox)
            logger.debug(
                "Gmail OTP poll attempt=%s fetched=%s mailbox=%s",
                attempt,
                len(messages),
                mailbox.get("address", ""),
            )
            for message in messages:
                if _message_before_code_boundary(mailbox, message):
                    logger.debug(
                        "Gmail OTP candidate skipped before boundary: subject=%s received_at=%s",
                        message.get("subject", ""),
                        message.get("received_at", ""),
                    )
                    continue
                if not _message_targets_address(message, str(mailbox.get("address") or "")):
                    logger.debug(
                        "Gmail OTP candidate skipped target mismatch: mailbox=%s recipients=%s subject=%s",
                        mailbox.get("address", ""),
                        message.get("recipients", []),
                        message.get("subject", ""),
                    )
                    continue
                subject_include = str(mailbox.get("subject_include") or "").strip().lower()
                if subject_include and subject_include not in str(message.get("subject") or "").lower():
                    logger.debug(
                        "Gmail OTP candidate skipped subject filter: include=%s subject=%s",
                        subject_include,
                        message.get("subject", ""),
                    )
                    continue
                ref = _message_tracking_ref(message)
                if ref in seen_refs:
                    logger.debug(
                        "Gmail OTP candidate skipped already seen: subject=%s received_at=%s",
                        message.get("subject", ""),
                        message.get("received_at", ""),
                    )
                    continue
                code = _extract_code(message)
                if code:
                    logger.debug(
                        "Verification code candidate from mailbox=%s "
                        "credential_email=%s subject=%s sender=%s received_at=%s code=%s",
                        mailbox.get("address", ""),
                        mailbox.get("_credential_email", ""),
                        message.get("subject", ""),
                        message.get("sender", ""),
                        message.get("received_at", ""),
                        code,
                    )
                    _remember_seen_code(mailbox, ref, code)
                    return code
                logger.debug(
                    "Gmail OTP candidate had no code: subject=%s sender=%s received_at=%s",
                    message.get("subject", ""),
                    message.get("sender", ""),
                    message.get("received_at", ""),
                )
                seen_refs.add(ref)
            time.sleep(max(0.2, self.conf["wait_interval"]))
        logger.debug(
            "Gmail OTP polling timed out: mailbox=%s credential_email=%s attempts=%s",
            mailbox.get("address", ""),
            mailbox.get("_credential_email", ""),
            attempt,
        )
        return None


# ── Public API ─────────────────────────────────────────────────────


def _make_config(mail_config: dict) -> dict:
    """Normalize mail config for provider construction."""
    return {
        "request_timeout": float(mail_config.get("request_timeout") or 30),
        "wait_timeout": float(mail_config.get("wait_timeout") or 30),
        "wait_interval": float(mail_config.get("wait_interval") or 2),
        "user_agent": str(
            mail_config.get("user_agent")
            or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        ),
        "proxy": str(mail_config.get("proxy") or "").strip(),
    }


def _enabled_provider_entries(mail_config: dict) -> list[dict[str, Any]]:
    providers = (
        mail_config.get("providers")
        if isinstance(mail_config.get("providers"), list)
        else []
    )
    entries: list[dict[str, Any]] = []
    for i, item in enumerate(providers):
        if not isinstance(item, dict) or not item.get("enable", True):
            continue
        provider_type = str(item.get("type") or "").strip()
        if provider_type not in {"outlook_token", "gmail"}:
            continue
        entry = dict(item)
        entry["provider_ref"] = str(entry.get("provider_ref") or f"{provider_type}#{i + 1}")
        entries.append(entry)
    return entries


def _build_provider(entry: dict[str, Any], conf: dict) -> BaseMailProvider:
    provider_type = str(entry.get("type") or "").strip()
    if provider_type == "outlook_token":
        return OutlookTokenProvider(entry, conf)
    if provider_type == "gmail":
        return GmailProvider(entry, conf)
    raise RuntimeError(f"Unsupported mail provider type: {provider_type}")


def create_mailbox(mail_config: dict, username: str | None = None) -> dict:
    """Create a mailbox from the first enabled provider with capacity."""
    entries = _enabled_provider_entries(mail_config)
    if not entries:
        raise RuntimeError("No enabled mail provider found in mail.providers config")

    conf = _make_config(mail_config)
    last_error = ""
    for entry in entries:
        provider = _build_provider(entry, conf)
        try:
            mailbox = provider.create_mailbox(username)
            mailbox["_code_not_before"] = datetime.now(timezone.utc)
            return mailbox
        except RuntimeError as error:
            last_error = str(error)
        finally:
            provider.close()
    raise RuntimeError(last_error or "All mail providers exhausted")


def mailbox_for_address(mail_config: dict, address: str) -> dict[str, Any]:
    """Build a mailbox descriptor for an existing email address."""
    target = str(address or "").strip()
    if not target:
        raise RuntimeError("Mailbox address is required")

    for entry in _enabled_provider_entries(mail_config):
        provider_type = str(entry.get("type") or "")
        if provider_type == "outlook_token":
            for credential in parse_outlook_credentials(
                str(entry.get("mailboxes") or entry.get("pool") or "")
            ):
                credential_email = str(credential.get("email") or "").strip()
                if credential_email.lower() != target.lower():
                    continue
                return {
                    "provider": "outlook_token",
                    "provider_ref": str(entry.get("provider_ref") or ""),
                    "address": target,
                    "label": str(entry.get("label") or ""),
                    "client_id": credential.get("client_id", ""),
                    "refresh_token": credential.get("refresh_token", ""),
                    "_credential_email": credential_email,
                }
        elif provider_type == "gmail" and _gmail_entry_matches_address(entry, target):
            return {
                "provider": "gmail",
                "provider_ref": str(entry.get("provider_ref") or ""),
                "address": target,
                "label": str(entry.get("label") or ""),
                "_credential_email": str(entry.get("user") or entry.get("email") or "").strip(),
            }

    raise RuntimeError(f"No mail provider credentials found for {target}")


def _provider_for_mailbox(mail_config: dict, mailbox: dict):
    entries = _enabled_provider_entries(mail_config)
    provider_ref = str(mailbox.get("provider_ref") or "")
    provider_name = str(mailbox.get("provider") or "")
    address = str(mailbox.get("address") or "").strip().lower()

    entry = next(
        (item for item in entries if item.get("provider_ref") == provider_ref),
        None,
    )
    if entry is None and address:
        try:
            matched = mailbox_for_address(mail_config, address)
            provider_ref = str(matched.get("provider_ref") or "")
            provider_name = str(matched.get("provider") or provider_name)
            mailbox.update({key: value for key, value in matched.items() if value})
            entry = next(
                (item for item in entries if item.get("provider_ref") == provider_ref),
                None,
            )
        except RuntimeError as error:
            if provider_name == OutlookTokenProvider.name or any(
                item.get("type") == "outlook_token" for item in entries
            ):
                raise RuntimeError(
                    f"No outlook_token mailbox credentials found for {address}"
                ) from error
            raise
    if entry is None and provider_name:
        entry = next(
            (item for item in entries if item.get("type") == provider_name),
            None,
        )
    if entry is None:
        raise RuntimeError(f"No mail provider found (ref={provider_ref})")

    conf = _make_config(mail_config)
    provider = _build_provider(entry, conf)
    if str(entry.get("type") or "") == "outlook_token":
        matched_email = _populate_mailbox_credentials(mailbox, entry)
    else:
        matched_email = _populate_gmail_mailbox(mailbox, entry)
    return provider, entry, matched_email


def prime_seen_code_messages(mail_config: dict, mailbox: dict) -> int:
    """Mark currently visible code emails as seen before requesting a new OTP."""
    provider, _entry, _matched_email = _provider_for_mailbox(mail_config, mailbox)
    count = 0
    try:
        for message in provider.fetch_recent_messages(mailbox):
            if not _message_matches_code_filters(mailbox, message):
                continue
            code = _extract_code(message)
            if not code:
                continue
            _remember_seen_code(mailbox, _message_tracking_ref(message), code)
            count += 1
        logger.debug(
            "Primed OTP seen cache: mailbox=%s credential_email=%s count=%s",
            mailbox.get("address", ""),
            mailbox.get("_credential_email", ""),
            count,
        )
        return count
    finally:
        provider.close()


def wait_for_code(mail_config: dict, mailbox: dict) -> str | None:
    """Wait for verification code from the mailbox's configured provider."""
    provider, entry, matched_email = _provider_for_mailbox(mail_config, mailbox)
    try:
        if matched_email and str(entry.get("type") or "") == "outlook_token":
            logger.debug(
                "Using OutlookToken credentials for mailbox address=%s credential_email=%s",
                mailbox.get("address", ""),
                matched_email,
            )
        elif matched_email:
            logger.debug(
                "Using Gmail credentials for mailbox address=%s credential_email=%s",
                mailbox.get("address", ""),
                matched_email,
            )
        return provider.wait_for_code(mailbox)
    finally:
        provider.close()


def _populate_mailbox_credentials(mailbox: dict, entry: dict) -> str:
    """Fill client_id/refresh_token for an existing mailbox from provider config."""
    if mailbox.get("client_id") and mailbox.get("refresh_token"):
        return str(mailbox.get("_credential_email") or mailbox.get("address") or "")

    address = str(mailbox.get("address") or "").strip().lower()
    if not address:
        return ""

    for credential in parse_outlook_credentials(
        str(entry.get("mailboxes") or entry.get("pool") or "")
    ):
        credential_email = str(credential.get("email") or "").strip()
        if credential_email.lower() != address:
            continue
        mailbox.setdefault("client_id", credential.get("client_id", ""))
        mailbox.setdefault("refresh_token", credential.get("refresh_token", ""))
        mailbox.setdefault("label", str(entry.get("label") or ""))
        mailbox["_credential_email"] = credential_email
        return credential_email
    return ""


def _populate_gmail_mailbox(mailbox: dict, entry: dict) -> str:
    credential_email = str(entry.get("user") or entry.get("email") or "").strip()
    if not credential_email:
        return ""
    mailbox.setdefault("provider", GmailProvider.name)
    mailbox.setdefault("provider_ref", str(entry.get("provider_ref") or ""))
    mailbox.setdefault("label", str(entry.get("label") or ""))
    mailbox["_credential_email"] = credential_email
    return credential_email


def mark_mailbox_result(
    mailbox: dict,
    *,
    success: bool,
    error: Exception | str | None = None,
) -> None:
    """Update pool state after registration attempt.

    - Success → mark as 'used'
    - Token invalid → mark as 'token_invalid'
    - Other failure → mark as 'failed'
    """
    if str(mailbox.get("provider") or "") != OutlookTokenProvider.name:
        return
    address = str(mailbox.get("address") or "").strip()
    if not address:
        return
    if success:
        _set_state(address, "used")
        return
    reason = str(error or "").strip()
    if (
        isinstance(error, OutlookTokenError)
        or "OutlookToken" in reason
        or "access_token" in reason
    ):
        _set_state(address, "token_invalid", reason[:300])
    else:
        _set_state(address, "failed", reason[:300])


def release_mailbox(mailbox: dict) -> None:
    """Release in_use state back to unused (if registration is abandoned)."""
    if str(mailbox.get("provider") or "") != OutlookTokenProvider.name:
        return
    _release_state(str(mailbox.get("address") or ""))
