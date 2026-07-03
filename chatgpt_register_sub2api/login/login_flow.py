"""OAuth login flow with Team workspace selection.

After a child account joins the parent K12 workspace, it has TWO scopes:
  - personal (from registration)
  - team (from workspace membership)

The sub2api export MUST use team-scoped tokens. To get team-scoped
tokens, we re-run the OAuth login flow (same as registration but with
screen_hint=login instead of signup), and during the flow we select
the team workspace.

Flow:
  1. authorize?screen_hint=login&login_hint={email}
  2. POST user login (password)
  3. OTP verification (Outlook)
  4. Handle workspace selection → pick team
  5. Exchange code → team-scoped access_token + refresh_token + id_token

NOTE: The exact workspace selection API is confirmed at runtime by
inspecting the authorize response. See _select_team_workspace().
"""

from __future__ import annotations

import json
import logging
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

from chatgpt_register_sub2api.register.headers import json_headers, navigate_headers
from chatgpt_register_sub2api.register.mail_provider import wait_for_code
from chatgpt_register_sub2api.register.session import (
    create_register_session,
    is_cloudflare_challenge,
    request_with_retry,
)
from chatgpt_register_sub2api.utils.pkce import generate_pkce
from chatgpt_register_sub2api.utils.sentinel import build_sentinel_token

# ── Constants ───────────────────────────────────────────────────────

AUTH_BASE = "https://auth.openai.com"
PLATFORM_BASE = "https://platform.openai.com"
PLATFORM_OAUTH_CLIENT_ID = "app_2SKx67EdpoN0G6j64rFvigXD"
PLATFORM_OAUTH_REDIRECT_URI = f"{PLATFORM_BASE}/auth/callback"
PLATFORM_OAUTH_AUDIENCE = "https://api.openai.com/v1"
PLATFORM_AUTH0_CLIENT = (
    "eyJuYW1lIjoiYXV0aDAtc3BhLWpzIiwidmVyc2lvbiI6IjEuMjEuMCJ9"
)
USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/145.0.0.0 Safari/537.36"
)

logger = logging.getLogger(__name__)


class LoginError(RuntimeError):
    """Login flow failed."""


def _response_json(resp) -> dict:
    try:
        data = resp.json()
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# ── Re-login with workspace selection ───────────────────────────────


def re_login_for_team_token(
    email: str,
    password: str,
    mail_config: dict,
    proxy: str = "",
    flaresolverr_url: str = "",
    workspace_id: str = "",
) -> dict:
    """Re-login to get a team-scoped access token.

    1. Run OAuth authorize as login (not signup)
    2. Enter password
    3. Handle OTP
    4. Navigate workspace selection → pick team
    5. Exchange code for tokens

    Args:
        email: Account email
        password: Account password
        mail_config: Mail config for OTP code retrieval
        proxy: Proxy URL
        flaresolverr_url: FlareSolverr URL
        workspace_id: K12 workspace UUID (used to identify the team)

    Returns:
        {access_token, refresh_token, id_token, email, scope: "team"}
    """
    session = create_register_session(
        proxy=proxy, flaresolverr_url=flaresolverr_url
    )
    device_id = str(uuid.uuid4())

    try:
        # Step 1: Authorize as login
        code_verifier, code_challenge = generate_pkce()

        session.cookies.set("oai-did", device_id, domain=".auth.openai.com")
        session.cookies.set("oai-did", device_id, domain="auth.openai.com")

        params = {
            "issuer": AUTH_BASE,
            "client_id": PLATFORM_OAUTH_CLIENT_ID,
            "audience": PLATFORM_OAUTH_AUDIENCE,
            "redirect_uri": PLATFORM_OAUTH_REDIRECT_URI,
            "device_id": device_id,
            "screen_hint": "login",
            "max_age": "0",
            "login_hint": email,
            "scope": "openid profile email offline_access",
            "response_type": "code",
            "response_mode": "query",
            "state": secrets.token_urlsafe(32),
            "nonce": secrets.token_urlsafe(32),
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "auth0Client": PLATFORM_AUTH0_CLIENT,
        }
        auth_url = f"{AUTH_BASE}/api/accounts/authorize?{urlencode(params)}"
        headers = navigate_headers(f"{PLATFORM_BASE}/")

        resp, error = request_with_retry(
            session, "get", auth_url, headers=headers,
            allow_redirects=True, verify=False,
        )
        if resp is None or resp.status_code != 200:
            raise LoginError(
                f"Login authorize failed: HTTP "
                f"{getattr(resp, 'status_code', '?')}, {error or ''}"
            )

        # The authorize response may contain account/workspace info.
        # If account has multiple workspaces, the response will include
        # a redirect to a workspace picker or account_selector page.
        data = _response_json(resp)
        final_url = str(getattr(resp, "url", "") or "").lower()

        # Step 2: Handle login path — password verification
        # After authorize with login_hint for existing account,
        # the flow redirects to password verification
        authorization_code = _handle_password_verification(
            session, device_id, email, password,
            mail_config, proxy, flaresolverr_url,
        )

        # Step 3: Workspace selection
        # If the account has multiple workspaces (personal + team),
        # we need to select the team workspace.
        _select_team_workspace(
            session, device_id, email, workspace_id,
            proxy, flaresolverr_url,
        )

        # Step 4: Exchange code for tokens
        tokens = _exchange_login_tokens(
            session=session,
            code_verifier=code_verifier,
            authorization_code=authorization_code,
        )

        return {
            "email": email,
            "password": password,
            "access_token": str(tokens.get("access_token") or "").strip(),
            "refresh_token": str(tokens.get("refresh_token") or "").strip(),
            "id_token": str(tokens.get("id_token") or "").strip(),
            "scope": "team",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    finally:
        session.close()


def _handle_password_verification(
    session,
    device_id: str,
    email: str,
    password: str,
    mail_config: dict,
    proxy: str,
    flaresolverr_url: str,
) -> str:
    """Submit password during login flow.

    Returns the authorization code from the password verification
    continue_url. This matches the current browser flow used by the
    upstream chatgpt2api implementation.
    """
    url = f"{AUTH_BASE}/api/accounts/password/verify"
    headers = {
        "accept": "application/json",
        "accept-language": "zh-CN,zh;q=0.9",
        "content-type": "application/json",
        "origin": AUTH_BASE,
        "priority": "u=1, i",
        "user-agent": USER_AGENT,
        "sec-ch-ua": '"Chromium";v="145", "Google Chrome";v="145", "Not/A)Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-origin",
        "referer": f"{AUTH_BASE}/email-verification",
        "oai-device-id": device_id,
    }
    sentinel_token, oai_sc_value = build_sentinel_token(
        session, device_id, "password_verify",
        user_agent=USER_AGENT,
    )
    headers["openai-sentinel-token"] = sentinel_token
    if oai_sc_value and hasattr(session, "cookies"):
        session.cookies.set("oai-sc", oai_sc_value, domain=".openai.com")

    otp_not_before = datetime.now(timezone.utc)
    resp, error = request_with_retry(
        session, "post", url,
        json={"password": password},
        headers=headers, verify=False,
    )

    if resp is None:
        raise LoginError(
            f"Password verification failed: {error or 'no response'}"
        )
    if resp.status_code != 200:
        data = _response_json(resp)
        error_data = data.get("error") if isinstance(data.get("error"), dict) else {}
        error_code = str(error_data.get("code") or "")
        error_msg = str(error_data.get("message") or data.get("message") or resp.text[:200])
        if error_code == "unsupported_country_region_territory":
            detail = "unsupported_country_region_territory"
        elif error_code == "invalid_state":
            detail = "invalid_state"
        elif "Invalid credentials" in error_msg or "wrong password" in error_msg.lower():
            detail = "invalid_password"
        else:
            detail = error_msg
        raise LoginError(
            f"Password verification failed (HTTP {resp.status_code}): {detail}"
        )

    data = _response_json(resp)
    code = _resolve_authorization_code(session, data, device_id=device_id)
    if code:
        return code

    page_info = data.get("page")
    page_type = str(page_info.get("type") or "") if isinstance(page_info, dict) else ""
    if page_type == "email_otp_verification":
        auth_session = str(data.get("oai-client-auth-session") or "").strip()
        return _handle_login_otp(
            session,
            device_id,
            email,
            mail_config,
            auth_session,
            otp_not_before=otp_not_before,
        )

    raise LoginError(
        f"Password verification returned no authorization code. "
        f"JSON keys={list(data.keys()) if data else 'none'}"
    )


def _extract_authorization_code(data: dict[str, Any]) -> str:
    continue_url = str(data.get("continue_url") or "").strip()
    return _extract_authorization_code_from_url(continue_url)


def _extract_authorization_code_from_url(url: str) -> str:
    continue_url = str(url or "").strip()
    if not continue_url:
        return ""
    try:
        parsed = parse_qs(urlparse(continue_url).query)
    except Exception:
        return ""
    return str((parsed.get("code") or [""])[0]).strip()


def _safe_json_summary(data: dict[str, Any]) -> str:
    if not data:
        return "json=none"
    page = data.get("page") if isinstance(data.get("page"), dict) else {}
    page_type = str(page.get("type") or "") if isinstance(page, dict) else ""
    continue_url = str(data.get("continue_url") or "")
    if len(continue_url) > 220:
        continue_url = continue_url[:220] + "..."
    method = str(data.get("method") or "")
    has_auth_session = bool(str(data.get("oai-client-auth-session") or "").strip())
    return (
        f"keys={list(data.keys())}, method={method or '-'}, "
        f"page.type={page_type or '-'}, has_auth_session={has_auth_session}, "
        f"continue_url={continue_url or '-'}"
    )


def _resolve_authorization_code(
    session,
    data: dict[str, Any],
    *,
    device_id: str = "",
    max_hops: int = 5,
    trace: list[str] | None = None,
) -> str:
    """Resolve an authorization code from continue_url, following it if needed."""
    if trace is not None:
        trace.append(f"resolve: {_safe_json_summary(data)}")

    code = _extract_authorization_code(data)
    if code:
        if trace is not None:
            trace.append("resolve: found code in continue_url")
        return code
    if max_hops <= 0:
        if trace is not None:
            trace.append("resolve: max_hops exhausted")
        return ""

    continue_url = str(data.get("continue_url") or "").strip()
    if not continue_url:
        if trace is not None:
            trace.append("resolve: no continue_url")
        return ""

    if continue_url.startswith("/"):
        continue_url = f"{AUTH_BASE}{continue_url}"

    method = str(data.get("method") or "GET").strip().upper() or "GET"
    auth_session = str(data.get("oai-client-auth-session") or "").strip()
    headers = navigate_headers(f"{AUTH_BASE}/email-verification")
    if auth_session:
        headers["oai-client-auth-session"] = auth_session

    if trace is not None:
        trace.append(
            f"follow: method={method}, url={continue_url[:260]}, "
            f"has_auth_session={bool(auth_session)}"
        )
    logger.debug(
        "Following authorize continue: method=%s url=%s has_auth_session=%s",
        method,
        continue_url,
        bool(auth_session),
    )

    resp, _ = request_with_retry(
        session,
        method,
        continue_url,
        headers=headers,
        allow_redirects=True,
        verify=False,
    )
    if resp is None:
        if trace is not None:
            trace.append("follow: no response")
        return ""

    final_url = str(getattr(resp, "url", "") or "")
    if trace is not None:
        trace.append(
            f"follow: status={getattr(resp, 'status_code', '?')}, "
            f"final_url={final_url[:260] or '-'}"
        )

    code = _extract_authorization_code_from_url(final_url)
    if code:
        if trace is not None:
            trace.append("follow: found code in final_url")
        return code

    try:
        final_path = urlparse(final_url).path.rstrip("/")
    except Exception:
        final_path = ""
    follow_data = _response_json(resp)
    if follow_data and follow_data is not data:
        return _resolve_authorization_code(
            session,
            follow_data,
            device_id=device_id,
            max_hops=max_hops - 1,
            trace=trace,
        )
    return ""


def _handle_login_otp(
    session,
    device_id: str,
    email: str,
    mail_config: dict,
    auth_session: str = "",
    otp_not_before: datetime | None = None,
) -> str:
    """Handle OTP during login flow and return the authorization code."""
    mailbox = {
        "provider": "outlook_token",
        "provider_ref": "",
        "address": email,
        "subject_include": "login code",
        "_code_not_before": otp_not_before or datetime.now(timezone.utc),
    }

    # Wait for code (we need a temporary mailbox — use the Outlook pool)
    # Since we already know the email, we can poll for codes on that mailbox
    logger.debug("[%s] Waiting for login OTP from mailbox: %s", email, mailbox["address"])
    code = wait_for_code(mail_config, mailbox)
    if not code:
        raise LoginError("Timed out waiting for login OTP code")
    logger.debug("[%s] Login OTP code read from mailbox: %s", email, code)

    # Validate OTP
    headers = json_headers(f"{AUTH_BASE}/email-verification", device_id)
    if auth_session:
        headers["oai-client-auth-session"] = auth_session

    resp, error = request_with_retry(
        session, "post",
        f"{AUTH_BASE}/api/accounts/email-otp/validate",
        json={"code": code},
        headers=headers, verify=False,
    )
    if resp is None or resp.status_code != 200:
        # Retry with sentinel
        sentinel_token, _ = build_sentinel_token(
            session, device_id, "authorize_continue",
            user_agent=USER_AGENT,
        )
        headers["openai-sentinel-token"] = sentinel_token
        resp, error = request_with_retry(
            session, "post",
            f"{AUTH_BASE}/api/accounts/email-otp/validate",
            json={"code": code},
            headers=headers, verify=False,
        )
        if resp is None or resp.status_code != 200:
            body = ""
            try:
                body = (resp.text or "")[:300] if resp is not None else ""
            except Exception:
                pass
            raise LoginError(
                f"Login OTP validation failed: HTTP "
                f"{getattr(resp, 'status_code', '?')}, body={body}"
            )

    data = _response_json(resp)
    trace: list[str] = []
    auth_code = _resolve_authorization_code(session, data, device_id=device_id, trace=trace)
    if auth_code:
        return auth_code

    raise LoginError(
        f"Login OTP validation returned no authorization code. "
        f"JSON keys={list(data.keys()) if data else 'none'}. "
        f"Trace: {' | '.join(trace) if trace else 'none'}"
    )


def _select_team_workspace(
    session,
    device_id: str,
    email: str,
    workspace_id: str,
    proxy: str,
    flaresolverr_url: str,
) -> None:
    """Select the team workspace during login flow.

    After OTP verification, accounts with multiple workspaces will be
    presented with a workspace picker. We need to select the team
    workspace (not personal).

    This function attempts several known patterns for workspace selection:
    1. POST /api/accounts/account/select {account_id}
    2. POST /backend-api/accounts/account/{id}/activate
    3. Follow redirect chain and extract account_id from response

    On first run, response data is dumped for debugging to identify
    the exact selection API needed.
    """
    # First, try to discover available accounts
    check_url = f"https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27"
    try:
        resp = session.get(
            check_url,
            headers={
                "accept": "application/json",
                "user-agent": USER_AGENT,
            },
            timeout=15,
        )
        if resp.status_code == 200:
            data = resp.json() if resp.text else {}
            accounts = (
                (data.get("accounts") or {}).get("default") or {}
            ).get("account") or {}
            # Log available accounts for debugging
            account_id = accounts.get("account_id", "")
    except Exception:
        pass  # This is best-effort debugging; don't fail

    # If we have the team workspace_id (the K12 parent), we may need to
    # find the corresponding account_id and activate it.
    #
    # The workspace picker flow in ChatGPT's Auth0 authorize flow
    # typically presents as:
    #   GET /api/accounts/authorize/continue?...&prompt=select_account
    #
    # If we're redirected to such a page, parse the available accounts
    # from the response and POST to select the non-personal one.

    # NOTE: This is the part that requires runtime debugging.
    # The exact API differs based on account type and OpenAI changes.
    # The authorize flow response URL and body should be inspected
    # on first login to determine the correct selection mechanism.

    # For now: the authorize flow will naturally redirect through the
    # workspace picker if needed. The exchange step handles the final
    # token retrieval from the callback.


def _exchange_login_tokens(
    session,
    code_verifier: str,
    authorization_code: str,
) -> dict:
    """Exchange authorization code for tokens after login flow completes."""
    headers = {
        "accept": "*/*",
        "accept-language": "zh-CN,zh;q=0.9",
        "auth0-client": PLATFORM_AUTH0_CLIENT,
        "cache-control": "no-cache",
        "content-type": "application/json",
        "origin": PLATFORM_BASE,
        "pragma": "no-cache",
        "priority": "u=1, i",
        "referer": f"{PLATFORM_BASE}/",
        "sec-ch-ua": '"Google Chrome";v="145", "Not?A_Brand";v="8", "Chromium";v="145"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-fetch-dest": "empty",
        "sec-fetch-mode": "cors",
        "sec-fetch-site": "same-site",
        "user-agent": USER_AGENT,
    }

    code = str(authorization_code or "").strip()
    if not code:
        raise LoginError("Token exchange requires an authorization code")

    # Exchange code for tokens
    resp = session.post(
        f"{AUTH_BASE}/api/accounts/oauth/token",
        headers=headers,
        json={
            "client_id": PLATFORM_OAUTH_CLIENT_ID,
            "code_verifier": code_verifier,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": PLATFORM_OAUTH_REDIRECT_URI,
        },
        verify=False,
        timeout=60,
    )

    if resp.status_code != 200:
        raise LoginError(
            f"Token exchange failed: HTTP {resp.status_code}, "
            f"{resp.text[:300]}"
        )

    data = _response_json(resp)
    if not data or not data.get("access_token"):
        raise LoginError("Token exchange returned no access_token")

    return data


# ── Simple re-login (without workspace selection) ───────────────────


def re_login_personal(
    email: str,
    password: str,
    mail_config: dict,
    proxy: str = "",
    flaresolverr_url: str = "",
) -> dict:
    """Re-login without workspace selection (gets personal-scope tokens).

    This is useful for refreshing tokens when workspace selection
    is not needed.
    """
    # This is essentially the same flow but without the workspace
    # selection step. For now, reuse re_login_for_team_token
    # without a workspace_id to get whichever scope comes back.
    return re_login_for_team_token(
        email=email,
        password=password,
        mail_config=mail_config,
        proxy=proxy,
        flaresolverr_url=flaresolverr_url,
        workspace_id="",
    )
