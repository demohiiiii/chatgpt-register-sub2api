"""Pipeline orchestrator — wires register → join → re-login → export.

The complete flow for one account:
  [1] Register account → get personal-scope tokens
  [2] Join parent K12 workspace → auto-accepted
  [3] Re-login with Team space selection → get team-scope tokens
  [4] Export team-scope tokens as sub2api JSON

Each account proceeds independently through all 4 stages.
Results are written to registered_accounts.json after each success.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from chatgpt_register_sub2api.register.registrar import register_worker
from chatgpt_register_sub2api.workspace.joiner import join_workspaces
from chatgpt_register_sub2api.login.login_flow import re_login_for_team_token
from chatgpt_register_sub2api.export.sub2api import export_sub2api_json

logger = logging.getLogger(__name__)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _timestamp() -> str:
    return datetime.now().strftime("%Y%m%d-%H%M%S")


def load_accounts(path: Path) -> list[dict[str, Any]]:
    """Load registered accounts from JSON file."""
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_accounts(path: Path, accounts: list[dict[str, Any]]) -> None:
    """Save accounts to JSON file (atomic write)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(accounts, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


# ── Pipeline stages ─────────────────────────────────────────────────


def run_register(
    config: dict[str, Any],
    accounts_file: Path,
    count: int | None = None,
) -> list[dict[str, Any]]:
    """Stage 1: Register N ChatGPT accounts.

    Returns list of newly registered account records.
    """
    reg_cfg = config.get("registration", {})
    mail_cfg = config.get("mail", {})
    proxy_cfg = config.get("proxy", {})

    total = count or int(reg_cfg.get("total", 10))
    threads = int(reg_cfg.get("threads", 3))
    proxy = str(proxy_cfg.get("url", "")).strip()
    flaresolverr_url = str(proxy_cfg.get("flaresolverr_url", "")).strip()

    logger.info(f"Starting registration: {total} accounts, {threads} threads")
    if proxy:
        logger.info(f"Proxy: {proxy}")
    if flaresolverr_url:
        logger.info(f"FlareSolverr: {flaresolverr_url}")

    results: list[dict[str, Any]] = []
    existing = load_accounts(accounts_file)
    success_count = 0
    fail_count = 0

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {
            executor.submit(
                register_worker,
                index=i,
                proxy=proxy,
                flaresolverr_url=flaresolverr_url,
                mail_config=mail_cfg,
            ): i
            for i in range(1, total + 1)
        }

        for future in as_completed(futures):
            result = future.result()
            if result["ok"]:
                success_count += 1
                account = result["result"]
                results.append(account)
                existing.append(account)
                save_accounts(accounts_file, existing)
                logger.info(
                    f"[{result['index']}/{total}] ✓ {account['email']} "
                    f"({result.get('cost_seconds', 0):.1f}s)"
                )
            else:
                fail_count += 1
                logger.warning(
                    f"[{result['index']}/{total}] ✗ {result.get('error', 'unknown')}"
                )

    logger.info(
        f"Registration complete: {success_count} success, {fail_count} failed"
    )
    return results


def run_join_workspace(
    config: dict[str, Any],
    accounts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Stage 2: Join each account to the K12 parent workspace.

    Modifies account records in-place with join status.
    """
    ws_cfg = config.get("workspace", {})
    if not ws_cfg.get("enabled", True):
        logger.info("Workspace join disabled — skipping")
        return accounts

    workspace_ids = ws_cfg.get("ids", [])
    if not workspace_ids:
        logger.warning("No workspace IDs configured — skipping join")
        return accounts

    route = str(ws_cfg.get("route", "request")).strip() or "request"
    max_retries = int(ws_cfg.get("max_retries", 3))
    retry_backoff = int(ws_cfg.get("retry_backoff_ms", 5000))
    proxy = str(config.get("proxy", {}).get("url", "")).strip()

    logger.info(
        f"Joining {len(accounts)} accounts to {len(workspace_ids)} workspace(s)"
    )

    for account in accounts:
        email = account.get("email", "?")
        access_token = account.get("access_token", "")
        if not access_token:
            logger.warning(f"[{email}] No access_token — skipping join")
            account["join_status"] = "skipped"
            continue

        results = join_workspaces(
            access_token=access_token,
            workspace_ids=workspace_ids,
            route=route,
            max_retries=max_retries,
            retry_backoff_ms=retry_backoff,
            proxy=proxy,
        )

        all_ok = all(r["ok"] for r in results)
        account["join_status"] = "ok" if all_ok else "failed"
        account["join_results"] = results

        if all_ok:
            logger.info(f"[{email}] ✓ Joined {len(workspace_ids)} workspace(s)")
        else:
            errors = [r.get("error", "?") for r in results if not r["ok"]]
            logger.warning(f"[{email}] ✗ Join failed: {', '.join(errors)}")

    return accounts


def run_re_login(
    config: dict[str, Any],
    accounts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Stage 3: Re-login each account with Team space selection.

    Gets team-scoped tokens for accounts that successfully joined.
    NOTE: This step requires browser-based OAuth login flow and is
    currently skipped by default. Use registration tokens directly.
    """
    ws_cfg = config.get("workspace", {})
    re_login_enabled = ws_cfg.get("re_login_enabled", False)

    if not re_login_enabled:
        logger.info("Team re-login disabled — using registration tokens for export")
        for account in accounts:
            account["team_login_status"] = "skipped"
        return accounts

    mail_cfg = config.get("mail", {})
    proxy_cfg = config.get("proxy", {})
    proxy = str(proxy_cfg.get("url", "")).strip()
    flaresolverr_url = str(proxy_cfg.get("flaresolverr_url", "")).strip()
    workspace_ids = ws_cfg.get("ids", [])

    logger.info(f"Re-logging {len(accounts)} accounts for team-scoped tokens")

    for account in accounts:
        email = account.get("email", "")
        password = account.get("password", "")
        join_status = account.get("join_status", "")

        if join_status != "ok":
            logger.info(f"[{email}] Join failed/skipped — skipping re-login")
            account["team_login_status"] = "skipped"
            continue

        if not email or not password:
            logger.warning(f"[{email}] Missing email or password — skipping re-login")
            account["team_login_status"] = "skipped"
            continue

        try:
            team_tokens = re_login_for_team_token(
                email=email,
                password=password,
                mail_config=mail_cfg,
                proxy=proxy,
                flaresolverr_url=flaresolverr_url,
                workspace_id=workspace_ids[0] if workspace_ids else "",
            )

            # Store team-scoped tokens in a separate field
            account["team_access_token"] = team_tokens["access_token"]
            account["team_refresh_token"] = team_tokens["refresh_token"]
            account["team_id_token"] = team_tokens["id_token"]
            account["team_login_status"] = "ok"

            logger.info(f"[{email}] ✓ Team login successful")
        except Exception as e:
            logger.warning(f"[{email}] ✗ Team login failed: {e}")
            account["team_login_status"] = "failed"
            account["team_login_error"] = str(e)

    return accounts


def run_refresh_tokens(
    config: dict[str, Any],
    accounts: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Refresh access tokens and enrich with workspace info from check API.

    After joining a workspace, refreshing the token ensures the token
    is valid for the current context.  Then we call /accounts/check
    to get the real plan_type and account_id (the JWT doesn't carry
    workspace claims).
    """
    import json as _json
    from chatgpt_register_sub2api.utils.jwt import decode_jwt_payload
    from datetime import datetime
    import time

    proxy = str(config.get("proxy", {}).get("url", "")).strip()
    workspace_id = ""
    ws_ids = config.get("workspace", {}).get("ids", [])
    if ws_ids:
        workspace_id = ws_ids[0]

    logger.info(f"Refreshing tokens and checking account info for {len(accounts)} accounts")

    for account in accounts:
        email = account.get("email", "")
        rt = account.get("refresh_token", "")

        if not rt and _workspace_session_matches(account, workspace_id):
            logger.info(
                f"[{email}] Already using target workspace session — skipping token refresh/check"
            )
            continue

        session = None
        try:
            kwargs = {"impersonate": "chrome", "verify": False}
            if proxy:
                kwargs["proxy"] = proxy
            from curl_cffi import requests
            session = requests.Session(**kwargs)

            # Step 1: Refresh the access token
            if rt:
                resp = session.post(
                    "https://auth.openai.com/oauth/token",
                    data={
                        "client_id": "app_2SKx67EdpoN0G6j64rFvigXD",
                        "grant_type": "refresh_token",
                        "refresh_token": rt,
                    },
                    headers={
                        "Content-Type": "application/x-www-form-urlencoded",
                    },
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    new_at = data.get("access_token", "")
                    new_rt = data.get("refresh_token", "")
                    if new_at:
                        account["access_token"] = new_at
                    if new_rt:
                        account["refresh_token"] = new_rt
                    logger.info(f"[{email}] Token refreshed")
                else:
                    logger.warning(f"[{email}] Token refresh failed: HTTP {resp.status_code}")
            else:
                logger.info(
                    f"[{email}] No refresh_token — skipping token refresh, checking current access_token"
                )

            # Step 2: Call check API to get real plan_type and account_id
            at = account.get("access_token", "")
            if at:
                resp = session.get(
                    "https://chatgpt.com/backend-api/accounts/check/v4-2023-04-27",
                    headers={"Authorization": f"Bearer {at}"},
                    timeout=30,
                )
                if resp.status_code == 200:
                    data = resp.json()
                    accts = data.get("accounts", {})
                    default = accts.get("default", {}).get("account", {})
                    plan = default.get("plan_type", "")
                    acct_id = default.get("account_id", "")
                    role = default.get("account_user_role", "")

                    if plan:
                        account["plan_type"] = plan
                    if acct_id:
                        account["chatgpt_account_id"] = acct_id
                    if role:
                        account["account_user_role"] = role

                    logger.info(
                        f"[{email}] Check API: plan={plan} account_id={acct_id[:30] if acct_id else '?'} role={role}"
                    )
                else:
                    logger.warning(f"[{email}] Check API failed: HTTP {resp.status_code}")

        except Exception as e:
            logger.warning(f"[{email}] Refresh/check error: {e}")
        finally:
            if session:
                session.close()

    return accounts


def run_export(
    config: dict[str, Any],
    accounts: list[dict[str, Any]],
    output_file: Path | None = None,
) -> str:
    """Stage 4: Export accounts as sub2api JSON.

    Uses team-scoped tokens (team_access_token) when available,
    falls back to personal tokens.
    """
    sub2api_cfg = config.get("sub2api", {})

    # Prepare accounts for export — use registration tokens directly
    # (Team-scoped tokens would require browser-based re-login, not yet implemented)
    export_accounts = []
    workspace_ids = _configured_workspace_ids(config)
    multi_workspace_export = len(workspace_ids) > 1
    for account in accounts:
        workspace_tokens = account.get("workspace_tokens")
        if workspace_ids and isinstance(workspace_tokens, dict):
            exported_workspace_token = False
            for workspace_id in workspace_ids:
                token_record = workspace_tokens.get(workspace_id)
                if not isinstance(token_record, dict):
                    continue
                export = dict(account)
                export.update(token_record)
                export["workspace_id"] = workspace_id
                export["source_type"] = str(
                    token_record.get("source_type")
                    or account.get("source_type")
                    or "workspace_tokens"
                )
                if multi_workspace_export:
                    export["multi_workspace_export"] = True
                export_accounts.append(export)
                exported_workspace_token = True
            if exported_workspace_token:
                continue

        export = dict(account)
        if account.get("team_login_status") == "ok":
            export["access_token"] = account.get("team_access_token", account.get("access_token", ""))
            export["refresh_token"] = account.get("team_refresh_token", account.get("refresh_token", ""))
            export["id_token"] = account.get("team_id_token", account.get("id_token", ""))
            export["source_type"] = "team_relogin"
        # else: use registration tokens as-is
        export_accounts.append(export)

    output_path = Path(output_file) if output_file else Path(
        config.get("_config_dir", ".")
    ) / f"sub2api-{_timestamp()}.json"

    json_str, actual_path = export_sub2api_json(export_accounts, output_path)
    logger.info(f"Exported {len(export_accounts)} accounts to {actual_path}")
    return actual_path


def _normalize_email(value: Any) -> str:
    return str(value or "").strip().lower()


def _login_default_password(config: dict[str, Any]) -> str:
    login_cfg = config.get("login", {})
    if isinstance(login_cfg, dict):
        password = str(login_cfg.get("password") or "").strip()
        if password:
            return password
    return ""


def _login_mode(config: dict[str, Any]) -> str:
    login_cfg = config.get("login", {})
    if isinstance(login_cfg, dict):
        mode = str(login_cfg.get("mode") or "password").strip().lower()
        if mode in {"password", "otp"}:
            return mode
    return "password"


def _configured_workspace_ids(config: dict[str, Any]) -> list[str]:
    ws_cfg = config.get("workspace", {})
    raw_ids = ws_cfg.get("ids", []) if isinstance(ws_cfg, dict) else []
    if isinstance(raw_ids, str):
        raw_values = [raw_ids]
    elif isinstance(raw_ids, (list, tuple)):
        raw_values = list(raw_ids)
    else:
        raw_values = []

    result: list[str] = []
    seen: set[str] = set()
    for value in raw_values:
        workspace_id = str(value or "").strip()
        if workspace_id and workspace_id not in seen:
            result.append(workspace_id)
            seen.add(workspace_id)
    return result


def _login_workspace_targets(config: dict[str, Any]) -> list[str]:
    workspace_ids = _configured_workspace_ids(config)
    return workspace_ids if workspace_ids else [""]


def _config_for_workspace(config: dict[str, Any], workspace_id: str) -> dict[str, Any]:
    scoped = dict(config)
    ws_cfg = dict(config.get("workspace", {}) or {})
    ws_cfg["ids"] = [workspace_id] if workspace_id else []
    scoped["workspace"] = ws_cfg
    return scoped


def _workspace_groups(accounts: list[dict[str, Any]]) -> dict[str, list[dict[str, Any]]]:
    groups: dict[str, list[dict[str, Any]]] = {}
    for account in accounts:
        workspace_id = str(account.get("workspace_id") or "").strip()
        groups.setdefault(workspace_id, []).append(account)
    return groups


def _remember_workspace_tokens(
    account: dict[str, Any],
    source: dict[str, Any],
    workspace_id: str,
) -> None:
    workspace_id = str(workspace_id or "").strip()
    if not workspace_id:
        return

    workspace_tokens = account.get("workspace_tokens")
    if not isinstance(workspace_tokens, dict):
        workspace_tokens = {}
        account["workspace_tokens"] = workspace_tokens

    fields = [
        "email",
        "access_token",
        "refresh_token",
        "id_token",
        "session_token",
        "chatgpt_account_id",
        "chatgpt_user_id",
        "plan_type",
        "organization_id",
        "account_user_role",
        "join_status",
        "join_results",
        "source_type",
        "updated_at",
    ]
    workspace_tokens[workspace_id] = {
        key: source.get(key)
        for key in fields
        if key in source
    }
    workspace_tokens[workspace_id]["workspace_id"] = workspace_id


def _apply_login_tokens(
    account: dict[str, Any],
    tokens: dict[str, Any],
    *,
    status_key: str,
    source_type: str,
    workspace_id: str,
) -> None:
    account["access_token"] = str(tokens.get("access_token") or "").strip()
    account["refresh_token"] = str(tokens.get("refresh_token") or "").strip()
    account["id_token"] = str(tokens.get("id_token") or "").strip()
    account["session_token"] = str(tokens.get("session_token") or "").strip()
    account["chatgpt_account_id"] = str(tokens.get("chatgpt_account_id") or "").strip()
    account["plan_type"] = str(
        tokens.get("plan_type") or account.get("plan_type") or ""
    ).strip()
    account["organization_id"] = str(
        tokens.get("organization_id") or account.get("organization_id") or ""
    ).strip()
    if tokens.get("chatgpt_user_id"):
        account["chatgpt_user_id"] = str(tokens.get("chatgpt_user_id") or "").strip()
    if tokens.get("account_user_role"):
        account["account_user_role"] = str(tokens.get("account_user_role") or "").strip()

    workspace_id = str(workspace_id or "").strip()
    if workspace_id:
        account["workspace_id"] = workspace_id
    else:
        account.pop("workspace_id", None)

    account[status_key] = "ok"
    account.pop(f"{status_key}_error", None)
    account["source_type"] = source_type
    account["updated_at"] = _now()
    _remember_workspace_tokens(account, account, workspace_id)


def _export_snapshot(
    account: dict[str, Any],
    *,
    source_type: str,
    workspace_id: str,
    multi_workspace_export: bool = False,
) -> dict[str, Any]:
    export = dict(account)
    workspace_id = str(workspace_id or "").strip()
    if workspace_id:
        workspace_tokens = account.get("workspace_tokens")
        if isinstance(workspace_tokens, dict):
            token_record = workspace_tokens.get(workspace_id)
            if isinstance(token_record, dict):
                export.update(token_record)
        export["workspace_id"] = workspace_id
    else:
        export.pop("workspace_id", None)
    export["source_type"] = source_type
    if multi_workspace_export:
        export["multi_workspace_export"] = True
    else:
        export.pop("multi_workspace_export", None)
    return export


def _sync_workspace_snapshots_to_accounts(
    by_email: dict[str, dict[str, Any]],
    snapshots: list[dict[str, Any]],
) -> None:
    for snapshot in snapshots:
        account = by_email.get(_normalize_email(snapshot.get("email")))
        if not account:
            continue

        for key in [
            "access_token",
            "refresh_token",
            "id_token",
            "session_token",
            "chatgpt_account_id",
            "chatgpt_user_id",
            "plan_type",
            "organization_id",
            "account_user_role",
            "workspace_id",
            "join_status",
            "join_results",
            "source_type",
            "updated_at",
        ]:
            if key in snapshot:
                account[key] = snapshot[key]
        _remember_workspace_tokens(
            account,
            snapshot,
            str(snapshot.get("workspace_id") or "").strip(),
        )


def _account_for_login(
    *,
    config: dict[str, Any],
    accounts: list[dict[str, Any]],
    by_email: dict[str, dict[str, Any]],
    email: str,
) -> tuple[dict[str, Any] | None, str, str]:
    """Return account, password, and failure reason for a login email."""
    login_mode = _login_mode(config)
    account = by_email.get(email)
    if account:
        if login_mode == "otp":
            return account, str(account.get("password") or "").strip(), ""
        password = str(account.get("password") or "").strip()
        if password:
            return account, password, ""
        password = _login_default_password(config)
        if password:
            account["password"] = password
            return account, password, ""
        return account, "", "missing_password"

    password = "" if login_mode == "otp" else _login_default_password(config)
    if not password:
        if login_mode != "otp":
            return None, "", "missing"

    account = {
        "email": email,
        "password": password,
        "source_type": "login_input",
        "created_at": _now(),
    }
    accounts.append(account)
    by_email[email] = account
    return account, password, ""


def _workspace_session_matches(account: dict[str, Any], workspace_id: str) -> bool:
    workspace_id = str(workspace_id or "").strip()
    if not workspace_id:
        return False
    account_id = str(account.get("chatgpt_account_id") or "").strip()
    plan_type = str(account.get("plan_type") or "").strip().lower()
    return account_id == workspace_id and plan_type == "k12"


def run_login_export(
    config: dict[str, Any],
    emails: list[str],
    output_file: Path | None = None,
    accounts_file: Path | None = None,
) -> dict[str, Any]:
    """Login selected existing accounts and export only successful logins.

    Passwords are read from registered_accounts.json. Existing tokens are not
    used as a fallback for failed logins.
    """
    af = Path(accounts_file) if accounts_file else Path("registered_accounts.json")
    accounts = load_accounts(af)
    by_email = {
        _normalize_email(account.get("email")): account
        for account in accounts
        if _normalize_email(account.get("email"))
    }

    requested: list[str] = []
    seen: set[str] = set()
    for email in emails:
        normalized = _normalize_email(email)
        if normalized and normalized not in seen:
            requested.append(normalized)
            seen.add(normalized)

    mail_cfg = config.get("mail", {})
    proxy_cfg = config.get("proxy", {})
    proxy = str(proxy_cfg.get("url", "")).strip()
    flaresolverr_url = str(proxy_cfg.get("flaresolverr_url", "")).strip()
    workspace_targets = _login_workspace_targets(config)
    include_workspace_in_status = len([ws for ws in workspace_targets if ws]) > 1
    login_mode = _login_mode(config)

    export_accounts: list[dict[str, Any]] = []
    succeeded: list[str] = []
    missing: list[str] = []
    missing_password: list[str] = []
    failed: list[dict[str, str]] = []

    logger.info(f"Login-export started for {len(requested)} account(s)")

    for email in requested:
        account, password, reason = _account_for_login(
            config=config,
            accounts=accounts,
            by_email=by_email,
            email=email,
        )
        if reason == "missing":
            missing.append(email)
            logger.warning(f"[{email}] Not found in {af}")
            continue
        if account is None:
            missing.append(email)
            logger.warning(f"[{email}] Not found in {af}")
            continue
        if reason == "missing_password":
            account["login_export_status"] = "missing_password"
            missing_password.append(email)
            logger.warning(f"[{email}] Missing password — skipping")
            continue

        email_succeeded = False
        for workspace_id in workspace_targets:
            try:
                tokens = re_login_for_team_token(
                    email=str(account.get("email") or email),
                    password=password,
                    mail_config=mail_cfg,
                    proxy=proxy,
                    flaresolverr_url=flaresolverr_url,
                    workspace_id=workspace_id,
                    login_mode=login_mode,
                )
            except Exception as e:
                error = str(e)
                account["login_export_status"] = "failed"
                account["login_export_error"] = error
                failure = {"email": email, "error": error}
                if include_workspace_in_status and workspace_id:
                    failure["workspace_id"] = workspace_id
                failed.append(failure)
                workspace_note = f" workspace={workspace_id}" if workspace_id else ""
                logger.warning(f"[{email}] Login failed{workspace_note}: {error}")
                continue

            _apply_login_tokens(
                account,
                tokens,
                status_key="login_export_status",
                source_type="login_export",
                workspace_id=workspace_id,
            )
            account.pop("login_export_error", None)
            export_accounts.append(
                _export_snapshot(
                    account,
                    source_type="login_export",
                    workspace_id=workspace_id,
                    multi_workspace_export=include_workspace_in_status,
                )
            )
            if not email_succeeded:
                succeeded.append(email)
                email_succeeded = True
            workspace_note = f" workspace={workspace_id}" if workspace_id else ""
            logger.info(f"[{email}] Login successful{workspace_note}")
        if email_succeeded and account.get("login_export_status") == "failed":
            account["login_export_status"] = "partial"

    save_accounts(af, accounts)

    if not export_accounts:
        logger.warning("Login-export had 0 successful account(s); skipping sub2api export")
        return {
            "requested": requested,
            "succeeded": succeeded,
            "missing": missing,
            "missing_password": missing_password,
            "failed": failed,
            "exported": 0,
            "accounts_file": str(af.resolve()),
            "output_file": "",
        }

    output_path = Path(output_file) if output_file else Path(
        config.get("_config_dir", ".")
    ) / f"sub2api-{_timestamp()}.json"
    _, actual_path = export_sub2api_json(export_accounts, output_path)
    logger.info(f"Login-export wrote {len(export_accounts)} account(s) to {actual_path}")

    return {
        "requested": requested,
        "succeeded": succeeded,
        "missing": missing,
        "missing_password": missing_password,
        "failed": failed,
        "exported": len(export_accounts),
        "accounts_file": str(af.resolve()),
        "output_file": actual_path,
    }


def run_login_join_export(
    config: dict[str, Any],
    emails: list[str],
    output_file: Path | None = None,
    accounts_file: Path | None = None,
) -> dict[str, Any]:
    """Login selected existing accounts, join workspace, refresh, and export.

    Passwords are read from registered_accounts.json. Only accounts that
    successfully complete the fresh login step continue to join/refresh/export.
    Existing tokens are not used as a fallback for failed logins.
    """
    af = Path(accounts_file) if accounts_file else Path("registered_accounts.json")
    accounts = load_accounts(af)
    by_email = {
        _normalize_email(account.get("email")): account
        for account in accounts
        if _normalize_email(account.get("email"))
    }

    requested: list[str] = []
    seen: set[str] = set()
    for email in emails:
        normalized = _normalize_email(email)
        if normalized and normalized not in seen:
            requested.append(normalized)
            seen.add(normalized)

    mail_cfg = config.get("mail", {})
    proxy_cfg = config.get("proxy", {})
    proxy = str(proxy_cfg.get("url", "")).strip()
    flaresolverr_url = str(proxy_cfg.get("flaresolverr_url", "")).strip()
    workspace_targets = _login_workspace_targets(config)
    include_workspace_in_status = len([ws for ws in workspace_targets if ws]) > 1
    login_mode = _login_mode(config)

    successful_accounts: list[dict[str, Any]] = []
    succeeded: list[str] = []
    missing: list[str] = []
    missing_password: list[str] = []
    failed: list[dict[str, str]] = []

    logger.info(f"Login-join-export started for {len(requested)} account(s)")

    for email in requested:
        account, password, reason = _account_for_login(
            config=config,
            accounts=accounts,
            by_email=by_email,
            email=email,
        )
        if reason == "missing":
            missing.append(email)
            logger.warning(f"[{email}] Not found in {af}")
            continue
        if account is None:
            missing.append(email)
            logger.warning(f"[{email}] Not found in {af}")
            continue
        if reason == "missing_password":
            account["login_join_export_status"] = "missing_password"
            missing_password.append(email)
            logger.warning(f"[{email}] Missing password — skipping")
            continue

        email_succeeded = False
        for workspace_id in workspace_targets:
            try:
                tokens = re_login_for_team_token(
                    email=str(account.get("email") or email),
                    password=password,
                    mail_config=mail_cfg,
                    proxy=proxy,
                    flaresolverr_url=flaresolverr_url,
                    workspace_id=workspace_id,
                    login_mode=login_mode,
                )
            except Exception as e:
                error = str(e)
                account["login_join_export_status"] = "failed"
                account["login_join_export_error"] = error
                failure = {"email": email, "error": error}
                if include_workspace_in_status and workspace_id:
                    failure["workspace_id"] = workspace_id
                failed.append(failure)
                workspace_note = f" workspace={workspace_id}" if workspace_id else ""
                logger.warning(f"[{email}] Login failed{workspace_note}: {error}")
                continue

            _apply_login_tokens(
                account,
                tokens,
                status_key="login_join_export_status",
                source_type="login_join_export",
                workspace_id=workspace_id,
            )
            account.pop("login_join_export_error", None)
            export_account = _export_snapshot(
                account,
                source_type="login_join_export",
                workspace_id=workspace_id,
                multi_workspace_export=include_workspace_in_status,
            )
            if _workspace_session_matches(export_account, workspace_id):
                export_account["join_status"] = "ok"
                export_account["join_results"] = [
                    {
                        "ok": True,
                        "status_code": 200,
                        "workspace_id": workspace_id,
                        "body": "already switched by login session",
                    }
                ]
                _remember_workspace_tokens(account, export_account, workspace_id)

            successful_accounts.append(export_account)
            if not email_succeeded:
                succeeded.append(email)
                email_succeeded = True
            workspace_note = f" workspace={workspace_id}" if workspace_id else ""
            logger.info(f"[{email}] Login successful{workspace_note}")
        if email_succeeded and account.get("login_join_export_status") == "failed":
            account["login_join_export_status"] = "partial"

    save_accounts(af, accounts)

    if successful_accounts:
        pending_join_accounts = [
            account for account in successful_accounts
            if account.get("join_status") != "ok"
        ]
        if pending_join_accounts:
            for workspace_id, grouped_accounts in _workspace_groups(pending_join_accounts).items():
                run_join_workspace(
                    _config_for_workspace(config, workspace_id),
                    grouped_accounts,
                )
        else:
            logger.info("All successful accounts already use the target workspace session")
        save_accounts(af, accounts)
        for workspace_id, grouped_accounts in _workspace_groups(successful_accounts).items():
            run_refresh_tokens(
                _config_for_workspace(config, workspace_id),
                grouped_accounts,
            )
        _sync_workspace_snapshots_to_accounts(by_email, successful_accounts)
        save_accounts(af, accounts)

    if not successful_accounts:
        logger.warning("Login-join-export had 0 successful account(s); skipping sub2api export")
        return {
            "requested": requested,
            "succeeded": succeeded,
            "missing": missing,
            "missing_password": missing_password,
            "failed": failed,
            "joined": 0,
            "refreshed": 0,
            "exported": 0,
            "accounts_file": str(af.resolve()),
            "output_file": "",
        }

    output_path = Path(output_file) if output_file else Path(
        config.get("_config_dir", ".")
    ) / f"sub2api-{_timestamp()}.json"
    _, actual_path = export_sub2api_json(successful_accounts, output_path)
    logger.info(
        f"Login-join-export wrote {len(successful_accounts)} account(s) to {actual_path}"
    )

    return {
        "requested": requested,
        "succeeded": succeeded,
        "missing": missing,
        "missing_password": missing_password,
        "failed": failed,
        "joined": sum(1 for a in successful_accounts if a.get("join_status") == "ok"),
        "refreshed": sum(1 for a in successful_accounts if a.get("plan_type") == "k12"),
        "exported": len(successful_accounts),
        "accounts_file": str(af.resolve()),
        "output_file": actual_path,
    }


# ── Full pipeline ───────────────────────────────────────────────────


def run_full_pipeline(
    config: dict[str, Any],
    count: int | None = None,
    output_file: str | None = None,
    accounts_file: str | None = None,
) -> dict[str, Any]:
    """Run the complete pipeline: register → join → re-login → export.

    Args:
        config: Full config dict from config.yaml
        count: Override registration count
        output_file: Override sub2api output path
        accounts_file: Override accounts storage path

    Returns:
        Summary dict with counts
    """
    config_dir = Path(config.get("_config_dir", "."))
    af = Path(accounts_file) if accounts_file else config_dir / "registered_accounts.json"
    of = Path(output_file) if output_file else None

    logger.info("=" * 60)
    logger.info("Pipeline started: register → join → re-login → export")
    logger.info("=" * 60)

    # Stage 1: Register
    new_accounts = run_register(config, af, count=count)
    if not new_accounts:
        logger.error("No accounts registered — pipeline aborted")
        return {"registered": 0, "joined": 0, "refreshed": 0, "exported": 0}

    # Stage 2: Join workspace
    joined_accounts = run_join_workspace(config, new_accounts)
    save_accounts(af, joined_accounts)

    # Stage 3: Refresh tokens + enrich with workspace info from check API
    refreshed_accounts = run_refresh_tokens(config, joined_accounts)
    save_accounts(af, refreshed_accounts)

    # Stage 4: Export (uses plan_type and account_id from check API)
    all_accounts = load_accounts(af)
    json_output = run_export(config, all_accounts, of)

    registered = len(new_accounts)
    joined = sum(1 for a in refreshed_accounts if a.get("join_status") == "ok")
    refreshed = sum(1 for a in refreshed_accounts if a.get("plan_type") == "k12")
    exported = len(all_accounts)

    logger.info("=" * 60)
    logger.info(
        f"Pipeline complete: "
        f"registered={registered}, joined={joined}, "
        f"refreshed={refreshed}, exported={exported}"
    )
    logger.info("=" * 60)

    return {
        "registered": registered,
        "joined": joined,
        "refreshed": refreshed,
        "exported": exported,
        "accounts_file": str(af),
    }
