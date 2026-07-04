from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chatgpt_register_sub2api.pipeline import (
    load_accounts,
    run_export,
    run_login_export,
    run_login_join_export,
    run_refresh_tokens,
)


class FakeHttpResponse:
    def __init__(self, status_code: int, data: dict | None = None) -> None:
        self.status_code = status_code
        self._data = data or {}
        self.text = json.dumps(self._data)

    def json(self) -> dict:
        return self._data

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 300


class FakeRefreshSession:
    response_data = {
        "accounts": {
            "default": {
                "account": {
                    "plan_type": "k12",
                    "account_id": "account-123",
                    "account_user_role": "member",
                }
            }
        }
    }

    def __init__(self) -> None:
        self.posts: list[dict] = []
        self.gets: list[dict] = []
        self.closed = False

    def post(self, url: str, **kwargs):
        self.posts.append({"url": url, "kwargs": kwargs})
        return FakeHttpResponse(500, {})

    def get(self, url: str, **kwargs):
        self.gets.append({"url": url, "kwargs": kwargs})
        return FakeHttpResponse(200, self.response_data)

    def close(self) -> None:
        self.closed = True


class LoginExportTests(unittest.TestCase):
    def test_logs_in_requested_emails_and_exports_only_successes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"
            accounts_file.write_text(
                json.dumps(
                    [
                        {
                            "email": "ok@example.com",
                            "password": "pw-ok",
                            "access_token": "old-access-ok",
                            "refresh_token": "old-refresh-ok",
                            "id_token": "old-id-ok",
                        },
                        {
                            "email": "nopass@example.com",
                            "password": "",
                            "access_token": "old-access-nopass",
                        },
                        {
                            "email": "fail@example.com",
                            "password": "pw-fail",
                            "access_token": "old-access-fail",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            def fake_login(**kwargs):
                if kwargs["email"] == "fail@example.com":
                    raise RuntimeError("login rejected")
                return {
                    "email": kwargs["email"],
                    "access_token": "new-access-ok",
                    "refresh_token": "new-refresh-ok",
                    "id_token": "new-id-ok",
                }

            config = {
                "_config_dir": str(root),
                "mail": {"wait_timeout": 1},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": ["workspace-1"]},
            }

            with patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login):
                summary = run_login_export(
                    config=config,
                    emails=[
                        "ok@example.com",
                        "missing@example.com",
                        "nopass@example.com",
                        "fail@example.com",
                    ],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            self.assertEqual(summary["exported"], 1)
            self.assertEqual(summary["succeeded"], ["ok@example.com"])
            self.assertEqual(summary["missing"], ["missing@example.com"])
            self.assertEqual(summary["missing_password"], ["nopass@example.com"])
            self.assertEqual(summary["failed"], [{"email": "fail@example.com", "error": "login rejected"}])
            self.assertEqual(summary["output_file"], str(output_file.resolve()))

            bundle = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(len(bundle["accounts"]), 1)
            self.assertEqual(bundle["accounts"][0]["name"], "ok@example.com")
            self.assertEqual(
                bundle["accounts"][0]["credentials"]["access_token"],
                "new-access-ok",
            )

            saved_accounts = load_accounts(accounts_file)
            saved_ok = next(acc for acc in saved_accounts if acc["email"] == "ok@example.com")
            saved_fail = next(acc for acc in saved_accounts if acc["email"] == "fail@example.com")
            self.assertEqual(saved_ok["access_token"], "new-access-ok")
            self.assertEqual(saved_ok["login_export_status"], "ok")
            self.assertEqual(saved_fail["access_token"], "old-access-fail")
            self.assertEqual(saved_fail["login_export_status"], "failed")

    def test_login_export_does_not_write_output_when_no_successes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"
            accounts_file.write_text(
                json.dumps(
                    [
                        {
                            "email": "fail@example.com",
                            "password": "pw-fail",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            def fake_login(**kwargs):
                raise RuntimeError("login rejected")

            config = {
                "_config_dir": str(root),
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": []},
            }

            with patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login):
                summary = run_login_export(
                    config=config,
                    emails=["fail@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            self.assertEqual(summary["succeeded"], [])
            self.assertEqual(summary["exported"], 0)
            self.assertEqual(summary["output_file"], "")
            self.assertFalse(output_file.exists())

    def test_default_accounts_file_is_read_from_current_directory(self) -> None:
        original_cwd = Path.cwd()
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"
            accounts_file.write_text(
                json.dumps(
                    [
                        {
                            "email": "ok@example.com",
                            "password": "pw-ok",
                        }
                    ]
                ),
                encoding="utf-8",
            )
            (root / "config-dir").mkdir()

            def fake_login(**kwargs):
                return {
                    "email": kwargs["email"],
                    "access_token": "new-access-ok",
                    "refresh_token": "new-refresh-ok",
                    "id_token": "new-id-ok",
                }

            config = {
                "_config_dir": str(root / "config-dir"),
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": []},
            }

            try:
                os.chdir(root)
                with patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login):
                    summary = run_login_export(
                        config=config,
                        emails=["ok@example.com"],
                        output_file=output_file,
                    )
            finally:
                os.chdir(original_cwd)

            self.assertEqual(summary["exported"], 1)
            self.assertEqual(summary["accounts_file"], str(accounts_file.resolve()))

    def test_can_login_email_not_in_accounts_file_with_config_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"

            def fake_login(**kwargs):
                self.assertEqual(kwargs["email"], "new@example.com")
                self.assertEqual(kwargs["password"], "shared-login-password")
                return {
                    "email": kwargs["email"],
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "id_token": "new-id",
                }

            config = {
                "_config_dir": str(root),
                "login": {"password": "shared-login-password"},
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": []},
            }

            with patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login):
                summary = run_login_export(
                    config=config,
                    emails=["new@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            self.assertEqual(summary["missing"], [])
            self.assertEqual(summary["missing_password"], [])
            self.assertEqual(summary["succeeded"], ["new@example.com"])
            self.assertEqual(summary["exported"], 1)

            saved_accounts = load_accounts(accounts_file)
            self.assertEqual(len(saved_accounts), 1)
            self.assertEqual(saved_accounts[0]["email"], "new@example.com")
            self.assertEqual(saved_accounts[0]["password"], "shared-login-password")
            self.assertEqual(saved_accounts[0]["access_token"], "new-access")

    def test_otp_mode_does_not_require_registered_account_or_password(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"

            def fake_login(**kwargs):
                self.assertEqual(kwargs["email"], "new@example.com")
                self.assertEqual(kwargs["password"], "")
                self.assertEqual(kwargs["login_mode"], "otp")
                return {
                    "email": kwargs["email"],
                    "access_token": "otp-access",
                    "refresh_token": "",
                    "id_token": "otp-access",
                    "session_token": "otp-session",
                }

            config = {
                "_config_dir": str(root),
                "login": {"mode": "otp"},
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": []},
            }

            with patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login):
                summary = run_login_export(
                    config=config,
                    emails=["new@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            self.assertEqual(summary["missing"], [])
            self.assertEqual(summary["missing_password"], [])
            self.assertEqual(summary["succeeded"], ["new@example.com"])
            self.assertEqual(summary["exported"], 1)

            saved_accounts = load_accounts(accounts_file)
            self.assertEqual(saved_accounts[0]["session_token"], "otp-session")
            bundle = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(
                bundle["accounts"][0]["credentials"]["session_token"],
                "otp-session",
            )

    def test_login_export_exports_one_record_per_workspace_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"
            accounts_file.write_text(
                json.dumps(
                    [
                        {
                            "email": "ok@example.com",
                            "password": "pw-ok",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            calls: list[str] = []

            def fake_login(**kwargs):
                workspace_id = kwargs["workspace_id"]
                calls.append(workspace_id)
                return {
                    "email": kwargs["email"],
                    "access_token": f"access-{workspace_id}",
                    "refresh_token": f"refresh-{workspace_id}",
                    "id_token": f"id-{workspace_id}",
                    "session_token": f"session-{workspace_id}",
                    "chatgpt_account_id": workspace_id,
                    "plan_type": "k12",
                }

            config = {
                "_config_dir": str(root),
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": ["workspace-1", "workspace-2"]},
            }

            with patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login):
                summary = run_login_export(
                    config=config,
                    emails=["ok@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            self.assertEqual(calls, ["workspace-1", "workspace-2"])
            self.assertEqual(summary["succeeded"], ["ok@example.com"])
            self.assertEqual(summary["exported"], 2)

            bundle = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(len(bundle["accounts"]), 2)
            self.assertEqual(
                [account["name"] for account in bundle["accounts"]],
                ["ok@example.com#workspace-1", "ok@example.com#workspace-2"],
            )
            self.assertEqual(
                [account["credentials"]["access_token"] for account in bundle["accounts"]],
                ["access-workspace-1", "access-workspace-2"],
            )
            self.assertEqual(
                [account["extra"]["workspace_id"] for account in bundle["accounts"]],
                ["workspace-1", "workspace-2"],
            )

class LoginJoinExportTests(unittest.TestCase):
    def test_logs_in_joins_refreshes_and_exports_only_successes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"
            accounts_file.write_text(
                json.dumps(
                    [
                        {
                            "email": "ok@example.com",
                            "password": "pw-ok",
                            "access_token": "old-access-ok",
                            "refresh_token": "old-refresh-ok",
                            "id_token": "old-id-ok",
                        },
                        {
                            "email": "fail@example.com",
                            "password": "pw-fail",
                            "access_token": "old-access-fail",
                            "refresh_token": "old-refresh-fail",
                        },
                    ]
                ),
                encoding="utf-8",
            )

            def fake_login(**kwargs):
                if kwargs["email"] == "fail@example.com":
                    raise RuntimeError("login rejected")
                return {
                    "email": kwargs["email"],
                    "access_token": "new-access-ok",
                    "refresh_token": "new-refresh-ok",
                    "id_token": "new-id-ok",
                }

            def fake_join(config, accounts):
                self.assertEqual([account["email"] for account in accounts], ["ok@example.com"])
                for account in accounts:
                    account["join_status"] = "ok"
                return accounts

            def fake_refresh(config, accounts):
                self.assertEqual([account["email"] for account in accounts], ["ok@example.com"])
                for account in accounts:
                    account["access_token"] = "refreshed-access-ok"
                    account["refresh_token"] = "refreshed-refresh-ok"
                    account["plan_type"] = "k12"
                return accounts

            config = {
                "_config_dir": str(root),
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": ["workspace-1"]},
            }

            with (
                patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login),
                patch("chatgpt_register_sub2api.pipeline.run_join_workspace", side_effect=fake_join),
                patch("chatgpt_register_sub2api.pipeline.run_refresh_tokens", side_effect=fake_refresh),
            ):
                summary = run_login_join_export(
                    config=config,
                    emails=["ok@example.com", "fail@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            self.assertEqual(summary["succeeded"], ["ok@example.com"])
            self.assertEqual(summary["failed"], [{"email": "fail@example.com", "error": "login rejected"}])
            self.assertEqual(summary["joined"], 1)
            self.assertEqual(summary["refreshed"], 1)
            self.assertEqual(summary["exported"], 1)

            bundle = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(len(bundle["accounts"]), 1)
            self.assertEqual(bundle["accounts"][0]["name"], "ok@example.com")
            self.assertEqual(
                bundle["accounts"][0]["credentials"]["access_token"],
                "refreshed-access-ok",
            )

            saved_accounts = load_accounts(accounts_file)
            saved_ok = next(acc for acc in saved_accounts if acc["email"] == "ok@example.com")
            saved_fail = next(acc for acc in saved_accounts if acc["email"] == "fail@example.com")
            self.assertEqual(saved_ok["login_join_export_status"], "ok")
            self.assertEqual(saved_ok["join_status"], "ok")
            self.assertEqual(saved_ok["plan_type"], "k12")
            self.assertEqual(saved_fail["login_join_export_status"], "failed")
            self.assertEqual(saved_fail["access_token"], "old-access-fail")

    def test_login_join_export_does_not_write_output_when_no_successes(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"
            accounts_file.write_text(
                json.dumps(
                    [
                        {
                            "email": "fail@example.com",
                            "password": "pw-fail",
                        }
                    ]
                ),
                encoding="utf-8",
            )

            def fake_login(**kwargs):
                raise RuntimeError("login rejected")

            config = {
                "_config_dir": str(root),
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": ["workspace-1"]},
            }

            with (
                patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login),
                patch("chatgpt_register_sub2api.pipeline.run_join_workspace") as join_mock,
                patch("chatgpt_register_sub2api.pipeline.run_refresh_tokens") as refresh_mock,
            ):
                summary = run_login_join_export(
                    config=config,
                    emails=["fail@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            join_mock.assert_not_called()
            refresh_mock.assert_not_called()
            self.assertEqual(summary["succeeded"], [])
            self.assertEqual(summary["exported"], 0)
            self.assertEqual(summary["output_file"], "")
            self.assertFalse(output_file.exists())

    def test_login_join_export_can_start_without_existing_account_record(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"

            def fake_login(**kwargs):
                self.assertEqual(kwargs["password"], "shared-login-password")
                return {
                    "email": kwargs["email"],
                    "access_token": "new-access",
                    "refresh_token": "new-refresh",
                    "id_token": "new-id",
                }

            def fake_join(config, accounts):
                self.assertEqual([account["email"] for account in accounts], ["new@example.com"])
                for account in accounts:
                    account["join_status"] = "ok"
                return accounts

            def fake_refresh(config, accounts):
                for account in accounts:
                    account["plan_type"] = "k12"
                return accounts

            config = {
                "_config_dir": str(root),
                "login": {"password": "shared-login-password"},
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": ["workspace-1"]},
            }

            with (
                patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login),
                patch("chatgpt_register_sub2api.pipeline.run_join_workspace", side_effect=fake_join),
                patch("chatgpt_register_sub2api.pipeline.run_refresh_tokens", side_effect=fake_refresh),
            ):
                summary = run_login_join_export(
                    config=config,
                    emails=["new@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            self.assertEqual(summary["missing"], [])
            self.assertEqual(summary["succeeded"], ["new@example.com"])
            self.assertEqual(summary["joined"], 1)
            self.assertEqual(summary["refreshed"], 1)
            self.assertEqual(summary["exported"], 1)

    def test_login_join_export_skips_join_when_login_already_returns_workspace_session(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"

            def fake_login(**kwargs):
                return {
                    "email": kwargs["email"],
                    "access_token": "k12-access",
                    "refresh_token": "",
                    "id_token": "k12-access",
                    "session_token": "k12-session",
                    "chatgpt_account_id": "workspace-1",
                    "plan_type": "k12",
                }

            def fake_refresh(config, accounts):
                self.assertEqual([account["email"] for account in accounts], ["new@example.com"])
                return accounts

            config = {
                "_config_dir": str(root),
                "login": {"mode": "otp"},
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": ["workspace-1"]},
            }

            with (
                patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login),
                patch("chatgpt_register_sub2api.pipeline.run_join_workspace") as join_mock,
                patch("chatgpt_register_sub2api.pipeline.run_refresh_tokens", side_effect=fake_refresh),
            ):
                summary = run_login_join_export(
                    config=config,
                    emails=["new@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            join_mock.assert_not_called()
            self.assertEqual(summary["joined"], 1)
            self.assertEqual(summary["refreshed"], 1)
            saved_accounts = load_accounts(accounts_file)
            self.assertEqual(saved_accounts[0]["join_status"], "ok")
            self.assertEqual(saved_accounts[0]["access_token"], "k12-access")

    def test_login_join_export_exports_one_record_per_workspace_id(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            accounts_file = root / "registered_accounts.json"
            output_file = root / "sub2api.json"

            calls: list[str] = []

            def fake_login(**kwargs):
                workspace_id = kwargs["workspace_id"]
                calls.append(workspace_id)
                return {
                    "email": kwargs["email"],
                    "access_token": f"access-{workspace_id}",
                    "refresh_token": "",
                    "id_token": f"id-{workspace_id}",
                    "session_token": f"session-{workspace_id}",
                    "chatgpt_account_id": workspace_id,
                    "plan_type": "k12",
                }

            def fake_refresh(config, accounts):
                self.assertEqual(config["workspace"]["ids"], [accounts[0]["workspace_id"]])
                return accounts

            config = {
                "_config_dir": str(root),
                "login": {"mode": "otp"},
                "mail": {},
                "proxy": {"url": "", "flaresolverr_url": ""},
                "workspace": {"ids": ["workspace-1", "workspace-2"]},
            }

            with (
                patch("chatgpt_register_sub2api.pipeline.re_login_for_team_token", side_effect=fake_login),
                patch("chatgpt_register_sub2api.pipeline.run_join_workspace") as join_mock,
                patch("chatgpt_register_sub2api.pipeline.run_refresh_tokens", side_effect=fake_refresh),
            ):
                summary = run_login_join_export(
                    config=config,
                    emails=["new@example.com"],
                    output_file=output_file,
                    accounts_file=accounts_file,
                )

            join_mock.assert_not_called()
            self.assertEqual(calls, ["workspace-1", "workspace-2"])
            self.assertEqual(summary["succeeded"], ["new@example.com"])
            self.assertEqual(summary["joined"], 2)
            self.assertEqual(summary["refreshed"], 2)
            self.assertEqual(summary["exported"], 2)

            bundle = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(len(bundle["accounts"]), 2)
            self.assertEqual(
                [account["name"] for account in bundle["accounts"]],
                ["new@example.com#workspace-1", "new@example.com#workspace-2"],
            )
            self.assertEqual(
                [account["credentials"]["access_token"] for account in bundle["accounts"]],
                ["access-workspace-1", "access-workspace-2"],
            )


class RefreshTokenTests(unittest.TestCase):
    def test_refresh_tokens_checks_account_info_without_refresh_token(self) -> None:
        session = FakeRefreshSession()
        accounts = [
            {
                "email": "otp@example.com",
                "access_token": "otp-access",
                "refresh_token": "",
                "session_token": "otp-session",
            }
        ]
        config = {
            "proxy": {"url": ""},
            "workspace": {"ids": ["workspace-1"]},
        }

        with patch("curl_cffi.requests.Session", return_value=session):
            refreshed = run_refresh_tokens(config, accounts)

        self.assertEqual(refreshed[0]["plan_type"], "k12")
        self.assertEqual(refreshed[0]["chatgpt_account_id"], "account-123")
        self.assertEqual(refreshed[0]["account_user_role"], "member")
        self.assertEqual(refreshed[0]["session_token"], "otp-session")
        self.assertEqual(session.posts, [])
        self.assertEqual(len(session.gets), 1)
        self.assertEqual(
            session.gets[0]["kwargs"]["headers"]["Authorization"],
            "Bearer otp-access",
        )

    def test_refresh_tokens_does_not_overwrite_confirmed_workspace_session_with_default_free_check(self) -> None:
        class FreeDefaultSession(FakeRefreshSession):
            response_data = {
                "accounts": {
                    "default": {
                        "account": {
                            "plan_type": "free",
                            "account_id": "personal-account",
                            "account_user_role": "account-owner",
                        }
                    }
                }
            }

        session = FreeDefaultSession()
        accounts = [
            {
                "email": "otp@example.com",
                "access_token": "k12-access",
                "refresh_token": "",
                "session_token": "k12-session",
                "chatgpt_account_id": "workspace-1",
                "plan_type": "k12",
                "join_status": "ok",
            }
        ]
        config = {
            "proxy": {"url": ""},
            "workspace": {"ids": ["workspace-1"]},
        }

        with patch("curl_cffi.requests.Session", return_value=session):
            refreshed = run_refresh_tokens(config, accounts)

        self.assertEqual(refreshed[0]["plan_type"], "k12")
        self.assertEqual(refreshed[0]["chatgpt_account_id"], "workspace-1")
        self.assertEqual(session.posts, [])
        self.assertEqual(session.gets, [])


class ExportWorkspaceTokenTests(unittest.TestCase):
    def test_export_uses_stored_workspace_tokens_for_multiple_workspace_ids(self) -> None:
        with tempfile.TemporaryDirectory() as tmp_dir:
            root = Path(tmp_dir)
            output_file = root / "sub2api.json"
            accounts = [
                {
                    "email": "ok@example.com",
                    "access_token": "top-access",
                    "workspace_tokens": {
                        "workspace-1": {
                            "email": "ok@example.com",
                            "workspace_id": "workspace-1",
                            "access_token": "access-workspace-1",
                            "refresh_token": "refresh-workspace-1",
                            "id_token": "id-workspace-1",
                            "source_type": "login_join_export",
                        },
                        "workspace-2": {
                            "email": "ok@example.com",
                            "workspace_id": "workspace-2",
                            "access_token": "access-workspace-2",
                            "refresh_token": "refresh-workspace-2",
                            "id_token": "id-workspace-2",
                            "source_type": "login_join_export",
                        },
                    },
                }
            ]
            config = {
                "_config_dir": str(root),
                "workspace": {"ids": ["workspace-1", "workspace-2"]},
            }

            run_export(config, accounts, output_file)

            bundle = json.loads(output_file.read_text(encoding="utf-8"))
            self.assertEqual(
                [account["name"] for account in bundle["accounts"]],
                ["ok@example.com#workspace-1", "ok@example.com#workspace-2"],
            )
            self.assertEqual(
                [account["credentials"]["access_token"] for account in bundle["accounts"]],
                ["access-workspace-1", "access-workspace-2"],
            )


if __name__ == "__main__":
    unittest.main()
