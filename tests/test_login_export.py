from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from chatgpt_register_sub2api.pipeline import load_accounts, run_login_export


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


if __name__ == "__main__":
    unittest.main()
