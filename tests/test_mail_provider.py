from __future__ import annotations

import unittest
from unittest.mock import patch
from datetime import datetime, timezone

from chatgpt_register_sub2api.register.mail_provider import OutlookTokenProvider, wait_for_code


class MailProviderTests(unittest.TestCase):
    def test_wait_for_code_enriches_existing_mailbox_from_config_pool(self) -> None:
        mail_config = {
            "providers": [
                {
                    "type": "outlook_token",
                    "enable": True,
                    "mode": "graph",
                    "mailboxes": (
                        "other@example.com----pw1----client-other----refresh-other\n"
                        "user@example.com----pw2----client-user----refresh-user"
                    ),
                }
            ],
            "wait_timeout": 1,
            "wait_interval": 1,
        }
        mailbox = {
            "provider": "outlook_token",
            "provider_ref": "",
            "address": "user@example.com",
        }
        seen_mailboxes: list[dict] = []

        def fake_wait_for_code(self, received_mailbox):
            seen_mailboxes.append(dict(received_mailbox))
            return "123456"

        with patch(
            "chatgpt_register_sub2api.register.mail_provider.OutlookTokenProvider._make_session",
            return_value=None,
        ), patch(
            "chatgpt_register_sub2api.register.mail_provider.OutlookTokenProvider.close",
            return_value=None,
        ), patch(
            "chatgpt_register_sub2api.register.mail_provider.OutlookTokenProvider.wait_for_code",
            fake_wait_for_code,
        ):
            code = wait_for_code(mail_config, mailbox)

        self.assertEqual(code, "123456")
        self.assertEqual(seen_mailboxes[0]["client_id"], "client-user")
        self.assertEqual(seen_mailboxes[0]["refresh_token"], "refresh-user")
        self.assertEqual(seen_mailboxes[0]["_credential_email"], "user@example.com")
        self.assertEqual(mailbox["client_id"], "client-user")
        self.assertEqual(mailbox["refresh_token"], "refresh-user")
        self.assertEqual(mailbox["_credential_email"], "user@example.com")

    def test_wait_for_code_does_not_fallback_to_wrong_mailbox_for_address(self) -> None:
        mail_config = {
            "providers": [
                {
                    "type": "outlook_token",
                    "enable": True,
                    "mode": "graph",
                    "mailboxes": "other@example.com----pw1----client-other----refresh-other",
                }
            ],
            "wait_timeout": 1,
            "wait_interval": 1,
        }
        mailbox = {
            "provider": "outlook_token",
            "provider_ref": "",
            "address": "missing@example.com",
        }

        with self.assertRaisesRegex(RuntimeError, "No outlook_token mailbox credentials found"):
            wait_for_code(mail_config, mailbox)

    def test_wait_for_code_can_filter_by_subject(self) -> None:
        provider = OutlookTokenProvider.__new__(OutlookTokenProvider)
        provider.conf = {"wait_timeout": 0.3, "wait_interval": 0.1}
        messages = [
            {
                "subject": "Your temporary OpenAI login code",
                "sender": "noreply@tm.openai.com",
                "text_content": "102869",
                "html_content": "",
                "received_at": datetime.now(timezone.utc),
            },
            {
                "subject": "Your temporary OpenAI verification code",
                "sender": "noreply@tm.openai.com",
                "text_content": "654321",
                "html_content": "",
                "received_at": datetime.now(timezone.utc),
            },
        ]

        def fake_fetch_recent_messages(mailbox):
            return messages

        provider.fetch_recent_messages = fake_fetch_recent_messages

        code = provider.wait_for_code(
            {
                "address": "user@example.com",
                "subject_include": "verification code",
            }
        )

        self.assertEqual(code, "654321")


if __name__ == "__main__":
    unittest.main()
