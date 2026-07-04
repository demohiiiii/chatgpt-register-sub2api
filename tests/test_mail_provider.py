from __future__ import annotations

import unittest
from unittest.mock import patch
from datetime import datetime, timezone

from chatgpt_register_sub2api.register.mail_provider import (
    GmailProvider,
    OutlookTokenProvider,
    create_mailbox,
    mailbox_for_address,
    prime_seen_code_messages,
    wait_for_code,
)


class MailProviderTests(unittest.TestCase):
    def test_create_mailbox_supports_gmail_alias_provider(self) -> None:
        mail_config = {
            "providers": [
                {
                    "type": "gmail",
                    "enable": True,
                    "user": "base@gmail.com",
                    "app_password": "abcd efgh ijkl mnop",
                    "alias_length": 8,
                }
            ],
            "wait_timeout": 1,
            "wait_interval": 1,
        }

        mailbox = create_mailbox(mail_config)

        self.assertEqual(mailbox["provider"], "gmail")
        self.assertEqual(mailbox["provider_ref"], "gmail#1")
        self.assertRegex(mailbox["address"], r"^base\+[a-z0-9]{8}@gmail\.com$")
        self.assertEqual(mailbox["_credential_email"], "base@gmail.com")
        self.assertIn("_code_not_before", mailbox)

    def test_wait_for_code_uses_gmail_provider_for_alias_address(self) -> None:
        mail_config = {
            "providers": [
                {
                    "type": "gmail",
                    "enable": True,
                    "user": "base@gmail.com",
                    "app_password": "abcd efgh ijkl mnop",
                }
            ],
            "wait_timeout": 1,
            "wait_interval": 1,
        }
        mailbox = {
            "address": "base+login123@gmail.com",
            "subject_include": "login code",
        }
        seen_mailboxes: list[dict] = []

        def fake_wait_for_code(self, received_mailbox):
            seen_mailboxes.append(dict(received_mailbox))
            return "654321"

        with patch(
            "chatgpt_register_sub2api.register.mail_provider.GmailProvider.wait_for_code",
            fake_wait_for_code,
        ):
            code = wait_for_code(mail_config, mailbox)

        self.assertEqual(code, "654321")
        self.assertEqual(seen_mailboxes[0]["provider"], "gmail")
        self.assertEqual(seen_mailboxes[0]["provider_ref"], "gmail#1")
        self.assertEqual(seen_mailboxes[0]["address"], "base+login123@gmail.com")
        self.assertEqual(seen_mailboxes[0]["_credential_email"], "base@gmail.com")

    def test_mailbox_for_address_matches_gmail_base_and_alias(self) -> None:
        mail_config = {
            "providers": [
                {
                    "type": "gmail",
                    "enable": True,
                    "user": "base@gmail.com",
                    "app_password": "app-pass",
                }
            ]
        }

        base = mailbox_for_address(mail_config, "base@gmail.com")
        alias = mailbox_for_address(mail_config, "base+tag@gmail.com")

        self.assertEqual(base["provider"], "gmail")
        self.assertEqual(alias["provider"], "gmail")
        self.assertEqual(alias["_credential_email"], "base@gmail.com")

    def test_gmail_wait_for_code_filters_target_alias(self) -> None:
        provider = GmailProvider.__new__(GmailProvider)
        provider.conf = {"wait_timeout": 0.3, "wait_interval": 0.1}
        messages = [
            {
                "subject": "Your temporary OpenAI login code",
                "sender": "noreply@tm.openai.com",
                "recipients": ["base+other@gmail.com"],
                "text_content": "111111",
                "html_content": "",
                "received_at": datetime.now(timezone.utc),
            },
            {
                "subject": "Your temporary OpenAI login code",
                "sender": "noreply@tm.openai.com",
                "recipients": ["base+target@gmail.com"],
                "text_content": "222222",
                "html_content": "",
                "received_at": datetime.now(timezone.utc),
            },
        ]

        def fake_fetch_recent_messages(mailbox):
            return messages

        provider.fetch_recent_messages = fake_fetch_recent_messages

        code = provider.wait_for_code(
            {
                "address": "base+target@gmail.com",
                "subject_include": "login code",
            }
        )

        self.assertEqual(code, "222222")

    def test_gmail_wait_for_code_skips_code_consumed_by_previous_mailbox(self) -> None:
        provider = GmailProvider.__new__(GmailProvider)
        provider.conf = {"wait_timeout": 0.3, "wait_interval": 0.1}
        address = "base+cachetest@gmail.com"
        old_message = {
            "provider": "gmail",
            "mailbox": address,
            "message_id": "old-message",
            "subject": "Your temporary ChatGPT login code",
            "sender": "noreply@tm.openai.com",
            "recipients": [address],
            "text_content": "Your code is 111111",
            "html_content": "",
            "received_at": datetime.now(timezone.utc),
        }
        new_message = {
            "provider": "gmail",
            "mailbox": address,
            "message_id": "new-message",
            "subject": "Your temporary ChatGPT login code",
            "sender": "noreply@tm.openai.com",
            "recipients": [address],
            "text_content": "Your code is 222222",
            "html_content": "",
            "received_at": datetime.now(timezone.utc),
        }
        messages = [old_message]
        wait_messages = [old_message, new_message]

        calls = {"count": 0}

        def fake_fetch_recent_messages(mailbox):
            calls["count"] += 1
            return messages if calls["count"] == 1 else wait_messages

        provider.fetch_recent_messages = fake_fetch_recent_messages

        first_code = provider.wait_for_code(
            {
                "provider": "gmail",
                "provider_ref": "gmail#cachetest",
                "address": address,
                "subject_include": "login code",
            }
        )
        second_code = provider.wait_for_code(
            {
                "provider": "gmail",
                "provider_ref": "gmail#cachetest",
                "address": address,
                "subject_include": "login code",
            }
        )

        self.assertEqual(first_code, "111111")
        self.assertEqual(second_code, "222222")

    def test_gmail_wait_for_code_allows_same_code_from_new_message_ref(self) -> None:
        provider = GmailProvider.__new__(GmailProvider)
        provider.conf = {"wait_timeout": 0.3, "wait_interval": 0.1}
        address = "base+samecode@gmail.com"
        old_message = {
            "provider": "gmail",
            "mailbox": address,
            "message_id": "old-message",
            "subject": "Your temporary ChatGPT login code",
            "sender": "noreply@tm.openai.com",
            "recipients": [address],
            "text_content": "Your code is 555555",
            "html_content": "",
            "received_at": datetime.now(timezone.utc),
        }
        new_message = {
            "provider": "gmail",
            "mailbox": address,
            "message_id": "new-message",
            "subject": "Your temporary ChatGPT login code",
            "sender": "noreply@tm.openai.com",
            "recipients": [address],
            "text_content": "Your code is 555555",
            "html_content": "",
            "received_at": datetime.now(timezone.utc),
        }
        calls = {"count": 0}

        def fake_fetch_recent_messages(mailbox):
            calls["count"] += 1
            return [old_message] if calls["count"] == 1 else [old_message, new_message]

        provider.fetch_recent_messages = fake_fetch_recent_messages

        first_code = provider.wait_for_code(
            {
                "provider": "gmail",
                "provider_ref": "gmail#samecode",
                "address": address,
                "subject_include": "login code",
            }
        )
        second_code = provider.wait_for_code(
            {
                "provider": "gmail",
                "provider_ref": "gmail#samecode",
                "address": address,
                "subject_include": "login code",
            }
        )

        self.assertEqual(first_code, "555555")
        self.assertEqual(second_code, "555555")

    def test_prime_seen_code_messages_skips_existing_code_on_next_wait(self) -> None:
        address = "base+primecache@gmail.com"
        old_message = {
            "provider": "gmail",
            "mailbox": address,
            "message_id": "old-message",
            "subject": "Your temporary ChatGPT login code",
            "sender": "noreply@tm.openai.com",
            "recipients": [address],
            "text_content": "Your code is 111111",
            "html_content": "",
            "received_at": datetime.now(timezone.utc),
        }
        new_message = {
            "provider": "gmail",
            "mailbox": address,
            "message_id": "new-message",
            "subject": "Your temporary ChatGPT login code",
            "sender": "noreply@tm.openai.com",
            "recipients": [address],
            "text_content": "Your code is 222222",
            "html_content": "",
            "received_at": datetime.now(timezone.utc),
        }
        messages = [old_message]
        wait_messages = [old_message, new_message]
        mail_config = {
            "providers": [
                {
                    "type": "gmail",
                    "provider_ref": "gmail#primecache",
                    "enable": True,
                    "user": "base@gmail.com",
                    "app_password": "app-pass",
                }
            ],
            "wait_timeout": 0.3,
            "wait_interval": 0.1,
        }

        calls = {"count": 0}

        def fake_fetch_recent_messages(self, mailbox):
            calls["count"] += 1
            return messages if calls["count"] == 1 else wait_messages

        with patch(
            "chatgpt_register_sub2api.register.mail_provider.GmailProvider.fetch_recent_messages",
            fake_fetch_recent_messages,
        ):
            count = prime_seen_code_messages(
                mail_config,
                {
                    "provider": "gmail",
                    "provider_ref": "gmail#primecache",
                    "address": address,
                    "subject_include": "login code",
                },
            )
            code = wait_for_code(
                mail_config,
                {
                    "provider": "gmail",
                    "provider_ref": "gmail#primecache",
                    "address": address,
                    "subject_include": "login code",
                },
            )

        self.assertEqual(count, 1)
        self.assertEqual(code, "222222")

    def test_gmail_fetch_recent_messages_searches_target_address_with_timeout(self) -> None:
        searches: list[str] = []
        created: list[dict] = []

        class FakeIMAP:
            def __init__(self, host, port, timeout=None):
                created.append({"host": host, "port": port, "timeout": timeout})

            def login(self, user, password):
                return "OK", []

            def select(self, mailbox, readonly=False):
                return "OK", []

            def uid(self, command, *args):
                if command == "search":
                    searches.append(" ".join(str(arg) for arg in args))
                    return "OK", [b""]
                return "OK", []

            def logout(self):
                return "OK", []

        provider = GmailProvider(
            {
                "type": "gmail",
                "user": "base@gmail.com",
                "app_password": "app-pass",
                "message_limit": 5,
            },
            {
                "request_timeout": 12,
                "wait_timeout": 1,
                "wait_interval": 1,
            },
        )

        with patch("chatgpt_register_sub2api.register.mail_provider.imaplib.IMAP4_SSL", FakeIMAP):
            messages = provider.fetch_recent_messages({"address": "base+target@gmail.com"})

        self.assertEqual(messages, [])
        self.assertEqual(created[0]["host"], "imap.gmail.com")
        self.assertEqual(created[0]["port"], 993)
        self.assertEqual(created[0]["timeout"], 12)
        self.assertIn('(TO "base+target@gmail.com")', searches[0])

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

    def test_outlook_wait_for_code_skips_code_consumed_by_previous_mailbox(self) -> None:
        provider = OutlookTokenProvider.__new__(OutlookTokenProvider)
        provider.conf = {"wait_timeout": 0.3, "wait_interval": 0.1}
        address = "cachetest@example.com"
        messages = [
            {
                "provider": "outlook_token",
                "mailbox": address,
                "message_id": "old-message",
                "subject": "Your temporary OpenAI login code",
                "sender": "noreply@tm.openai.com",
                "text_content": "Your code is 333333",
                "html_content": "",
                "received_at": datetime.now(timezone.utc),
            },
            {
                "provider": "outlook_token",
                "mailbox": address,
                "message_id": "new-message",
                "subject": "Your temporary OpenAI login code",
                "sender": "noreply@tm.openai.com",
                "text_content": "Your code is 444444",
                "html_content": "",
                "received_at": datetime.now(timezone.utc),
            },
        ]

        def fake_fetch_recent_messages(mailbox):
            return messages

        provider.fetch_recent_messages = fake_fetch_recent_messages

        first_code = provider.wait_for_code(
            {
                "provider": "outlook_token",
                "provider_ref": "outlook#cachetest",
                "address": address,
                "subject_include": "login code",
            }
        )
        second_code = provider.wait_for_code(
            {
                "provider": "outlook_token",
                "provider_ref": "outlook#cachetest",
                "address": address,
                "subject_include": "login code",
            }
        )

        self.assertEqual(first_code, "333333")
        self.assertEqual(second_code, "444444")


if __name__ == "__main__":
    unittest.main()
