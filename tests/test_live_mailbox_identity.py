from __future__ import annotations

import os
import unittest
from pathlib import Path

from chatgpt_register_sub2api.config import load_config
from chatgpt_register_sub2api.pipeline import load_accounts
from chatgpt_register_sub2api.register.mail_provider import (
    OutlookTokenProvider,
    _make_config,
    _populate_mailbox_credentials,
)


OUTLOOK_GRAPH_IDENTITY_SCOPE = (
    "offline_access "
    "https://graph.microsoft.com/User.Read "
    "https://graph.microsoft.com/Mail.Read"
)


class LiveMailboxIdentityTests(unittest.TestCase):
    @unittest.skipUnless(
        os.getenv("LIVE_MAILBOX_IDENTITY") == "1",
        "Set LIVE_MAILBOX_IDENTITY=1 to verify the real Outlook token mailbox.",
    )
    def test_configured_outlook_token_belongs_to_target_mailbox(self) -> None:
        target_email = os.getenv("LIVE_MAILBOX_EMAIL", "").strip()
        self.assertTrue(target_email, "Set LIVE_MAILBOX_EMAIL to the mailbox to verify")
        config = load_config("config.yaml")
        accounts = load_accounts(Path("registered_accounts.json"))
        self.assertTrue(
            any(
                str(item.get("email") or "").strip().lower() == target_email.lower()
                for item in accounts
            ),
            f"{target_email} not found in registered_accounts.json",
        )

        providers = [
            item
            for item in config.get("mail", {}).get("providers", [])
            if isinstance(item, dict)
            and item.get("type") == "outlook_token"
            and item.get("enable", True)
        ]
        mailbox = {
            "provider": "outlook_token",
            "provider_ref": "",
            "address": target_email,
        }

        matched_entry = None
        matched_email = ""
        for entry in providers:
            probe = dict(mailbox)
            matched_email = _populate_mailbox_credentials(probe, entry)
            if matched_email:
                matched_entry = entry
                mailbox = probe
                break

        self.assertIsNotNone(
            matched_entry,
            f"No config mailboxes entry found for {target_email}",
        )
        self.assertEqual(matched_email.lower(), target_email.lower())

        provider = OutlookTokenProvider(matched_entry, _make_config(config.get("mail", {})))
        try:
            access_token = provider._cached_access_token(
                mailbox,
                str(mailbox.get("client_id") or ""),
                str(mailbox.get("refresh_token") or ""),
                OUTLOOK_GRAPH_IDENTITY_SCOPE,
            )
            resp = provider.session.get(
                "https://graph.microsoft.com/v1.0/me",
                headers={
                    "Authorization": f"Bearer {access_token}",
                    "Accept": "application/json",
                },
                timeout=30,
                verify=False,
            )
            self.assertEqual(resp.status_code, 200, resp.text[:500])
            data = resp.json() if resp.text else {}
        finally:
            provider.close()

        graph_mail = str(data.get("mail") or "").strip()
        graph_upn = str(data.get("userPrincipalName") or "").strip()
        graph_other = [
            str(item).strip()
            for item in data.get("otherMails", [])
            if str(item).strip()
        ] if isinstance(data.get("otherMails"), list) else []

        identities = {graph_mail.lower(), graph_upn.lower(), *(item.lower() for item in graph_other)}
        identities.discard("")

        print(f"target_email={target_email}")
        print(f"config_credential_email={matched_email}")
        print(f"graph_mail={graph_mail}")
        print(f"graph_userPrincipalName={graph_upn}")
        print(f"graph_otherMails={graph_other}")

        self.assertIn(
            target_email.lower(),
            identities,
            f"Outlook token does not belong to {target_email}; Graph identities={sorted(identities)}",
        )


if __name__ == "__main__":
    unittest.main()
