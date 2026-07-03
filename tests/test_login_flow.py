from __future__ import annotations

import unittest
from unittest.mock import patch

from chatgpt_register_sub2api.login.login_flow import (
    LoginError,
    _exchange_login_tokens,
    _handle_password_verification,
)


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        data: dict | None = None,
        text: str = "",
        url: str = "",
    ) -> None:
        self.status_code = status_code
        self._data = data or {}
        self.text = text or ("{}" if data is not None else "")
        self.url = url

    def json(self) -> dict:
        return self._data


class FakeSession:
    def __init__(self, responses: list[FakeResponse]) -> None:
        self.responses = responses
        self.requests: list[dict] = []
        self.cookies = FakeCookies()

    def request(self, method: str, url: str, timeout: int = 30, **kwargs):
        self.requests.append(
            {
                "method": method,
                "url": url,
                "timeout": timeout,
                "kwargs": kwargs,
            }
        )
        return self.responses.pop(0)

    def post(self, url: str, **kwargs):
        self.requests.append(
            {
                "method": "POST",
                "url": url,
                "kwargs": kwargs,
            }
        )
        return self.responses.pop(0)

    def get(self, url: str, **kwargs):
        self.requests.append(
            {
                "method": "GET",
                "url": url,
                "kwargs": kwargs,
            }
        )
        return self.responses.pop(0)


class FakeCookies:
    def __init__(self) -> None:
        self.values: list[dict] = []

    def set(self, name: str, value: str, domain: str = "") -> None:
        self.values.append({"name": name, "value": value, "domain": domain})


class LoginFlowTests(unittest.TestCase):
    def test_password_verification_uses_password_verify_endpoint_and_returns_auth_code(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "continue_url": "https://platform.openai.com/auth/callback?code=auth-code-123&state=abc"
                    },
                )
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.build_sentinel_token",
            return_value=("sentinel-token", "oai-sc-value"),
        ):
            code = _handle_password_verification(
                session=session,
                device_id="device-1",
                email="user@example.com",
                password="secret",
                mail_config={},
                proxy="",
                flaresolverr_url="",
            )

        self.assertEqual(code, "auth-code-123")
        request = session.requests[0]
        self.assertEqual(request["method"], "POST")
        self.assertEqual(
            request["url"],
            "https://auth.openai.com/api/accounts/password/verify",
        )
        self.assertEqual(request["kwargs"]["json"], {"password": "secret"})
        self.assertEqual(
            request["kwargs"]["headers"]["openai-sentinel-token"],
            "sentinel-token",
        )
        self.assertEqual(
            session.cookies.values,
            [{"name": "oai-sc", "value": "oai-sc-value", "domain": ".openai.com"}],
        )

    def test_password_verification_handles_email_otp_requirement(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "page": {"type": "email_otp_verification"},
                        "oai-client-auth-session": "auth-session-123",
                    },
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "https://platform.openai.com/auth/callback?code=otp-code-456"
                    },
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.build_sentinel_token",
            return_value=("sentinel-token", ""),
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
        ) as wait_for_code_mock:
            wait_for_code_mock.return_value = "123456"
            code = _handle_password_verification(
                    session=session,
                    device_id="device-1",
                    email="user@example.com",
                    password="secret",
                    mail_config={"wait_timeout": 1},
                    proxy="",
                    flaresolverr_url="",
                )

        self.assertEqual(code, "otp-code-456")
        self.assertEqual(
            [request["url"] for request in session.requests],
            [
                "https://auth.openai.com/api/accounts/password/verify",
                "https://auth.openai.com/api/accounts/email-otp/validate",
            ],
        )
        self.assertEqual(session.requests[1]["kwargs"]["json"], {"code": "123456"})
        self.assertEqual(
            session.requests[1]["kwargs"]["headers"]["oai-client-auth-session"],
            "auth-session-123",
        )
        self.assertIn("traceparent", session.requests[1]["kwargs"]["headers"])
        self.assertIn("sec-ch-ua", session.requests[1]["kwargs"]["headers"])
        mailbox = wait_for_code_mock.call_args.args[1]
        self.assertEqual(mailbox["address"], "user@example.com")
        self.assertEqual(mailbox["subject_include"], "login code")
        self.assertIn("_code_not_before", mailbox)

    def test_email_otp_follows_continue_url_when_validation_has_no_code(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {"page": {"type": "email_otp_verification"}},
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "/api/accounts/authorize/continue?state=needs-follow",
                        "method": "GET",
                        "page": {"type": "account_selection"},
                        "oai-client-auth-session": "session-1",
                    },
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "/api/accounts/authorize/continue?state=second-follow",
                        "method": "GET",
                        "oai-client-auth-session": "session-1",
                    },
                ),
                FakeResponse(
                    200,
                    {},
                    url="https://platform.openai.com/auth/callback?code=followed-code-789&state=done",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.build_sentinel_token",
            return_value=("sentinel-token", ""),
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            code = _handle_password_verification(
                session=session,
                device_id="device-1",
                email="user@example.com",
                password="secret",
                mail_config={"wait_timeout": 1},
                proxy="",
                flaresolverr_url="",
            )

        self.assertEqual(code, "followed-code-789")
        self.assertEqual(
            session.requests[2]["url"],
            "https://auth.openai.com/api/accounts/authorize/continue?state=needs-follow",
        )
        self.assertTrue(session.requests[2]["kwargs"]["allow_redirects"])
        self.assertEqual(
            session.requests[2]["kwargs"]["headers"]["oai-client-auth-session"],
            "session-1",
        )
        self.assertEqual(
            session.requests[3]["url"],
            "https://auth.openai.com/api/accounts/authorize/continue?state=second-follow",
        )

    def test_exchange_login_tokens_uses_provided_authorization_code(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "access_token": "access-new",
                        "refresh_token": "refresh-new",
                        "id_token": "id-new",
                    },
                )
            ]
        )

        tokens = _exchange_login_tokens(
            session=session,
            code_verifier="verifier-1",
            authorization_code="auth-code-123",
        )

        self.assertEqual(tokens["access_token"], "access-new")
        request = session.requests[0]
        self.assertEqual(
            request["url"],
            "https://auth.openai.com/api/accounts/oauth/token",
        )
        self.assertEqual(request["kwargs"]["json"]["code"], "auth-code-123")
        self.assertEqual(request["kwargs"]["json"]["code_verifier"], "verifier-1")

    def test_email_otp_failure_includes_authorize_continue_trace(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    {
                        "page": {"type": "email_otp_verification"},
                        "oai-client-auth-session": "auth-session-123",
                    },
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "/api/accounts/authorize/continue?state=needs-follow",
                        "method": "GET",
                        "page": {"type": "account_selection"},
                        "oai-client-auth-session": "session-1",
                    },
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "/api/accounts/authorize/continue?state=still-no-code",
                        "method": "GET",
                        "page": {"type": "account_selection"},
                    },
                    url="https://auth.openai.com/api/accounts/authorize/continue?state=needs-follow",
                ),
                FakeResponse(
                    200,
                    {"page": {"type": "account_selection"}},
                    url="https://auth.openai.com/api/accounts/authorize/continue?state=still-no-code",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.build_sentinel_token",
            return_value=("sentinel-token", ""),
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            with self.assertRaisesRegex(LoginError, "Trace: .*account_selection.*still-no-code"):
                _handle_password_verification(
                    session=session,
                    device_id="device-1",
                    email="user@example.com",
                    password="secret",
                    mail_config={"wait_timeout": 1},
                    proxy="",
                    flaresolverr_url="",
                )

if __name__ == "__main__":
    unittest.main()
