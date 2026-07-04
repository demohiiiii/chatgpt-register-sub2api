from __future__ import annotations

from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from chatgpt_register_sub2api.login.login_flow import (
    LoginError,
    _exchange_login_tokens,
    _handle_password_verification,
    re_login_for_team_token,
)


class FakeResponse:
    def __init__(
        self,
        status_code: int,
        data: dict | None = None,
        text: str = "",
        url: str = "",
        headers: dict | None = None,
    ) -> None:
        self.status_code = status_code
        self._data = data or {}
        self.text = text or ("{}" if data is not None else "")
        self.url = url
        self.headers = headers or {}

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

    def close(self) -> None:
        pass


class FakeCookies:
    def __init__(self) -> None:
        self.values: list[dict] = []

    def set(self, name: str, value: str, domain: str = "") -> None:
        self.values.append({"name": name, "value": value, "domain": domain})


class AdvancingFakeSession(FakeSession):
    def __init__(
        self,
        responses: list[FakeResponse],
        current_time: list[datetime],
        next_time: datetime,
    ) -> None:
        super().__init__(responses)
        self.current_time = current_time
        self.next_time = next_time

    def request(self, method: str, url: str, timeout: int = 30, **kwargs):
        response = super().request(method, url, timeout=timeout, **kwargs)
        if "api/auth/signin/openai" in url:
            self.current_time[0] = self.next_time
        return response


LOGIN_MAIL_CONFIG = {
    "providers": [
        {
            "type": "gmail",
            "enable": True,
            "user": "user@example.com",
            "app_password": "app-pass",
        }
    ],
    "wait_timeout": 1,
    "wait_interval": 1,
    "prime_existing_otp": False,
}


class LoginFlowTests(unittest.TestCase):
    def test_otp_login_code_boundary_is_captured_before_signin_sends_email(self) -> None:
        first_time = datetime(2026, 7, 4, 7, 35, tzinfo=timezone.utc)
        after_email_sent = first_time + timedelta(minutes=3)
        current_time = [first_time]
        session = AdvancingFakeSession(
            [
                FakeResponse(
                    200,
                    text="<html></html>",
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-123%7Csig; Path=/"},
                    url="https://chatgpt.com/auth/login",
                ),
                FakeResponse(
                    200,
                    {"csrfToken": "csrf-456"},
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-456%7Csig; Path=/"},
                    url="https://chatgpt.com/api/auth/csrf",
                ),
                FakeResponse(
                    200,
                    {"url": "https://auth.openai.com/email-verification"},
                    url="https://chatgpt.com/api/auth/signin/openai",
                ),
                FakeResponse(
                    200,
                    text="<html>Email verification</html>",
                    url="https://auth.openai.com/email-verification",
                ),
                FakeResponse(
                    200,
                    {"continue_url": "https://chatgpt.com/api/auth/callback/openai?state=done"},
                    url="https://auth.openai.com/api/accounts/email-otp/validate",
                ),
                FakeResponse(
                    302,
                    text="",
                    headers={"Location": "https://chatgpt.com/"},
                    url="https://chatgpt.com/api/auth/callback/openai?state=done",
                ),
                FakeResponse(
                    200,
                    text="<html>ChatGPT</html>",
                    url="https://chatgpt.com/",
                ),
                FakeResponse(
                    200,
                    {"accessToken": "web-access-token", "sessionToken": "web-session-token"},
                    url="https://chatgpt.com/api/auth/session",
                ),
            ],
            current_time,
            after_email_sent,
        )

        class FakeDateTime(datetime):
            @classmethod
            def now(cls, tz=None):
                return current_time[0]

        with patch(
            "chatgpt_register_sub2api.login.login_flow.create_register_session",
            return_value=session,
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ) as wait_for_code_mock, patch(
            "chatgpt_register_sub2api.login.login_flow.datetime",
            FakeDateTime,
        ):
            re_login_for_team_token(
                email="user@example.com",
                password="",
                mail_config=LOGIN_MAIL_CONFIG,
                login_mode="otp",
            )

        mailbox = wait_for_code_mock.call_args.args[1]
        self.assertLess(mailbox["_code_not_before"], after_email_sent)

    def test_otp_login_uses_email_code_without_password_verify(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    text="<html></html>",
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-123%7Csig; Path=/"},
                    url="https://chatgpt.com/auth/login",
                ),
                FakeResponse(
                    200,
                    {"csrfToken": "csrf-456"},
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-456%7Csig; Path=/"},
                    url="https://chatgpt.com/api/auth/csrf",
                ),
                FakeResponse(
                    200,
                    {"url": "https://auth.openai.com/email-verification"},
                    url="https://chatgpt.com/api/auth/signin/openai",
                ),
                FakeResponse(
                    200,
                    text="<html>Email verification</html>",
                    url="https://auth.openai.com/email-verification",
                ),
                FakeResponse(
                    200,
                    {"continue_url": "https://chatgpt.com/api/auth/callback/openai?state=done"},
                    url="https://auth.openai.com/api/accounts/email-otp/validate",
                ),
                FakeResponse(
                    302,
                    text="",
                    headers={"Location": "https://chatgpt.com/"},
                    url="https://chatgpt.com/api/auth/callback/openai?state=done",
                ),
                FakeResponse(
                    200,
                    text="<html>ChatGPT</html>",
                    url="https://chatgpt.com/",
                ),
                FakeResponse(
                    200,
                    {
                        "accessToken": "web-access-token",
                        "sessionToken": "web-session-token",
                        "user": {"email": "user@example.com"},
                        "account": {"id": "account-id"},
                    },
                    url="https://chatgpt.com/api/auth/session",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.create_register_session",
            return_value=session,
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            tokens = re_login_for_team_token(
                email="user@example.com",
                password="",
                mail_config=LOGIN_MAIL_CONFIG,
                login_mode="otp",
            )

        urls = [request["url"] for request in session.requests]
        self.assertNotIn("https://auth.openai.com/api/accounts/password/verify", urls)
        self.assertIn("https://chatgpt.com/api/auth/csrf", urls)
        self.assertIn("https://auth.openai.com/api/accounts/email-otp/validate", urls)
        self.assertEqual(tokens["access_token"], "web-access-token")
        self.assertEqual(tokens["id_token"], "web-access-token")
        self.assertEqual(tokens["session_token"], "web-session-token")
        self.assertEqual(tokens["scope"], "otp")

    def test_otp_login_joins_and_switches_to_workspace_session(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    text="<html></html>",
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-123%7Csig; Path=/"},
                    url="https://chatgpt.com/auth/login",
                ),
                FakeResponse(
                    200,
                    {"csrfToken": "csrf-456"},
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-456%7Csig; Path=/"},
                    url="https://chatgpt.com/api/auth/csrf",
                ),
                FakeResponse(
                    200,
                    {"url": "https://auth.openai.com/email-verification"},
                    url="https://chatgpt.com/api/auth/signin/openai",
                ),
                FakeResponse(
                    200,
                    text="<html>Email verification</html>",
                    url="https://auth.openai.com/email-verification",
                ),
                FakeResponse(
                    200,
                    {"continue_url": "https://chatgpt.com/api/auth/callback/openai?state=done"},
                    url="https://auth.openai.com/api/accounts/email-otp/validate",
                ),
                FakeResponse(
                    302,
                    text="",
                    headers={"Location": "https://chatgpt.com/"},
                    url="https://chatgpt.com/api/auth/callback/openai?state=done",
                ),
                FakeResponse(
                    200,
                    text="<html>ChatGPT</html>",
                    url="https://chatgpt.com/",
                ),
                FakeResponse(
                    200,
                    {
                        "accessToken": "personal-access-token",
                        "sessionToken": "personal-session-token",
                        "user": {"email": "user@example.com"},
                        "account": {"id": "personal-account-id", "planType": "free"},
                    },
                    url="https://chatgpt.com/api/auth/session",
                ),
                FakeResponse(
                    200,
                    {},
                    url="https://chatgpt.com/backend-api/accounts/workspace-1/invites/request",
                ),
                FakeResponse(
                    200,
                    {
                        "accessToken": "k12-access-token",
                        "sessionToken": "k12-session-token",
                        "user": {"email": "user@example.com"},
                        "account": {"id": "workspace-1", "planType": "k12"},
                    },
                    url="https://chatgpt.com/api/auth/session",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.create_register_session",
            return_value=session,
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            tokens = re_login_for_team_token(
                email="user@example.com",
                password="",
                mail_config=LOGIN_MAIL_CONFIG,
                workspace_id="workspace-1",
                login_mode="otp",
            )

        urls = [request["url"] for request in session.requests]
        self.assertIn(
            "https://chatgpt.com/backend-api/accounts/workspace-1/invites/request",
            urls,
        )
        self.assertEqual(tokens["access_token"], "k12-access-token")
        self.assertEqual(tokens["session_token"], "k12-session-token")
        self.assertEqual(tokens["chatgpt_account_id"], "workspace-1")
        self.assertEqual(tokens["plan_type"], "k12")
        self.assertIn(
            {"name": "_account", "value": "workspace-1", "domain": ".chatgpt.com"},
            session.cookies.values,
        )

    def test_otp_login_workspace_picker_without_session_token_has_clear_error(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    text="<html></html>",
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-123%7Csig; Path=/"},
                    url="https://chatgpt.com/auth/login",
                ),
                FakeResponse(
                    200,
                    {"csrfToken": "csrf-456"},
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-456%7Csig; Path=/"},
                    url="https://chatgpt.com/api/auth/csrf",
                ),
                FakeResponse(
                    200,
                    {"url": "https://auth.openai.com/email-verification"},
                    url="https://chatgpt.com/api/auth/signin/openai",
                ),
                FakeResponse(
                    200,
                    text="<html>Email verification</html>",
                    url="https://auth.openai.com/email-verification",
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "https://auth.openai.com/workspace",
                        "page": {"type": "workspace"},
                        "oai-client-auth-session": {
                            "workspaces": [
                                {"id": "workspace-1", "name": "K12", "kind": "organization"}
                            ]
                        },
                    },
                    url="https://auth.openai.com/api/accounts/email-otp/validate",
                ),
                FakeResponse(
                    200,
                    {"continue_url": "https://chatgpt.com/api/auth/callback/openai?state=done"},
                    url="https://auth.openai.com/api/accounts/workspace/select",
                ),
                FakeResponse(
                    302,
                    text="",
                    headers={"Location": "https://chatgpt.com/"},
                    url="https://chatgpt.com/api/auth/callback/openai?state=done",
                ),
                FakeResponse(
                    200,
                    text="<html>ChatGPT</html>",
                    url="https://chatgpt.com/",
                ),
                FakeResponse(
                    200,
                    {
                        "accessToken": "k12-access-token",
                        "sessionToken": "k12-session-token",
                        "account": {"id": "workspace-1", "planType": "k12"},
                    },
                    url="https://chatgpt.com/api/auth/session",
                ),
                FakeResponse(
                    200,
                    {},
                    url="https://chatgpt.com/backend-api/accounts/workspace-1/invites/request",
                ),
                FakeResponse(
                    200,
                    {
                        "accessToken": "k12-access-token",
                        "sessionToken": "k12-session-token",
                        "account": {"id": "workspace-1", "planType": "k12"},
                    },
                    url="https://chatgpt.com/api/auth/session",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.create_register_session",
            return_value=session,
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            tokens = re_login_for_team_token(
                email="user@example.com",
                password="",
                mail_config=LOGIN_MAIL_CONFIG,
                workspace_id="workspace-1",
                login_mode="otp",
            )

        urls = [request["url"] for request in session.requests]
        self.assertIn("https://auth.openai.com/api/accounts/workspace/select", urls)
        workspace_select = next(
            request for request in session.requests
            if request["url"] == "https://auth.openai.com/api/accounts/workspace/select"
        )
        self.assertEqual(workspace_select["kwargs"]["json"], {"workspace_id": "workspace-1"})
        self.assertEqual(tokens["access_token"], "k12-access-token")
        self.assertEqual(tokens["chatgpt_account_id"], "workspace-1")

    def test_otp_login_joins_target_workspace_when_not_in_auth_picker(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    text="<html></html>",
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-123%7Csig; Path=/"},
                    url="https://chatgpt.com/auth/login",
                ),
                FakeResponse(
                    200,
                    {"csrfToken": "csrf-456"},
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-456%7Csig; Path=/"},
                    url="https://chatgpt.com/api/auth/csrf",
                ),
                FakeResponse(
                    200,
                    {"url": "https://auth.openai.com/email-verification"},
                    url="https://chatgpt.com/api/auth/signin/openai",
                ),
                FakeResponse(
                    200,
                    text="<html>Email verification</html>",
                    url="https://auth.openai.com/email-verification",
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "https://auth.openai.com/workspace",
                        "page": {"type": "workspace"},
                        "oai-client-auth-session": {
                            "workspaces": [
                                {"id": "personal-account", "name": None, "kind": "personal"}
                            ]
                        },
                    },
                    url="https://auth.openai.com/api/accounts/email-otp/validate",
                ),
                FakeResponse(
                    200,
                    {"continue_url": "https://chatgpt.com/api/auth/callback/openai?state=done"},
                    url="https://auth.openai.com/api/accounts/workspace/select",
                ),
                FakeResponse(
                    302,
                    text="",
                    headers={"Location": "https://chatgpt.com/"},
                    url="https://chatgpt.com/api/auth/callback/openai?state=done",
                ),
                FakeResponse(
                    200,
                    text="<html>ChatGPT</html>",
                    url="https://chatgpt.com/",
                ),
                FakeResponse(
                    200,
                    {
                        "accessToken": "personal-access-token",
                        "sessionToken": "personal-session-token",
                        "account": {"id": "personal-account", "planType": "free"},
                    },
                    url="https://chatgpt.com/api/auth/session",
                ),
                FakeResponse(
                    200,
                    {},
                    url="https://chatgpt.com/backend-api/accounts/workspace-1/invites/request",
                ),
                FakeResponse(
                    200,
                    {
                        "accessToken": "k12-access-token",
                        "sessionToken": "k12-session-token",
                        "account": {"id": "workspace-1", "planType": "k12"},
                    },
                    url="https://chatgpt.com/api/auth/session",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.create_register_session",
            return_value=session,
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            tokens = re_login_for_team_token(
                email="user@example.com",
                password="",
                mail_config=LOGIN_MAIL_CONFIG,
                workspace_id="workspace-1",
                login_mode="otp",
            )

        workspace_select = next(
            request for request in session.requests
            if request["url"] == "https://auth.openai.com/api/accounts/workspace/select"
        )
        self.assertEqual(workspace_select["kwargs"]["json"], {"workspace_id": "personal-account"})
        self.assertIn(
            "https://chatgpt.com/backend-api/accounts/workspace-1/invites/request",
            [request["url"] for request in session.requests],
        )
        self.assertEqual(tokens["access_token"], "k12-access-token")
        self.assertEqual(tokens["chatgpt_account_id"], "workspace-1")

    def test_otp_login_does_not_select_first_workspace_when_personal_missing(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    text="<html></html>",
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-123%7Csig; Path=/"},
                    url="https://chatgpt.com/auth/login",
                ),
                FakeResponse(
                    200,
                    {"csrfToken": "csrf-456"},
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-456%7Csig; Path=/"},
                    url="https://chatgpt.com/api/auth/csrf",
                ),
                FakeResponse(
                    200,
                    {"url": "https://auth.openai.com/email-verification"},
                    url="https://chatgpt.com/api/auth/signin/openai",
                ),
                FakeResponse(
                    200,
                    text="<html>Email verification</html>",
                    url="https://auth.openai.com/email-verification",
                ),
                FakeResponse(
                    200,
                    {
                        "continue_url": "https://auth.openai.com/workspace",
                        "page": {"type": "workspace"},
                        "oai-client-auth-session": {
                            "workspaces": [
                                {"id": "other-workspace", "name": "Other", "kind": "organization"}
                            ]
                        },
                    },
                    url="https://auth.openai.com/api/accounts/email-otp/validate",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.create_register_session",
            return_value=session,
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            with self.assertRaisesRegex(LoginError, "no personal workspace"):
                re_login_for_team_token(
                    email="user@example.com",
                    password="",
                    mail_config=LOGIN_MAIL_CONFIG,
                    workspace_id="workspace-1",
                    login_mode="otp",
                )

        self.assertNotIn(
            "https://auth.openai.com/api/accounts/workspace/select",
            [request["url"] for request in session.requests],
        )

    def test_otp_login_workspace_picker_without_selection_response_has_clear_error(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    200,
                    text="<html></html>",
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-123%7Csig; Path=/"},
                    url="https://chatgpt.com/auth/login",
                ),
                FakeResponse(
                    200,
                    {"csrfToken": "csrf-456"},
                    headers={"Set-Cookie": "__Host-next-auth.csrf-token=csrf-456%7Csig; Path=/"},
                    url="https://chatgpt.com/api/auth/csrf",
                ),
                FakeResponse(
                    200,
                    {"url": "https://auth.openai.com/email-verification"},
                    url="https://chatgpt.com/api/auth/signin/openai",
                ),
                FakeResponse(
                    200,
                    text="<html>Email verification</html>",
                    url="https://auth.openai.com/email-verification",
                ),
                FakeResponse(
                    200,
                    {"continue_url": "https://auth.openai.com/workspace", "page": {"type": "workspace"}},
                    url="https://auth.openai.com/api/accounts/email-otp/validate",
                ),
                FakeResponse(
                    200,
                    {"error": {"message": "bad workspace"}},
                    url="https://auth.openai.com/api/accounts/workspace/select",
                ),
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.create_register_session",
            return_value=session,
        ), patch(
            "chatgpt_register_sub2api.login.login_flow.wait_for_code",
            return_value="123456",
        ):
            with self.assertRaisesRegex(LoginError, "Workspace selection failed"):
                re_login_for_team_token(
                    email="user@example.com",
                    password="",
                    mail_config=LOGIN_MAIL_CONFIG,
                    workspace_id="workspace-1",
                    login_mode="otp",
                )

        urls = [request["url"] for request in session.requests]
        self.assertIn("https://auth.openai.com/api/accounts/workspace/select", urls)

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
        self.assertEqual(
            request["kwargs"]["headers"]["referer"],
            "https://auth.openai.com/email-verification",
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
                    mail_config=LOGIN_MAIL_CONFIG,
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
        self.assertEqual(mailbox["provider"], "gmail")
        self.assertEqual(mailbox["address"], "user@example.com")
        self.assertEqual(mailbox["_credential_email"], "user@example.com")
        self.assertEqual(mailbox["subject_include"], "login code")
        self.assertIn("_code_not_before", mailbox)

    def test_password_verification_invalid_state_includes_body_and_context(self) -> None:
        session = FakeSession(
            [
                FakeResponse(
                    409,
                    {
                        "error": {
                            "message": "Invalid state",
                            "type": "invalid_request_error",
                            "code": "invalid_state",
                        }
                    },
                    text='{"error":{"message":"Invalid state","code":"invalid_state"}}',
                    url="https://auth.openai.com/api/accounts/password/verify",
                )
            ]
        )

        with patch(
            "chatgpt_register_sub2api.login.login_flow.build_sentinel_token",
            return_value=("sentinel-token", ""),
        ):
            with self.assertRaisesRegex(
                LoginError,
                r"invalid_state.*password_verify.*body=.*Invalid state",
            ):
                _handle_password_verification(
                    session=session,
                    device_id="device-1",
                    email="user@example.com",
                    password="secret",
                    mail_config=LOGIN_MAIL_CONFIG,
                    proxy="",
                    flaresolverr_url="",
                )

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
                mail_config=LOGIN_MAIL_CONFIG,
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
                    mail_config=LOGIN_MAIL_CONFIG,
                    proxy="",
                    flaresolverr_url="",
                )

if __name__ == "__main__":
    unittest.main()
