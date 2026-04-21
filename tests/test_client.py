import json
import os
import unittest
from unittest import mock

from softprobe.client import Client, SoftprobeRuntimeError


class ClientTests(unittest.TestCase):
    def test_sessions_create_load_case_and_close(self) -> None:
        calls: list[dict[str, object]] = []

        def transport(method: str, url: str, headers: dict[str, str], body: str | None) -> dict[str, object]:
            calls.append({
                "method": method,
                "url": url,
                "headers": headers,
                "body": body,
            })

            if url.endswith("/close"):
                return {"status": 200, "body": json.dumps({"sessionId": "sess_123", "closed": True})}

            return {
                "status": 200,
                "body": json.dumps({
                    "sessionId": "sess_123",
                    "sessionRevision": len(calls) - 1,
                }),
            }

        client = Client("http://runtime.test", transport=transport)

        created = client.sessions.create(mode="replay")
        loaded = client.sessions.load_case(
            "sess_123",
            {"version": "1.0.0", "caseId": "checkout", "traces": []},
        )
        closed = client.sessions.close("sess_123")

        self.assertEqual(created, {"sessionId": "sess_123", "sessionRevision": 0})
        self.assertEqual(loaded, {"sessionId": "sess_123", "sessionRevision": 1})
        self.assertEqual(closed, {"sessionId": "sess_123", "closed": True})

        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[0]["method"], "POST")
        self.assertEqual(calls[0]["url"], "http://runtime.test/v1/sessions")
        self.assertEqual(json.loads(calls[0]["body"] or "{}"), {"mode": "replay"})

        self.assertEqual(calls[1]["url"], "http://runtime.test/v1/sessions/sess_123/load-case")
        self.assertEqual(
            json.loads(calls[1]["body"] or "{}"),
            {"version": "1.0.0", "caseId": "checkout", "traces": []},
        )

        self.assertEqual(calls[2]["url"], "http://runtime.test/v1/sessions/sess_123/close")
        self.assertEqual(json.loads(calls[2]["body"] or "{}"), {})

    def test_surfaces_stable_error_type_with_status_and_body(self) -> None:
        def transport(method: str, url: str, headers: dict[str, str], body: str | None) -> dict[str, object]:
            return {"status": 404, "body": '{"error":"unknown session"}'}

        client = Client("http://runtime.test", transport=transport)

        with self.assertRaises(SoftprobeRuntimeError) as ctx:
            client.sessions.close("missing")

        self.assertEqual(ctx.exception.status, 404)
        self.assertEqual(ctx.exception.body, '{"error":"unknown session"}')


class BearerTokenAuthenticationTests(unittest.TestCase):
    """Mirrors softprobe-js/src/__tests__/runtime-client.test.ts: the Python SDK
    must attach ``Authorization: Bearer $SOFTPROBE_API_TOKEN`` on every call
    when a token is configured, matching the runtime's
    ``withOptionalBearerAuth`` contract.
    """

    def _recording_transport(self, calls: list[dict[str, object]]):
        def transport(method: str, url: str, headers: dict[str, str], body: str | None) -> dict[str, object]:
            calls.append({"method": method, "url": url, "headers": dict(headers), "body": body})
            return {"status": 200, "body": json.dumps({"sessionId": "s", "sessionRevision": 0})}

        return transport

    def test_attaches_bearer_from_explicit_api_token_argument(self) -> None:
        calls: list[dict[str, object]] = []
        client = Client(
            "http://runtime.test",
            transport=self._recording_transport(calls),
            api_token="sp_explicit_token",
        )
        client.sessions.create(mode="replay")
        self.assertEqual(calls[0]["headers"].get("authorization"), "Bearer sp_explicit_token")

    def test_falls_back_to_softprobe_api_token_env_var(self) -> None:
        calls: list[dict[str, object]] = []
        with mock.patch.dict(os.environ, {"SOFTPROBE_API_TOKEN": "sp_env_token"}, clear=False):
            client = Client("http://runtime.test", transport=self._recording_transport(calls))
            client.sessions.create(mode="replay")
        self.assertEqual(calls[0]["headers"].get("authorization"), "Bearer sp_env_token")

    def test_api_token_argument_overrides_env_var(self) -> None:
        calls: list[dict[str, object]] = []
        with mock.patch.dict(os.environ, {"SOFTPROBE_API_TOKEN": "sp_env_token"}, clear=False):
            client = Client(
                "http://runtime.test",
                transport=self._recording_transport(calls),
                api_token="sp_explicit_wins",
            )
            client.sessions.create(mode="replay")
        self.assertEqual(calls[0]["headers"].get("authorization"), "Bearer sp_explicit_wins")

    def test_sends_no_authorization_header_when_unconfigured(self) -> None:
        calls: list[dict[str, object]] = []
        env = {k: v for k, v in os.environ.items() if k != "SOFTPROBE_API_TOKEN"}
        with mock.patch.dict(os.environ, env, clear=True):
            client = Client("http://runtime.test", transport=self._recording_transport(calls))
            client.sessions.create(mode="replay")
        self.assertNotIn("authorization", calls[0]["headers"])

    def test_treats_whitespace_token_as_no_token(self) -> None:
        calls: list[dict[str, object]] = []
        with mock.patch.dict(os.environ, {"SOFTPROBE_API_TOKEN": "   "}, clear=False):
            client = Client("http://runtime.test", transport=self._recording_transport(calls), api_token="")
            client.sessions.create(mode="replay")
        self.assertNotIn("authorization", calls[0]["headers"])


if __name__ == "__main__":
    unittest.main()
