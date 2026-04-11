import json
import unittest

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


if __name__ == "__main__":
    unittest.main()
