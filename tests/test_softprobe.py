from __future__ import annotations

import json
import os
import tempfile
import unittest
from typing import Any

from softprobe import Softprobe, SoftprobeSession


def _make_case(spans: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "version": "1.0.0",
        "caseId": "test",
        "traces": [
            {
                "resourceSpans": [
                    {
                        "resource": {
                            "attributes": [
                                {"key": "service.name", "value": {"stringValue": "api"}}
                            ]
                        },
                        "scopeSpans": [{"spans": spans}],
                    }
                ]
            }
        ],
    }


def _span(
    *,
    trace_id: str,
    span_id: str,
    direction: str,
    method: str,
    url_path: str,
    host: str | None = None,
    status: int | None = None,
    body: str | None = None,
    headers: dict[str, str] | None = None,
    span_type: str = "inject",
) -> dict[str, Any]:
    attrs: list[dict[str, Any]] = [
        {"key": "sp.span.type", "value": {"stringValue": span_type}},
        {"key": "sp.traffic.direction", "value": {"stringValue": direction}},
        {"key": "url.path", "value": {"stringValue": url_path}},
        {"key": "http.request.method", "value": {"stringValue": method}},
    ]
    if host is not None:
        attrs.append({"key": "url.host", "value": {"stringValue": host}})
    if status is not None:
        attrs.append({"key": "http.response.status_code", "value": {"intValue": status}})
    if body is not None:
        attrs.append({"key": "http.response.body", "value": {"stringValue": body}})
    for name, value in (headers or {}).items():
        attrs.append(
            {"key": f"http.response.header.{name}", "value": {"stringValue": value}}
        )
    return {
        "traceId": trace_id,
        "spanId": span_id,
        "name": f"HTTP {method}",
        "attributes": attrs,
    }


class FakeTransport:
    """Collects HTTP calls and returns canned JSON responses."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(
        self,
        method: str,
        url: str,
        headers: dict[str, str],
        body: str | None,
    ) -> dict[str, object]:
        self.calls.append(
            {"method": method, "url": url, "headers": headers, "body": body}
        )
        if url.endswith("/v1/sessions"):
            return {
                "status": 200,
                "body": json.dumps(
                    {"sessionId": "sess_py", "sessionRevision": 0}
                ),
            }
        if url.endswith("/load-case"):
            return {
                "status": 200,
                "body": json.dumps(
                    {"sessionId": "sess_py", "sessionRevision": 1}
                ),
            }
        if url.endswith("/rules"):
            return {
                "status": 200,
                "body": json.dumps(
                    {"sessionId": "sess_py", "sessionRevision": len(self.calls)}
                ),
            }
        if url.endswith("/close"):
            return {
                "status": 200,
                "body": json.dumps({"sessionId": "sess_py", "closed": True}),
            }
        raise AssertionError(f"unexpected url: {url}")


class SoftprobeTests(unittest.TestCase):
    def test_start_session_posts_mode_and_returns_session(self) -> None:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)

        session = softprobe.start_session(mode="replay")
        self.assertIsInstance(session, SoftprobeSession)
        self.assertEqual(session.id, "sess_py")

        self.assertEqual(transport.calls[0]["method"], "POST")
        self.assertEqual(transport.calls[0]["url"], "http://runtime.test/v1/sessions")
        self.assertEqual(
            json.loads(transport.calls[0]["body"] or "{}"), {"mode": "replay"}
        )

    def test_mock_outbound_builds_mock_rule_payload(self) -> None:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)
        session = softprobe.start_session(mode="replay")

        session.mock_outbound(
            id="mock-fragment",
            priority=10,
            direction="outbound",
            method="GET",
            path="/fragment",
            response={"status": 200, "body": '{"dep":"ok"}'},
        )

        rules_call = transport.calls[-1]
        self.assertTrue(rules_call["url"].endswith("/rules"))
        payload = json.loads(rules_call["body"] or "{}")
        self.assertEqual(
            payload,
            {
                "version": 1,
                "rules": [
                    {
                        "id": "mock-fragment",
                        "priority": 10,
                        "when": {
                            "direction": "outbound",
                            "method": "GET",
                            "path": "/fragment",
                        },
                        "then": {
                            "action": "mock",
                            "response": {
                                "status": 200,
                                "body": '{"dep":"ok"}',
                            },
                        },
                    }
                ],
            },
        )

    def test_multiple_mock_outbound_calls_accumulate_rules(self) -> None:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)
        session = softprobe.start_session(mode="replay")

        session.mock_outbound(
            direction="outbound",
            method="GET",
            path="/a",
            response={"status": 200},
        )
        session.mock_outbound(
            direction="outbound",
            method="GET",
            path="/b",
            response={"status": 201},
        )

        second_rules = json.loads(transport.calls[-1]["body"] or "{}")
        self.assertEqual(len(second_rules["rules"]), 2)
        self.assertEqual(second_rules["rules"][0]["when"]["path"], "/a")
        self.assertEqual(second_rules["rules"][1]["when"]["path"], "/b")

    def test_clear_rules_sends_empty_rule_list(self) -> None:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)
        session = softprobe.start_session(mode="replay")
        session.mock_outbound(
            direction="outbound", path="/x", response={"status": 200}
        )
        session.clear_rules()

        payload = json.loads(transport.calls[-1]["body"] or "{}")
        self.assertEqual(payload, {"version": 1, "rules": []})

    def test_close_posts_empty_body(self) -> None:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)
        session = softprobe.start_session(mode="replay")
        session.close()

        self.assertTrue(transport.calls[-1]["url"].endswith("/close"))
        self.assertEqual(json.loads(transport.calls[-1]["body"] or "{}"), {})

    def test_load_case_from_file_posts_document(self) -> None:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)
        session = softprobe.start_session(mode="replay")

        case_doc = _make_case(
            [
                _span(
                    trace_id="t1",
                    span_id="s1",
                    direction="outbound",
                    method="GET",
                    url_path="/fragment",
                    status=200,
                    body='{"dep":"ok"}',
                )
            ]
        )
        with tempfile.TemporaryDirectory() as tmp:
            case_path = os.path.join(tmp, "case.json")
            with open(case_path, "w", encoding="utf-8") as f:
                json.dump(case_doc, f)
            session.load_case_from_file(case_path)

        load_call = transport.calls[-1]
        self.assertTrue(load_call["url"].endswith("/load-case"))
        self.assertEqual(json.loads(load_call["body"] or "{}"), case_doc)


class FindInCaseTests(unittest.TestCase):
    def _session_with_case(self, case_doc: dict[str, Any]) -> SoftprobeSession:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)
        session = softprobe.start_session(mode="replay")
        tmpdir = tempfile.mkdtemp()
        case_path = os.path.join(tmpdir, "case.json")
        with open(case_path, "w", encoding="utf-8") as f:
            json.dump(case_doc, f)
        session.load_case_from_file(case_path)
        return session

    def test_returns_captured_response_when_single_match(self) -> None:
        session = self._session_with_case(
            _make_case(
                [
                    _span(
                        trace_id="t1",
                        span_id="s1",
                        direction="outbound",
                        method="GET",
                        url_path="/fragment",
                        status=200,
                        body='{"dep":"ok"}',
                        headers={"content-type": "application/json"},
                    ),
                    _span(
                        trace_id="t1",
                        span_id="s2",
                        direction="outbound",
                        method="GET",
                        url_path="/other",
                        status=404,
                    ),
                ]
            )
        )

        hit = session.find_in_case(
            direction="outbound", method="GET", path="/fragment"
        )
        self.assertEqual(hit.response.status, 200)
        self.assertEqual(hit.response.body, '{"dep":"ok"}')
        self.assertEqual(hit.response.headers, {"content-type": "application/json"})
        self.assertEqual(hit.span["spanId"], "s1")

    def test_raises_when_zero_matches(self) -> None:
        session = self._session_with_case(
            _make_case(
                [
                    _span(
                        trace_id="t1",
                        span_id="s1",
                        direction="outbound",
                        method="GET",
                        url_path="/fragment",
                        status=200,
                        body="",
                    )
                ]
            )
        )
        with self.assertRaisesRegex(
            LookupError, r"find_in_case.*no span.*POST.*fragment"
        ):
            session.find_in_case(
                direction="outbound", method="POST", path="/fragment"
            )

    def test_raises_when_multiple_matches(self) -> None:
        session = self._session_with_case(
            _make_case(
                [
                    _span(
                        trace_id="t1",
                        span_id="span-a",
                        direction="outbound",
                        method="GET",
                        url_path="/fragment",
                        status=500,
                        body="err",
                    ),
                    _span(
                        trace_id="t1",
                        span_id="span-b",
                        direction="outbound",
                        method="GET",
                        url_path="/fragment",
                        status=200,
                        body="ok",
                    ),
                ]
            )
        )
        with self.assertRaisesRegex(LookupError, r"2 spans.*span-a.*span-b"):
            session.find_in_case(
                direction="outbound", method="GET", path="/fragment"
            )

    def test_matches_path_prefix_and_host(self) -> None:
        session = self._session_with_case(
            _make_case(
                [
                    _span(
                        trace_id="t1",
                        span_id="s1",
                        direction="outbound",
                        method="GET",
                        url_path="/v1/payment_intents/pi_123",
                        host="api.stripe.com",
                        status=200,
                        body="{}",
                    )
                ]
            )
        )
        hit = session.find_in_case(
            direction="outbound",
            method="GET",
            path_prefix="/v1/payment_intents",
            host="api.stripe.com",
        )
        self.assertEqual(hit.response.status, 200)

    def test_defaults_body_and_headers_when_attrs_missing(self) -> None:
        session = self._session_with_case(
            _make_case(
                [
                    _span(
                        trace_id="t1",
                        span_id="s1",
                        direction="outbound",
                        method="GET",
                        url_path="/health",
                        status=204,
                    )
                ]
            )
        )
        hit = session.find_in_case(direction="outbound", path="/health")
        self.assertEqual(hit.response.status, 204)
        self.assertEqual(hit.response.body, "")
        self.assertEqual(hit.response.headers, {})

    def test_raises_when_no_case_loaded(self) -> None:
        transport = FakeTransport()
        softprobe = Softprobe(base_url="http://runtime.test", transport=transport)
        session = softprobe.start_session(mode="replay")
        with self.assertRaisesRegex(RuntimeError, r"load_case_from_file"):
            session.find_in_case(path="/anything")

    def test_falls_back_to_pseudo_headers(self) -> None:
        """Captures produced by the proxy can carry HTTP/2 :method / :path pseudo
        headers instead of the top-level attributes; the extractor must honor both."""
        case_doc = _make_case(
            [
                {
                    "traceId": "t1",
                    "spanId": "s1",
                    "name": "HTTP GET",
                    "attributes": [
                        {"key": "sp.span.type", "value": {"stringValue": "extract"}},
                        {"key": "sp.traffic.direction", "value": {"stringValue": "outbound"}},
                        {"key": "http.request.header.:method", "value": {"stringValue": "GET"}},
                        {"key": "http.request.header.:path", "value": {"stringValue": "/legacy"}},
                        {"key": "http.response.status_code", "value": {"intValue": 200}},
                        {"key": "http.response.body", "value": {"stringValue": "legacy-body"}},
                    ],
                }
            ]
        )
        session = self._session_with_case(case_doc)
        hit = session.find_in_case(
            direction="outbound", method="GET", path="/legacy"
        )
        self.assertEqual(hit.response.body, "legacy-body")


if __name__ == "__main__":
    unittest.main()
