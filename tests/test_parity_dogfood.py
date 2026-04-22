"""
PD7.3b — Python SDK parity test.

Drives the full Softprobe facade (start_session → load_case_from_file →
find_in_case → mock_outbound → close) against a fake HTTP runtime using the
checked-in golden case fragment-happy-path.case.json.
"""
from __future__ import annotations

import http.server
import json
import os
import pathlib
import threading
import unittest

from softprobe import Softprobe

GOLDEN_CASE = (
    pathlib.Path(__file__).parent.parent.parent
    / "spec"
    / "examples"
    / "cases"
    / "fragment-happy-path.case.json"
)


class _FakeRuntimeHandler(http.server.BaseHTTPRequestHandler):
    """Minimal fake runtime that handles the SDK control-API calls."""

    def log_message(self, *args):  # silence logs
        pass

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        if self.path == "/v1/sessions":
            self._json({"sessionId": "dogfood-session", "sessionRevision": 0})
        elif "/load-case" in self.path:
            self._json({"sessionId": "dogfood-session", "sessionRevision": 1})
        elif "/rules" in self.path:
            self._json({"sessionId": "dogfood-session", "sessionRevision": 2})
        elif "/close" in self.path:
            self._json({"sessionId": "dogfood-session", "closed": True})
        else:
            self.send_response(500)
            self.end_headers()

    def _json(self, payload):
        data = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


class TestParityDogfood(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = http.server.HTTPServer(("127.0.0.1", 0), _FakeRuntimeHandler)
        cls.port = cls.server.server_address[1]
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def test_full_facade_against_golden_case(self):
        base_url = f"http://127.0.0.1:{self.port}"
        sp = Softprobe(base_url=base_url)

        session = sp.start_session(mode="replay")
        self.assertEqual(session.id, "dogfood-session")

        session.load_case_from_file(str(GOLDEN_CASE))

        hit = session.find_in_case(direction="outbound", method="GET", path="/fragment")
        self.assertIsNotNone(hit)
        self.assertIsNotNone(hit.response)

        session.mock_outbound(
            direction="outbound",
            method="GET",
            path="/fragment",
            response=hit.response,
        )

        session.close()


if __name__ == "__main__":
    unittest.main()
