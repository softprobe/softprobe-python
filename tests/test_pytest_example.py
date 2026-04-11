from __future__ import annotations

import json
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Iterator
from urllib import request as urllib_request

try:
    import pytest
except ModuleNotFoundError:  # pragma: no cover - the pytest example is exercised with pytest itself.
    pytest = None

from softprobe.client import Client


@contextmanager
def serve(handler_factory: type[BaseHTTPRequestHandler]) -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler_factory)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        thread.join()
        server.server_close()


def make_runtime_handler() -> type[BaseHTTPRequestHandler]:
    class RuntimeHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            if self.path != "/v1/sessions":
                self.send_error(404)
                return

            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"sessionId": "sess_pytest_001", "sessionRevision": 0}).encode("utf-8"))

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    return RuntimeHandler


def make_sut_handler(seen_headers: list[str]) -> type[BaseHTTPRequestHandler]:
    class SutHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            seen_headers.append(self.headers.get("x-softprobe-session-id", ""))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A003
            return

    return SutHandler


if pytest is not None:

    @pytest.fixture
    def runtime_url() -> Iterator[str]:
        with serve(make_runtime_handler()) as url:
            yield url


    @pytest.fixture
    def sut_server() -> Iterator[tuple[str, list[str]]]:
        seen_headers: list[str] = []
        with serve(make_sut_handler(seen_headers)) as url:
            yield url, seen_headers


def test_checkout_passes_session_header(runtime_url: str, sut_server: tuple[str, list[str]]) -> None:
    sut_url, seen_headers = sut_server

    client = Client(runtime_url)
    session = client.sessions.create(mode="replay")

    request = urllib_request.Request(
        f"{sut_url}/checkout",
        headers={"x-softprobe-session-id": session["sessionId"]},
    )
    with urllib_request.urlopen(request, timeout=5) as response:
        assert response.status == 200
        assert response.read().decode("utf-8") == "ok"

    assert seen_headers == [session["sessionId"]]
