from __future__ import annotations

import json
from typing import Any, Callable, TypedDict
from urllib import request as urllib_request
from urllib.error import HTTPError


class TransportResponse(TypedDict):
    status: int
    body: str


TransportFn = Callable[[str, str, dict[str, str], str | None], TransportResponse]


class SoftprobeRuntimeError(RuntimeError):
    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"softprobe runtime request failed: status {status}: {body.strip()}")
        self.status = status
        self.body = body


def _default_transport(method: str, url: str, headers: dict[str, str], body: str | None) -> TransportResponse:
    data = body.encode("utf-8") if body is not None else None
    req = urllib_request.Request(url=url, data=data, headers=headers, method=method)
    try:
        with urllib_request.urlopen(req, timeout=5) as response:
            return {"status": response.status, "body": response.read().decode("utf-8")}
    except HTTPError as exc:
        return {"status": exc.code, "body": exc.read().decode("utf-8")}


class _SessionsClient:
    def __init__(self, client: "Client") -> None:
        self._client = client

    def create(self, *, mode: str) -> dict[str, Any]:
        return self._client._post_json("/v1/sessions", {"mode": mode})

    def load_case(self, session_id: str, case_document: Any) -> dict[str, Any]:
        return self._client._post_json(f"/v1/sessions/{session_id}/load-case", case_document)

    def close(self, session_id: str) -> dict[str, Any]:
        return self._client._post_json(f"/v1/sessions/{session_id}/close", {})


class Client:
    """Thin HTTP client for the Softprobe control runtime."""

    def __init__(self, base_url: str, transport: TransportFn | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._transport = transport or _default_transport
        self.sessions = _SessionsClient(self)

    def _post_json(self, path: str, body: Any) -> dict[str, Any]:
        response = self._transport(
            "POST",
            f"{self._base_url}{path}",
            {"content-type": "application/json"},
            json.dumps(body),
        )
        if response["status"] < 200 or response["status"] >= 300:
            raise SoftprobeRuntimeError(response["status"], response["body"])
        return json.loads(response["body"])
