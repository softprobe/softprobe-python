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
    """Raised when the control runtime returns a non-2xx response."""

    def __init__(self, status: int, body: str) -> None:
        super().__init__(f"softprobe runtime request failed: status {status}: {body.strip()}")
        self.status = status
        self.body = body


class SoftprobeRuntimeUnreachableError(RuntimeError):
    """Raised when the transport layer fails before getting an HTTP response
    (connection refused, DNS failure, timeout, ...).
    """

    def __init__(self, message: str) -> None:
        super().__init__(message)


class SoftprobeUnknownSessionError(SoftprobeRuntimeError):
    """Raised when the runtime returns a stable ``unknown_session`` error envelope.

    The runtime emits ``{"error": {"code": "unknown_session", ...}}`` for any
    control-plane call against a session id that does not exist (e.g. after
    ``close``). SDKs catch this shape so authors can handle the signal without
    parsing messages.
    """


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

    def set_policy(self, session_id: str, policy_document: Any) -> dict[str, Any]:
        return self._client._post_json(f"/v1/sessions/{session_id}/policy", policy_document)

    def set_auth_fixtures(
        self, session_id: str, fixtures_document: Any
    ) -> dict[str, Any]:
        return self._client._post_json(
            f"/v1/sessions/{session_id}/fixtures/auth", fixtures_document
        )

    def update_rules(self, session_id: str, rules_document: Any) -> dict[str, Any]:
        return self._client._post_json(
            f"/v1/sessions/{session_id}/rules", rules_document
        )

    def close(self, session_id: str) -> dict[str, Any]:
        return self._client._post_json(f"/v1/sessions/{session_id}/close", {})


class Client:
    """Thin HTTP client for the Softprobe control runtime."""

    def __init__(self, base_url: str, transport: TransportFn | None = None) -> None:
        self._base_url = base_url.rstrip("/")
        self._transport = transport or _default_transport
        self.sessions = _SessionsClient(self)

    def _post_json(self, path: str, body: Any) -> dict[str, Any]:
        try:
            response = self._transport(
                "POST",
                f"{self._base_url}{path}",
                {"content-type": "application/json"},
                json.dumps(body),
            )
        except (SoftprobeRuntimeError, SoftprobeRuntimeUnreachableError):
            raise
        except Exception as exc:  # pragma: no cover - network failures
            raise SoftprobeRuntimeUnreachableError(
                f"softprobe runtime is unreachable: {exc}"
            ) from exc

        status = response["status"]
        if status < 200 or status >= 300:
            raise _classify_runtime_error(status, response["body"])
        return json.loads(response["body"])


def _classify_runtime_error(status: int, body: str) -> SoftprobeRuntimeError:
    try:
        parsed = json.loads(body)
        error = parsed.get("error") if isinstance(parsed, dict) else None
        if isinstance(error, dict) and error.get("code") == "unknown_session":
            return SoftprobeUnknownSessionError(status, body)
    except (ValueError, AttributeError):
        pass
    return SoftprobeRuntimeError(status, body)
