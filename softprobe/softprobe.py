"""Ergonomic Softprobe SDK facade for Python.

Mirrors the TypeScript SDK in `softprobe-js/src/softprobe.ts`. See
`docs/design.md` §3.2 for the happy path and the division of labor
between client-side case lookup (`find_in_case`) and the runtime-side
rule evaluator (`mock_outbound` → `POST /v1/sessions/{id}/rules`).
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from typing import Any, Mapping, MutableMapping

from .client import Client, TransportFn
from .core.case_lookup import (
    CapturedHit,
    CapturedResponse,
    CaseSpanPredicate,
    find_spans,
    format_predicate,
    response_from_span,
)


DEFAULT_BASE_URL = "http://127.0.0.1:8080"


@dataclass(frozen=True)
class _MockOutboundRule:
    when: dict[str, Any]
    then: dict[str, Any]
    id: str | None = None
    priority: int | None = None

    def to_dict(self) -> dict[str, Any]:
        rule: dict[str, Any] = {"when": self.when, "then": self.then}
        if self.id is not None:
            rule["id"] = self.id
        if self.priority is not None:
            rule["priority"] = self.priority
        return rule


class Softprobe:
    """Entry point for creating sessions against the Softprobe runtime."""

    def __init__(
        self,
        base_url: str | None = None,
        *,
        transport: TransportFn | None = None,
    ) -> None:
        url = base_url or os.environ.get("SOFTPROBE_RUNTIME_URL") or DEFAULT_BASE_URL
        self._client = Client(url, transport=transport) if transport else Client(url)
        if transport is not None:
            # Client() only records the transport when it is passed explicitly; the
            # public signature keeps `transport` an optional kw to mirror the JS API.
            self._client = Client(url, transport=transport)

    def start_session(self, *, mode: str) -> "SoftprobeSession":
        response = self._client.sessions.create(mode=mode)
        session_id = response.get("sessionId")
        if not isinstance(session_id, str) or not session_id:
            raise RuntimeError(
                f"start_session: runtime response missing sessionId: {response}"
            )
        return SoftprobeSession(session_id, self._client)

    def attach(self, session_id: str) -> "SoftprobeSession":
        return SoftprobeSession(session_id, self._client)


class SoftprobeSession:
    """Session-bound helper. Holds the parsed case in memory after
    :meth:`load_case_from_file` so :meth:`find_in_case` is a pure
    synchronous lookup.
    """

    def __init__(self, session_id: str, client: Client) -> None:
        self._id = session_id
        self._client = client
        self._loaded_case: Mapping[str, Any] | None = None
        self._rules: list[dict[str, Any]] = []

    @property
    def id(self) -> str:
        return self._id

    def load_case_from_file(self, case_path: str) -> None:
        with open(case_path, "r", encoding="utf-8") as f:
            case_document = json.load(f)
        self._loaded_case = case_document
        self._client.sessions.load_case(self._id, case_document)

    def find_in_case(
        self,
        *,
        direction: str | None = None,
        service: str | None = None,
        host: str | None = None,
        host_suffix: str | None = None,
        method: str | None = None,
        path: str | None = None,
        path_prefix: str | None = None,
    ) -> CapturedHit:
        """Pure in-memory lookup against the loaded case.

        Throws :class:`RuntimeError` if no case has been loaded,
        :class:`LookupError` for zero or multiple matches.
        """

        if self._loaded_case is None:
            raise RuntimeError(
                "find_in_case requires a case: call load_case_from_file(path) "
                "before find_in_case."
            )

        predicate = CaseSpanPredicate(
            direction=direction,
            service=service,
            host=host,
            host_suffix=host_suffix,
            method=method,
            path=path,
            path_prefix=path_prefix,
        )
        matches = find_spans(self._loaded_case, predicate)
        if not matches:
            raise LookupError(
                f"find_in_case: no span in the loaded case matches "
                f"{format_predicate(predicate)}. Check the predicate "
                f"(direction / method / path / host) or re-capture the case."
            )
        if len(matches) > 1:
            ids = ", ".join(span.get("spanId", "<unknown>") for span in matches)
            raise LookupError(
                f"find_in_case: {len(matches)} spans match "
                f"{format_predicate(predicate)}. Disambiguate the predicate — "
                f"candidate span ids: {ids}."
            )
        (span,) = matches
        return CapturedHit(response=response_from_span(span), span=span)

    def mock_outbound(
        self,
        *,
        response: Mapping[str, Any] | CapturedResponse,
        direction: str | None = None,
        service: str | None = None,
        host: str | None = None,
        host_suffix: str | None = None,
        method: str | None = None,
        path: str | None = None,
        path_prefix: str | None = None,
        id: str | None = None,
        priority: int | None = None,
    ) -> None:
        """Register an outbound mock rule on the session."""

        when = _build_when(
            direction=direction,
            service=service,
            host=host,
            host_suffix=host_suffix,
            method=method,
            path=path,
            path_prefix=path_prefix,
        )
        rule = _MockOutboundRule(
            when=when,
            then={
                "action": "mock",
                "response": _response_to_payload(response),
            },
            id=id,
            priority=priority,
        ).to_dict()
        self._rules.append(rule)
        self._sync_rules()

    def clear_rules(self) -> None:
        self._rules = []
        self._client._post_json(  # type: ignore[attr-defined]
            f"/v1/sessions/{self._id}/rules",
            {"version": 1, "rules": []},
        )

    def close(self) -> None:
        self._client.sessions.close(self._id)

    def _sync_rules(self) -> None:
        self._client._post_json(  # type: ignore[attr-defined]
            f"/v1/sessions/{self._id}/rules",
            {"version": 1, "rules": self._rules},
        )


def _build_when(
    *,
    direction: str | None,
    service: str | None,
    host: str | None,
    host_suffix: str | None,
    method: str | None,
    path: str | None,
    path_prefix: str | None,
) -> dict[str, Any]:
    when: dict[str, Any] = {}
    if direction:
        when["direction"] = direction
    if service:
        when["service"] = service
    if host:
        when["host"] = host
    if not host and host_suffix:
        when["host"] = host_suffix
    if method:
        when["method"] = method
    if path:
        when["path"] = path
    if path_prefix:
        when["pathPrefix"] = path_prefix
    return when


def _response_to_payload(
    response: Mapping[str, Any] | CapturedResponse,
) -> dict[str, Any]:
    if isinstance(response, CapturedResponse):
        return {
            "status": response.status,
            "headers": dict(response.headers),
            "body": response.body,
        }
    return dict(response)
