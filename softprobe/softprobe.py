"""Ergonomic Softprobe SDK facade for Python.

Mirrors the TypeScript SDK in `softprobe-js/src/softprobe.ts`. See
`docs/design.md` §3.2 for the happy path and the division of labor
between client-side case lookup (`find_in_case`) and the runtime-side
rule evaluator (`mock_outbound` → `POST /v1/sessions/{id}/rules`).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Mapping

from .client import (
    Client,
    SoftprobeRuntimeError,
    SoftprobeRuntimeUnreachableError,
    SoftprobeUnknownSessionError,
    TransportFn,
)
from .core.case_lookup import (
    CapturedHit,
    CapturedResponse,
    CaseSpanPredicate,
    find_spans,
    format_predicate,
    response_from_span,
)


DEFAULT_BASE_URL = "http://127.0.0.1:8080"


class SoftprobeCaseLoadError(RuntimeError):
    """Raised when a case document cannot be loaded (file read/parse error,
    or a non-typed runtime failure while pushing the case to the runtime).

    Unknown-session and runtime-unreachable failures are re-raised as-is so
    callers can distinguish them via ``except``.
    """

    def __init__(self, message: str, cause: BaseException | None = None) -> None:
        super().__init__(message)
        self.cause = cause


class SoftprobeCaseLookupAmbiguityError(LookupError):
    """Raised when :meth:`SoftprobeSession.find_in_case` matches more than
    one span. Inherits from :class:`LookupError` for backwards compatibility
    with existing callers.
    """


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
        api_token: str | None = None,
    ) -> None:
        url = base_url or os.environ.get("SOFTPROBE_RUNTIME_URL") or DEFAULT_BASE_URL
        self._client = Client(url, transport=transport, api_token=api_token)

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
        """Read an OTLP-shaped case document from ``case_path``, push it to
        the runtime, and keep a parsed copy in memory for :meth:`find_in_case`.

        File read / JSON parse failures raise :class:`SoftprobeCaseLoadError`.
        Runtime failures pass through their typed form (unknown-session /
        unreachable) and are otherwise wrapped in :class:`SoftprobeCaseLoadError`.
        """

        try:
            with open(case_path, "r", encoding="utf-8") as f:
                case_document = json.load(f)
        except (OSError, ValueError) as exc:
            raise SoftprobeCaseLoadError(
                f"failed to load case from {case_path}", exc
            ) from exc
        self.load_case(case_document)

    def load_case(self, case_document: Mapping[str, Any]) -> None:
        """Push an already-parsed case document to the runtime and keep a
        reference for :meth:`find_in_case`.
        """

        try:
            self._client.sessions.load_case(self._id, case_document)
        except (SoftprobeUnknownSessionError, SoftprobeRuntimeUnreachableError):
            raise
        except SoftprobeRuntimeError as exc:
            raise SoftprobeCaseLoadError(
                "failed to load case into the runtime", exc
            ) from exc
        self._loaded_case = case_document

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

        Raises :class:`SoftprobeCaseLoadError` if no case has been loaded,
        :class:`LookupError` when zero spans match, and
        :class:`SoftprobeCaseLookupAmbiguityError` when more than one span
        matches.
        """

        predicate, matches = self._lookup(
            direction=direction,
            service=service,
            host=host,
            host_suffix=host_suffix,
            method=method,
            path=path,
            path_prefix=path_prefix,
        )
        if not matches:
            raise LookupError(
                f"find_in_case: no span in the loaded case matches "
                f"{format_predicate(predicate)}. Check the predicate "
                f"(direction / method / path / host) or re-capture the case."
            )
        if len(matches) > 1:
            ids = ", ".join(span.get("spanId", "<unknown>") for span in matches)
            raise SoftprobeCaseLookupAmbiguityError(
                f"find_in_case: {len(matches)} spans match "
                f"{format_predicate(predicate)}. Disambiguate the predicate — "
                f"candidate span ids: {ids}."
            )
        (span,) = matches
        return CapturedHit(response=response_from_span(span), span=span)

    def find_all_in_case(
        self,
        *,
        direction: str | None = None,
        service: str | None = None,
        host: str | None = None,
        host_suffix: str | None = None,
        method: str | None = None,
        path: str | None = None,
        path_prefix: str | None = None,
    ) -> list[CapturedHit]:
        """Return every span that matches the predicate (never raises on
        zero matches; authors handle the empty list).
        """

        _, matches = self._lookup(
            direction=direction,
            service=service,
            host=host,
            host_suffix=host_suffix,
            method=method,
            path=path,
            path_prefix=path_prefix,
        )
        return [
            CapturedHit(response=response_from_span(span), span=span)
            for span in matches
        ]

    def _lookup(
        self,
        *,
        direction: str | None,
        service: str | None,
        host: str | None,
        host_suffix: str | None,
        method: str | None,
        path: str | None,
        path_prefix: str | None,
    ) -> tuple[CaseSpanPredicate, list[dict[str, Any]]]:
        if self._loaded_case is None:
            raise SoftprobeCaseLoadError(
                "find_in_case requires a case: call load_case_from_file(path) "
                "or load_case(document) before find_in_case."
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
        return predicate, find_spans(self._loaded_case, predicate)

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
        self._client.sessions.update_rules(
            self._id, {"version": 1, "rules": []}
        )

    def set_policy(self, policy_document: Mapping[str, Any]) -> None:
        """Push a policy document to ``POST /v1/sessions/{id}/policy``."""

        self._client.sessions.set_policy(self._id, policy_document)

    def set_auth_fixtures(self, fixtures_document: Mapping[str, Any]) -> None:
        """Push an auth fixtures document to
        ``POST /v1/sessions/{id}/fixtures/auth``.
        """

        self._client.sessions.set_auth_fixtures(self._id, fixtures_document)

    def close(self) -> None:
        self._client.sessions.close(self._id)

    def _sync_rules(self) -> None:
        self._client.sessions.update_rules(
            self._id, {"version": 1, "rules": self._rules}
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
