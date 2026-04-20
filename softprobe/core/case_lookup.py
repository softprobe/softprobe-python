"""In-memory lookup against a loaded OTLP-shaped case document.

Mirrors `softprobe-js/src/core/case/find-span.ts`; see `docs/design.md`
§3.2.1 / §3.2.3 for the design.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping


HTTP_RESPONSE_HEADER_PREFIX = "http.response.header."


@dataclass(frozen=True)
class CaseSpanPredicate:
    direction: str | None = None
    service: str | None = None
    host: str | None = None
    host_suffix: str | None = None
    method: str | None = None
    path: str | None = None
    path_prefix: str | None = None


@dataclass(frozen=True)
class CapturedResponse:
    status: int
    headers: Mapping[str, str]
    body: str


@dataclass(frozen=True)
class CapturedHit:
    response: CapturedResponse
    span: Mapping[str, Any]


def find_spans(
    case_document: Mapping[str, Any] | None,
    predicate: CaseSpanPredicate,
) -> list[dict[str, Any]]:
    """Return every inject/extract span whose attributes satisfy *predicate*."""

    if not case_document:
        return []

    matches: list[dict[str, Any]] = []
    for trace in case_document.get("traces", []) or []:
        for resource_span in trace.get("resourceSpans", []) or []:
            resource_attrs = (resource_span.get("resource") or {}).get(
                "attributes", []
            )
            service_name = _read_attribute_string(resource_attrs, "service.name")
            for scope_span in resource_span.get("scopeSpans", []) or []:
                for span in scope_span.get("spans", []) or []:
                    if _span_satisfies(span, service_name, predicate):
                        matches.append(span)
    return matches


def response_from_span(span: Mapping[str, Any]) -> CapturedResponse:
    """Materialize a `CapturedResponse` from an OTLP span's attributes.

    `http.response.status_code` must be present (captured spans without a
    status are authoring errors); `http.response.body` defaults to empty
    string and headers to an empty map.
    """

    headers: dict[str, str] = {}
    status: int | None = None
    body = ""

    for attr in span.get("attributes", []) or []:
        key = attr.get("key", "")
        value = attr.get("value", {})
        if key == "http.response.status_code":
            raw = value.get("intValue")
            if isinstance(raw, int):
                status = raw
            elif isinstance(raw, str):
                try:
                    status = int(raw)
                except ValueError:  # pragma: no cover - defensive
                    pass
        elif key == "http.response.body":
            body = _any_value_to_string(value)
        elif key.startswith(HTTP_RESPONSE_HEADER_PREFIX):
            header_name = key[len(HTTP_RESPONSE_HEADER_PREFIX) :]
            headers[header_name] = _any_value_to_string(value)

    if status is None:
        raise ValueError(
            "Captured span "
            f"{span.get('spanId', '<unknown>')} is missing http.response.status_code; "
            "cannot materialize a captured response."
        )

    return CapturedResponse(status=status, headers=headers, body=body)


def format_predicate(predicate: CaseSpanPredicate) -> str:
    """Produce a compact `{ key: "value", ... }` string for error messages."""

    def fmt(value: Any) -> str:
        if isinstance(value, str):
            return f'"{value}"'
        return str(value)

    fields: list[tuple[str, Any]] = [
        ("direction", predicate.direction),
        ("service", predicate.service),
        ("host", predicate.host),
        ("hostSuffix", predicate.host_suffix),
        ("method", predicate.method),
        ("path", predicate.path),
        ("pathPrefix", predicate.path_prefix),
    ]
    present = [(k, v) for k, v in fields if v is not None and v != ""]
    if not present:
        return "{}"
    return "{ " + ", ".join(f"{k}: {fmt(v)}" for k, v in present) + " }"


def _span_satisfies(
    span: Mapping[str, Any],
    resource_service_name: str | None,
    predicate: CaseSpanPredicate,
) -> bool:
    attrs = span.get("attributes", []) or []
    span_type = _read_attribute_string(attrs, "sp.span.type") or ""
    if span_type not in ("inject", "extract"):
        return False

    if predicate.direction is not None:
        direction = _read_attribute_string(attrs, "sp.traffic.direction")
        if direction != predicate.direction:
            return False

    if predicate.method is not None:
        method = _read_attribute_string(attrs, "http.request.method") or _read_attribute_string(
            attrs, "http.request.header.:method"
        )
        if method != predicate.method:
            return False

    url_path = _read_attribute_string(attrs, "url.path") or _read_attribute_string(
        attrs, "http.request.header.:path"
    ) or ""
    if predicate.path is not None and url_path != predicate.path:
        return False
    if predicate.path_prefix is not None and not url_path.startswith(
        predicate.path_prefix
    ):
        return False

    host = _read_attribute_string(attrs, "url.host") or ""
    if predicate.host is not None and host != predicate.host:
        return False
    if predicate.host_suffix is not None and not host.endswith(
        predicate.host_suffix
    ):
        return False

    span_service = (
        _read_attribute_string(attrs, "sp.service.name")
        or resource_service_name
        or ""
    )
    if predicate.service is not None and span_service != predicate.service:
        return False

    return True


def _read_attribute_string(
    attributes: Iterable[Mapping[str, Any]] | None, key: str
) -> str | None:
    if attributes is None:
        return None
    for attr in attributes:
        if attr.get("key") == key:
            return _any_value_to_string(attr.get("value", {}))
    return None


def _any_value_to_string(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (int, float, bool)):
        return str(value)
    if isinstance(value, Mapping):
        if "stringValue" in value and isinstance(value["stringValue"], str):
            return value["stringValue"]
        if "intValue" in value:
            raw = value["intValue"]
            if isinstance(raw, int):
                return str(raw)
            if isinstance(raw, str):
                return raw
        if "boolValue" in value:
            return str(value["boolValue"])
        if "doubleValue" in value:
            return str(value["doubleValue"])
    return ""
