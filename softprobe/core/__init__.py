"""Shared, framework-agnostic helpers for the Softprobe Python SDK.

Per the layout convention in `AGENTS.md` rule 11, this package owns the
OTLP attribute plumbing that multiple instrumentation layers consume.
"""

from .case_lookup import (
    CapturedHit,
    CapturedResponse,
    CaseSpanPredicate,
    find_spans,
    format_predicate,
    response_from_span,
)

__all__ = [
    "CapturedHit",
    "CapturedResponse",
    "CaseSpanPredicate",
    "find_spans",
    "format_predicate",
    "response_from_span",
]
