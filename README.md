# softprobe (Python SDK)

Python SDK for the **Softprobe Hybrid** platform. It talks HTTP to
`softprobe-runtime` and gives test authors an ergonomic `Softprobe` /
`SoftprobeSession` pair that mirrors the TypeScript, Java, and Go SDKs.

## Status

This package is **not yet published to PyPI** from this monorepo. Use it
directly from source inside the workspace (for example via a relative path in
your virtualenv or an editable install). The `pip install softprobe` command
on the docs site refers to a **planned** PyPI release and is not wired to this
repository today.

See [`docs/design.md`](../docs/design.md) §3.2 for the normative authoring
flow and `docs-site/reference/sdk-python.md` for the public SDK reference.

## Install (from source)

```bash
cd softprobe-python
python3 -m pip install -e .         # once pyproject.toml is added
# or, for quick exploratory use:
python3 -c "import sys; sys.path.insert(0, 'softprobe-python'); from softprobe import Softprobe"
```

The in-repo harnesses under [`e2e/pytest-replay/`](../e2e/pytest-replay/)
import this package by relative path rather than from PyPI.

## Minimal replay example

```python
from softprobe import Softprobe

softprobe = Softprobe(base_url="http://127.0.0.1:8080")
session = softprobe.start_session(mode="replay")
session.load_case_from_file("spec/examples/cases/fragment-happy-path.case.json")

hit = session.find_in_case(direction="outbound", method="GET", path="/fragment")
session.mock_outbound(
    direction="outbound",
    method="GET",
    path="/fragment",
    response=hit.response,
)

# Then drive the SUT through the proxy with the session header:
#   x-softprobe-session-id: session.id
session.close()
```

## Public surface

The supported SDK surface mirrors the TypeScript SDK:

- `Softprobe` — entry point (`start_session`, `attach`)
- `SoftprobeSession` — session-bound helper
  - `load_case_from_file(path)` / `load_case(document)`
  - `find_in_case(**predicate)` / `find_all_in_case(**predicate)`
  - `mock_outbound(response=..., **predicate)`
  - `clear_rules()`
  - `set_policy(document)`
  - `set_auth_fixtures(document)`
  - `close()`

Typed error classes:

- `SoftprobeRuntimeError` — non-2xx response from the runtime
- `SoftprobeRuntimeUnreachableError` — transport-layer failure
- `SoftprobeUnknownSessionError` — stable `unknown_session` envelope
- `SoftprobeCaseLoadError` — file read / parse / runtime load failure
- `SoftprobeCaseLookupAmbiguityError` — more than one `find_in_case` match

## Tests

```bash
cd softprobe-python
python3 -m unittest discover -s tests
```

The pytest end-to-end harness at [`e2e/pytest-replay/`](../e2e/pytest-replay/)
drives this SDK against the compose stack in [`e2e/`](../e2e/).

## Canonical CLI

The `softprobe` command lives in [`softprobe-runtime/`](../softprobe-runtime/),
not in this package. This SDK only speaks the JSON control API over HTTP.
