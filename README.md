# Legacy / Deprecated Code

> **DO NOT IMPORT FROM THIS DIRECTORY IN NEW CODE.**

This folder contains the original prototype implementation of the IOC Enricher
Agent. It is kept for historical reference only and is **deprecated** as of the
canonical package re-organisation.

## What is here

| Path                       | Origin                                | Status     |
|----------------------------|---------------------------------------|------------|
| `legacy/src/`              | Original root-level `src/` package    | Deprecated |
| `legacy/main.py`           | Original root-level CLI entry-point   | Deprecated |
| `legacy/test_all.py`       | Original root-level monolithic test   | Deprecated |
| `legacy/tests_test_all.py` | Duplicate copy under former `tests/`  | Deprecated |

All of these reference the obsolete `src.*` module path and use the old result
shape (plain dictionaries with `success`/`report` keys), not the strongly typed
`EnrichmentResult` data class.

## Canonical layout

The supported package lives entirely under:

```
ioc_enricher/ioc_enricher/
```

with the public entry-point:

```bash
python -m ioc_enricher --version
python -m ioc_enricher --status
python -m ioc_enricher --ioc 203.0.113.7
```

Programmatic use:

```python
from ioc_enricher import IOCEnricher

enricher = IOCEnricher()
result = enricher.enrich("203.0.113.7")
print(result.risk_score.score, result.risk_score.level.value)
```

Tests live in `ioc_enricher/tests/` and (for the new web adapter) `tests/`.

## Why is this still here?

- Provides a paper trail for the refactor.
- Some historical reports / examples in `docs/` may still reference the old API.
- Removal will happen in a later clean-up PR once nothing in the repo or
  downstream tooling points at `src.*` or `python main.py` anymore.
