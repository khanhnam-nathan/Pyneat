# PyNEAT Test & CLI Issues Report
Generated: 2026-05-13 (updated: scan hang fixed)

## Summary
- **655 passed**, **0 failed**
- Test suite: All 655 collectable tests from `tests/` pass
- CLI: `pyneat.exe` binary (v3.1.0), `pyneat-cli` from PyPI (v3.1.7)
- Scan hang: **FIXED** in Python package (v3.1.7) via `sys.stdin.isatty()` guard

---

## Fixes Applied by Author

| # | Issue | Status |
|---|-------|--------|
| 1 | `_build_engine` export missing | FIXED by author |
| 2a | Magic number detection test | FIXED by author's rewrite |
| 2b | Unused import heuristic test | FIXED by author's rewrite |
| 2c | PHP rule ID `PY-CRYPT-001` prefix | FIXED by author's rewrite |
| 2d | PHP SQL injection rule ID | FIXED by author's rewrite |
| 3 | `test_integration.clean.py` | FIXED by author (deleted) |
| 4 | `Path` not imported in security.py | FIXED |
| 5 | `meta` undefined in `_add_finding` | FIXED |

## Regression Fixes Applied

### 4. `NameError: name 'Path' is not defined` -- `pyneat/rules/security.py`
The author's rewrite of `security.py` forgot to import `Path` and `json`.
**Fix:** Added imports at top of file:
```python
import json
from pathlib import Path
```

### 5. `NameError: name 'meta' is not defined` -- `pyneat/rules/security.py`
The `_add_finding()` method references `meta` variable which was never defined. It should call `get_security_rule(rule_id)` to look up rule metadata from the registry.
**Fix:** Added the missing call in `_add_finding`:
```python
def _add_finding(self, rule_id, start_line, end_line, snippet, problem, ...):
    meta = get_security_rule(rule_id)  # was missing -- all _add_finding calls failed
    if meta is None:
        return
```

---

## Fixed Issues (v3.1.7)

| # | Issue | Status |
|---|-------|--------|
| 6 | `pyneat scan` hangs due to blocking `stdin.readline()` | **FIXED** -- added `sys.stdin.isatty()` guard in `show_feature_menu()` |
| 7 | Version mismatch (pyneat.exe reports 3.1.0 vs pyproject.toml 3.1.7) | **PENDING** -- Rust/Cargo not installed on this machine |
| 8 | PyPI name collision | **IGNORED** -- not a code issue |

## No Remaining Open Issues
