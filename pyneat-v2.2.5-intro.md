I spent 1 months fixing "AI-generated" code. Here's what I built from the nightmares.

So a few months ago I was stuck debugging some Python code that an AI assistant had generated. The code looked clean at first glance, it had proper indentation, decent variable names, and even some comments. But it was an absolute disaster underneath.

The AI loved opening files without `with` statements. It loved calling APIs without timeouts. It loved doing `list[0]` with no empty check. It loved creating files called `utils.py`, `helpers.py`, and `ai.py` like those are actual package names. It loved `param1=x` as a function argument name. It loved `range(len())` everywhere. It loved `x != None` instead of `x is not None`.

Long story short: AI-generated code isn't bad because it looks messy. It's bad because it looks clean but has a thousand tiny landmines waiting to blow up in production.

That's why I built **PyNeat**.

It's not just a formatter (Black does that better). It's not just a linter (Ruff is faster). PyNeat is an **AST-level code surgeon** that actually restructures your code at the deepest level.

Here's what it does that no other tool does:

**Detects AI-generated bugs specifically:**
- Resource leaks (no `with` for open(), no timeout for requests)
- Boundary errors (list[0] without empty check)
- Phantom packages (imports named `utils`, `helpers`, `ai`)
- Fake arguments (`param1=x`, `fake=True`, `dummy_arg`)
- Redundant API calls (same request 3+ times)
- Naming chaos (camelCase and snake_case in the same file)

**50+ security rules built-in, enabled by default:**
- Command injection: os.system(), subprocess.run(shell=True)
- SQL injection
- Eval/exec usage
- YAML unsafe loading (auto-fixes to SafeLoader)
- Pickle deserialization
- Hardcoded API keys and secrets
- Empty except blocks (auto-fixes to `raise`)
- And a bunch more...

**7 layers of protection so it never breaks your code:**
- AST Guard, Semantic Guard, Type Shield, Atomic Operations, Scope Guard, Type Checking, and Fuzz Testing. Yeah I went overkill on this part.

**Rust backend for when you actually need speed:**
```bash
pip install pyneat[rust]
```

That gives you tree-sitter parsing, precompiled regexes, and Rayon for true parallel processing without GIL contention. 50-100x faster on large codebases.

**Usage is dead simple:**

```python
from pyneat import clean_code

# One-liner
clean_code("x == None")  # → "x is not None"
clean_code("print('debug')", remove_debug=True)  # → ""
```

```bash
# CLI
pyneat clean my_file.py --dry-run --diff
pyneat check my_file.py --severity --cvss
pyneat check ./src --fail-on critical --format sarif --output report.sarif
```

**3 safety tiers:**
- `safe` (default) — never breaks anything, always on
- `conservative` — adds cleanup like removing unused imports, converting to f-strings
- `destructive` — enables all rules including refactoring, dead code removal, comment cleaning

**Export to everything:**
SARIF (GitHub Security, Azure DevOps), Code Climate (GitLab), Markdown reports, and JSON manifest files.

**It also integrates with CI/CD** out of the box — pre-commit hooks and GitHub Actions workflow example included.

I'm not gonna pretend it's a silver bullet. But if you're working with AI-generated code, legacy code that nobody wants to touch, or just want a security scanner that also cleans up your mess — it's pretty useful.

pypi: `pip install pyneat`
github: https://github.com/pyneat/pyneat

Version 2.4.5 is out now. Would love feedback. AMA.
