# PyNEAT API Reference

Detailed API documentation for PyNEAT 2.0.0.

## Table of Contents

- [Installation](#installation)
- [RuleEngine](#ruleengine)
- [CodeFile](#codefile)
- [TransformationResult](#transformationresult)
- [RuleConfig](#ruleconfig)
- [CLI API](#cli-api)
- [Security Rules API](#security-rules-api)
- [Examples](#examples)

---

## Installation

```bash
pip install pyneat-cli
```

With optional dependencies:

```bash
pip install pyneat-cli[security]   # Security rules
pip install pyneat-cli[server]     # LSP server
pip install pyneat-cli[all]        # All features
```

---

## RuleEngine

Main engine for applying rules to code.

### Import

```python
from pyneat.core.engine import RuleEngine
```

### Constructor

```python
engine = RuleEngine(
    enable_security: bool = False,
    enable_quality: bool = False,
    enable_performance: bool = False,
    enable_unused_imports: bool = True,
    enable_redundant: bool = True,
    package: str = "safe",
    check_only: bool = False,
    verbose: bool = False
)
```

### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `enable_security` | bool | `False` | Enable security scanning (50+ rules) |
| `enable_quality` | bool | `False` | Enable quality rules |
| `enable_performance` | bool | `False` | Enable performance rules |
| `enable_unused_imports` | bool | `True` | Remove unused imports |
| `enable_redundant` | bool | `True` | Remove redundant expressions |
| `package` | str | `"safe"` | Package: `safe`, `conservative`, `destructive` |
| `check_only` | bool | `False` | Check only, do not fix |
| `verbose` | bool | `False` | Verbose output |

### Methods

#### `process_code(code: str, filename: str) -> TransformationResult`

Process a code string.

```python
engine = RuleEngine()
result = engine.process_code('''
import os

def hello():
    print("Hello")  # Debug artifact
    return None
''', "example.py")

print(result.transformed_content)
print(result.changes_made)
```

#### `process_file(filepath: str, backup: bool = True) -> TransformationResult`

Process a file.

```python
result = engine.process_file("myapp.py", backup=True)
if result.success:
    print(f"Applied {len(result.changes_made)} changes")
```

#### `check_file(filepath: str) -> List[Issue]`

Check a file only, do not fix.

```python
issues = engine.check_file("myapp.py")
for issue in issues:
    print(f"{issue.rule_id}: {issue.message} at line {issue.line}")
```

---

## CodeFile

Container for source code.

### Import

```python
from pyneat.core.types import CodeFile
```

### Constructor

```python
code_file = CodeFile(
    path: str,
    content: str,
    encoding: str = "utf-8"
)
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `path` | str | File path |
| `content` | str | Source code content |
| `encoding` | str | File encoding (default: utf-8) |
| `lines` | List[str] | Content as lines |
| `tree` | CST | Parsed CST tree |

---

## TransformationResult

Result of a transformation.

### Import

```python
from pyneat.core.types import TransformationResult
```

### Attributes

| Attribute | Type | Description |
|-----------|------|-------------|
| `original` | CodeFile | Original file |
| `transformed_content` | str | Transformed content |
| `changes_made` | List[str] | List of changes |
| `success` | bool | Success flag |
| `error` | Optional[str] | Error message if failed |

### Example

```python
result = engine.process_code(code, "test.py")

if result.success:
    print("Changes made:")
    for change in result.changes_made:
        print(f"  - {change}")

    # Write output
    with open("output.py", "w") as f:
        f.write(result.transformed_content)
```

---

## RuleConfig

Configuration for individual rules.

### Import

```python
from pyneat.core.types import RuleConfig
```

### Constructor

```python
config = RuleConfig(
    enabled: bool = True,
    aggressive: bool = False,
    allowed_semantic_nodes: List[str] = None
)
```

### Example

```python
from pyneat.rules.debug import DebugCleaner
from pyneat.core.types import RuleConfig

config = RuleConfig(
    aggressive=True,
    allowed_semantic_nodes=["FunctionDef"]
)

rule = DebugCleaner(config)
result = rule.apply(code_file)
```

---

## Security Rules API

### Import

```python
from pyneat.rules.security_registry import (
    get_security_rule,
    get_rules_by_severity,
    get_all_rule_ids
)
```

### Functions

#### `get_security_rule(rule_id: str) -> Optional[SecurityRuleMetadata]`

Get metadata for a specific rule.

```python
from pyneat.rules.security_registry import get_security_rule

rule = get_security_rule("SEC-001")
if rule:
    print(f"Name: {rule.name}")
    print(f"CVSS: {rule.cvss_base}")
    print(f"Auto-fix: {rule.auto_fix_available}")
```

#### `get_rules_by_severity(severity: str) -> List[SecurityRuleMetadata]`

Get all rules by severity level.

```python
from pyneat.rules.security_registry import get_rules_by_severity

critical_rules = get_rules_by_severity("critical")
for rule in critical_rules:
    print(f"{rule.id}: {rule.name}")
```

#### `get_all_rule_ids() -> List[str]`

Get all rule IDs.

```python
from pyneat.rules.security_registry import get_all_rule_ids

all_rules = get_all_rule_ids()
print(f"Total: {len(all_rules)} rules")
```

---

## CLI API

### Import

```python
from pyneat.cli import cli
```

### Using Click

```python
import click
from pyneat.cli import cli

# Run CLI
cli.main(standalone_mode=False)
```

---

## Examples

### Basic Usage

```python
from pyneat.core.engine import RuleEngine

# Create engine
engine = RuleEngine(
    package="safe",
    enable_unused_imports=True,
    enable_redundant=True
)

# Process code
code = '''
import os
import os  # Duplicate

def example():
    if value == True:  # Redundant
        return True
    return False
'''

result = engine.process_code(code, "example.py")
print(result.transformed_content)
```

### Security Scan

```python
from pyneat.core.engine import RuleEngine

engine = RuleEngine(enable_security=True)

# Scan code
issues = engine.check_file("vulnerable.py")

print(f"Found {len(issues)} security issues:")
for issue in issues:
    print(f"  [{issue.severity}] {issue.rule_id}: {issue.message}")
```

### Custom Rule

```python
from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult, RuleConfig

class MyCustomRule(Rule):
    @property
    def description(self) -> str:
        return "My custom rule"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        original = code_file.content
        # Custom logic here
        transformed = original.replace("old", "new")
        changes = ["Replaced 'old' with 'new'"] if original != transformed else []

        return self._create_result(code_file, transformed, changes)

# Use it
rule = MyCustomRule()
result = rule.apply(code_file)
```

### Batch Processing

```python
from pathlib import Path
from pyneat.core.engine import RuleEngine

engine = RuleEngine()

# Process all Python files in directory
for py_file in Path("./src").rglob("*.py"):
    result = engine.process_file(str(py_file), backup=True)
    print(f"{py_file}: {len(result.changes_made)} changes")
```

### Report Generation

```python
import json
from pyneat.core.engine import RuleEngine

engine = RuleEngine(enable_security=True)

issues = engine.check_file("app.py")

# Generate SARIF report
sarif_report = {
    "version": "2.1.0",
    "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
    "runs": [{
        "results": [
            {
                "ruleId": issue.rule_id,
                "level": issue.severity,
                "message": {"text": issue.message}
            }
            for issue in issues
        ]
    }]
}

with open("report.sarif", "w") as f:
    json.dump(sarif_report, f, indent=2)
```

---

## Error Handling

```python
from pyneat.core.engine import RuleEngine
from pyneat.core.types import TransformationResult

engine = RuleEngine()

try:
    result = engine.process_file("myapp.py")

    if result.success:
        print(f"Success! {len(result.changes_made)} changes")
    else:
        print(f"Failed: {result.error}")

except Exception as e:
    print(f"Unexpected error: {e}")
    # Fallback: use original content
    original = result.original.content if result else None
```

---

## Type Hints

PyNEAT uses full type hints. Import types:

```python
from pyneat.core.types import (
    CodeFile,
    TransformationResult,
    RuleConfig,
    SecuritySeverity,
    Issue
)

# Issue type
class Issue:
    rule_id: str
    severity: str  # critical, high, medium, low, info
    message: str
    line: int
    column: int
    end_line: Optional[int]
    end_column: Optional[int]
```

---

## Performance Tips

1. **Cache parsed trees** - LibCST parsing can be time-consuming

```python
from libcst.metadata import MetadataWrapper
from pyneat.core.types import CodeFile

# Parse once, use multiple times
wrapper = MetadataWrapper.parse_module(code_file.content)
```

2. **Batch processing** - Process multiple files at once

```python
from concurrent.futures import ThreadPoolExecutor

with ThreadPoolExecutor(max_workers=4) as executor:
    results = list(executor.map(engine.process_file, files))
```

3. **Use check_only for scanning** - Faster when only scanning is needed

```python
# Check only - skip transform parsing
issues = engine.check_file("large_file.py")
```
