# Writing Rules

This guide explains how to write custom rules for PyNeat.

## Overview

A rule is a Python class that:
1. Inherits from `pyneat.rules.base.Rule`
2. Implements `apply(CodeFile) -> TransformationResult`
3. Returns the modified code and a list of changes

## Basic Rule Structure

```python
from typing import List
from pyneat.rules.base import Rule
from pyneat.core.types import CodeFile, TransformationResult, RuleConfig

class MyCustomRule(Rule):
    """Description of what this rule does."""

    def __init__(self, config: RuleConfig = None):
        super().__init__(config)
        # Rule-specific initialization

    @property
    def description(self) -> str:
        return "One-line description of the rule"

    def apply(self, code_file: CodeFile) -> TransformationResult:
        # Read the source code
        content = code_file.content

        # Analyze and transform
        transformed = self._transform(content)

        # Return result
        return TransformationResult(
            original=code_file,
            transformed_content=transformed,
            changes_made=["Change description"],
            success=True,
        )

    def _transform(self, content: str) -> str:
        # Transformation logic
        return content
```

## Using LibCST

For Python code transformations, use LibCST:

```python
import libcst as cst

class MyLibCSTRule(Rule):
    """Rule using LibCST for transformations."""

    def apply(self, code_file: CodeFile) -> TransformationResult:
        # Parse code
        tree = cst.parse_module(code_file.content)

        # Transform
        transformer = MyTransformer()
        new_tree = tree.visit(transformer)

        return TransformationResult(
            original=code_file,
            transformed_content=new_tree.code,
            changes_made=transformer.changes,
            success=True,
        )


class MyTransformer(cst.CSTTransformer):
    """CST transformer for the rule."""

    def __init__(self):
        super().__init__()
        self.changes: List[str] = []

    def leave_Name(self, original: cst.Name, updated: cst.Name) -> cst.Name:
        # Transform name nodes
        if original.value == "old_name":
            self.changes.append("Renamed old_name to new_name")
            return updated.with_changes(value="new_name")
        return updated
```

## Security Rules

For security rules, use the security registry:

```python
from pyneat.rules.security import SecurityScannerRule
from pyneat.core.types import SecurityFinding

class MySecurityRule:
    """Mixin for security rules."""

    def create_finding(
        self,
        rule_id: str,
        problem: str,
        line_no: int,
        snippet: str,
    ) -> SecurityFinding:
        """Create a security finding."""
        return SecurityFinding(
            rule_id=rule_id,
            severity="high",
            confidence=0.95,
            cwe_id="CWE-123",
            owasp_id="A01",
            cvss_score=7.5,
            cvss_vector="CVSS:3.1/...",
            file="",
            start_line=line_no,
            end_line=line_no,
            snippet=snippet,
            problem=problem,
            fix_constraints=("Fix by doing X",),
            do_not=("Don't do Y",),
            verify=("Verify by checking Z",),
            resources=("https://example.com",),
            can_auto_fix=True,
            auto_fix_available=True,
        )
```

## Rule Configuration

### RuleConfig

```python
from pyneat.core.types import RuleConfig

rule = MyRule(RuleConfig(
    enabled=True,
    priority=100,  # Lower = runs first
    params={"option": "value"},
))
```

### Priority Levels

| Priority | Range | Usage |
|----------|-------|-------|
| 10-50 | Safe rules | Always run, won't break code |
| 50-100 | Conservative | Optional, may change style |
| 100+ | Destructive | Aggressive, may break code |

## Testing Rules

```python
import pytest
from pathlib import Path
from pyneat.core.types import CodeFile, RuleConfig

from my_rule import MyCustomRule


def test_rule_basic():
    rule = MyCustomRule(RuleConfig(enabled=True))
    code_file = CodeFile(path=Path("test.py"), content="old_name = 1")
    result = rule.apply(code_file)

    assert result.success
    assert "new_name" in result.transformed_content
    assert len(result.changes_made) > 0


def test_rule_no_change():
    rule = MyCustomRule(RuleConfig(enabled=True))
    code_file = CodeFile(path=Path("test.py"), content="new_name = 1")
    result = rule.apply(code_file)

    assert result.success
    assert "new_name" in result.transformed_content
    assert len(result.changes_made) == 0
```

## Registering Rules

Register rules with the RuleRegistry:

```python
from pyneat.rules.registry import RuleRegistry, register_rule

# Method 1: Decorator
@RuleRegistry.register(package="safe", priority=50)
class MyRule(Rule):
    ...

# Method 2: Manual registration
register_rule(MyRule, package="conservative", priority=75)
```

## Best Practices

1. **Idempotent**: Running the rule twice should produce the same result
2. **Safe by default**: Don't break working code
3. **Clear descriptions**: Explain what the rule does
4. **Handle edge cases**: Return success even if no changes needed
5. **Log warnings**: Use logger.warning() for unexpected cases
6. **Test thoroughly**: Cover edge cases and error conditions

## Examples

See these existing rules for reference:

- `pyneat/rules/is_not_none.py` - Simple transformation
- `pyneat/rules/security/` - Security rules
- `pyneat/rules/deadcode.py` - AST analysis
