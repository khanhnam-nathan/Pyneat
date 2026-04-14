"""Universal rules — work on all languages.

These rules use LN-AST from the Rust parser, making them
truly cross-language without any language-specific branching.

Available rules:
    - HardcodedSecretsRule: Detect hardcoded passwords/API keys
    - DebugArtifactsRule: Detect debug print/log statements
    - EmptyCatchRule: Detect empty except/catch blocks
    - TodoCommentRule: Detect TODO/FIXME comments
    - ArrowAntiPatternRule: Detect deeply nested if/else chains

Usage:
    from pyneat.rules.universal import HardcodedSecretsRule

    rule = HardcodedSecretsRule()
    result = rule.apply(code_file)
"""

from pyneat.rules.universal.base import UniversalRule
from pyneat.rules.universal.hardcoded_secrets import HardcodedSecretsRule
from pyneat.rules.universal.debug_artifacts import DebugArtifactsRule
from pyneat.rules.universal.empty_catch import EmptyCatchRule
from pyneat.rules.universal.todos import TodoCommentRule
from pyneat.rules.universal.arrow_antipattern import ArrowAntiPatternRule

__all__ = [
    "UniversalRule",
    "HardcodedSecretsRule",
    "DebugArtifactsRule",
    "EmptyCatchRule",
    "TodoCommentRule",
    "ArrowAntiPatternRule",
]
