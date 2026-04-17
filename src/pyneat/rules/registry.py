# PyNeat - AI Code Cleaner.
#
# Copyright (C) 2026 PyNEAT Authors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# For commercial licensing, contact: khanhnam.copywriting@gmail.com

"""Rule Registry System.

This module provides a decorator-based registry for PyNeat rules.
Rules can be registered with package (safe/conservative/destructive) and priority.

Usage:
    from pyneat.rules.registry import RuleRegistry, register_rule

    @RuleRegistry.register(package="safe", priority=10)
    class MyRule(Rule):
        ...
"""

from typing import Dict, List, Type, Optional, Tuple
from dataclasses import dataclass

from pyneat.rules.base import Rule


@dataclass
class RuleRegistration:
    """Registration info for a rule."""
    cls: Type[Rule]
    package: str  # "safe", "conservative", "destructive", or "universal"
    priority: int  # Lower = runs first
    enabled_by_default: bool = True


class RuleRegistry:
    """Registry for PyNeat rules with package and priority management.

    This registry replaces the if/else chain in _build_engine() with
    a decorator-based approach. Rules can be registered with metadata
    and retrieved by package or priority.
    """

    _rules: Dict[str, RuleRegistration] = {}
    _initialized: bool = False

    @classmethod
    def register(
        cls,
        package: str = "safe",
        priority: int = 100,
        enabled_by_default: bool = True,
    ) -> callable:
        """Decorator to register a rule with the registry.

        Args:
            package: Package the rule belongs to ("safe", "conservative", "destructive")
            priority: Execution priority (lower = runs first)
            enabled_by_default: Whether the rule is enabled by default

        Returns:
            Decorator function
        """
        def decorator(rule_cls: Type[Rule]) -> Type[Rule]:
            reg = RuleRegistration(
                cls=rule_cls,
                package=package,
                priority=priority,
                enabled_by_default=enabled_by_default,
            )
            cls._rules[rule_cls.__name__] = reg
            return rule_cls

        return decorator

    @classmethod
    def get_rule(cls, name: str) -> Optional[RuleRegistration]:
        """Get a rule by class name."""
        return cls._rules.get(name)

    @classmethod
    def get_all_rules(cls) -> Dict[str, RuleRegistration]:
        """Get all registered rules."""
        return cls._rules.copy()

    @classmethod
    def get_rules_by_package(cls, package: str) -> List[RuleRegistration]:
        """Get all rules for a specific package."""
        return [
            r for r in cls._rules.values()
            if r.package == package or r.package == "universal"
        ]

    @classmethod
    def get_rules_sorted(cls) -> List[RuleRegistration]:
        """Get all rules sorted by priority."""
        return sorted(cls._rules.values(), key=lambda r: r.priority)

    @classmethod
    def get_enabled_rules(cls, package: str) -> List[Type[Rule]]:
        """Get all enabled rules for a package, sorted by priority."""
        rules = cls.get_rules_by_package(package)
        return [
            r.cls for r in rules if r.enabled_by_default
        ]

    @classmethod
    def clear(cls) -> None:
        """Clear all registrations."""
        cls._rules.clear()
        cls._initialized = False

    @classmethod
    def initialize_from_module(cls, module_name: str) -> None:
        """Import a module to trigger its @register decorators.

        This should be called at startup to register all rules.
        """
        if cls._initialized:
            return

        import importlib
        try:
            importlib.import_module(module_name)
        except ImportError:
            pass

        cls._initialized = True


# Convenience function for registering rules
def register_rule(
    rule_cls: Type[Rule],
    package: str = "safe",
    priority: int = 100,
    enabled_by_default: bool = True,
) -> Type[Rule]:
    """Register a rule class with the registry.

    Alternative to using the @RuleRegistry.register decorator.
    """
    reg = RuleRegistration(
        cls=rule_cls,
        package=package,
        priority=priority,
        enabled_by_default=enabled_by_default,
    )
    RuleRegistry._rules[rule_cls.__name__] = reg
    return rule_cls


# Builder function that uses the registry
def build_engine_from_registry(
    package: str = "safe",
    config: Optional[Dict] = None,
) -> List[Rule]:
    """Build a list of rules from the registry based on package.

    Args:
        package: Package to use ("safe", "conservative", "destructive")
        config: Optional config dict for rule parameters

    Returns:
        List of Rule instances sorted by priority
    """
    from pyneat.core.types import RuleConfig

    config = config or {}
    rules: List[Rule] = []

    # Get all rules for the package
    package_rules = RuleRegistry.get_rules_by_package(package)

    # Also include universal rules
    universal_rules = RuleRegistry.get_rules_by_package("universal")

    # Combine and deduplicate
    all_rules = {}
    for r in package_rules + universal_rules:
        if r.cls.__name__ not in all_rules:
            all_rules[r.cls.__name__] = r

    # Create rule instances in priority order
    for reg in sorted(all_rules.values(), key=lambda r: r.priority):
        if reg.enabled_by_default:
            # Check if rule is explicitly disabled in config
            rule_name = reg.cls.__name__
            if config.get(f"disable_{rule_name}", False):
                continue

            # Create rule instance with config
            rule_config = RuleConfig(
                enabled=True,
                priority=reg.priority,
            )
            try:
                rule_instance = reg.cls(rule_config)
                rules.append(rule_instance)
            except TypeError:
                # Rule doesn't take config argument
                try:
                    rule_instance = reg.cls()
                    rules.append(rule_instance)
                except Exception:
                    pass

    return rules


# Pre-defined package configurations
SAFE_PACKAGE_RULES = [
    # Priority 10-20: Core safe rules
    ("IsNotNoneRule", "safe", 10),
    ("RangeLenRule", "safe", 15),
    ("SecurityScannerRule", "safe", 20),
    ("TypingRule", "safe", 25),
    ("CodeQualityRule", "safe", 30),
    ("PerformanceRule", "safe", 35),
]

CONSERVATIVE_PACKAGE_RULES = [
    # Additional rules for conservative package
    ("UnusedImportRule", "conservative", 40),
    ("FStringRule", "conservative", 45),
    ("DataclassSuggestionRule", "conservative", 50),
    ("MagicNumberRule", "conservative", 55),
]

DESTRUCTIVE_PACKAGE_RULES = [
    # Aggressive rules (may break code)
    ("ImportCleaningRule", "destructive", 60),
    ("NamingConventionRule", "destructive", 65),
    ("RefactoringRule", "destructive", 70),
    ("CommentCleaner", "destructive", 75),
    ("RedundantExpressionRule", "destructive", 80),
    ("DeadCodeRule", "destructive", 85),
    ("MatchCaseRule", "destructive", 90),
]