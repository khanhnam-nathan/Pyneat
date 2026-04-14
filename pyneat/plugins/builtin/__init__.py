"""PyNeat - AI Code Cleaner.

Copyright (C) 2026 PyNEAT Authors

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

"""Built-in plugins for PyNeat.

This module provides additional functionality through built-in plugins.
"""

from typing import List, Type

from pyneat.plugins.base import Plugin, BuiltinPlugin
from pyneat.rules.base import Rule


class CustomRulesPlugin(BuiltinPlugin):
    """Plugin that provides custom rules for specific use cases.

    This is an example plugin that can be extended for custom rule sets.
    """

    name = "custom-rules"
    version = "1.0.0"
    description = "Custom rules for project-specific checks"
    author = "PyNeat"

    def get_rules(self) -> List[Type[Rule]]:
        """Return custom rules provided by this plugin."""
        # Import rules here to avoid circular imports
        from pyneat.rules.security import SecurityScannerRule

        # Return SecurityScannerRule as an example
        # In a real plugin, this would be custom rule classes
        return [SecurityScannerRule]


class LanguagePackPlugin(BuiltinPlugin):
    """Plugin that provides additional language support.

    This plugin can be extended to add support for more languages.
    """

    name = "language-packs"
    version = "1.0.0"
    description = "Additional language support packs"
    author = "PyNeat"

    def get_rules(self) -> List[Type[Rule]]:
        """Return rules for additional languages."""
        from pyneat.rules.security import SecurityScannerRule
        return [SecurityScannerRule]


class BuiltinPlugins:
    """Registry for all built-in plugins."""

    _plugins: List[Type[BuiltinPlugin]] = [
        CustomRulesPlugin,
        LanguagePackPlugin,
    ]

    @classmethod
    def register(cls, plugin_cls: Type[BuiltinPlugin]) -> None:
        """Register a built-in plugin.

        Args:
            plugin_cls: Plugin class to register
        """
        if plugin_cls not in cls._plugins:
            cls._plugins.append(plugin_cls)

    @classmethod
    def get_all(cls) -> List[Type[BuiltinPlugin]]:
        """Get all registered built-in plugins.

        Returns:
            List of plugin classes
        """
        return cls._plugins.copy()

    @classmethod
    def get_by_name(cls, name: str) -> Type[BuiltinPlugin]:
        """Get a plugin by name.

        Args:
            name: Plugin name

        Returns:
            Plugin class or None
        """
        for plugin_cls in cls._plugins:
            if plugin_cls.name == name:
                return plugin_cls
        return None