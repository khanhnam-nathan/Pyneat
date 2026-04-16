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

"""PyNeat Plugin System.

This module provides a plugin system for extending PyNeat with custom rules.

Usage:
    from pyneat.plugins import Plugin, PluginLoader

    class MyPlugin(Plugin):
        name = "my-plugin"
        description = "My custom plugin"

        def get_rules(self):
            return [MyCustomRule]

    # Load plugins
    loader = PluginLoader()
    plugins = loader.load_all()

    # Register rules from plugins
    for plugin in plugins:
        for rule_cls in plugin.get_rules():
            engine.add_rule(rule_cls())
"""

from abc import ABC, abstractmethod
from typing import List, Type, Dict, Any, Optional
import importlib
import pkgutil

from pyneat.rules.base import Rule


class Plugin(ABC):
    """Base class for PyNeat plugins.

    Plugins can provide:
    - Custom rules
    - New language support
    - Custom scanners
    - Custom reporters

    Attributes:
        name: Unique identifier for the plugin
        version: Plugin version
        description: Human-readable description
        author: Plugin author
    """

    name: str = ""
    version: str = "1.0.0"
    description: str = ""
    author: str = ""

    @abstractmethod
    def get_rules(self) -> List[Type[Rule]]:
        """Return a list of Rule classes provided by this plugin.

        Returns:
            List of Rule subclasses
        """
        pass

    def get_config_schema(self) -> Optional[Dict[str, Any]]:
        """Return a JSON schema for plugin configuration.

        Returns:
            JSON schema dict or None if plugin doesn't need config
        """
        return None

    def validate_config(self, config: Dict[str, Any]) -> bool:
        """Validate plugin configuration.

        Args:
            config: Configuration dictionary

        Returns:
            True if valid, False otherwise
        """
        return True

    def on_load(self) -> None:
        """Called when plugin is loaded."""
        pass

    def on_unload(self) -> None:
        """Called when plugin is unloaded."""
        pass


class BuiltinPlugin(Plugin):
    """Plugin that provides built-in functionality."""

    @abstractmethod
    def get_rules(self) -> List[Type[Rule]]:
        return []


class PluginMetadata:
    """Metadata for a loaded plugin."""

    def __init__(self, plugin: Plugin):
        self.plugin = plugin
        self.name = plugin.name
        self.version = plugin.version
        self.description = plugin.description
        self.author = plugin.author
        self.rules = plugin.get_rules()

    def __repr__(self) -> str:
        return f"PluginMetadata(name={self.name!r}, version={self.version!r}, rules={len(self.rules)})"


class PluginLoader:
    """Loads and manages PyNeat plugins.

    Plugins can be loaded from:
    - Entry points (pyneat.plugins)
    - Builtin plugins
    - Custom paths
    """

    def __init__(self):
        self._plugins: Dict[str, PluginMetadata] = {}
        self._loaded: bool = False

    def load_builtin(self) -> List[PluginMetadata]:
        """Load built-in plugins.

        Returns:
            List of loaded plugin metadata
        """
        from pyneat.plugins.builtin import BuiltinPlugins

        plugins = []
        for plugin_cls in BuiltinPlugins.get_all():
            try:
                plugin = plugin_cls()
                plugin.on_load()
                metadata = PluginMetadata(plugin)
                self._plugins[metadata.name] = metadata
                plugins.append(metadata)
            except Exception as e:
                print(f"Failed to load plugin {plugin_cls.__name__}: {e}")

        return plugins

    def load_from_entry_points(self) -> List[PluginMetadata]:
        """Load plugins from entry points.

        Uses the 'pyneat.plugins' entry point group.

        Returns:
            List of loaded plugin metadata
        """
        from importlib.metadata import entry_points

        plugins = []

        try:
            eps = entry_points(group='pyneat.plugins')
            for ep in eps:
                try:
                    plugin_cls = ep.load()
                    plugin = plugin_cls()
                    plugin.on_load()
                    metadata = PluginMetadata(plugin)
                    self._plugins[metadata.name] = metadata
                    plugins.append(metadata)
                except Exception as e:
                    print(f"Failed to load plugin {ep.name}: {e}")
        except Exception:
            pass

        return plugins

    def load_from_path(self, path: str) -> Optional[PluginMetadata]:
        """Load a plugin from a specific path.

        Args:
            path: Import path or file path to the plugin

        Returns:
            Plugin metadata or None
        """
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("plugin", path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                for name in dir(module):
                    obj = getattr(module, name)
                    if isinstance(obj, type) and issubclass(obj, Plugin) and obj != Plugin:
                        plugin = obj()
                        plugin.on_load()
                        metadata = PluginMetadata(plugin)
                        self._plugins[metadata.name] = metadata
                        return metadata
        except Exception as e:
            print(f"Failed to load plugin from {path}: {e}")

        return None

    def load_all(self) -> Dict[str, PluginMetadata]:
        """Load all available plugins.

        Returns:
            Dictionary of plugin name -> metadata
        """
        if self._loaded:
            return self._plugins

        # Load builtin plugins
        self.load_builtin()

        # Load from entry points
        self.load_from_entry_points()

        self._loaded = True
        return self._plugins

    def get_plugin(self, name: str) -> Optional[PluginMetadata]:
        """Get a plugin by name.

        Args:
            name: Plugin name

        Returns:
            Plugin metadata or None
        """
        if not self._loaded:
            self.load_all()
        return self._plugins.get(name)

    def get_all_rules(self) -> List[Type[Rule]]:
        """Get all rules from all loaded plugins.

        Returns:
            List of Rule classes
        """
        if not self._loaded:
            self.load_all()

        rules = []
        for metadata in self._plugins.values():
            rules.extend(metadata.rules)

        return rules

    def unload_plugin(self, name: str) -> bool:
        """Unload a plugin.

        Args:
            name: Plugin name

        Returns:
            True if unloaded, False if not found
        """
        if name in self._plugins:
            plugin = self._plugins[name].plugin
            plugin.on_unload()
            del self._plugins[name]
            return True
        return False

    def reload_plugin(self, name: str) -> Optional[PluginMetadata]:
        """Reload a plugin.

        Args:
            name: Plugin name

        Returns:
            New plugin metadata or None
        """
        self.unload_plugin(name)
        if name in self._plugins:
            return self._plugins[name]

        # Try to reload from entry points
        self.load_from_entry_points()
        return self._plugins.get(name)


# Convenience function
def load_plugins() -> Dict[str, PluginMetadata]:
    """Load all available plugins.

    Returns:
        Dictionary of plugin name -> metadata
    """
    loader = PluginLoader()
    return loader.load_all()