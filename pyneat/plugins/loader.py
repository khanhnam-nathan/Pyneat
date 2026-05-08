"""Plugin loader for PyNEAT plugins."""

from __future__ import annotations

import importlib
import importlib.metadata
import logging
from pathlib import Path
from typing import List, Type, Optional

from pyneat.plugins.base import Plugin

logger = logging.getLogger(__name__)


class PluginLoader:
    """Loads and manages PyNEAT plugins via entry points."""

    ENTRY_POINT_GROUP = "pyneat.plugins"

    def __init__(self):
        self._plugins: List[Plugin] = []
        self._loaded = False

    def load_all(self) -> List[Plugin]:
        """Load all plugins registered via entry points."""
        if self._loaded:
            return self._plugins

        try:
            # Python 3.10+ style
            eps = importlib.metadata.entry_points()
            if isinstance(eps, dict):
                plugin_eps = eps.get(self.ENTRY_POINT_GROUP, [])
            else:
                # Python 3.9 style - entry_points() returns a SelectableGroups
                plugin_eps = getattr(eps, self.ENTRY_POINT_GROUP, [])
        except Exception as e:
            logger.warning(f"Failed to load entry points: {e}")
            plugin_eps = []

        for ep in plugin_eps:
            try:
                plugin_module = ep.load()
                # Find Plugin subclass in the loaded module
                plugin_instance = self._find_plugin_class(plugin_module)
                if plugin_instance:
                    plugin_instance.on_load()
                    self._plugins.append(plugin_instance)
                    logger.info(f"Loaded plugin: {plugin_instance.name} v{plugin_instance.version}")
            except Exception as e:
                logger.warning(f"Failed to load plugin '{ep.name}': {e}")

        self._loaded = True
        return self._plugins

    def _find_plugin_class(self, module) -> Optional[Plugin]:
        """Find a Plugin subclass in a loaded module."""
        for name in dir(module):
            cls = getattr(module, name, None)
            if isinstance(cls, type) and issubclass(cls, Plugin) and cls is not Plugin:
                return cls()
        return None

    def load_from_path(self, path: Path) -> Plugin:
        """Load a plugin from a file path (for development/testing)."""
        import importlib.util

        spec = importlib.util.spec_from_file_location("pyneat_plugin", path)
        if spec is None or spec.loader is None:
            raise ValueError(f"Cannot load plugin from {path}")

        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)  # type: ignore

        plugin = self._find_plugin_class(module)
        if plugin is None:
            raise ValueError(f"No Plugin subclass found in {path}")

        plugin.on_load()
        self._plugins.append(plugin)
        return plugin

    def get_rules(self) -> List[Type]:
        """Collect all Rule classes from loaded plugins."""
        rules = []
        for plugin in self._plugins:
            rules.extend(plugin.get_rules())
        return rules

    def get_plugins(self) -> List[Plugin]:
        """Return all loaded plugins."""
        return self._plugins

    def get_plugin(self, name: str) -> Optional[Plugin]:
        """Get a plugin by name."""
        for plugin in self._plugins:
            if plugin.name == name:
                return plugin
        return None
