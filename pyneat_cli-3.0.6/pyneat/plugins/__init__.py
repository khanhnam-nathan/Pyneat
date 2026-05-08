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

This package provides a plugin system for extending PyNeat with custom rules.

Example usage:
    from pyneat.plugins import PluginLoader, Plugin

    class MyRule(Rule):
        ...

    class MyPlugin(Plugin):
        name = "my-plugin"

            def get_rules(self):
                return [MyRule]

    # Load and use plugins
    loader = PluginLoader()
    plugins = loader.load_all()
"""

from pyneat.plugins.base import (
    Plugin,
    BuiltinPlugin,
    PluginMetadata,
    PluginLoader,
    load_plugins,
)

__all__ = [
    "Plugin",
    "BuiltinPlugin",
    "PluginMetadata",
    "PluginLoader",
    "load_plugins",
]