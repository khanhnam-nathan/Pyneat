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

"""Configuration loader for PyNeat.

Supports loading configuration from:
- .pyneat.yaml in current directory
- .pyneat.yml in current directory
- pyproject.toml [tool.pyneat] section
- Environment variables (PYNEAT_*)
- Command-line arguments (passed to load_config)
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List

import yaml


class ConfigLoader:
    """Loads and merges configuration from multiple sources.

    Priority (highest to lowest):
    1. Command-line arguments
    2. Environment variables
    3. .pyneat.yaml / .pyneat.yml
    4. pyproject.toml [tool.pyneat]
    5. Default values
    """

    DEFAULT_CONFIG = {
        "version": "1.0",
        "rules": {
            "enabled": ["safe"],
            "disabled": [],
        },
        "severity_threshold": "info",
        "exclude": [
            "__pycache__",
            ".venv",
            "venv",
            ".git",
            "node_modules",
            ".pytest_cache",
            ".egg-info",
        ],
        "security": {
            "fail_on": None,
            "auto_fix": True,
            "interactive": True,
        },
        "output": {
            "format": "text",
            "path": None,
        },
        "cache": {
            "enabled": True,
            "ttl": 3600,
        },
    }

    def __init__(self, config_path: Optional[Path] = None):
        self.config_path = config_path
        self._config: Optional[Dict[str, Any]] = None

    def load(self) -> Dict[str, Any]:
        """Load configuration from all sources.

        Returns:
            Merged configuration dictionary
        """
        if self._config is not None:
            return self._config

        # Start with defaults
        config = self.DEFAULT_CONFIG.copy()

        # Load from pyproject.toml
        pyproject_config = self._load_pyproject()
        if pyproject_config:
            config = self._merge(config, pyproject_config)

        # Load from .pyneat.yaml
        yaml_config = self._load_yaml()
        if yaml_config:
            config = self._merge(config, yaml_config)

        # Load from environment variables
        env_config = self._load_env()
        if env_config:
            config = self._merge(config, env_config)

        self._config = config
        return config

    def _load_pyproject(self) -> Dict[str, Any]:
        """Load configuration from pyproject.toml."""
        path = Path.cwd() / "pyproject.toml"
        if not path.exists():
            return {}

        try:
            if sys.version_info >= (3, 11):
                import tomllib
                with open(path, "rb") as f:
                    data = tomllib.load(f)
            else:
                import tomli
                with open(path, "rb") as f:
                    data = tomli.load(f)

            return data.get("tool", {}).get("pyneat", {})
        except Exception:
            return {}

    def _load_yaml(self) -> Dict[str, Any]:
        """Load configuration from .pyneat.yaml or .pyneat.yml."""
        if self.config_path:
            path = Path(self.config_path)
            if path.exists():
                return self._parse_yaml(path)

        # Look for config files in current directory
        for name in [".pyneat.yaml", ".pyneat.yml"]:
            path = Path.cwd() / name
            if path.exists():
                return self._parse_yaml(path)

        return {}

    def _parse_yaml(self, path: Path) -> Dict[str, Any]:
        """Parse a YAML configuration file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)
            if data and isinstance(data, dict):
                return data.get("pyneat", data)
            return {}
        except Exception:
            return {}

    def _load_env(self) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config = {}

        # Map environment variables to config keys
        env_mappings = {
            "PYNEAT_SEVERITY_THRESHOLD": ("severity_threshold",),
            "PYNEAT_RULES_ENABLED": ("rules", "enabled"),
            "PYNEAT_RULES_DISABLED": ("rules", "disabled"),
            "PYNEAT_SECURITY_FAIL_ON": ("security", "fail_on"),
            "PYNEAT_SECURITY_AUTO_FIX": ("security", "auto_fix"),
            "PYNEAT_OUTPUT_FORMAT": ("output", "format"),
            "PYNEAT_CACHE_ENABLED": ("cache", "enabled"),
        }

        for env_var, path in env_mappings.items():
            value = os.environ.get(env_var)
            if value is None:
                continue

            # Parse value
            if value.lower() in ("true", "yes", "1"):
                parsed_value = True
            elif value.lower() in ("false", "no", "0"):
                parsed_value = False
            elif value.isdigit():
                parsed_value = int(value)
            else:
                parsed_value = value

            # Set nested value
            current = config
            for key in path[:-1]:
                if key not in current:
                    current[key] = {}
                current = current[key]
            current[path[-1]] = parsed_value

        return config

    def _merge(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two configuration dictionaries.

        Args:
            base: Base configuration
            override: Override configuration

        Returns:
            Merged configuration
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge(result[key], value)
            else:
                result[key] = value

        return result

    def get(self, key: str, default: Any = None) -> Any:
        """Get a configuration value.

        Args:
            key: Dot-separated key path (e.g., "security.fail_on")
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        config = self.load()
        keys = key.split(".")

        current = config
        for k in keys:
            if isinstance(current, dict) and k in current:
                current = current[k]
            else:
                return default

        return current

    def get_rules_enabled(self) -> List[str]:
        """Get list of enabled rules/packages."""
        return self.get("rules.enabled", ["safe"])

    def get_exclude_patterns(self) -> List[str]:
        """Get list of exclude patterns."""
        return self.get("exclude", [])

    def get_severity_threshold(self) -> str:
        """Get severity threshold."""
        return self.get("severity_threshold", "info")


# Global config loader instance
_global_loader: Optional[ConfigLoader] = None


def get_config_loader() -> ConfigLoader:
    """Get the global config loader instance.

    Returns:
        ConfigLoader instance
    """
    global _global_loader
    if _global_loader is None:
        _global_loader = ConfigLoader()
    return _global_loader


def load_config(config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Load configuration from all sources.

    Args:
        config_path: Optional path to config file

    Returns:
        Merged configuration dictionary
    """
    loader = ConfigLoader(config_path)
    return loader.load()


def get_config(key: str, default: Any = None) -> Any:
    """Get a configuration value.

    Args:
        key: Dot-separated key path (e.g., "security.fail_on")
        default: Default value if key not found

    Returns:
        Configuration value or default
    """
    return get_config_loader().get(key, default)
