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

"""Configuration loader for PyNeat.

Supports loading configuration from:
- .pyneat.yaml in current directory
- .pyneat.yml in current directory
- pyproject.toml [tool.pyneat] section
- Environment variables (PYNEAT_*)
- Command-line arguments (passed to load_config)

Example .pyneat.yaml:
    rules:
      SEC-010:
        enabled: true
        params:
          min_entropy: 4.5
          skip_patterns: [".*_TEST.*", "MOCK_.*"]
          include_patterns: []
      SEC-076:
        enabled: true
        params:
          min_hash_bits: 256
      SEC-084:
        enabled: false
"""

import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Any, Optional, List

import yaml


# --------------------------------------------------------------------------
# Rule Configuration Spec
# --------------------------------------------------------------------------


@dataclass
class RuleConfigSpec:
    """Per-rule configuration from .pyneat.yaml.
    
    Attributes:
        rule_id: The rule identifier (e.g., "SEC-010", "QUAL-001")
        enabled: Whether the rule is enabled (default: True)
        params: Rule-specific parameters (e.g., min_entropy, skip_patterns)
    """
    rule_id: str
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "RuleConfigSpec":
        """Create a RuleConfigSpec from a dict."""
        return cls(
            rule_id=data.get("rule_id", data.get("id", "")),
            enabled=data.get("enabled", True),
            params=data.get("params", {}),
        )
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get a parameter value with a default."""
        return self.params.get(key, default)
    
    def get_float(self, key: str, default: float = 0.0) -> float:
        """Get a float parameter."""
        val = self.params.get(key)
        if val is None:
            return default
        try:
            return float(val)
        except (ValueError, TypeError):
            return default
    
    def get_int(self, key: str, default: int = 0) -> int:
        """Get an int parameter."""
        val = self.params.get(key)
        if val is None:
            return default
        try:
            return int(val)
        except (ValueError, TypeError):
            return default
    
    def get_list(self, key: str, default: Optional[List[str]] = None) -> List[str]:
        """Get a list of strings parameter."""
        val = self.params.get(key)
        if val is None:
            return default if default is not None else []
        if isinstance(val, list):
            return [str(v) for v in val]
        return default if default is not None else []


@dataclass
class PyneatConfig:
    """Full PyNEAT configuration loaded from .pyneat.yaml.
    
    Attributes:
        rules: List of per-rule configurations
        severity_threshold: Minimum severity to report
        exclude: Paths to exclude from scanning
        cache: Cache settings
    """
    rules: List[RuleConfigSpec] = field(default_factory=list)
    severity_threshold: str = "info"
    exclude: List[str] = field(default_factory=list)
    cache_enabled: bool = True
    
    @classmethod
    def from_yaml(cls, path: Path) -> "PyneatConfig":
        """Load PyneatConfig from a YAML file."""
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
        except Exception:
            return cls()
        
        raw_rules = data.get("rules", {})
        rule_specs = []
        if isinstance(raw_rules, dict):
            for rule_id, cfg in raw_rules.items():
                if isinstance(cfg, dict):
                    spec = RuleConfigSpec(
                        rule_id=rule_id,
                        enabled=cfg.get("enabled", True),
                        params=cfg.get("params", {}),
                    )
                else:
                    spec = RuleConfigSpec(rule_id=rule_id, enabled=bool(cfg))
                rule_specs.append(spec)
        elif isinstance(raw_rules, list):
            for item in raw_rules:
                if isinstance(item, dict):
                    rule_specs.append(RuleConfigSpec.from_dict(item))
        
        return cls(
            rules=rule_specs,
            severity_threshold=data.get("severity_threshold", "info"),
            exclude=data.get("exclude", []),
            cache_enabled=data.get("cache", {}).get("enabled", True),
        )
    
    def get_rule_config(self, rule_id: str) -> Optional[RuleConfigSpec]:
        """Get the configuration for a specific rule."""
        for spec in self.rules:
            if spec.rule_id == rule_id:
                return spec
        return None
    
    def is_enabled(self, rule_id: str) -> bool:
        """Check if a rule is enabled (default: True if not specified)."""
        cfg = self.get_rule_config(rule_id)
        return cfg.enabled if cfg else True
    
    def get_rule_params(self, rule_id: str) -> Dict[str, Any]:
        """Get the parameters for a specific rule (empty dict if not configured)."""
        cfg = self.get_rule_config(rule_id)
        return cfg.params if cfg else {}


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
                    return tomllib.load(f).get("tool", {}).get("pyneat", {})
            else:
                import tomli
                with open(path, "rb") as f:
                    return tomli.load(f).get("tool", {}).get("pyneat", {})
        except ImportError:
            raise
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


def get_rule_params(rule_id: str) -> Dict[str, Any]:
    """Get the configured parameters for a specific rule.

    Args:
        rule_id: The rule identifier (e.g., "SEC-010")

    Returns:
        Dictionary of parameters for the rule, or empty dict if not configured.
    """
    cfg = get_config_loader().load()
    rules = cfg.get("rules", {})
    if isinstance(rules, dict):
        rule_cfg = rules.get(rule_id, {})
        if isinstance(rule_cfg, dict):
            return rule_cfg.get("params", {})
        if isinstance(rule_cfg, bool):
            return {}
    return {}


def is_rule_enabled(rule_id: str) -> bool:
    """Check if a rule is enabled in the config.

    Args:
        rule_id: The rule identifier

    Returns:
        True if the rule is enabled (default) or not explicitly disabled.
    """
    cfg = get_config_loader().load()
    rules = cfg.get("rules", {})
    if isinstance(rules, dict):
        rule_cfg = rules.get(rule_id)
        if rule_cfg is None:
            return True
        if isinstance(rule_cfg, bool):
            return rule_cfg
        if isinstance(rule_cfg, dict):
            return rule_cfg.get("enabled", True)
    return True
