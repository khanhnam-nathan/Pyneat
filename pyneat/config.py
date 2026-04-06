"""Configuration management for PyNeat.

Supports:
- pyproject.toml section [tool.pyneat]
- .pyneat.toml file
- pyneat.toml file
- Environment variables: PYNEAT_*
"""

import os
import sys
from typing import Dict, Any, Optional
from pathlib import Path


class PyNeatConfig:
    """Configuration manager for PyNeat."""

    DEFAULT_CONFIG = {
        'enabled_rules': [
            'imports', 'naming', 'refactoring', 'debug', 'comments'
        ],
        'optional_rules': {
            'security': False,
            'quality': False,
            'performance': False,
            'unused_imports': False,
            'redundant': False,
            'is_not_none': False,
            'magic_numbers': False,
            'fstring': False,
            'typing': False,
        },
        'debug_mode': 'safe',
        'auto_fix': False,
        'skip_directories': [
            '__pycache__', '.venv', 'venv', '.git', 'node_modules',
            '.pytest_cache', '.egg-info', '.mypy_cache', '.ruff_cache'
        ],
        'file_patterns': ['*.py'],
    }

    def __init__(self, config_path: Optional[Path] = None):
        self._config = self.DEFAULT_CONFIG.copy()
        self._load_config(config_path)

    def _load_config(self, config_path: Optional[Path] = None) -> None:
        """Load configuration from various sources."""
        # Priority: explicit path > .pyneat.toml > pyneat.toml > pyproject.toml > env

        # 1. Explicit config file
        if config_path and config_path.exists():
            self._load_from_file(config_path)
            return

        # 2. .pyneat.toml in current directory
        pyneat_toml = Path.cwd() / '.pyneat.toml'
        if pyneat_toml.exists():
            self._load_from_file(pyneat_toml)
            return

        # 3. pyneat.toml in current directory
        pyneat_config = Path.cwd() / 'pyneat.toml'
        if pyneat_config.exists():
            self._load_from_file(pyneat_config)
            return

        # 4. pyproject.toml section [tool.pyneat]
        pyproject = Path.cwd() / 'pyproject.toml'
        if pyproject.exists():
            self._load_from_pyproject(pyproject)
            return

        # 5. Environment variables
        self._load_from_env()

    def _load_from_file(self, path: Path) -> None:
        """Load config from TOML file."""
        try:
            import tomllib
            with open(path, 'rb') as f:
                data = tomllib.load(f)
                self._apply_dict(data)
        except Exception as e:
            print(f"Warning: Failed to load config from {path}: {e}")

    def _load_from_pyproject(self, path: Path) -> None:
        """Load config from pyproject.toml [tool.pyneat] section."""
        try:
            if sys.version_info >= (3, 11):
                import tomllib
                with open(path, 'rb') as f:
                    data = tomllib.load(f)
                    pyneat_config = data.get('tool', {}).get('pyneat', {})
                    self._apply_dict(pyneat_config)
            else:
                # For Python < 3.11, use tomli or toml
                try:
                    import tomli
                except ImportError:
                    try:
                        import toml as tomli
                    except ImportError:
                        return

                with open(path, 'rb') as f:
                    data = tomli.load(f)
                    pyneat_config = data.get('tool', {}).get('pyneat', {})
                    self._apply_dict(pyneat_config)
        except Exception as e:
            print(f"Warning: Failed to load pyproject.toml config: {e}")

    def _load_from_env(self) -> None:
        """Load config from environment variables."""
        prefix = 'PYNEAT_'

        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()

                # Parse boolean values
                if value.lower() in ('true', '1', 'yes', 'on'):
                    value = True
                elif value.lower() in ('false', '0', 'no', 'off'):
                    value = False

                self._config[config_key] = value

    def _apply_dict(self, data: Dict[str, Any]) -> None:
        """Apply configuration dictionary to internal config."""
        if 'enabled_rules' in data:
            self._config['enabled_rules'] = data['enabled_rules']

        if 'optional_rules' in data:
            for key, value in data['optional_rules'].items():
                if key in self._config['optional_rules']:
                    self._config['optional_rules'][key] = value

        if 'debug_mode' in data:
            self._config['debug_mode'] = data['debug_mode']

        if 'auto_fix' in data:
            self._config['auto_fix'] = data['auto_fix']

        if 'skip_directories' in data:
            self._config['skip_directories'] = data['skip_directories']

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value."""
        return self._config.get(key, default)

    def is_rule_enabled(self, rule: str) -> bool:
        """Check if a rule is enabled."""
        if rule in self._config.get('enabled_rules', []):
            return True

        # Check optional rules
        optional_key = f'{rule}_enabled'
        return self._config.get('optional_rules', {}).get(rule, False)

    def to_dict(self) -> Dict[str, Any]:
        """Return configuration as dictionary."""
        return self._config.copy()


# Global config instance
_config: Optional[PyNeatConfig] = None


def get_config() -> PyNeatConfig:
    """Get global configuration instance."""
    global _config
    if _config is None:
        _config = PyNeatConfig()
    return _config


def reload_config(config_path: Optional[Path] = None) -> PyNeatConfig:
    """Reload configuration from file."""
    global _config
    _config = PyNeatConfig(config_path)
    return _config