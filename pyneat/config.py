"""Configuration management for PyNeat.

Copyright (c) 2026 PyNEAT Authors

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

For commercial licensing, contact: license@pyneat.dev

Supports:
- pyproject.toml section [tool.pyneat]
- .pyneat.toml file
- pyneat.toml file
- Environment variables: PYNEAT_*
"""

import os
import sys
from dataclasses import dataclass
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
        # Rust scanner integration
        'use_rust_scanner': 'auto',  # auto, true, false
        'rust_timeout_ms': 5000,  # timeout for Rust subprocess
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


# --------------------------------------------------------------------------
# Ignore Manager
# --------------------------------------------------------------------------

@dataclass
class IgnoreEntryData:
    """Data for an ignore entry."""
    rule_id: str
    file: str
    line: Optional[int]
    reason: str
    created_by: str = "cli"


class IgnoreManager:
    """Manages per-instance and global rule ignores.

    Ignores are stored in pyproject.toml [tool.pyneat] section:
    - disabled_rules: Rules disabled globally
    - ignore_rules: Per-instance ignores (specific file+line)

    Usage:
        manager = IgnoreManager()
        if manager.should_ignore("SEC-001", Path("deploy.py"), 42):
            # Skip this finding
            pass
    """

    def __init__(self, config_path: Optional[Path] = None):
        self._config_path = config_path
        self._per_instance: List[IgnoreEntryData] = []
        self._global_disabled: Dict[str, str] = {}
        self._load()

    def _find_config(self) -> Optional[Path]:
        """Find the nearest config file."""
        from pathlib import Path as P
        search = [P.cwd() / "pyproject.toml"]
        search.append(P.cwd() / ".pyneat.toml")
        search.append(P.cwd() / "pyneat.toml")
        for p in search:
            if p.exists():
                return p
        return None

    def _load(self) -> None:
        """Load ignore entries from config file."""
        config_path = self._config_path or self._find_config()
        if not config_path:
            return

        try:
            if sys.version_info >= (3, 11):
                import tomllib
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)
            else:
                try:
                    import tomli
                except ImportError:
                    import toml as tomli
                with open(config_path, "rb") as f:
                    data = tomli.load(f)

            pyneat = data.get("tool", {}).get("pyneat", {})

            # Load global disabled rules
            disabled = pyneat.get("disabled_rules", {})
            for rule_id, reason in disabled.items():
                self._global_disabled[rule_id] = reason

            # Load per-instance ignores
            ignores = pyneat.get("ignore_rules", [])
            for entry in ignores:
                if isinstance(entry, dict):
                    self._per_instance.append(IgnoreEntryData(
                        rule_id=entry.get("rule", ""),
                        file=entry.get("file", ""),
                        line=entry.get("line"),
                        reason=entry.get("reason", ""),
                        created_by=entry.get("created_by", "config"),
                    ))

        except Exception:
            pass

    def _save(self) -> None:
        """Save ignore entries to config file."""
        config_path = self._config_path or self._find_config()
        if not config_path:
            return

        try:
            # Read existing config
            if sys.version_info >= (3, 11):
                import tomllib
                with open(config_path, "rb") as f:
                    data = tomllib.load(f)
            else:
                try:
                    import tomli
                except ImportError:
                    import toml as tomli
                with open(config_path, "rb") as f:
                    data = tomli.load(f)

            if "tool" not in data:
                data["tool"] = {}
            if "pyneat" not in data["tool"]:
                data["tool"]["pyneat"] = {}

            # Write disabled rules
            data["tool"]["pyneat"]["disabled_rules"] = self._global_disabled

            # Write per-instance ignores
            ignore_list = [
                {
                    "rule": e.rule_id,
                    "file": e.file,
                    "line": e.line,
                    "reason": e.reason,
                    "created_by": e.created_by,
                }
                for e in self._per_instance
            ]
            data["tool"]["pyneat"]["ignore_rules"] = ignore_list

            # Write back
            with open(config_path, "w", encoding="utf-8") as f:
                import json
                # Convert to TOML manually (simple format)
                self._write_toml(f, data)

        except Exception:
            pass

    def _write_toml(self, f, data: Dict[str, Any], indent: int = 0) -> None:
        """Simple TOML writer for config."""
        prefix = "  " * indent
        for key, value in data.items():
            if isinstance(value, dict):
                f.write(f"{prefix}[tool.pyneat.{key}]\n" if indent == 0 and key == "pyneat" else f"{prefix}[{key}]\n")
                self._write_toml(f, value, indent + 1)
            elif isinstance(value, list):
                f.write(f"{prefix}[[tool.pyneat.ignore_rules]]\n" if key == "ignore_rules" else f"{prefix}{key} = []\n")
                for item in value:
                    if isinstance(item, dict):
                        for k, v in item.items():
                            f.write(f'{prefix}  {k} = {json.dumps(v)}\n')
            elif isinstance(value, str):
                f.write(f'{prefix}{key} = {json.dumps(value)}\n')
            elif isinstance(value, bool):
                f.write(f"{prefix}{key} = {'true' if value else 'false'}\n")
            elif isinstance(value, (int, float)):
                f.write(f"{prefix}{key} = {value}\n")

    def should_ignore(self, rule_id: str, file: Path, line: int) -> bool:
        """Check if a rule should be ignored at the given location.

        Args:
            rule_id: Rule ID (e.g. "SEC-001")
            file: File path
            line: Line number (1-indexed)

        Returns:
            True if the rule should be ignored.
        """
        # Check global disables
        if rule_id in self._global_disabled:
            return True

        # Check per-instance ignores
        file_str = str(file)
        for entry in self._per_instance:
            if entry.rule_id != rule_id:
                continue
            # Match file (exact or glob)
            if entry.file and entry.file != "*":
                import fnmatch
                if not fnmatch.fnmatch(file_str, entry.file) and file_str != entry.file:
                    continue
            # Match line
            if entry.line is not None and entry.line != line:
                continue
            return True

        return False

    def add_per_instance(self, rule_id: str, file: Path, line: int, reason: str) -> None:
        """Add a per-instance ignore entry."""
        # Check for duplicate
        for entry in self._per_instance:
            if entry.rule_id == rule_id and entry.file == str(file) and entry.line == line:
                entry.reason = reason
                self._save()
                return

        self._per_instance.append(IgnoreEntryData(
            rule_id=rule_id,
            file=str(file),
            line=line,
            reason=reason,
            created_by="cli",
        ))
        self._save()

    def add_global(self, rule_id: str, reason: str) -> None:
        """Add a global disable for a rule."""
        self._global_disabled[rule_id] = reason
        self._save()

    def remove_per_instance(self, rule_id: str, file: Optional[Path] = None, line: Optional[int] = None) -> bool:
        """Remove a per-instance ignore entry. Returns True if removed."""
        file_str = str(file) if file else None
        original_len = len(self._per_instance)
        self._per_instance = [
            e for e in self._per_instance
            if not (e.rule_id == rule_id
                    and (file_str is None or e.file == file_str or e.file == "*")
                    and (line is None or e.line == line))
        ]
        removed = len(self._per_instance) < original_len
        if removed:
            self._save()
        return removed

    def remove_global(self, rule_id: str) -> bool:
        """Remove a global disable. Returns True if removed."""
        if rule_id in self._global_disabled:
            del self._global_disabled[rule_id]
            self._save()
            return True
        return False

    def list_ignores(self) -> Dict[str, Any]:
        """List all ignore entries."""
        return {
            "global_disabled": dict(self._global_disabled),
            "per_instance": [
                {
                    "rule_id": e.rule_id,
                    "file": e.file,
                    "line": e.line,
                    "reason": e.reason,
                }
                for e in self._per_instance
            ],
        }