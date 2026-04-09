"""Naming convention utilities shared across rules.

Copyright (c) 2024-2026 PyNEAT Authors

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
"""

import re


def _is_pascal_case(name: str) -> bool:
    """Check if a name is in PascalCase."""
    if not name:
        return False
    if '_' in name:
        parts = name.split('_')
        return all(part and part[0].isupper() for part in parts if part)
    return name[0].isupper()


def _is_snake_case(name: str) -> bool:
    """Check if a name is in snake_case."""
    if not name:
        return False
    if name.startswith('_') or name.endswith('_'):
        return True
    if '_' in name:
        parts = name.split('_')
        return all(part.islower() or part.isdigit() for part in parts if part)
    return name.islower()


def _to_pascal_case(name: str) -> str:
    """Convert a name to PascalCase."""
    if not name:
        return name
    if '_' in name:
        parts = name.split('_')
        return ''.join(part.capitalize() for part in parts if part)
    if name and not name[0].isupper():
        return name[0].upper() + name[1:]
    return name


def _to_snake_case(name: str) -> str:
    """Convert a name to snake_case."""
    if not name:
        return name
    # Insert underscores before uppercase letters, then lowercase all
    result = []
    for i, char in enumerate(name):
        if char.isupper() and i > 0:
            result.append('_')
        result.append(char.lower())
    return ''.join(result)
