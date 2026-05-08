from abc import ABC, abstractmethod
from typing import List, Type, Dict, Any

class Plugin(ABC):
    """Base class for PyNEAT plugins."""

    name: str = "unnamed"
    version: str = "0.0.1"
    description: str = ""

    @abstractmethod
    def get_rules(self) -> List[Type["Rule"]]:
        """Return list of Rule classes this plugin provides."""
        ...

    def get_config_schema(self) -> Dict[str, Any]:
        """Return JSON schema for rule configuration validation. Override to provide custom schema."""
        return {}

    def on_load(self) -> None:
        """Lifecycle hook called when plugin loads."""
        pass

    def on_unload(self) -> None:
        """Lifecycle hook called when plugin unloads."""
        pass
