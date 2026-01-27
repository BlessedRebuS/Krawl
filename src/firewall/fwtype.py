from abc import ABC, abstractmethod
from typing import Dict, Type


class FWType(ABC):
    """Abstract base class for firewall types."""

    # Registry to store child classes
    _registry: Dict[str, Type['FWType']] = {}

    def __init_subclass__(cls, **kwargs):
        """Automatically register subclasses with their class name."""
        super().__init_subclass__(**kwargs)
        cls._registry[cls.__name__.lower()] = cls

    @classmethod
    def create(cls, fw_type: str, **kwargs) -> 'FWType':
        """
        Factory method to create instances of child classes.

        Args:
            fw_type: String name of the firewall type class to instantiate
            **kwargs: Arguments to pass to the child class constructor

        Returns:
            Instance of the requested child class

        Raises:
            ValueError: If fw_type is not registered
        """
        fw_type = fw_type.lower()
        if fw_type not in cls._registry:
            available = ', '.join(cls._registry.keys())
            raise ValueError(f"Unknown firewall type: '{fw_type}'. Available: {available}")

        return cls._registry[fw_type](**kwargs)

    @abstractmethod
    def getBanlist(self,ips):
        """Return the ruleset for the specific server"""
