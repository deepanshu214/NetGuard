"""
Base interface for NetGuard intrusion detection rules.
"""
from abc import ABC, abstractmethod
from typing import List, Optional

from netguard.models import PacketEvent, Alert


class BaseDetector(ABC):
    """
    Abstract base detector class.
    Detectors implement `on_packet(event, now)` with an optional timestamp parameter
    for deterministic unit testing and PCAP replay without system clock skew.
    """

    def __init__(self, name: str, enabled: bool = True):
        self.name = name
        self.enabled = enabled

    @abstractmethod
    def on_packet(self, event: PacketEvent, now: Optional[float] = None) -> List[Alert]:
        """
        Process a decoded packet event and return any triggered alerts.

        Args:
            event: The parsed PacketEvent.
            now: Optional current timestamp override (useful for testing or replaying pcaps).
        """
        pass

    @abstractmethod
    def reset(self):
        """Clears all in-memory tracking state."""
        pass
