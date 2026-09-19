"""
Abstract base class for alert action handlers.
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from fang.models import SecurityAlert


class ActionHandler(ABC):
    """Base interface for security alert handling and response dispatchers."""

    @abstractmethod
    def handle_alert(self, alert: SecurityAlert) -> None:
        """
        Process or dispatch a detected security alert.
        Implementations must handle exceptions internally to prevent disruption
        to the log analysis pipeline.
        """
        raise NotImplementedError
