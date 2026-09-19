"""
Fang - Fast, secure, and extensible SSH log analyzer and brute-force detection engine.
"""

__version__ = "1.0.0"
__author__ = "Security Automation Engineering Team"

from fang.models import (
    AlertSeverity,
    EventType,
    SecurityAlert,
    SshAuthEvent,
)
from fang.parser import SshLogParser
from fang.detector import BruteForceDetector

__all__ = [
    "AlertSeverity",
    "EventType",
    "SecurityAlert",
    "SshAuthEvent",
    "SshLogParser",
    "BruteForceDetector",
]
