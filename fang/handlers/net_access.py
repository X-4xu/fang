"""
Extension point interface for integration with net-access-controller.

Design Note:
In accordance with the defensive security specifications for v1.0, this module
provides a clean integration interface and canonical payload generator for
net-access-controller without executing any active blocking operations.
"""

from __future__ import annotations

import ipaddress
import logging
from typing import Any

from fang.handlers.base import ActionHandler
from fang.models import SecurityAlert

logger = logging.getLogger(__name__)

# Default safety whitelist of IP addresses that should NEVER be blocked
DEFAULT_SAFETY_WHITELIST = {
    "127.0.0.1",
    "::1",
    "localhost",
}


class NetAccessControllerHook(ActionHandler):
    """
    Extension point for automated IP blocking integration with net-access-controller.

    Future versions can connect this hook to a local daemon (via Unix domain socket
    or HTTP API) or invoke net-access-controller CLI commands.

    In v1.0, active blocking is intentionally disabled. When invoked, it builds
    and validates the standardized blocking payload in DRY-RUN mode.
    """

    def __init__(
        self,
        enabled: bool = False,
        dry_run: bool = True,
        endpoint: str | None = None,
        whitelist: set[str] | None = None,
    ) -> None:
        self.enabled = enabled
        self.dry_run = dry_run
        self.endpoint = endpoint
        self.whitelist = set(whitelist) if whitelist else set(DEFAULT_SAFETY_WHITELIST)

    def handle_alert(self, alert: SecurityAlert) -> None:
        """
        Handle alert by constructing payload and checking safety constraints.
        Does not execute blocking in v1.0.
        """
        if not self.enabled:
            logger.debug(
                "NetAccessControllerHook is disabled. Skipping IP block evaluation for %s",
                alert.source_ip,
            )
            return

        if self.is_whitelisted(alert.source_ip):
            logger.warning(
                "Refusing to dispatch block action for whitelisted IP: %s", alert.source_ip
            )
            return

        payload = self.build_block_payload(alert)
        self.dispatch_block(payload)

    def build_block_payload(self, alert: SecurityAlert) -> dict[str, Any]:
        """
        Generate the canonical structured JSON payload expected by net-access-controller.
        """
        return {
            "schema_version": "1.0",
            "action": "BLOCK_IP",
            "target_ip": alert.source_ip,
            "reason": alert.pattern,
            "severity": alert.severity.value,
            "evidence": {
                "alert_id": alert.alert_id,
                "failed_attempts": alert.failed_attempts_count,
                "time_window_seconds": alert.window_seconds,
                "start_time": alert.start_time.isoformat(),
                "end_time": alert.end_time.isoformat(),
                "targeted_usernames": alert.target_usernames,
            },
            "suggested_duration_seconds": self._calculate_block_duration(alert),
            "triggered_by": "fang",
        }

    def dispatch_block(self, payload: dict[str, Any]) -> dict[str, Any]:
        """
        Dispatch block payload to net-access-controller.

        In v1.0, this returns a DRY-RUN confirmation.
        A future release will transmit the payload over the configured transport
        (e.g., REST API / Unix Domain Socket / IPC).
        """
        target_ip = payload.get("target_ip")
        logger.info(
            "[EXTENSION POINT] net-access-controller hook triggered for %s (Dry-run: %s)",
            target_ip,
            self.dry_run,
        )

        return {
            "status": "dry_run",
            "message": (
                "Fang: net-access-controller integration hook invoked in dry-run mode. "
                "Automatic blocking is not active in v1.0.0."
            ),
            "payload": payload,
        }

    def is_whitelisted(self, ip_str: str) -> bool:
        """Check if target IP belongs to safety whitelist or loopback."""
        if ip_str in self.whitelist:
            return True
        try:
            addr = ipaddress.ip_address(ip_str)
            if addr.is_loopback or addr.is_unspecified:
                return True
        except ValueError:
            return True  # If invalid IP, treat as unsafe to block
        return False

    @staticmethod
    def _calculate_block_duration(alert: SecurityAlert) -> int:
        """Recommend block duration based on severity (in seconds)."""
        match alert.severity.value:
            case "critical":
                return 86400  # 24 hours
            case "high":
                return 14400  # 4 hours
            case "medium":
                return 3600  # 1 hour
            case _:
                return 1800  # 30 minutes
