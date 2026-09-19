"""
Console action handler using Rich to print alerts in real-time.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from fang.handlers.base import ActionHandler
from fang.models import AlertSeverity, SecurityAlert


class ConsoleAlertHandler(ActionHandler):
    """Prints detected security alerts to the terminal with rich color coding."""

    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def handle_alert(self, alert: SecurityAlert) -> None:
        """Render alert panel to console."""
        color = self._severity_color(alert.severity)
        usernames = (
            ", ".join(alert.target_usernames) if alert.target_usernames else "unknown"
        )
        ports = (
            ", ".join(str(p) for p in alert.ports) if alert.ports else "standard (22)"
        )

        text = (
            f"[bold]Alert ID:[/bold] {alert.alert_id}\n"
            f"[bold]Source IP:[/bold] [underline]{alert.source_ip}[/underline]\n"
            f"[bold]Severity:[/bold] [{color}]{alert.severity.value.upper()}[/{color}]\n"
            f"[bold]Failed Attempts:[/bold] {alert.failed_attempts_count} (in {alert.window_seconds}s window)\n"
            f"[bold]Time Range:[/bold] {alert.start_time.strftime('%Y-%m-%d %H:%M:%S')} -> {alert.end_time.strftime('%H:%M:%S')}\n"
            f"[bold]Target Users:[/bold] {usernames}\n"
            f"[bold]Target Ports:[/bold] {ports}\n"
            f"[bold]Pattern:[/bold] {alert.pattern}"
        )

        panel = Panel(
            text,
            title=f"[{color} bold]FANG ALERT: SSH BRUTE-FORCE DETECTED[/{color} bold]",
            border_style=color,
            expand=False,
        )
        self.console.print(panel)

    @staticmethod
    def _severity_color(severity: AlertSeverity) -> str:
        match severity:
            case AlertSeverity.CRITICAL:
                return "red"
            case AlertSeverity.HIGH:
                return "bright_red"
            case AlertSeverity.MEDIUM:
                return "yellow"
            case AlertSeverity.LOW:
                return "cyan"
            case _:
                return "white"
