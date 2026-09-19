"""
Integration tests for CLI functionality.
"""

from __future__ import annotations

import json
from pathlib import Path

from fang.cli import main, run_analyzer


def test_run_analyzer_classic_fixture(classic_log_path: Path, tmp_path: Path) -> None:
    output_json = tmp_path / "classic_report.json"
    summary, alerts = run_analyzer(
        log_file=str(classic_log_path),
        threshold=5,
        window=60,
        output_path=str(output_json),
        quiet=True,
    )

    assert summary.total_lines_read == 11
    assert summary.total_events_parsed >= 8
    assert summary.failed_attempts_count >= 7
    assert len(alerts) == 1

    alert = alerts[0]
    assert alert.source_ip == "192.168.1.100"
    assert alert.failed_attempts_count >= 5
    assert output_json.exists()

    with open(output_json, "r", encoding="utf-8") as f:
        report = json.load(f)
    assert report["alerts_count"] == 1
    assert report["alerts"][0]["source_ip"] == "192.168.1.100"


def test_run_analyzer_rfc3339_fixture(rfc3339_log_path: Path) -> None:
    summary, alerts = run_analyzer(
        log_file=str(rfc3339_log_path),
        threshold=5,
        window=60,
        quiet=True,
    )

    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.source_ip == "203.0.113.42"
    assert "root" in alert.target_usernames
    assert alert.severity.value in ("high", "critical")


def test_cli_main_success(classic_log_path: Path, tmp_path: Path) -> None:
    output_json = tmp_path / "cli_out.json"
    exit_code = main([
        "--log-file", str(classic_log_path),
        "--threshold", "5",
        "--window", "60",
        "--output", str(output_json),
        "--quiet",
    ])
    assert exit_code == 0
    assert output_json.exists()


def test_cli_main_exit_code_on_alert(classic_log_path: Path) -> None:
    exit_code = main([
        "--log-file", str(classic_log_path),
        "--threshold", "5",
        "--window", "60",
        "--exit-code-on-alert",
        "--quiet",
    ])
    # Expect exit code 2 because an alert was detected
    assert exit_code == 2


def test_cli_main_file_not_found() -> None:
    exit_code = main(["--log-file", "non_existent_file_xyz.log"])
    assert exit_code == 1
