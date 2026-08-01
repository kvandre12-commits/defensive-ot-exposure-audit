from __future__ import annotations

import socket
import threading

import pytest

from ot_defense.core import (
    ScanFinding,
    ScanReport,
    TargetParseError,
    highest_severity,
    parse_ports,
    parse_target_tokens,
    render_markdown,
    scan_tcp_exposure,
)


def test_parse_target_tokens_supports_ip_and_small_cidr() -> None:
    hosts = parse_target_tokens(["192.0.2.1, 192.0.2.0/30"], max_hosts=8)

    assert hosts == ["192.0.2.1", "192.0.2.2"]


def test_parse_target_tokens_blocks_overbroad_scope() -> None:
    with pytest.raises(TargetParseError, match="max-hosts"):
        parse_target_tokens(["10.0.0.0/24"], max_hosts=8)


def test_parse_ports_defaults_and_custom_values() -> None:
    assert 20256 in parse_ports("default")
    assert parse_ports("502, 20256") == [502, 20256]


@pytest.mark.parametrize("bad", ["0", "65536"])
def test_parse_ports_rejects_invalid_values(bad: str) -> None:
    with pytest.raises(ValueError):
        parse_ports(bad)


def test_highest_severity_returns_none_without_findings() -> None:
    assert highest_severity([]) == "none"


def test_render_markdown_includes_unitronics_remediation() -> None:
    finding = ScanFinding(
        host="192.0.2.10",
        port=20256,
        service="Unitronics PLC programming",
        severity="critical",
        rationale="targeted in incidents",
        remediation="Remove internet exposure.",
    )
    report = ScanReport(
        generated_at="2026-01-01T00:00:00+00:00",
        authorized_scope_statement="authorized",
        scanner_mode="tcp-connect-only-no-payloads",
        scanned_hosts=["192.0.2.10"],
        scanned_ports=[20256],
        findings=[finding],
    )

    markdown = render_markdown(report)

    assert "Unitronics PLC programming" in markdown
    assert "Remove internet exposure" in markdown


def test_scan_tcp_exposure_finds_local_open_port() -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    stop = threading.Event()

    def accept_once() -> None:
        try:
            conn, _addr = server.accept()
            conn.close()
        finally:
            stop.set()
            server.close()

    thread = threading.Thread(target=accept_once, daemon=True)
    thread.start()

    report = scan_tcp_exposure(["127.0.0.1"], [port], timeout=1.0, workers=1)

    stop.wait(timeout=1.0)
    assert len(report.findings) == 1
    assert report.findings[0].host == "127.0.0.1"
    assert report.findings[0].port == port
