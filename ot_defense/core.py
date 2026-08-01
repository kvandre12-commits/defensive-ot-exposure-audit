"""Safe defensive scanner for owned OT exposure audits.

The scanner performs TCP connect checks only. It does not authenticate, send
protocol payloads, fuzz, exploit, or grab banners. Its job is to answer a boring
but important question: "are risky control/remote-access ports reachable?"
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from datetime import UTC, datetime


class TargetParseError(ValueError):
    """Raised when targets are invalid or too broad for safe default use."""


@dataclass(frozen=True)
class ServiceRisk:
    port: int
    name: str
    severity: str
    rationale: str
    remediation: str


@dataclass(frozen=True)
class ScanFinding:
    host: str
    port: int
    service: str
    severity: str
    rationale: str
    remediation: str


@dataclass(frozen=True)
class ScanReport:
    generated_at: str
    authorized_scope_statement: str
    scanner_mode: str
    scanned_hosts: list[str]
    scanned_ports: list[int]
    findings: list[ScanFinding]

    def to_dict(self) -> dict:
        data = asdict(self)
        data["finding_count"] = len(self.findings)
        data["highest_severity"] = highest_severity(self.findings)
        return data


TCP_RISKS: dict[int, ServiceRisk] = {
    21: ServiceRisk(
        21,
        "FTP",
        "medium",
        "Cleartext file transfer can expose configs or credentials.",
        "Disable internet exposure; prefer VPN-only SFTP/SSH with MFA.",
    ),
    22: ServiceRisk(
        22,
        "SSH",
        "medium",
        "Remote shell access must be tightly scoped and monitored.",
        "Restrict to VPN/jump host, enforce MFA/key auth, disable passwords.",
    ),
    23: ServiceRisk(
        23,
        "Telnet",
        "critical",
        "Telnet is cleartext remote administration. Block it from public networks.",
        "Disable Telnet immediately; replace with VPN-restricted SSH if required.",
    ),
    80: ServiceRisk(
        80,
        "HTTP admin/HMI",
        "high",
        "Unauthenticated or weak web HMIs are common control-system entry points.",
        "Move behind VPN/jump host, require MFA, and validate firmware/auth settings.",
    ),
    443: ServiceRisk(
        443,
        "HTTPS admin/HMI",
        "medium",
        "Encrypted admin surfaces still carry risk when internet reachable.",
        "Restrict to VPN/jump host, enforce MFA, patch, and log access.",
    ),
    502: ServiceRisk(
        502,
        "Modbus/TCP",
        "critical",
        "Modbus commonly lacks authentication and can expose process control.",
        "Block from internet; allow only required OT hosts through firewall rules.",
    ),
    3389: ServiceRisk(
        3389,
        "RDP",
        "high",
        "Exposed remote desktop is routinely abused for initial access.",
        "Disable public RDP; require VPN, MFA, lockouts, and patching.",
    ),
    44818: ServiceRisk(
        44818,
        "EtherNet/IP",
        "critical",
        "Industrial protocol exposure can reveal or affect PLC/control assets.",
        "Block from internet and segment behind OT firewalls.",
    ),
    5900: ServiceRisk(
        5900,
        "VNC",
        "high",
        "Exposed remote screens often rely on weak passwords and no MFA.",
        "Disable public VNC; use VPN/jump host with MFA and session recording.",
    ),
    8080: ServiceRisk(
        8080,
        "Alternate web admin/HMI",
        "high",
        "Alternate web ports frequently host admin panels or HMIs.",
        "Restrict to VPN/jump host and verify strong authentication.",
    ),
    20256: ServiceRisk(
        20256,
        "Unitronics PLC programming",
        "critical",
        "Unitronics PLC exposure has been targeted in water-sector incidents.",
        "Remove internet exposure, rotate PLC passwords, patch, and verify backups.",
    ),
}

DEFAULT_TCP_PORTS = tuple(sorted(TCP_RISKS))
SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def parse_target_tokens(raw_targets: Iterable[str], max_hosts: int = 256) -> list[str]:
    """Parse IP/CIDR target tokens into a de-duplicated IPv4 host list."""
    hosts: set[ipaddress.IPv4Address] = set()
    tokens = _split_tokens(raw_targets)
    if not tokens:
        raise TargetParseError("No targets supplied.")

    for token in tokens:
        try:
            if "/" in token:
                network = ipaddress.ip_network(token, strict=False)
                if network.version != 4:
                    raise TargetParseError(f"IPv6 target is not supported: {token}")
                if network.num_addresses > max_hosts:
                    raise TargetParseError(
                        f"Target {token} has {network.num_addresses} addresses; "
                        f"max-hosts is {max_hosts}. Narrow scope or raise the limit."
                    )
                iterable = network.hosts() if network.num_addresses > 2 else network
                hosts.update(ipaddress.IPv4Address(host) for host in iterable)
            else:
                address = ipaddress.ip_address(token)
                if address.version != 4:
                    raise TargetParseError(f"IPv6 target is not supported: {token}")
                hosts.add(ipaddress.IPv4Address(address))
        except TargetParseError:
            raise
        except ValueError as exc:
            raise TargetParseError(f"Invalid target token: {token}") from exc

    if len(hosts) > max_hosts:
        raise TargetParseError(
            f"Expanded target set has {len(hosts)} hosts; max-hosts is {max_hosts}."
        )
    return [str(host) for host in sorted(hosts, key=int)]


def parse_ports(value: str | None) -> list[int]:
    """Parse a comma-separated TCP port list, or return defensive defaults."""
    if not value or value.strip().lower() in {"default", "critical"}:
        return list(DEFAULT_TCP_PORTS)

    ports: set[int] = set()
    for token in value.replace("\n", ",").split(","):
        stripped = token.strip()
        if not stripped:
            continue
        port = int(stripped)
        if not 1 <= port <= 65535:
            raise ValueError(f"Invalid TCP port: {port}")
        ports.add(port)
    if not ports:
        raise ValueError("No ports supplied.")
    return sorted(ports)


def scan_tcp_exposure(
    hosts: list[str],
    ports: list[int],
    *,
    timeout: float = 0.6,
    workers: int = 64,
    authorized_scope_statement: str = "Operator confirmed authorization.",
) -> ScanReport:
    """Run TCP connect checks and return a structured report."""
    if not hosts:
        raise ValueError("hosts cannot be empty")
    if not ports:
        raise ValueError("ports cannot be empty")

    capped_workers = max(1, min(workers, len(hosts) * len(ports), 128))
    findings: list[ScanFinding] = []
    with ThreadPoolExecutor(max_workers=capped_workers) as executor:
        future_map = {
            executor.submit(_is_tcp_open, host, port, timeout): (host, port)
            for host in hosts
            for port in ports
        }
        for future in as_completed(future_map):
            host, port = future_map[future]
            if future.result():
                risk = TCP_RISKS.get(
                    port,
                    ServiceRisk(
                        port,
                        f"TCP/{port}",
                        "medium",
                        "Unexpected open TCP service in an OT audit scope.",
                        "Confirm business need; restrict exposure to approved paths.",
                    ),
                )
                findings.append(
                    ScanFinding(
                        host=host,
                        port=port,
                        service=risk.name,
                        severity=risk.severity,
                        rationale=risk.rationale,
                        remediation=risk.remediation,
                    )
                )

    findings.sort(key=lambda item: (item.host, item.port))
    return ScanReport(
        generated_at=datetime.now(UTC).isoformat(),
        authorized_scope_statement=authorized_scope_statement,
        scanner_mode="tcp-connect-only-no-payloads",
        scanned_hosts=hosts,
        scanned_ports=ports,
        findings=findings,
    )


def render_markdown(report: ScanReport) -> str:
    """Render a human-readable remediation report."""
    data = report.to_dict()
    lines = [
        "# Defensive OT Exposure Audit",
        "",
        f"Generated: `{report.generated_at}`",
        f"Mode: `{report.scanner_mode}`",
        f"Authorization: {report.authorized_scope_statement}",
        f"Scanned hosts: `{len(report.scanned_hosts)}`",
        f"Scanned TCP ports: `{', '.join(map(str, report.scanned_ports))}`",
        f"Findings: `{data['finding_count']}`",
        f"Highest severity: `{data['highest_severity']}`",
        "",
        "## Immediate containment checklist",
        "",
        "- Remove PLC/HMI/admin interfaces from direct internet exposure.",
        "- Require VPN + MFA + named accounts for remote access.",
        "- Rotate PLC, HMI, VPN, vendor, and Windows credentials.",
        "- Confirm current controller logic against known-good backups.",
        "- Preserve logs/configs and coordinate with CISA/FBI/EPA/WaterISAC "
        "if incident indicators exist.",
        "",
    ]

    if not report.findings:
        lines.extend(
            [
                "## Findings",
                "",
                "No open risky TCP services were observed from this scan point.",
                "That does **not** prove the environment is secure; it only means "
                "these ports did not answer here.",
                "",
            ]
        )
        return "\n".join(lines)

    lines.extend(
        [
            "## Findings",
            "",
            "| Host | Port | Service | Severity | Remediation |",
            "| --- | ---: | --- | --- | --- |",
        ]
    )
    for finding in report.findings:
        lines.append(
            "| "
            f"{finding.host} | {finding.port} | {finding.service} | "
            f"{finding.severity} | {finding.remediation} |"
        )

    lines.extend(["", "## Why these ports matter", ""])
    for finding in report.findings:
        lines.append(
            f"- `{finding.host}:{finding.port}` **{finding.service}**: "
            f"{finding.rationale}"
        )
    lines.append("")
    return "\n".join(lines)


def highest_severity(findings: Iterable[ScanFinding]) -> str:
    """Return the highest severity label present in findings."""
    highest = "none"
    highest_score = 0
    for finding in findings:
        score = SEVERITY_ORDER.get(finding.severity, 0)
        if score > highest_score:
            highest = finding.severity
            highest_score = score
    return highest


def _split_tokens(raw_targets: Iterable[str]) -> list[str]:
    tokens: list[str] = []
    for raw in raw_targets:
        normalized = raw.replace("\n", ",").replace(" ", ",")
        tokens.extend(token.strip() for token in normalized.split(",") if token.strip())
    return tokens


def _is_tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False
