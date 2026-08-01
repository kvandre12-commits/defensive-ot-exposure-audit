"""CLI for the defensive OT exposure audit tool."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from ot_defense.core import (
    TargetParseError,
    parse_ports,
    parse_target_tokens,
    render_markdown,
    scan_tcp_exposure,
)

AUTH_TEXT = "I confirm I own/administer these targets or have written authorization."


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Authorized defensive TCP exposure audit for water/OT environments."
    )
    parser.add_argument(
        "--targets",
        action="append",
        default=[],
        help="Authorized IPv4 targets/CIDRs, comma or space separated. Repeatable.",
    )
    parser.add_argument(
        "--target-file",
        type=Path,
        help=(
            "File containing authorized IPv4 targets/CIDRs, "
            "one per line or comma separated."
        ),
    )
    parser.add_argument(
        "--ports",
        default="default",
        help="Comma-separated TCP ports, or 'default' for risky OT ports.",
    )
    parser.add_argument(
        "--timeout", type=float, default=0.6, help="TCP connect timeout in seconds."
    )
    parser.add_argument(
        "--workers", type=int, default=64, help="Maximum concurrent TCP checks."
    )
    parser.add_argument(
        "--max-hosts", type=int, default=256, help="Safety cap for expanded targets."
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("outputs/ot_defense"),
        help="Directory for JSON and Markdown reports.",
    )
    parser.add_argument(
        "--i-am-authorized",
        action="store_true",
        help=AUTH_TEXT,
    )
    parser.add_argument(
        "--scan",
        action="store_true",
        help="Actually perform TCP connect checks. Without this, only prints the plan.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.i_am_authorized:
        parser.error(
            "Refusing to proceed without --i-am-authorized. Keep the puppy legal."
        )

    try:
        raw_targets = collect_raw_targets(args.targets, args.target_file)
        hosts = parse_target_tokens(raw_targets, max_hosts=args.max_hosts)
        ports = parse_ports(args.ports)
    except (OSError, TargetParseError, ValueError) as exc:
        parser.error(str(exc))

    if not args.scan:
        print_plan(hosts, ports, args.output_dir)
        return 0

    report = scan_tcp_exposure(
        hosts,
        ports,
        timeout=args.timeout,
        workers=args.workers,
        authorized_scope_statement=AUTH_TEXT,
    )
    json_path, md_path = write_reports(report, args.output_dir)
    print(f"Wrote JSON report: {json_path}")
    print(f"Wrote Markdown report: {md_path}")
    print(f"Findings: {len(report.findings)}")
    return 1 if report.findings else 0


def collect_raw_targets(cli_targets: list[str], target_file: Path | None) -> list[str]:
    raw_targets = list(cli_targets)
    if target_file is not None:
        raw_targets.append(target_file.read_text(encoding="utf-8"))
    return raw_targets


def print_plan(hosts: list[str], ports: list[int], output_dir: Path) -> None:
    print("Defensive OT exposure audit plan")
    print(f"Hosts: {len(hosts)}")
    print(f"TCP ports: {', '.join(map(str, ports))}")
    print(f"Output directory: {output_dir}")
    print("Dry run only. Add --scan to perform TCP connect checks.")


def write_reports(report, output_dir: Path) -> tuple[Path, Path]:
    output_dir.mkdir(parents=True, exist_ok=True)
    stamp = report.generated_at.replace(":", "").replace("+", "Z").split(".")[0]
    json_path = output_dir / f"ot_exposure_audit_{stamp}.json"
    md_path = output_dir / f"ot_exposure_audit_{stamp}.md"
    json_path.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    md_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, md_path


if __name__ == "__main__":
    sys.exit(main())
