# Defensive OT Exposure Audit

Authorized-only TCP exposure checker for water, wastewater, and OT defensive audits.

This project exists because many water-sector incidents are not movie-hacker magic.
They often involve internet-reachable PLC/HMI/admin/remote-access services, weak or
default credentials, and poor network segmentation. This tool helps operators ask
one boring but important question:

> Are risky OT/admin ports reachable from this scan point?

## What is a PLC?

A PLC, or Programmable Logic Controller, is a small industrial computer that can
control physical equipment such as pumps, valves, tanks, chemical dosing, pressure
systems, mixers, and alarms.

If PLC programming access, an HMI, or a remote admin surface is reachable from the
public internet, an attacker may be able to disrupt operations or attempt unsafe
control changes. That is exactly the kind of clown-shoes risk this tool is meant
to find early.

## What this tool does

It checks authorized IPv4 targets for risky exposed TCP services and writes
remediation-focused JSON and Markdown reports.

Default watched TCP services:

| Port | Service | Why it matters |
| ---: | --- | --- |
| 20256 | Unitronics PLC programming | Public reporting has tied exposed Unitronics PLC access to water-sector targeting. |
| 502 | Modbus/TCP | Common industrial protocol; often lacks authentication. |
| 44818 | EtherNet/IP | Industrial protocol exposure can reveal or affect PLC/control assets. |
| 3389 | RDP | Exposed remote desktop is routinely abused. |
| 5900 | VNC | Exposed remote screens often rely on weak passwords and no MFA. |
| 23 | Telnet | Cleartext remote administration. Nope. |
| 80/443/8080 | Web HMI/admin | Common control/admin surfaces. |
| 21/22 | FTP/SSH | Remote file/shell access must be tightly scoped. |

## What this tool does **not** do

It does not:

- exploit vulnerabilities
- attempt authentication
- brute-force credentials
- fuzz protocols
- send PLC/control commands
- alter systems
- grab banners

It performs TCP connect checks only. Tiny cyber broom, not felony crowbar.

## Install / run from source

```bash
git clone https://github.com/kvandre12-commits/defensive-ot-exposure-audit.git
cd defensive-ot-exposure-audit
python -m venv .venv
. .venv/bin/activate
pip install -e .
```

Dry-run plan:

```bash
ot-defense-audit \
  --targets 192.0.2.10 \
  --i-am-authorized
```

Run TCP connect checks against an authorized scope:

```bash
ot-defense-audit \
  --targets 192.0.2.0/29 \
  --i-am-authorized \
  --scan
```

Use a target file:

```bash
ot-defense-audit \
  --target-file authorized_targets.txt \
  --i-am-authorized \
  --scan
```

Reports are written to `outputs/ot_defense/` by default.

## Safety rails

- Requires `--i-am-authorized`.
- Dry-run by default.
- Requires `--scan` before network checks.
- Defaults to max 256 expanded hosts.
- IPv4 only in this version. YAGNI is a law, not a suggestion.

## Immediate remediation guidance

If a risky OT/admin port is reachable from the public internet:

1. Remove direct internet exposure.
2. Require VPN + MFA + named accounts.
3. Segment IT and OT networks.
4. Rotate PLC/HMI/VPN/vendor credentials.
5. Validate controller logic against known-good backups.
6. Preserve logs.
7. Coordinate with CISA, EPA, WaterISAC, FBI, and state cyber teams if compromise is suspected.

## Responsible use

Use only against networks you own, administer, or have written authorization to
assess. If you do not have permission, do not scan. The water people have enough
problems without random internet cowboys making noise.

## Development

```bash
pip install -e '.[dev]'
ruff check .
ruff format .
pytest
```
