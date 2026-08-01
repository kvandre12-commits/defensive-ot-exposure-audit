from __future__ import annotations

import pytest

from ot_defense import cli


def test_cli_refuses_without_authorization() -> None:
    with pytest.raises(SystemExit) as exc:
        cli.main(["--targets", "192.0.2.10"])

    assert exc.value.code == 2


def test_cli_dry_run_prints_plan(capsys: pytest.CaptureFixture[str]) -> None:
    exit_code = cli.main(["--targets", "192.0.2.10", "--i-am-authorized"])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Dry run only" in output
    assert "Hosts: 1" in output


def test_collect_raw_targets_reads_target_file(tmp_path) -> None:
    target_file = tmp_path / "targets.txt"
    target_file.write_text("192.0.2.10\n", encoding="utf-8")

    assert cli.collect_raw_targets(["192.0.2.11"], target_file) == [
        "192.0.2.11",
        "192.0.2.10\n",
    ]
