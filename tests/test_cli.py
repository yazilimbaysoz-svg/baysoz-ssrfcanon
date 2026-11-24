# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""CLI integration tests — Baysöz Labs <baysozlabs@proton.me>."""

from __future__ import annotations

import json

import pytest

from baysoz_ssrfcanon.cli import main


def test_version_lists_attribution(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert "Baysöz Labs <baysozlabs@proton.me>" in capsys.readouterr().out


def test_help_lists_attribution(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--help"])
    assert exc.value.code == 0
    assert "Baysöz Labs <baysozlabs@proton.me>" in capsys.readouterr().out


def test_scan_text_finding(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "http://0177.0.0.1/"])
    output = capsys.readouterr().out
    assert code == 1
    assert "SSRF-CANON-001" in output
    assert "Baysöz Labs" in output


def test_scan_sarif_json(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["scan", "--format", "sarif", "http://2130706433/"])
    report = json.loads(capsys.readouterr().out)
    assert code == 1
    assert report["version"] == "2.1.0"
    assert report["properties"]["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"


def test_scan_clean_url(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "https://example.com/"]) == 0
    assert "No SSRF divergences" in capsys.readouterr().out


def test_scan_chain(capsys: pytest.CaptureFixture[str], tmp_path: object) -> None:
    from pathlib import Path

    config = Path(str(tmp_path)) / "guard.toml"
    config.write_text('[guard]\nname = "chain"\nfollow_redirects = true\n', encoding="utf-8")
    code = main(
        [
            "scan",
            "--policy",
            str(config),
            "--chain",
            "https://trusted.example.com/",
            "http://127.0.0.1/admin",
        ],
    )
    assert code == 1
    assert "SSRF-CANON-004" in capsys.readouterr().out


def test_scan_rejects_mixed_inputs(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["scan", "https://example.com", "--chain", "https://example.com"]) == 2
    assert "not both" in capsys.readouterr().err


def test_forge_json(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["forge", "--format", "json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["cases"]) == 14
    assert payload["attribution"] == "Baysöz Labs <baysozlabs@proton.me>"


def test_explain(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["explain", "http://2130706433/"]) == 0
    output = capsys.readouterr().out
    assert "whatwg" in output and "python-313" in output
    assert "Baysöz Labs" in output


def test_selftest(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["selftest"]) == 0
    assert "UNANIMOUS PASS" in capsys.readouterr().out


def test_bad_policy_reports_error(capsys: pytest.CaptureFixture[str], tmp_path: object) -> None:
    from pathlib import Path

    config = Path(str(tmp_path)) / "bad.toml"
    config.write_text('[guard]\nprofile = "nope"\n', encoding="utf-8")
    assert main(["scan", "--policy", str(config), "https://example.com"]) == 2
    assert "unknown guard profile" in capsys.readouterr().err
