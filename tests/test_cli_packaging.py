"""CLI and packaging smoke tests."""

import json
import subprocess
import sys
from importlib.metadata import entry_points

import pytest

from app import __version__
from app.cli import build_parser, main


SCENARIO = "I can view another user's data"


def test_parser_analyze_json_flag():
    args = build_parser().parse_args(["analyze", "--json"])
    assert args.command == "analyze"
    assert args.json is True


def test_parser_analyze_default_is_human():
    args = build_parser().parse_args(["analyze"])
    assert args.command == "analyze"
    assert args.json is False


def test_cli_no_command_prints_help(capsys):
    code = main([])
    captured = capsys.readouterr()
    assert code == 0
    assert "analyze" in captured.out
    assert "usage:" in captured.out.lower() or "usage:" in captured.err.lower() or "Educational" in captured.out


def test_cli_version(capsys):
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    captured = capsys.readouterr()
    assert __version__ in captured.out


def test_analyze_human_mode_preserves_report_and_optional_ai(monkeypatch, capsys):
    from app.ai.provider import NullProvider

    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: SCENARIO)
    monkeypatch.setattr("app.cli.get_provider", NullProvider)

    code = main(["analyze"])
    out = capsys.readouterr().out
    assert code == 0
    assert "IDOR" in out or "Insecure Direct Object Reference" in out
    assert "AI Explanation (optional)" not in out
    assert not out.lstrip().startswith("{")


def test_analyze_json_mode_emits_structured_result_only(monkeypatch, capsys):
    monkeypatch.setattr("builtins.input", lambda *args, **kwargs: SCENARIO)
    called = {"ai": False}

    def boom(_report, _provider):
        called["ai"] = True
        raise AssertionError("AI must not run in --json mode")

    monkeypatch.setattr("app.cli.explain_structured_result", boom)

    code = main(["analyze", "--json"])
    captured = capsys.readouterr()
    assert code == 0
    assert called["ai"] is False
    assert "Enter a security scenario:" in captured.err

    payload = json.loads(captured.out)
    assert "scenario" in payload
    assert "findings" in payload
    assert "vulnerability_indicated" in payload
    assert "ai_explanation" not in payload
    assert payload["vulnerability_indicated"] is True
    assert any(f.get("issue_type") == "idor" for f in payload["findings"])


def test_console_script_entry_point_registered():
    scripts = entry_points(group="console_scripts")
    matches = [ep for ep in scripts if ep.name == "ai-security-assistant"]
    assert matches, "ai-security-assistant console script is not installed"
    assert matches[0].value == "app.cli:main"


def test_installed_cli_help_subprocess():
    result = subprocess.run(
        [sys.executable, "-m", "app", "--help"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    combined = result.stdout + result.stderr
    assert "analyze" in combined
    assert "ai-security-assistant" in combined or "Educational" in combined


def test_installed_cli_version_subprocess():
    result = subprocess.run(
        ["ai-security-assistant", "--version"],
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert __version__ in result.stdout
