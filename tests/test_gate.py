import json
import os
import tempfile
from pathlib import Path

from mcpsec.gate import run_gate
from mcpsec.server import ToyMCP


def test_gate_all_pass():
    report = run_gate()
    assert report["not_a_full_eval"] is True
    assert report["covered_ids"] == ["T09", "T10", "T14", "T16", "T17"]
    failed = [r for r in report["results"] if not r["pass"]]
    assert report["all_pass"], json.dumps(failed, indent=2)


def test_toy_add_local():
    t = ToyMCP(enforce=True)
    r = t.call_tool("add", {"a": 2, "b": 3})
    assert r == {"ok": True, "result": 5}


def test_no_invented_scores_in_report():
    report = run_gate()
    blob = json.dumps(report)
    assert "ASR" not in blob
    assert "Claude" not in blob


def test_mcpsec_demo_aliases_gate(monkeypatch):
    import mcpsec.cli as cli

    called = {}

    def fake(argv=None):
        called["argv"] = argv
        return 0

    monkeypatch.setattr(cli, "gate_main", fake)
    assert cli.main(["demo", "--json"]) == 0
    assert called["argv"] == ["--json"]
    assert cli.main(["gate"]) == 0
    assert called["argv"] == []
    assert cli.main(["--json"]) == 0
    assert called["argv"] == ["--json"]


def test_gate_main_returns_int(capsys):
    from mcpsec.gate import main

    code = main(["--json"])
    assert code == 0
    out = capsys.readouterr().out
    assert '"all_pass": true' in out
    assert "2508.13220" in out
