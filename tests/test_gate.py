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
