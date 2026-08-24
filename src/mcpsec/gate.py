"""CI gate: start toy servers, run subset attacks, assert defenses, tear down."""

from __future__ import annotations

import argparse
import json
import threading
import time
from typing import Any

from mcpsec import COVERED_TAXONOMY_IDS, __version__
from mcpsec.client import ToyClient
from mcpsec.server import serve
from mcpsec.taxonomy import covered


def _run_server(host: str, port: int, enforce: bool):
    httpd = serve(host, port, enforce)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, thread


def _wait(client: ToyClient, tries: int = 40) -> None:
    for _ in range(tries):
        try:
            client.list_tools()
            return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("toy server did not start")


def run_gate(host: str = "127.0.0.1") -> dict[str, Any]:
    results: list[dict[str, Any]] = []
    httpd_open = httpd_safe = None
    try:
        httpd_open, _ = _run_server(host, 0, enforce=False)
        httpd_safe, _ = _run_server(host, 0, enforce=True)
        port_open = httpd_open.server_address[1]
        port_safe = httpd_safe.server_address[1]
        open_c = ToyClient(f"http://{host}:{port_open}")
        safe_c = ToyClient(f"http://{host}:{port_safe}")
        _wait(open_c)
        _wait(safe_c)

        # T09 data exfiltration via extra tool_list param
        vul = open_c.call("add", a=4, b=5, tool_list="ALL")
        den = safe_c.call("add", a=4, b=5, tool_list="ALL")
        results.append(
            {
                "id": "T09",
                "name": "Data Exfiltration",
                "vulnerable_exfil": bool(vul.get("exfil")),
                "defense_blocked": bool(den.get("blocked")),
                "pass": bool(vul.get("exfil")) and bool(den.get("blocked")),
            }
        )

        # T10 tool name squatting
        vul = open_c.call("addd", a=1, b=2)
        den = safe_c.call("addd", a=1, b=2)
        results.append(
            {
                "id": "T10",
                "name": "Package Name Squatting (tool name)",
                "vulnerable_squat": vul.get("result") == "SQUATTED",
                "defense_blocked": bool(den.get("blocked")),
                "pass": vul.get("result") == "SQUATTED" and bool(den.get("blocked")),
            }
        )

        # T14 sandbox escape (shell metachar). Uses only `echo` + token; no network.
        marker = "MCPSEC_T14"
        vul = open_c.call("run_cmd", token=f"x; echo {marker}")
        den = safe_c.call("run_cmd", token=f"x; echo {marker}")
        results.append(
            {
                "id": "T14",
                "name": "Sandbox Escape",
                "vulnerable_injected": bool(vul.get("injected")) and marker in (vul.get("stdout") or ""),
                "defense_blocked": bool(den.get("blocked")),
                "pass": bool(vul.get("injected")) and bool(den.get("blocked")),
            }
        )

        # T16 path traversal — write a secret *outside* toy root, try to read it
        import os
        import tempfile
        from pathlib import Path

        with tempfile.TemporaryDirectory() as td:
            secret = Path(td) / "secret.txt"
            secret.write_text("toy-secret", encoding="utf-8")
            # relative traversal from MCPSEC_ROOT default
            # Use absolute path in vulnerable mode; relative ../ in both
            rel = os.path.relpath(secret, start=os.environ.get("MCPSEC_ROOT", "/tmp/mcpsec-toy"))
            vul = open_c.call("read_file", path=rel)
            den = safe_c.call("read_file", path=rel)
            results.append(
                {
                    "id": "T16",
                    "name": "Vulnerable Server",
                    "vulnerable_read": "toy-secret" in (vul.get("content") or ""),
                    "defense_blocked": bool(den.get("blocked")),
                    "pass": "toy-secret" in (vul.get("content") or "") and bool(den.get("blocked")),
                }
            )

        # T17 rug pull — mutate tool after N calls
        open_c.call("add", a=1, b=1)
        open_c.call("add", a=1, b=1)
        vul = open_c.call("add", a=1, b=1)
        safe_c.call("add", a=1, b=1)
        safe_c.call("add", a=1, b=1)
        # force definition drift check: third call on safe should still be enrolled hash
        den = safe_c.call("add", a=1, b=1)
        results.append(
            {
                "id": "T17",
                "name": "Rug Pull Attack",
                "vulnerable_leak": "leaked_env_keys" in vul,
                "defense_no_leak": "leaked_env_keys" not in den and den.get("ok") is True,
                "pass": "leaked_env_keys" in vul and den.get("ok") is True and "leaked_env_keys" not in den,
            }
        )
    finally:
        for httpd in (httpd_open, httpd_safe):
            if httpd is not None:
                httpd.shutdown()
                httpd.server_close()

    report = {
        "package": "mcpsec",
        "version": __version__,
        "citation": {
            "title": "MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols",
            "authors": "Yang, Wu, Chen",
            "arxiv": "https://arxiv.org/abs/2508.13220",
            "code": "https://github.com/AIS2Lab/MCPSecBench",
        },
        "covered_ids": list(COVERED_TAXONOMY_IDS),
        "not_a_full_eval": True,
        "results": results,
        "all_pass": all(r["pass"] for r in results),
    }
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run mcpsec local CI gate")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    report = run_gate()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print(f"mcpsec {report['version']} subset gate")
        print("cite:", report["citation"]["arxiv"])
        print("covered:", ", ".join(report["covered_ids"]))
        print("NOT a Claude/Cursor/OpenAI reproduction.")
        for r in report["results"]:
            flag = "PASS" if r["pass"] else "FAIL"
            print(f"  {r['id']} {r['name']}: {flag}")
        print("all_pass:", report["all_pass"])
    return 0 if report["all_pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
