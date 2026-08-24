# Measured numbers (do not invent more)

Source: clean venv, `pip install "git+https://github.com/abinesha312/mcpsec.git"`, then `mcpsec demo` (alias of `mcpsec-gate`).

Box: Linux, Python 3.13. Date: 2026-08-24 America/Chicago.

This is a **local toy JSON-RPC subset**, not MCPSecBench’s Claude / Cursor / OpenAI eval and not their ASR/RR tables.

## `mcpsec demo`

cite: https://arxiv.org/abs/2508.13220  
covered IDs: T09, T10, T14, T16, T17

| ID | Name | Result |
|----|------|--------|
| T09 | Data Exfiltration | PASS |
| T10 | Package Name Squatting (tool name) | PASS |
| T14 | Sandbox Escape | PASS |
| T16 | Vulnerable Server | PASS |
| T17 | Rug Pull Attack | PASS |

`all_pass: True`

PASS here means: the vulnerable path was hit **and** the enforce/policy path blocked it on this box.

## What this does not show

No host-app jailbreak rates. No claim we reproduced the paper’s 17-vector host eval. No third-party installs.
