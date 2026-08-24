# mcpsec 0.1.0

Local **pip CI gate** for a **toy** MCP-like JSON-RPC server, checking a **subset** of the MCPSecBench 17-vector taxonomy.

This is **not** MCPSecBench and **does not** reproduce Claude Desktop / OpenAI / Cursor evaluations, ASR/RR tables, prompt datasets, or transport exploits from the paper.

## Citation

Yang, Wu, Chen. *MCPSecBench: A Systematic Security Benchmark and Playground for Testing Model Context Protocols*. arXiv:2508.13220, 2025.

- Paper: https://arxiv.org/abs/2508.13220
- Code: https://github.com/AIS2Lab/MCPSecBench

Use their IDs ①–⑰ as `T01`–`T17`.

## Taxonomy (paper) vs this package

| ID | Paper name | Surface | Here? |
|----|------------|---------|-------|
| T01 | Prompt Injection | user | no |
| T02 | Tool/Service Misuse via “Confused AI” | user | no |
| T03 | Schema Inconsistencies | client | no |
| T04 | Slash Command Overlap | client | no |
| T05 | Vulnerable Client (e.g. CVE-2025-6514) | client | no |
| T06 | MCP Rebinding | transport | no |
| T07 | Man-in-the-Middle | transport | no |
| T08 | Tool Shadowing | server | no |
| **T09** | **Data Exfiltration** | server | **yes** (extra `tool_list` param) |
| **T10** | **Package Name Squatting (tool name)** | server | **yes** (`add` vs `addd`) |
| T11 | Indirect Prompt Injection | server | no |
| T12 | Package Name Squatting (server name) | server | no |
| T13 | Configuration Drift | server | no |
| **T14** | **Sandbox Escape** | server | **yes** (`echo` + `;` via `shell=True` vs allowlist) |
| T15 | Tool Poisoning | server | no |
| **T16** | **Vulnerable Server** | server | **yes** (path traversal vs root jail) |
| **T17** | **Rug Pull** | server | **yes** (description mutation after N calls vs signed hash) |

Covered locally: **T09, T10, T14, T16, T17**.

## Signed-tool policy stub

`mcpsec.policy.SignedToolPolicy` enrolls `sha256` of a canonical `{name, description, parameters}` blob. It is **not** ETDI/OAuth. It denies:

- unsigned names
- near-miss names (T10)
- extra arguments (T09)
- hash change after enroll (T17)

## Install and run

```bash
cd /workspace/pocs/mcpsec
python3 -m pip install -e ".[dev]"
pytest
mcpsec-gate
mcpsec-gate --json
```

Servers bind `127.0.0.1` ephemeral ports in a thread and `shutdown()` in `finally`. No leftover listeners if the process exits.

## Honest limits

- Toy JSON-RPC over HTTP `/rpc`, not the official MCP SDK, stdio/SSE, or a real host.
- No LLM in the loop (T01/T02/T08/T11/T15 need a model).
- No DNS rebinding, MITM, mcp-remote CVE, or slash-command host tests.
- Do not treat results as platform scores.

MIT licensed.
