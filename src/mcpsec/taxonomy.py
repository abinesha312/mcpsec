"""MCPSecBench 17-vector taxonomy (Yang, Wu, Chen, arXiv:2508.13220).

IDs T01–T17 match paper items ①–⑰. This package implements *local* checks
for a subset only. It does not reproduce Claude / OpenAI / Cursor ASR tables.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class Vector:
    id: str
    paper_num: int
    name: str
    surface: str
    covered: bool


TAXONOMY: tuple[Vector, ...] = (
    Vector("T01", 1, "Prompt Injection", "user interaction", False),
    Vector("T02", 2, 'Tool/Service Misuse via "Confused AI"', "user interaction", False),
    Vector("T03", 3, "Schema Inconsistencies", "client", False),
    Vector("T04", 4, "Slash Command Overlap", "client", False),
    Vector("T05", 5, "Vulnerable Client", "client", False),
    Vector("T06", 6, "MCP Rebinding", "transport", False),
    Vector("T07", 7, "Man-in-the-Middle", "transport", False),
    Vector("T08", 8, "Tool Shadowing Attack", "server", False),
    Vector("T09", 9, "Data Exfiltration", "server", True),
    Vector("T10", 10, "Package Name Squatting (tool name)", "server", True),
    Vector("T11", 11, "Indirect Prompt Injection", "server", False),
    Vector("T12", 12, "Package Name Squatting (server name)", "server", False),
    Vector("T13", 13, "Configuration Drift", "server", False),
    Vector("T14", 14, "Sandbox Escape", "server", True),
    Vector("T15", 15, "Tool Poisoning", "server", False),
    Vector("T16", 16, "Vulnerable Server", "server", True),
    Vector("T17", 17, "Rug Pull Attack", "server", True),
)


def covered() -> tuple[Vector, ...]:
    return tuple(v for v in TAXONOMY if v.covered)


def by_id(tid: str) -> Vector:
    for v in TAXONOMY:
        if v.id == tid:
            return v
    raise KeyError(tid)
