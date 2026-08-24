"""Signed-tool policy stub.

Not ETDI/OAuth. A local allowlist of (tool_name, sha256 of canonical tool
definition). Unsigned, renamed-near-miss, extra-parameter, and post-enroll
hash changes are denied.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass


def canonical_hash(name: str, description: str, parameters: list[str]) -> str:
    blob = json.dumps(
        {"name": name, "description": description, "parameters": list(parameters)},
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class SignedToolPolicy:
    """Enroll hashes; enforce exact name + hash + parameter allowlist."""

    enrolled: dict[str, str]
    max_name_distance: int = 1  # Levenshtein-ish for T10 near-miss

    def enroll(self, name: str, description: str, parameters: list[str]) -> str:
        h = canonical_hash(name, description, parameters)
        self.enrolled[name] = h
        return h

    def check(
        self,
        name: str,
        description: str,
        parameters: list[str],
        extra_args: list[str] | None = None,
    ) -> tuple[bool, str]:
        if name not in self.enrolled:
            for enrolled_name in self.enrolled:
                if _edit_distance(name, enrolled_name) <= self.max_name_distance:
                    return False, "T10_tool_name_squatting"
            return False, "unsigned_tool"
        expected = self.enrolled[name]
        actual = canonical_hash(name, description, parameters)
        if actual != expected:
            return False, "T17_rug_pull_or_definition_drift"
        extras = extra_args or []
        allowed = set(parameters)
        leaked = [a for a in extras if a not in allowed]
        if leaked:
            return False, "T09_data_exfiltration_extra_param"
        return True, "ok"


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
