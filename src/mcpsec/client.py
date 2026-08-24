"""Minimal JSON-RPC client for the toy server."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any


class ToyClient:
    def __init__(self, base: str, timeout: float = 2.0) -> None:
        self.base = base.rstrip("/")
        self.timeout = timeout
        self._id = 0

    def rpc(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        self._id += 1
        payload = json.dumps(
            {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        ).encode("utf-8")
        req = urllib.request.Request(
            f"{self.base}/rpc",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def list_tools(self) -> list[dict[str, Any]]:
        return self.rpc("tools/list")["result"]["tools"]

    def call(self, name: str, **arguments: Any) -> dict[str, Any]:
        return self.rpc("tools/call", {"name": name, "arguments": arguments})["result"]
