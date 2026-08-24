"""mcpsec CLI: `mcpsec demo` / `mcpsec gate` run the local subset gate."""

from __future__ import annotations

import sys

from mcpsec.gate import main as gate_main


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in {"demo", "gate"}:
        argv = argv[1:]
    return gate_main(argv)


if __name__ == "__main__":
    raise SystemExit(main())
