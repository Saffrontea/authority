#!/usr/bin/env python3
"""Check migration inventory, immutability, and module boundaries."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parent.parent
MIGRATIONS = ROOT / "migrations"
FILENAME = re.compile(r"^[0-9]{4}_[a-z0-9_]+\.sql$")
FORBIDDEN = re.compile(
    r"\b(?:BEGIN|COMMIT|TRUNCATE)\b|\bDROP\s+(?:TABLE|SCHEMA|COLUMN|INDEX|TYPE)\b",
    re.IGNORECASE,
)
CROSS_SCHEMA_REFERENCE = re.compile(
    r"CREATE\s+TABLE\s+([a-z_]+)\.[a-z_]+.*?REFERENCES\s+([a-z_]+)\.[a-z_]",
    re.IGNORECASE | re.DOTALL,
)


def main() -> int:
    manifest = json.loads((MIGRATIONS / "manifest.json").read_text(encoding="utf-8"))
    expected = manifest.get("migrations", {})
    paths = sorted(MIGRATIONS.glob("*.sql"))
    names = {path.name for path in paths}
    if names != set(expected):
        print(f"migration inventory mismatch: expected={sorted(expected)} actual={sorted(names)}", file=sys.stderr)
        return 1

    for path in paths:
        if not FILENAME.fullmatch(path.name):
            print(f"invalid migration filename: {path.name}", file=sys.stderr)
            return 1
        sql = path.read_text(encoding="utf-8")
        forbidden = FORBIDDEN.search(sql)
        if forbidden:
            print(f"{path.name}: forbidden transaction/destructive operation {forbidden.group(0)!r}", file=sys.stderr)
            return 1
        for owner, target in CROSS_SCHEMA_REFERENCE.findall(sql):
            if owner.lower() != target.lower():
                print(f"{path.name}: cross-schema reference {owner} -> {target}", file=sys.stderr)
                return 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected[path.name]["sha256"]:
            print(f"{path.name}: digest changed; add a new migration instead", file=sys.stderr)
            return 1

    print(f"migrations: {len(paths)} file(s), digests and module boundaries verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
