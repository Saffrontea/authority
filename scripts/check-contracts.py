#!/usr/bin/env python3
"""Validate the contract artifact inventory and its locked digests."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
CONTRACTS = ROOT / "contracts"
MANIFEST = CONTRACTS / "manifest.json"


def main() -> int:
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    expected = manifest.get("artifacts", {})
    actual_paths = sorted((CONTRACTS / "artifacts").glob("*.json"))
    actual_names = {path.relative_to(CONTRACTS).as_posix() for path in actual_paths}
    if actual_names != set(expected):
        print(f"contract inventory mismatch: expected={sorted(expected)} actual={sorted(actual_names)}", file=sys.stderr)
        return 1

    for path in actual_paths:
        relative = path.relative_to(CONTRACTS).as_posix()
        document = json.loads(path.read_text(encoding="utf-8"))
        if document.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
            print(f"{relative}: unsupported JSON Schema draft", file=sys.stderr)
            return 1
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if digest != expected[relative]["sha256"]:
            print(f"{relative}: digest changed; review compatibility and update manifest", file=sys.stderr)
            return 1

    vectors = list((CONTRACTS / "test-vectors").rglob("*.json"))
    if not vectors:
        print("no contract test vectors found", file=sys.stderr)
        return 1
    for vector in vectors:
        json.loads(vector.read_text(encoding="utf-8"))

    print(f"contracts: {len(actual_paths)} artifact(s), {len(vectors)} vector(s), digests verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
