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
        if not local_references_exist(document, path.parent):
            return 1

        vector_root = CONTRACTS / "test-vectors" / path.stem.removesuffix(".schema")
        for kind in ("valid", "invalid"):
            vector_directory = vector_root / kind
            if not vector_directory.is_dir() or not any(vector_directory.glob("*.json")):
                print(
                    f"{relative}: missing {kind} vectors in "
                    f"{vector_directory.relative_to(CONTRACTS)}",
                    file=sys.stderr,
                )
                return 1

    vectors = list((CONTRACTS / "test-vectors").rglob("*.json"))
    if not vectors:
        print("no contract test vectors found", file=sys.stderr)
        return 1
    for vector in vectors:
        json.loads(vector.read_text(encoding="utf-8"))

    print(f"contracts: {len(actual_paths)} artifact(s), {len(vectors)} vector(s), digests verified")
    return 0


def local_references_exist(value: object, base: Path) -> bool:
    if isinstance(value, dict):
        reference = value.get("$ref")
        if (
            isinstance(reference, str)
            and "://" not in reference
            and not reference.startswith("#")
        ):
            target = (base / reference.split("#", 1)[0]).resolve()
            if not target.is_file() or CONTRACTS.resolve() not in target.parents:
                print(f"unresolved or escaping contract reference: {reference}", file=sys.stderr)
                return False
        return all(local_references_exist(child, base) for child in value.values())
    if isinstance(value, list):
        return all(local_references_exist(child, base) for child in value)
    return True


if __name__ == "__main__":
    raise SystemExit(main())
