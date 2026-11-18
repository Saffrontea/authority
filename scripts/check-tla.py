#!/usr/bin/env python3
"""Run the pinned TLC checker and optionally check deliberate safety mutations."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
TLC_SHA256 = "936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88"
TLC_URL = "https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    java = os.environ.get("TLA_JAVA") or shutil.which("java")
    if not java:
        raise SystemExit("Java 11+ is required; set TLA_JAVA to its executable (no checks skipped)")
    jar = Path(os.environ.get("TLA_JAR", ROOT / ".cache/formal/tla2tools-1.7.4.jar"))
    if not jar.exists():
        jar.parent.mkdir(parents=True, exist_ok=True)
        # Do not leave a partial cached download after a failed transfer.
        with tempfile.NamedTemporaryFile(dir=jar.parent) as download:
            urllib.request.urlretrieve(TLC_URL, download.name)
            data = Path(download.name).read_bytes()
            if hashlib.sha256(data).hexdigest() != TLC_SHA256:
                raise SystemExit("downloaded TLC checksum mismatch")
            jar.write_bytes(data)
    if hashlib.sha256(jar.read_bytes()).hexdigest() != TLC_SHA256:
        raise SystemExit("TLC checksum mismatch")
    source = (ROOT / "formal/tla/Revocation.tla").read_text()
    config = (ROOT / "formal/tla/Revocation.cfg").read_text()
    models = [("baseline", source, None)]
    if args.mutations:
        guard = "Install(p) == /\\ p \\in consumed\n              /\\ p \\notin tombstones"
        assert source.count(guard) == 1
        models.append(("grant-after-tombstone", source.replace(guard,
            "Install(p) == /\\ p \\in consumed"), "NoResurrection"))
        cleanup = "active' = active \\ {p}"
        assert source.count(cleanup) == 1
        models.append(("ack-without-cleanup", source.replace(cleanup,
            "active' = active"), "NoResurrection"))
        fairness = "        /\\ \\A p \\in Pairs: WF_vars(Persist(p)) /\\ WF_vars(Complete(p))"
        assert source.count(fairness) == 1
        models.append(("delivery-without-fairness", source.replace(fairness, ""), "EventuallyRevoked"))
    lifecycle = (ROOT / "formal/tla/PeerLifecycle.tla").read_text()
    lifecycle_config = (ROOT / "formal/tla/PeerLifecycle.cfg").read_text()
    models.append(("peer-lifecycle", lifecycle, None))
    models.append(("peer-lifecycle-same-deadline", lifecycle, None))
    if args.mutations:
        guard = "Apply(d) == /\\ ready /\\ Live(d)"
        assert lifecycle.count(guard) == 1
        models.append(("expired-grant-after-gc", lifecycle.replace(guard,
            "Apply(d) == /\\ ready"), "NoResurrection"))
        cleanup = "kernel' = IF registry = d THEN None ELSE kernel"
        assert lifecycle.count(cleanup) == 2
        # Mutate only timer cleanup; revocation cleanup keeps its identity guard.
        before, expiry = lifecycle.split("Expire(d) ==", 1)
        models.append(("stale-timer-removes-replacement", before + "Expire(d) ==" +
            expiry.replace(cleanup, "kernel' = None", 1), "RegistryTracksKernel"))
        restart = "Restart == /\\ ~ready /\\ ready' = TRUE /\\ kernel' = None"
        assert lifecycle.count(restart) == 1
        models.append(("restart-without-cleanup", lifecycle.replace(restart,
            "Restart == /\\ ~ready /\\ ready' = TRUE /\\ UNCHANGED kernel"), "RegistryTracksKernel"))
    for name, model, expected_failure in models:
        with tempfile.TemporaryDirectory(prefix="authority-tlc-") as directory:
            directory = Path(directory)
            module = "PeerLifecycle" if "MODULE PeerLifecycle" in model else "Revocation"
            (directory / f"{module}.tla").write_text(model)
            selected_config = lifecycle_config if module == "PeerLifecycle" else config
            if name == "peer-lifecycle-same-deadline":
                selected_config = selected_config.replace("LateDeadline = 3", "LateDeadline = 2")
            (directory / f"{module}.cfg").write_text(selected_config)
            result = subprocess.run([java, "-XX:+UseParallelGC", "-jar", str(jar.resolve()),
                "-workers", "2", "-metadir", str(directory / "states"), f"{module}.tla"],
                cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=180)
            if expected_failure:
                marker = ("Temporal properties were violated" if expected_failure == "EventuallyRevoked"
                    else f"Invariant {expected_failure} is violated")
                if result.returncode == 0 or marker not in result.stdout:
                    print(result.stdout)
                    raise SystemExit(f"TLC mutation did not produce the expected counterexample: {name}")
                print(f"{name}: expected {expected_failure} counterexample detected")
            else:
                print(result.stdout)
                if result.returncode != 0 or "Model checking completed. No error has been found." not in result.stdout:
                    raise SystemExit(f"TLC baseline failed: {name}")


if __name__ == "__main__":
    main()
