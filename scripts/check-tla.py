#!/usr/bin/env python3
"""Run the pinned TLC checker and optionally check deliberate safety mutations."""
import argparse
from pathlib import Path
import subprocess
import tempfile

from tlc_tools import ROOT, checker


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mutations", action="store_true")
    args = parser.parse_args()
    java, jar = checker()
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
    models.append(("peer-lifecycle-liveness", lifecycle, None))
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
        failed_expiry = "FailExpire(d) == /\\ ready /\\ d \\in timers /\\ ~Live(d) /\\ registry = d\n                 /\\ UNCHANGED vars"
        assert lifecycle.count(failed_expiry) == 1
        models.append(("failed-expiry-forgets-registry", lifecycle.replace(failed_expiry,
            "FailExpire(d) == /\\ ready /\\ d \\in timers /\\ ~Live(d) /\\ registry = d\n"
            "                 /\\ registry' = None\n"
            "                 /\\ UNCHANGED <<now, ready, kernel, consumed, tombstones, published, completed, timers, badCleanup>>"),
            "RegistryTracksKernel"))
        expiry_fairness = "                 /\\ \\A d \\in Decisions: WF_vars(Expire(d))"
        assert lifecycle.count(expiry_fairness) == 1
        models.append(("expiry-without-fairness", lifecycle.replace(expiry_fairness, ""),
            "EventuallyExpiredPeerRemoved"))
        restart = "Restart == /\\ ~ready /\\ ready' = TRUE /\\ kernel' = None"
        assert lifecycle.count(restart) == 1
        models.append(("restart-without-cleanup", lifecycle.replace(restart,
            "Restart == /\\ ~ready /\\ ready' = TRUE /\\ UNCHANGED kernel"), "RegistryTracksKernel"))
    timed = (ROOT / "formal/tla/TimedAdmission.tla").read_text()
    timed_config = (ROOT / "formal/tla/TimedAdmission.cfg").read_text()
    models.append(("timed-admission", timed, None))
    if args.mutations:
        timeout = "tcpActive' = {d \\in tcpActive: now' < TcpExpiries[d]}"
        assert timed.count(timeout) == 1
        models.append(("tcp-timeout-lost", timed.replace(timeout, "tcpActive' = tcpActive"), "NoExpiredTcp"))
        guard = "TcpApply(d) == /\\ ready /\\ TcpLive(d) /\\ d \\notin tcpConsumed /\\ d \\notin tcpTombstones"
        assert timed.count(guard) == 1
        models.append(("tcp-revoked-grant-reinstalled", timed.replace(guard,
            "TcpApply(d) == /\\ ready /\\ TcpLive(d)"), "NoTcpResurrection"))

    for name, model, expected_failure in models:
        with tempfile.TemporaryDirectory(prefix="authority-tlc-") as directory:
            directory = Path(directory)
            module = "TimedAdmission" if "MODULE TimedAdmission" in model else ("PeerLifecycle" if "MODULE PeerLifecycle" in model else "Revocation")
            (directory / f"{module}.tla").write_text(model)
            if module == "TimedAdmission":
                (directory / "PeerLifecycle.tla").write_text(lifecycle)
            selected_config = timed_config if module == "TimedAdmission" else (lifecycle_config if module == "PeerLifecycle" else config)
            if name == "peer-lifecycle-same-deadline":
                selected_config = selected_config.replace("LateDeadline = 3", "LateDeadline = 2")
            if name in {"peer-lifecycle-liveness", "expiry-without-fairness"}:
                selected_config = selected_config.replace("SPECIFICATION Spec", "SPECIFICATION SpecFair")
                selected_config += "\nPROPERTY EventuallyExpiredPeerRemoved\n"
            (directory / f"{module}.cfg").write_text(selected_config)
            result = subprocess.run([java, "-XX:+UseParallelGC", f"-Djava.io.tmpdir={directory}", "-jar", str(jar.resolve()),
                "-workers", "2", "-metadir", str(directory / "states"), f"{module}.tla"],
                cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                timeout=180)
            if expected_failure:
                marker = ("Temporal properties were violated" if expected_failure in {"EventuallyRevoked", "EventuallyExpiredPeerRemoved"}
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
