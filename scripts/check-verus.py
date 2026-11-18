#!/usr/bin/env python3
"""Verify the solver model and the actual production validity predicate."""
import argparse
import hashlib
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

from verus_sources import scopes_source, expiry_source, projection_source, authorized_source, factory_source, closure_source, bfs_source

ROOT = Path(__file__).resolve().parents[1]
VERSION = "0.2026.11.02.8bf68ee"
RUST = "1.99.1"
RELEASE = f"https://github.com/verus-lang/verus/releases/download/release/{VERSION}"
ASSETS = {
    "aarch64": ("arm64-linux", "bc28850dd5efd1679a4cf4ffd3309921c3523c69fa4757079e5d12d4122d400d"),
    "x86_64": ("x86-linux", "f3a0119292df8855e4435da8130bee1873b0e6a60c306accf81a08ea687bba3c"),
}
FORBIDDEN = re.compile(r"\b(?:assume|admit)\s*\(|verifier::external_body|verifier::external_fn_specification")


def verifier(install):
    if platform.system() != "Linux" or platform.machine() not in ASSETS:
        raise SystemExit("pinned Verus setup supports Linux aarch64/x86_64")
    target, digest = ASSETS[platform.machine()]
    cache = ROOT / ".cache/formal"
    archive = cache / f"verus-{VERSION}-{target}.zip"
    if not archive.exists():
        if not install:
            raise SystemExit("Verus is not installed; run mise run verification:verus:setup")
        cache.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=cache) as download:
            urllib.request.urlretrieve(f"{RELEASE}/{archive.name}", download.name)
            data = Path(download.name).read_bytes()
            if hashlib.sha256(data).hexdigest() != digest:
                raise SystemExit("downloaded Verus checksum mismatch")
            archive.write_bytes(data)
    if hashlib.sha256(archive.read_bytes()).hexdigest() != digest:
        raise SystemExit("Verus archive checksum mismatch")
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            relative = Path(member.filename)
            if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != f"verus-{target}":
                raise SystemExit("unexpected path in Verus archive")
            if member.is_dir():
                continue
            destination = cache / relative
            data = bundle.read(member)
            if install:
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(data)
            elif not destination.exists() or destination.read_bytes() != data:
                raise SystemExit(f"installed Verus file differs from pinned archive: {relative}")
        for name in ("verus", "rust_verify", "z3", "cargo-verus"):
            (cache / f"verus-{target}" / name).chmod(0o755)
    env = os.environ.copy()
    # This toolchain is private to verification; do not change the user's Rust
    # installation, default toolchain, Cargo cache or workspace compiler.
    env["RUSTUP_HOME"] = str(cache / "rustup")
    if install:
        rustup = shutil.which("rustup")
        if not rustup:
            raise SystemExit("rustup is required to install the pinned verification toolchain")
        subprocess.run([rustup, "toolchain", "install", RUST, "--profile", "minimal",
            "--component", "rustc-dev", "--component", "llvm-tools", "--no-self-update"],
            env=env, check=True)
    binary = cache / f"verus-{target}/verus"
    version = subprocess.run([str(binary), "--version"], env=env, text=True,
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    if version.returncode != 0 or f"Version: {VERSION}" not in version.stdout:
        print(version.stdout)
        raise SystemExit("pinned Verus/toolchain unavailable; run mise run verification:verus:setup")
    return binary, env


def validity_source():
    source = (ROOT / "crates/policy-core/src/scoped.rs").read_text()
    structs = re.findall(r"pub struct Validity \{([^{}]*)\}", source)
    if len(structs) != 1 or re.sub(r"\s+", "", structs[0]) != "pubnot_before:i64,pubexpires_at:i64,":
        raise SystemExit("Validity fields changed; update the proof extraction and specification")
    blocks = re.findall(r"impl Validity \{(.*?)\n\}", source, re.DOTALL)
    if len(blocks) != 1:
        raise SystemExit("expected exactly one production Validity implementation")
    functions = re.findall(r"pub const fn contains\(self, other: Self\) -> bool \{([^{}]*)\}", blocks[0])
    if len(functions) != 1:
        raise SystemExit("Validity::contains shape changed; update source extraction, do not skip verification")
    template = (ROOT / "formal/verus/validity.rs").read_text()
    for marker in ("/* PRODUCTION_VALIDITY_STRUCT */", "/* PRODUCTION_VALIDITY_BODY */"):
        if template.count(marker) != 1:
            raise SystemExit(f"missing or duplicated proof injection point: {marker}")
    return template.replace("/* PRODUCTION_VALIDITY_STRUCT */", "pub struct Validity {" + structs[0] + "}") \
        .replace("/* PRODUCTION_VALIDITY_BODY */", functions[0].strip())


def verify(binary, env, name, source, minimum=1, expect_failure=False):
    if FORBIDDEN.search(source):
        raise SystemExit(f"unchecked proof admission in {name}")
    with tempfile.TemporaryDirectory(prefix="authority-verus-") as directory:
        path = Path(directory) / f"{name}.rs"
        path.write_text(source)
        result = subprocess.run([str(binary), "--crate-type=lib", "--triggers-mode", "silent", str(path)],
            env=env, cwd=directory, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=120)
        counts = re.search(r"verification results:: (\d+) verified, (\d+) errors", result.stdout)
        if expect_failure:
            if result.returncode == 0 or not counts or int(counts[2]) == 0:
                print(result.stdout)
                raise SystemExit(f"unsafe mutation failed to produce a proof error: {name}")
            print(f"{name}: expected proof failure detected")
        elif result.returncode != 0 or not counts or int(counts[1]) < minimum or int(counts[2]) != 0:
            print(result.stdout)
            raise SystemExit(f"verification failed or proof obligations disappeared: {name}")
        else:
            print(f"{name}: {counts[1]} verified, 0 errors")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--install", action="store_true", help="install pinned Verus and private Rust toolchain")
    parser.add_argument("--mutations", action="store_true", help="also require unsafe changes to fail proof")
    args = parser.parse_args()
    binary, env = verifier(args.install)
    validity = validity_source()
    solver = (ROOT / "formal/verus/solver.rs").read_text()
    verify(binary, env, "production_validity", validity, minimum=4)
    verify(binary, env, "solver", solver, minimum=20)
    scopes = scopes_source()
    expiry = expiry_source()
    projection = projection_source()
    verify(binary, env, "production_scopes", scopes, minimum=7)
    verify(binary, env, "production_expiry", expiry, minimum=8)
    verify(binary, env, "production_projection", projection, minimum=9)
    pipeline = authorized_source()
    verify(binary, env, "production_contract_pipeline", pipeline, minimum=33)
    factory = factory_source()
    verify(binary, env, "checked_plan_factory", factory, minimum=35)
    concrete_closure = closure_source()
    verify(binary, env, "concrete_closure", concrete_closure, minimum=26)
    bfs = bfs_source()
    verify(binary, env, "concrete_bfs", bfs, minimum=51)
    if args.mutations:
        mutations = [
            ("widened_deadline", validity, "other.expires_at <= self.expires_at", "other.expires_at >= self.expires_at"),
            ("unauthorized_effects", solver, "&& abilities(c, after).subset_of(c.permitted)", "&& true"),
            ("nonminimal_search", solver, "Some(length) => Some(length)", "Some(_length) => Some(bound)"),
            ("expanded_tcp_ports", scopes, "selected.subset_of(ports)", "true"),
            ("expanded_ssh_principals", scopes, "selected.subset_of(principals)", "true"),
            ("rebound_identity", scopes, "self.binding == requested.binding", "true"),
            ("reversed_lifetime", expiry, "expires_at.checked_sub(not_before)", "not_before.checked_sub(expires_at)"),
            ("unchecked_expiry_overflow", expiry, "issued_at.checked_add(ttl_seconds)", "Some(issued_at + ttl_seconds)"),
            ("rebound_projection_domain", projection, "common.domain_id != uuid_text(binding.domain_id)", "false"),
            ("wrong_tcp_source", projection, "source_address: ip_text(source),", "source_address: ip_text(destination),"),
            ("wrong_ssh_key", projection, "public_key_fingerprint: public_key_fingerprint,", "public_key_fingerprint: terminal_token_hash,"),
            ("wrong_contract_tcp_ports", pipeline, "destination_ports: tcp.destination_ports,", "destination_ports: Seq::empty(),"),
            ("wrong_contract_endpoint", pipeline, "source_address: tcp.source_address,", "source_address: tcp.destination_address,"),
            ("wrong_wireguard_audience", pipeline, "audience: node_audience(),", "audience: network_audience(),"),
            ("wrong_terminal_nonce", pipeline, "nonce: nonce,", "nonce: common.decision_id,"),
            ("wrong_mtls_identity", pipeline, "identity_uri: mtls.identity_uri,", "identity_uri: mtls.service_audience,"),
            ("omitted_ssh_install", pipeline, "result.ssh_node_install = Some(install);", "result.ssh_node_install = None;"),
            ("unselected_wireguard", pipeline, "AccessMechanism::NetworkRoute => {}",
                'AccessMechanism::NetworkRoute => { let (request, ttl) = require_some!(inputs.network, ProjectionError::MissingInput("network".view())); result.network_grant = Some(propagate!(project_network(common, request, ttl))); }'),
            ("narrowed_collected_tcp_ttl", pipeline, "ScopeProjection::Tcp(request) => tcp = Some((request, ttl)),", "ScopeProjection::Tcp(request) => tcp = Some((request, 1)),"),
            ("factory_ignores_binding", factory, "ability.binding != binding || ability.validity.not_before != issued_at", "false || ability.validity.not_before != issued_at"),
            ("factory_ignores_start", factory, "ability.binding != binding || ability.validity.not_before != issued_at", "ability.binding != binding || false"),
            ("factory_accepts_negative_time", factory, "if issued_at < 0 {", "if false {"),
            ("closure_ignores_prerequisites", concrete_closure, "if rule.requires.subset_of(abilities) {", "if true {"),
            ("closure_omits_effects", concrete_closure, "abilities = abilities.union(rule.provides);", "abilities = abilities;"),
            ("closure_stops_early", concrete_closure, "if abilities.len() == count {", "if true {"),
            ("bfs_ignores_constraints", bfs, "c.goals.subset_of(plan.abilities) && (c.accepts)(key(plan), plan.abilities)", "c.goals.subset_of(plan.abilities)"),
            ("bfs_ignores_forbidden", bfs, "|| c.forbidden.contains(id as nat)", "|| false"),
            ("bfs_ignores_permissions", bfs, "if !next.abilities.subset_of(c.permitted) {", "if false {"),
            ("bfs_reuses_parent_as_visit_key", bfs, "if visited.contains(next_selected) {", "if visited.contains(selected) {"),
            ("bfs_violates_fifo", bfs, "queue = queue.push(next);", "queue = seq![next] + queue;"),
            ("bfs_exceeds_mechanism_bound", bfs, "if plan.mechanisms.len() >= bound {", "if plan.mechanisms.len() > bound {"),
            ("bfs_exceeds_state_budget", bfs, "if visited.len() >= budget {", "if visited.len() > budget {"),
            ("bfs_fails_with_sufficient_budget", bfs, "if visited.len() >= budget {", "if true {"),
        ]
        for name, source, before, after in mutations:
            if source.count(before) != 1:
                raise SystemExit(f"mutation injection point changed: {name}")
            verify(binary, env, name, source.replace(before, after), expect_failure=True)


if __name__ == "__main__":
    main()
