"""Fail-closed source adapters for Verus value-level proofs.

These adapters preserve expressions and pattern/field wiring, while lifting
standard value operations (String, BTreeSet, IP/UUID equality) to logical values.
They do not prove the internals of Rust's standard library or wire encodings.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def block(source, signature):
    if source.count(signature) != 1:
        raise SystemExit(f"expected one source declaration: {signature}")
    start = source.index(signature)
    opening = source.index("{", start)
    depth = 1
    position = opening + 1
    while depth and position < len(source):
        if source.startswith("//", position):
            end = source.find("\n", position)
            position = len(source) if end < 0 else end + 1
            continue
        if source.startswith("/*", position):
            comments = 1
            position += 2
            while comments and position < len(source):
                if source.startswith("/*", position):
                    comments += 1
                    position += 2
                elif source.startswith("*/", position):
                    comments -= 1
                    position += 2
                else:
                    position += 1
            if comments:
                raise SystemExit("unterminated Rust block comment")
            continue
        raw = re.match(r'r(#+)?"', source[position:])
        if raw:
            terminator = '"' + (raw[1] or "")
            end = source.find(terminator, position + raw.end())
            if end < 0:
                raise SystemExit("unterminated Rust raw string")
            position = end + len(terminator)
            continue
        if source[position] == '"':
            position += 1
            while position < len(source) and source[position] != '"':
                position += 2 if source[position] == "\\" else 1
            if position >= len(source):
                raise SystemExit("unterminated Rust string")
            position += 1
            continue
        # A char literal can contain a brace; a lifetime such as 'a cannot.
        char = re.match(r"'(?:\\(?:u\{[0-9a-fA-F_]+\}|x[0-9a-fA-F]{2}|.)|[^'\\])'", source[position:])
        if char:
            position += char.end()
            continue
        depth += (source[position] == "{") - (source[position] == "}")
        position += 1
    if depth:
        raise SystemExit(f"unbalanced declaration: {signature}")
    return source[start:position], source[opening + 1:position - 1]


def inject(template, replacements):
    for marker, value in replacements.items():
        marker = f"/* {marker} */"
        if template.count(marker) != 1:
            raise SystemExit(f"expected one proof injection point: {marker}")
        template = template.replace(marker, value)
    return template


def value_types(source):
    for concrete, logical in [("BTreeSet", "Set"), ("String", "Seq<char>"),
                              ("Uuid", "u128"), ("Ipv4Addr", "u32")]:
        source = re.sub(rf"\b{concrete}\b", logical, source)
    return source


def scopes_source():
    source = (ROOT / "crates/policy-core/src/scoped.rs").read_text()
    enums = (ROOT / "crates/policy-core/src/realization.rs").read_text()
    protocol = (ROOT / "crates/contracts-model/src/protocol.rs").read_text()
    scope_declaration, _ = block(source, "pub enum AbilityScope {")
    variants = re.findall(r"^    (\w+) \{", scope_declaration, re.MULTILINE)
    if set(variants) != {"MeshMembership", "NetworkReachability", "SshSession", "ServiceIdentity", "TcpConnection"} or len(variants) != 5:
        raise SystemExit("scope variants changed; extend the authority model and proofs")
    declarations = []
    for signature in ["pub struct AccessBinding {", "pub struct Validity {",
                      "pub enum AbilityScope {", "pub struct ScopedAbility {"]:
        declaration, _ = block(source, signature)
        declarations.append(value_types(declaration))
    declarations.append(block(enums, "pub enum Ability {")[0])
    maximum = re.findall(r"pub const MAX_TCP_PORTS: usize = (\d+);", protocol)
    if len(maximum) != 1:
        raise SystemExit("MAX_TCP_PORTS must remain an explicit protocol bound")
    _, validity = block(source, "pub const fn contains(self, other: Self) -> bool {")
    _, ability_impl = block(source, "impl AbilityScope {")
    _, contains = block(ability_impl, "fn contains(&self, requested: &Self) -> bool {")
    # The receiver is a value in the spec, so pattern bindings are logical values
    # rather than shared references. Each operation is the standard value view.
    contains = contains.replace("selected.iter().all(|principal| !principal.is_empty())",
        "(forall|principal: Seq<char>| selected.contains(principal) ==> principal.len() > 0)")
    contains = contains.replace("!selected.is_empty()", "selected.len() > 0")
    contains = contains.replace(".is_subset(", ".subset_of(").replace(".contains(&0)", ".contains(0)")
    contains = contains.replace("authority_contracts_model::protocol::MAX_TCP_PORTS", "MAX_TCP_PORTS")
    _, kind = block(ability_impl, "pub const fn kind(&self) -> Ability {")
    _, scoped_impl = block(source, "impl ScopedAbility {")
    _, scoped = block(scoped_impl, "pub fn contains(&self, requested: &Self) -> bool {")
    scoped = scoped.replace(".contains(&requested.scope)", ".contains(requested.scope)")
    template = (ROOT / "formal/verus/scopes.rs").read_text()
    return inject(template, {
        "PRODUCTION_TYPES": "\n\n".join(declarations),
        "MAX_TCP_PORTS": maximum[0],
        "PRODUCTION_VALIDITY": validity,
        "PRODUCTION_SCOPE_CONTAINS": contains,
        "PRODUCTION_SCOPE_KIND": kind,
        "PRODUCTION_SCOPED_CONTAINS": scoped,
    })


def expiry_source():
    protocol = (ROOT / "crates/contracts-model/src/protocol.rs").read_text()
    projection = (ROOT / "crates/projection-core/src/lib.rs").read_text()
    values = {}
    for name in ("MIN_TTL_SECONDS", "MAX_TTL_SECONDS"):
        matches = re.findall(rf"pub const {name}: i64 = (\d+);", protocol)
        if len(matches) != 1:
            raise SystemExit(f"expected explicit protocol bound: {name}")
        values[name] = matches[0]
    _, ttl = block(protocol, "pub const fn valid_ttl_seconds(seconds: i64) -> bool {")
    _, expiry = block(projection, "fn projection_expiry(issued_at: i64, ttl_seconds: i64) -> Option<i64> {")
    _, lifetime = block(protocol, "pub const fn lifetime_seconds(not_before: i64, expires_at: i64) -> Option<i64> {")
    return inject((ROOT / "formal/verus/expiry.rs").read_text(), {
        "MIN_TTL": values["MIN_TTL_SECONDS"], "MAX_TTL": values["MAX_TTL_SECONDS"],
        "PRODUCTION_VALID_TTL": ttl, "PRODUCTION_EXPIRY": expiry, "PRODUCTION_LIFETIME": lifetime,
    })


def projection_source():
    source = (ROOT / "crates/projection-core/src/scoped.rs").read_text()
    library = (ROOT / "crates/projection-core/src/lib.rs").read_text()
    declarations = []
    for name in ("CommonDecisionClaims", "NetworkProjectionRequest", "SshProjectionRequest", "MtlsProjectionRequest", "TcpProjectionRequest"):
        declaration, _ = block(library, f"pub struct {name} {{")
        declarations.append(value_types(declaration).replace("Vec<", "Seq<"))
    declaration, _ = block(source, "enum ScopeProjection {")
    declarations.append("pub " + declaration)
    _, body = block(source, "fn project_scope(scope: &AbilityScope) -> ScopeProjection {")
    # IP Display remains an opaque function. We prove equality to the exact
    # approved IP's encoding, without assuming/proving Display is injective.
    body = re.sub(r"\b(address|source|destination)\.to_string\(\)", r"ip_text(\1)", body)
    body = body.replace(".iter().cloned().collect()", ".to_seq()")
    body = body.replace(".iter().copied().collect()", ".to_seq()")
    body = body.replace(".clone()", "")
    _, authorized = block(source, "pub fn project_authorized(")
    guard = re.match(r"\s*let binding = plan.binding\(\);\s*if (.*?)\s*\{\s*return Err\(ProjectionError::ScopeMismatch\);\s*\}", authorized, re.DOTALL)
    if not guard:
        raise SystemExit("authorization binding guard changed; update proof extraction")
    matches = re.sub(r"binding\.(domain_id|subject_user_id|device_id|target_node_id)\.to_string\(\)", r"uuid_text(binding.\1)", guard[1])
    matches = matches.replace("plan.issued_at()", "authorized_at").replace("plan.policy_reference()", "policy_reference")
    matches = matches.replace("authority_contracts_model::protocol::domain_issuer", "domain_issuer")
    return scopes_source() + inject((ROOT / "formal/verus/projection.rs").read_text(), {
        "PRODUCTION_PROJECTION_TYPES": "\n\n".join(declarations),
        "PRODUCTION_PROJECT_SCOPE": body, "PRODUCTION_COMMON_MATCHES": "!(" + matches + ")",
    })
