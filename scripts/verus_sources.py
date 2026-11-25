"""Fail-closed source adapters for Verus value-level proofs.

These adapters preserve expressions and pattern/field wiring, while lifting
standard value operations (String, BTreeSet, IP/UUID equality) to logical values.
They do not prove the internals of Rust's standard library or wire encodings.
"""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]


def delimiter_end(source, opening, left="{", right="}"):
    if source[opening] != left:
        raise SystemExit("invalid delimiter opening")
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
        depth += (source[position] == left) - (source[position] == right)
        position += 1
    if depth:
        raise SystemExit("unbalanced source delimiters")
    return position


def block(source, signature):
    if source.count(signature) != 1:
        raise SystemExit(f"expected one source declaration: {signature}")
    start = source.index(signature)
    opening = source.index("{", start)
    end = delimiter_end(source, opening)
    return source[start:end], source[opening + 1:end - 1]


def inject(template, replacements):
    for marker, value in replacements.items():
        marker = f"/* {marker} */"
        if template.count(marker) != 1:
            raise SystemExit(f"expected one proof injection point: {marker}")
        template = template.replace(marker, value)
    return template


def value_types(source):
    source = source.replace("authority_contracts_model::resources::", "").replace("crate::resources::", "")
    # Trusted semantic views of canonical interval sets; interval algorithms are
    # verified independently by executable property tests, not this adapter.
    for concrete, logical in [("PortSet", "Set<u16>"), ("Ipv4Set", "Set<u32>"), ("BTreeSet", "Set"), ("String", "Seq<char>"),
                              ("Uuid", "u128"), ("Ipv4Addr", "u32")]:
        source = re.sub(rf"\b{concrete}\b", logical, source)
    return source


def scopes_source():
    source = (ROOT / "crates/policy-core/src/scoped.rs").read_text()
    enums = (ROOT / "crates/policy-core/src/realization.rs").read_text()
    protocol = (ROOT / "crates/contracts-model/src/protocol.rs").read_text()
    scope_declaration, _ = block(source, "pub enum AbilityScope {")
    variants = re.findall(r"^    (\w+) \{", scope_declaration, re.MULTILINE)
    if set(variants) != {"MeshMembership", "NetworkReachability", "SshSession", "ServiceIdentity", "TcpConnection", "NetworkRouteAuthorization", "SshCredential", "MtlsCredential", "TcpAdmission"} or len(variants) != 9:
        raise SystemExit("scope variants changed; extend the authority model and proofs")
    declarations = []
    for signature in ["pub struct AccessBinding {", "pub struct Validity {",
                      "pub enum AbilityScope {", "pub struct ScopedAbility {"]:
        declaration, _ = block(source, signature)
        declarations.append(value_types(declaration))
    declarations.append(checked_declaration((ROOT / "crates/contracts-model/src/resources.rs").read_text(), "TcpResourcesV1", {"source_addresses": "Ipv4Set", "destination_addresses": "Ipv4Set", "destination_ports": "PortSet"}))
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
    contains = re.sub(r"!(selected|from|to)\.is_empty\(\)", r"\1.len() > 0", contains)
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


def checked_declaration(source, name, fields):
    declaration, body = block(source, f"pub struct {name} {{")
    actual = dict(re.findall(r"^\s*pub (\w+): ([^\n]+),\s*$", body, re.MULTILINE))
    if actual != fields:
        raise SystemExit(f"{name} fields changed; extend the contract authority specification")
    return value_types(declaration).replace("Vec<", "Seq<")


REQUEST_FIELDS = {
    "CommonDecisionClaims": {name: ("i64" if name == "issued_at" else "String") for name in
        ["decision_id", "issuer", "domain_id", "subject_user_id", "device_id", "target_node_id", "policy_id", "issued_at"]},
    "NetworkProjectionRequest": {"wireguard_public_key": "String", "mesh_address": "String"},
    "SshProjectionRequest": {"public_key_fingerprint": "String", "principals": "Vec<String>", "terminal_token_hash": "String"},
    "MtlsProjectionRequest": {"client_spki_sha256": "String", "identity_uri": "String", "service_audience": "String"},
    "TcpProjectionRequest": {"resources": "authority_contracts_model::resources::TcpResourcesV1"},
}


def projection_source():
    source = (ROOT / "crates/projection-core/src/scoped.rs").read_text()
    library = (ROOT / "crates/projection-core/src/lib.rs").read_text()
    declarations = []
    for name in ("CommonDecisionClaims", "NetworkProjectionRequest", "SshProjectionRequest", "MtlsProjectionRequest", "TcpProjectionRequest"):
        declarations.append(checked_declaration(library, name, REQUEST_FIELDS[name]))
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
        "PRODUCTION_PROJECT_SCOPE": value_types(body), "PRODUCTION_COMMON_MATCHES": "!(" + matches + ")",
    })


def result_calls(body, names):
    """Lift Rust Result propagation to proof-mode match, preserving early return."""
    for name in names:
        position = 0
        while True:
            match = re.search(rf"\b{re.escape(name)}\s*\(", body[position:])
            if not match:
                break
            start = position + match.start()
            opening = position + match.end() - 1
            end = delimiter_end(body, opening, "(", ")")
            question = end
            while question < len(body) and body[question].isspace():
                question += 1
            if body[question:question + 1] == "?":
                lifted = "propagate!(" + body[start:end] + ")"
                body = body[:start] + lifted + body[question + 1:]
                position = start + len(lifted)
            else:
                position = end
    return body


def protocol_string(name):
    source = (ROOT / "crates/contracts-model/src/protocol.rs").read_text()
    values = re.findall(rf'pub const {name}: &str = ("[^"\\]*");', source)
    if len(values) != 1:
        raise SystemExit(f"expected explicit protocol string: {name}")
    return values[0] + "@"


def contract_values(body):
    constants = {
        "authority_contracts_model::protocol::CONTRACT_VERSION_V1": "version_v1()",
        "authority_contracts_model::protocol::CONTRACT_VERSION_V2": "version_v2()",
        "CREDENTIAL_ISSUER_AUDIENCE": "credential_audience()",
        "NODE_AGENT_AUDIENCE": "node_audience()",
        "NETWORK_AGENT_AUDIENCE": "network_audience()",
    }
    for native, logical in constants.items():
        body = body.replace(native, logical)
    nonce = '''format!("{}_mtls_{}", common.decision_id, audience.replace('-', "_"))'''
    body = body.replace(nonce, "mtls_nonce(common.decision_id, audience)")
    body = body.replace("authority_contracts_model::TcpAccessGrantV2", "TcpAccessGrantV2")
    body = body.replace(".clone()", "").replace(".to_owned()", "")
    body = body.replace("&common.decision_id", "common.decision_id")
    body = body.replace("&request.terminal_token_hash", "request.terminal_token_hash")
    # Only these known Option conversions are lifted. Any new unsupported '?'
    # path remains visible and fails proof-mode compilation, rather than skipped.
    body = re.sub(r"projection_expiry\(common\.issued_at, (ttl|ttl_seconds)\)\s*"
        r"\.ok_or\(ProjectionError::InvalidLifetime\)\?",
        r"require_some!(expiry_spec(common.issued_at, \1), ProjectionError::InvalidLifetime)", body)
    body = re.sub(r'(inputs\s*\.\s*(?:ssh|mtls|tcp|network))\s*\.ok_or\(ProjectionError::MissingInput\("(\w+)"\)\)\?',
        r'require_some!(\1, ProjectionError::MissingInput("\2".view()))', body)
    body = re.sub(r"(\b\w+)\.validate\(\)\?", r"propagate!(\1.validate())", body)
    return result_calls(body, ["ssh_contract", "mtls_contract", "project_network", "project_tcp"])


def constructors_source():
    library = (ROOT / "crates/projection-core/src/lib.rs").read_text()
    contract_files = [ROOT / "crates/contracts-model/src/lib.rs", ROOT / "crates/contracts-model/src/tcp.rs"]
    names = ["IssuanceAuthorizationV2", "MtlsIssuanceAuthorizationV1", "NetworkAccessGrantV1", "TcpAccessGrantV2"]
    declarations = []
    for name in names:
        source = next(path.read_text() for path in contract_files if f"pub struct {name} {{" in path.read_text())
        common_fields = ["version", "issuer", "domain_id", "subject_user_id", "device_id", "target_node_id", "policy_id", "issued_at", "not_before", "expires_at", "audience"]
        extras = {
            "IssuanceAuthorizationV2": ["ssh_public_key_fingerprint", "principals", "decision_id", "nonce"],
            "MtlsIssuanceAuthorizationV1": ["client_spki_sha256", "identity_uri", "service_audience", "decision_id", "nonce"],
            "NetworkAccessGrantV1": ["wireguard_public_key", "mesh_address", "nonce"],
            "TcpAccessGrantV2": ["resources", "decision_id"],
        }
        fields = {field: ("i64" if field in ["issued_at", "not_before", "expires_at"] else
            "Vec<String>" if field == "principals" else "crate::resources::TcpResourcesV1" if field == "resources" else "String")
            for field in common_fields + extras[name]}
        declarations.append(checked_declaration(source, name, fields))
    replacements = {"PRODUCTION_CONTRACT_TYPES": "\n\n".join(declarations)}
    for name in ["ssh_contract", "mtls_contract", "project_network", "project_tcp"]:
        _, body = block(library, f"fn {name}(")
        replacements[f"PRODUCTION_{name.upper()}"] = contract_values(body)
    for name in ["CONTRACT_VERSION_V1", "CONTRACT_VERSION_V2", "CREDENTIAL_ISSUER_AUDIENCE", "NODE_AGENT_AUDIENCE", "NETWORK_AGENT_AUDIENCE"]:
        replacements[name] = protocol_string(name)
    template = (ROOT / "formal/verus/constructors.rs").read_text()
    # The previous units are checked again here so no theorem is imported via an
    # unchecked external specification. All shared definitions keep the same name.
    return projection_source() + expiry_source().replace("use vstd::prelude::*;\n", "", 1) + inject(template, replacements)


def selected_source():
    source = (ROOT / "crates/projection-core/src/selection.rs").read_text()
    topology = (ROOT / "crates/policy-core/src/realization.rs").read_text()
    planner = (ROOT / "crates/planning-core/src/lib.rs").read_text()
    declarations = []
    declaration, _ = block(topology, "pub enum AccessMechanism {")
    declaration = re.sub(r"^\s*#\[serde\([^\n]*\)\]\n", "\n", declaration, flags=re.MULTILINE)
    declarations.append(declaration)
    declaration, _ = block(planner, "pub struct Plan<A, M> {")
    declaration = declaration.replace("Plan<A, M>", "AccessPlan")
    declaration = re.sub(r"\bA\b", "Ability", declaration)
    declaration = re.sub(r"\bM\b", "AccessMechanism", declaration)
    declarations.append(value_types(declaration).replace("Vec<", "Seq<"))
    declaration, _ = block(source, "pub struct ProjectionInputs<'a> {")
    declaration = declaration.replace("<'a>", "").replace("&'a ", "")
    declarations.append(declaration)
    if not re.search(r"#\[derive\([^]]*\bDefault\b[^]]*\)\]\s*pub struct SelectedProjections", source) or "impl Default for SelectedProjections" in source:
        raise SystemExit("SelectedProjections must use field-derived Default; update proof if changed")
    selected_fields = {"ssh_issuance": "Option<IssuanceAuthorizationV2>", "ssh_node_install": "Option<IssuanceAuthorizationV2>",
        "network_grant": "Option<NetworkAccessGrantV1>", "mtls_issuance": "Option<MtlsIssuanceAuthorizationV1>",
        "mtls_node_install": "Option<MtlsIssuanceAuthorizationV1>", "tcp_grant": "Option<TcpAccessGrantV2>"}
    declarations.append(checked_declaration(source, "SelectedProjections", selected_fields))
    _, body = block(source, "pub fn project_plan(")
    prefix = re.match(r"\s*let mut result = SelectedProjections::default\(\);\s*for mechanism in &plan.mechanisms\s*\{", body)
    if not prefix:
        raise SystemExit("projection loop initialization changed; update proof extraction")
    opening = prefix.end() - 1
    end = delimiter_end(body, opening)
    if body[end:].strip() != "Ok(result)":
        raise SystemExit("projection return boundary changed; update proof extraction")
    loop = contract_values(body[opening + 1:end - 1])
    return constructors_source() + inject((ROOT / "formal/verus/selected.rs").read_text(), {
        "PRODUCTION_SELECTED_TYPES": "\n\n".join(declarations),
        "PRODUCTION_SELECTED_LOOP": loop,
    })


def authorized_source():
    policy = (ROOT / "crates/policy-core/src/scoped.rs").read_text()
    _, accessors = block(policy, "impl AuthorizedPlan {")
    getters = {
        "pub const fn binding(&self) -> AccessBinding {": "self.binding",
        "pub const fn issued_at(&self) -> i64 {": "self.issued_at",
        "pub fn policy_reference(&self) -> &str {": "&self.policy_reference",
        "pub const fn realization(&self) -> &Plan<ScopedAbility, AccessMechanism> {": "&self.realization",
    }
    for signature, expected in getters.items():
        if block(accessors, signature)[1].strip() != expected:
            raise SystemExit(f"AuthorizedPlan accessor changed: {signature}")
    source = (ROOT / "crates/projection-core/src/scoped.rs").read_text()
    _, body = block(source, "pub fn project_authorized(")
    initialization = "let (mut ssh, mut mtls, mut network, mut tcp) = (None, None, None, None);"
    if body.count(initialization) != 1:
        raise SystemExit("authorized input initialization changed; update source proof")
    guard, rest = body.split(initialization)
    header = re.match(r"\s*for ability in &plan.realization\(\).abilities\s*\{", rest)
    if not header:
        raise SystemExit("authorized ability iteration changed; update source proof")
    opening = header.end() - 1
    end = delimiter_end(rest, opening)
    loop = rest[opening + 1:end - 1]
    loop = re.sub(r"authority_contracts_model::protocol::lifetime_seconds\(\s*common.issued_at,\s*ability.validity.expires_at,?\s*\)\s*"
        r"\.ok_or\(ProjectionError::InvalidLifetime\)\?",
        "require_some!(lifetime_spec(common.issued_at, ability.validity.expires_at), ProjectionError::InvalidLifetime)", loop)
    loop = loop.replace("project_scope(&ability.scope)", "project_scope(ability.scope)")
    tail = rest[end:]
    literal, _ = block(tail, "ProjectionInputs {")
    normalized = re.sub(r"(ssh|mtls|network|tcp)\.as_ref\(\)\.map\(\|\(input, ttl\)\| \(input, \*ttl\)\)", r"\1", literal)
    expected = "ProjectionInputs{ssh:ssh,mtls:mtls,network:network,tcp:tcp,}"
    if re.sub(r"\s+", "", normalized) != expected:
        raise SystemExit("authorized input assembly changed; update source proof")
    tail = tail.replace(literal, "inputs").replace("&selection", "selection").replace(".clone()", "")
    tail = re.sub(r"plan\s*\.realization\(\)\s*\.abilities\s*\.iter\(\)\s*\.map\(\|ability\| ability.scope.kind\(\)\)\s*\.collect\(\)",
        "plan.realization().abilities.map(|ability: ScopedAbility| ability.scope.kind())", tail)
    selection, _ = block(tail, "AccessPlan {")
    if tail[:tail.index(selection)].strip() != "let selection =":
        raise SystemExit("authorized selection initialization changed")
    final_call = tail[tail.index(selection) + len(selection):].strip()
    if not final_call.startswith(";"):
        raise SystemExit("authorized selection terminator changed")
    final_call = final_call[1:].strip()
    guard = re.sub(r"binding\.(domain_id|subject_user_id|device_id|target_node_id)\.to_string\(\)",
        r"uuid_text(binding.\1)", guard)
    guard = guard.replace("authority_contracts_model::protocol::domain_issuer", "domain_issuer")
    template = (ROOT / "formal/verus/authorized.rs").read_text()
    return selected_source() + inject(template, {
        "PRODUCTION_AUTHORIZED_GUARD": guard,
        "PRODUCTION_GATHER_STEP": loop,
        "PRODUCTION_AUTHORIZED_SELECTION": "let selection = " + selection + ";",
        "PRODUCTION_AUTHORIZED_CALL": final_call,
    })


def check_private_plan_declaration(source):
    _, body = block(source, "pub struct AuthorizedPlan {")
    fields = re.findall(r"^\s*(\w+): ([^\n]+),\s*$", body, re.MULTILINE)
    expected = {"binding": "AccessBinding", "issued_at": "i64", "policy_reference": "String",
        "realization": "Plan<ScopedAbility,AccessMechanism>", "evidence": "crate::selection::PlanningEvidence"}
    actual = {name: re.sub(r"\s+", "", kind) for name, kind in fields}
    if len(fields) != len(expected) or actual != expected or re.search(r"^\s*pub\b", body, re.MULTILINE):
        raise SystemExit("AuthorizedPlan fields must retain checked private layout")
    if len(re.findall(r"\bimpl[^{}]*\bAuthorizedPlan\b[^{}]*\{", source)) != 1:
        raise SystemExit("additional AuthorizedPlan implementation requires invariant review")


def factory_source():
    source = (ROOT / "crates/policy-core/src/scoped.rs").read_text()
    production = source.split("#[cfg(test)]", 1)[0]
    check_private_plan_declaration(production)
    _, implementation = block(production, "impl AuthorizedPlan {")
    methods = re.findall(r"\bfn (\w+)\(", implementation)
    expected_methods = {"new", "evidence", "set_selection", "binding", "issued_at", "policy_reference", "realization"}
    if set(methods) != expected_methods or len(methods) != len(expected_methods):
        raise SystemExit("AuthorizedPlan methods changed; extend invariant-preservation proof")
    # There must be no additional direct construction path in the production
    # module. Clone is field-derived; Deserialize/Default cannot bypass checks.
    if len(re.findall(r"\bAuthorizedPlan\s*\{", production)) != 2:
        raise SystemExit("AuthorizedPlan direct construction bypasses checked constructor")
    if not re.search(r"#\[derive\(Debug, Clone, PartialEq, Eq\)\]\s*pub struct AuthorizedPlan", production):
        raise SystemExit("AuthorizedPlan derives changed; review construction invariant")
    _, setter = block(implementation, "pub(crate) fn set_selection(")
    expected_setter = '''self.evidence.route_choice = options.choice;
        self.evidence.deployment = (options.choice == crate::selection::RouteChoice::Automatic)
            .then(|| options.availability.clone());
        self.evidence.candidates = candidates;'''
    if re.sub(r"\s+", "", setter) != re.sub(r"\s+", "", expected_setter):
        raise SystemExit("selection setter changed; prove invariant preservation")
    for entrypoint in ("evaluate_scoped", "evaluate_ability_scoped"):
        _, evaluate = block(production, "pub fn " + entrypoint + "(")
        call = evaluate.find("let plan = AuthorizedPlan::new(")
        if call < 0:
            raise SystemExit("evaluate_scoped must use the checked plan constructor")
        opening = evaluate.index("(", call)
        end = delimiter_end(evaluate, opening, "(", ")")
        if re.sub(r"\s+", "", evaluate[end:]) != "?;Ok((decision,plan))":
            raise SystemExit("plan modified after checked construction; extend factory proof")
    _, body = block(implementation, "fn new(")
    body = body.replace("Ok(Self {", "Ok(AuthorizedPlan {")
    pattern = re.search(r"realization\s*\.abilities\s*\.iter\(\)\s*\.any\(", body)
    if not pattern:
        raise SystemExit("plan invariant guard changed; update source lift")
    opening = pattern.end() - 1
    end = delimiter_end(body, opening, "(", ")")
    predicate = body[opening + 1:end - 1].strip()
    if not predicate.startswith("|ability|"):
        raise SystemExit("unexpected constructor predicate binder")
    predicate = predicate[len("|ability|"):].strip()
    if predicate.startswith("{"):
        if delimiter_end(predicate, 0) != len(predicate):
            raise SystemExit("unexpected constructor predicate block")
        predicate = predicate[1:-1]
    lifted = "(exists|ability: ScopedAbility| realization.abilities.contains(ability) && (" + predicate + "))"
    body = body[:pattern.start()] + lifted + body[end:]
    return authorized_source() + inject((ROOT / "formal/verus/factory.rs").read_text(), {"PRODUCTION_PLAN_CONSTRUCTOR": body})


def closure_source():
    source = (ROOT / "crates/planning-core/src/lib.rs").read_text()
    declaration = checked_declaration(source, "Derivation<A>", {"requires": "BTreeSet<A>", "provides": "BTreeSet<A>"})
    declaration = declaration.replace("Derivation<A>", "NativeRule")
    declaration = re.sub(r"\bA\b", "nat", declaration)
    declaration = value_types(declaration)
    _, body = block(source, "fn closure<A: Ord + Clone>(")
    match = re.fullmatch(r"\s*loop\s*\{(.*)\}\s*", body, re.DOTALL)
    if not match:
        raise SystemExit("closure loop shape changed; extend concrete proof")
    loop = match[1]
    prefix = re.match(r"\s*let count = abilities.len\(\);\s*for rule in derivations\s*\{", loop)
    if not prefix:
        raise SystemExit("closure round initialization/iteration changed")
    opening = prefix.end() - 1
    end = delimiter_end(loop, opening)
    step = loop[opening + 1:end - 1]
    step = step.replace(".is_subset(abilities)", ".subset_of(abilities)")
    step = step.replace("abilities.extend(rule.provides.iter().cloned());", "abilities = abilities.union(rule.provides);")
    guard = loop[end:].strip()
    if not re.fullmatch(r"if (.*?)\s*\{\s*return;\s*\}", guard, re.DOTALL):
        raise SystemExit("closure return boundary changed")
    condition = re.fullmatch(r"if (.*?)\s*\{\s*return;\s*\}", guard, re.DOTALL)[1]
    template = (ROOT / "formal/verus/closure.rs").read_text()
    return (ROOT / "formal/verus/solver.rs").read_text() + inject(template, {
        "PRODUCTION_DERIVATION_TYPE": declaration,
        "PRODUCTION_RULE_APPLICATION": step,
        "PRODUCTION_CLOSURE_STOP": condition,
    })


def bfs_source():
    source = (ROOT / "crates/planning-core/src/lib.rs").read_text()
    for name, fields in {
        "Mechanism<A, M>": {"id": "M", "requires": "BTreeSet<A>", "provides": "BTreeSet<A>"},
        "Model<A, M>": {"mechanisms": "Vec<Mechanism<A, M>>", "derivations": "Vec<Derivation<A>>"},
        "Request<A, M>": {"goals": "BTreeSet<A>", "available": "BTreeSet<A>", "permitted": "BTreeSet<A>",
            "forbidden_mechanisms": "BTreeSet<M>", "max_mechanisms": "usize", "max_states": "usize"},
        "Plan<A, M>": {"mechanisms": "Vec<M>", "abilities": "BTreeSet<A>"},
    }.items():
        checked_declaration(source, name, fields)
    _, solver = block(source, "pub fn solve<A: Ord + Clone, M: Ord + Clone>(")
    header = "for (id, mechanism) in &catalog {"
    _, expansion = block(solver, header)
    opening = expansion.index("let mut next = plan.clone();")
    end = expansion.index("if !next.abilities.is_subset(&request.permitted)", opening)
    native_next = expansion[opening:end]
    expected_next = '''let mut next = plan.clone();
            next.mechanisms.push(id.clone());
            next.abilities.extend(mechanism.provides.iter().cloned());
            closure(&mut next.abilities, &model.derivations);'''
    if re.sub(r"\s+", "", native_next) != re.sub(r"\s+", "", expected_next):
        raise SystemExit("next-node data construction changed; extend source refinement")
    next_body = native_next.replace("plan.clone()", "plan")
    next_body = next_body.replace("next.mechanisms.push(id.clone());", "next.mechanisms = next.mechanisms.push(id as nat);")
    next_body = next_body.replace("next.abilities.extend(mechanism.provides.iter().cloned());", "next.abilities = next.abilities.union(mechanism.provides);")
    next_body = next_body.replace("closure(&mut next.abilities, &model.derivations);", "next.abilities = closure(c.derivations, next.abilities);")
    expansion = expansion[:opening] + "let next = extend_node(c, plan, id);\n" + expansion[end:]
    expansion = expansion.replace("selected.contains(id)", "selected.contains(id as nat)")
    expansion = expansion.replace("request.forbidden_mechanisms.contains(id)", "c.forbidden.contains(id as nat)")
    expansion = expansion.replace(".is_subset(&plan.abilities)", ".subset_of(plan.abilities)")
    expansion = expansion.replace("let mut next_selected = selected.clone();\n            next_selected.insert(id.clone());", "let next_selected = selected.insert(id as nat);")
    expansion = expansion.replace("visited.contains(&next_selected)", "visited.contains(next_selected)")
    expansion = expansion.replace("next.abilities.is_subset(&request.permitted)", "next.abilities.subset_of(c.permitted)")
    expansion = expansion.replace("request.max_states", "budget").replace("PlanningError::", "SearchFailure::")
    expansion = expansion.replace("visited.insert(next_selected);", "visited = visited.insert(next_selected);")
    expansion = expansion.replace("queue.push_back(next);", "queue = queue.push(next);")
    expansion = expansion.replace("continue;", "return Ok(SearchState { queue, visited, done: before.done, representatives: before.representatives });")
    expansion = expansion.replace("return Err(SearchFailure::SearchLimit);",
        "node_representation(c, next); capacity_at_failure(c, budget, visited, next_selected); return Err(SearchFailure::SearchLimit);")
    _, queue_loop = block(solver, "while let Some(plan) = queue.pop_front() {")
    goal_match = re.match(r"\s*if (.*?)\s*\{\s*return Ok\(plan\);\s*\}\s*if (.*?)\s*\{\s*continue;\s*\}", queue_loop, re.DOTALL)
    if not goal_match:
        raise SystemExit("BFS goal/bound guards changed; extend proof lift")
    goal_guard = goal_match[1].replace("request.goals.is_subset(&plan.abilities)", "c.goals.subset_of(plan.abilities)")
    goal_guard = goal_guard.replace("satisfies(&plan)", "(c.accepts)(key(plan), plan.abilities)")
    bound_guard = goal_match[2].replace("request.max_mechanisms", "bound")
    prefix = solver[:solver.index("while let Some(plan)")]
    map_end = prefix.index("if request.max_states")
    expected_map = """let catalog: BTreeMap<_, _> = model.mechanisms.iter().map(|mechanism| (mechanism.id.clone(), mechanism)).collect();
        if catalog.len() != model.mechanisms.len() { return Err(PlanningError::DuplicateMechanism); }"""
    if re.sub(r"\s+", "", prefix[:map_end]) != re.sub(r"\s+", "", expected_map):
        raise SystemExit("catalog construction/duplicate guard changed; extend value-view proof")
    budget_match = re.search(r"if (.*?)\s*\{\s*return Err\(PlanningError::SearchLimit\);\s*\}", prefix[map_end:], re.DOTALL)
    if not budget_match:
        raise SystemExit("initial budget guard changed")
    zero_budget = budget_match[1].replace("request.max_states", "budget")
    initial = re.search(r"let mut initial = request.available.clone\(\);\s*closure\(&mut initial, &model.derivations\);\s*if (.*?)\s*\{\s*return Err\(PlanningError::NoSolution\);\s*\}", prefix, re.DOTALL)
    if not initial:
        raise SystemExit("initial authority closure/permission boundary changed")
    if prefix[map_end + budget_match.end():initial.start()].strip():
        raise SystemExit("unmodeled statements before initial closure")
    initial_guard = initial[1].replace("initial.is_subset(&request.permitted)", "initial.subset_of(c.permitted)")
    initialization = prefix[initial.end():].strip()
    expected_init = """let mut queue = VecDeque::from([Plan { mechanisms: Vec::new(), abilities: initial, }]);
        let mut visited = BTreeSet::from([BTreeSet::<M>::new()]);"""
    if re.sub(r"\s+", "", initialization) != re.sub(r"\s+", "", expected_init):
        raise SystemExit("BFS queue/visited initialization changed; extend proof")
    # Every remaining loop statement and terminal boundary must be consumed.
    remainder = queue_loop[goal_match.end():]
    before_expand = remainder[:remainder.index(header)]
    expected_selected = "let selected: BTreeSet<_> = plan.mechanisms.iter().cloned().collect();"
    if re.sub(r"\s+", "", before_expand) != re.sub(r"\s+", "", expected_selected):
        raise SystemExit("BFS selected-state key construction changed")
    loop_open = solver.index("{", solver.index("while let Some(plan)"))
    loop_end = delimiter_end(solver, loop_open)
    if re.sub(r"\s+", "", solver[loop_end:]) != "Err(PlanningError::NoSolution)":
        raise SystemExit("BFS exhaustion boundary changed")
    expand_pos = remainder.index(header)
    expand_end = delimiter_end(remainder, remainder.index("{", expand_pos))
    if remainder[expand_end:].strip():
        raise SystemExit("unmodeled statements after BFS expansion")
    return closure_source() + (ROOT / "formal/verus/lexicographic.rs").read_text() + inject((ROOT / "formal/verus/bfs.rs").read_text(), {
        "PRODUCTION_EXTEND_NODE": next_body, "PRODUCTION_EXPAND_ONE": expansion,
        "PRODUCTION_GOAL_GUARD": goal_guard, "PRODUCTION_BOUND_GUARD": bound_guard,
        "PRODUCTION_INITIAL_QUEUE": "seq![SearchNode { mechanisms: Seq::empty(), abilities: initial }]",
        "PRODUCTION_INITIAL_VISITED": "Set::<Set<nat>>::empty().insert(Set::<nat>::empty())",
        "PRODUCTION_ZERO_BUDGET_GUARD": zero_budget, "PRODUCTION_INITIAL_PERMISSION_GUARD": initial_guard,
    })
