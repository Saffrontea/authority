"""Source extraction is part of the proof boundary, so test it independently."""
import unittest
from unittest.mock import patch
from verus_sources import (block, inject, scopes_source, projection_source, checked_declaration,
                           contract_values, result_calls, authorized_source, factory_source, closure_source,
                           check_private_plan_declaration, ROOT, bfs_source)


class SourceExtraction(unittest.TestCase):
    def test_braces_in_strings_comments_and_chars_do_not_truncate_body(self):
        source = '''fn f() {
  // } is not code
  /* } /* { nested */ } */
  let a = "} escaped \\\" {";
  let b = r###"} \" {"###;
  let c = '}'; let d = '\\u{7b}';
  if true { 1 } else { 2 }
} fn other() { 3 }'''
        declaration, body = block(source, "fn f() {")
        self.assertTrue(declaration.endswith("else { 2 }\n}"))
        self.assertIn("if true", body)
        self.assertNotIn("fn other", body)

    def test_unterminated_input_and_duplicate_declaration_fail_closed(self):
        for source in ['fn f() { /* }', 'fn f() { "}', 'fn f() { r###"}']:
            with self.assertRaises(SystemExit):
                block(source, "fn f() {")
        with self.assertRaises(SystemExit):
            block('fn f() {} fn f() {}', "fn f() {")

    def test_injection_requires_exactly_one_target(self):
        for source in ['missing', '/* TARGET */ /* TARGET */']:
            with self.assertRaises(SystemExit):
                inject(source, {"TARGET": "expression"})
        self.assertEqual(inject('/* TARGET */', {"TARGET": "expression"}), "expression")

    def test_result_propagation_keeps_nested_arguments_and_unknown_paths(self):
        source = 'let value = project_tcp(common, tuple(")?", nested(1)))?; next();'
        lifted = result_calls(source, ["project_tcp"])
        self.assertEqual(lifted, 'let value = propagate!(project_tcp(common, tuple(")?", nested(1)))); next();')
        self.assertEqual(result_calls("unknown()?;", ["project_tcp"]), "unknown()?;")
        self.assertIn('require_some!', contract_values('inputs\n .tcp.ok_or(ProjectionError::MissingInput("tcp"))?'))

    def test_new_or_changed_contract_authority_fields_fail_closed(self):
        original = "pub struct C {\n    pub key: String,\n}"
        self.assertIn("Seq<char>", checked_declaration(original, "C", {"key": "String"}))
        for changed in [original.replace("String", "u128"), original.replace("\n}", "\n    pub can_delegate: bool,\n}")]:
            with self.assertRaises(SystemExit):
                checked_declaration(changed, "C", {"key": "String"})

    def test_full_pipeline_contains_constructor_collection_and_selection_code(self):
        pipeline = authorized_source()
        for text in ["nonce: nonce", "resources: tcp.resources", "result.ssh_node_install = Some(install)",
                     "ScopeProjection::Tcp(request) => tcp = Some((request, ttl))", "plan.realization().mechanisms"]:
            self.assertIn(text, pipeline)
        self.assertNotIn("/* PRODUCTION_", pipeline)
        self.assertIn("requires plan_bindings_valid(plan)", pipeline)

    def test_plan_layout_and_checked_constructor_are_part_of_proof_boundary(self):
        source = (ROOT / "crates/policy-core/src/scoped.rs").read_text().split("#[cfg(test)]", 1)[0]
        check_private_plan_declaration(source)
        for changed in [source.replace("    binding: AccessBinding,", "    pub binding: AccessBinding,", 1),
                        source + "\nimpl Default for AuthorizedPlan { fn default() -> Self { todo!() } }"]:
            with self.assertRaises(SystemExit):
                check_private_plan_declaration(changed)
        self.assertIn("pub proof fn checked_factory_then_projection", factory_source())
        self.assertIn("decreases universe.len() - seed.len()", closure_source())
        self.assertNotIn("/* PRODUCTION_", closure_source())

    def test_bfs_view_covers_queue_budget_candidates_and_complete_return_boundary(self):
        bfs = bfs_source()
        for fragment in ["pub proof fn solve_canonical", "pub proof fn full_budget_completeness",
                         "queue = queue.push(next)", "visited = visited.insert(next_selected)",
                         "c.goals.subset_of(plan.abilities) && (c.accepts)(key(plan), plan.abilities)",
                         "capacity_at_failure(c, budget, visited, next_selected)",
                         "pub proof fn goal_at_head_is_lex_minimum", "representative_inv(c, state)",
                         "admitted_child_is_canonical(c, bound, budget, plan, before, id, next)"]:
            self.assertIn(fragment, bfs)
        self.assertNotIn("/* PRODUCTION_", bfs)

    def test_bfs_reversed_catalog_scan_fails_closed(self):
        path = ROOT / "crates/planning-core/src/lib.rs"
        read_text = type(path).read_text
        source = path.read_text()
        header = "for (id, mechanism) in &catalog {"
        _, solver = block(source, "pub fn solve<A: Ord + Clone, M: Ord + Clone>(")
        self.assertEqual(solver.count(header), 1)
        self.assertEqual(source.count(solver), 1)
        reversed_scan = source.replace(solver, solver.replace(header, "for (id, mechanism) in catalog.iter().rev() {"))

        def changed_read(current, *args, **kwargs):
            return reversed_scan if current == path else read_text(current, *args, **kwargs)

        with patch("pathlib.Path.read_text", changed_read):
            with self.assertRaises(SystemExit):
                bfs_source()

    def test_source_correspondence_includes_material_and_binding_guards(self):
        scope = scopes_source()
        projection = projection_source()
        self.assertIn('selected.subset_of(ports)', scope)
        self.assertIn('self.binding == requested.binding', scope)
        self.assertIn('common.domain_id != uuid_text(binding.domain_id)', projection)
        self.assertIn('source_addresses: source', projection)
        self.assertNotIn('/* PRODUCTION_', projection)


if __name__ == "__main__":
    unittest.main()
