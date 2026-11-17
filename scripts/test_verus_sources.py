"""Source extraction is part of the proof boundary, so test it independently."""
import unittest
from verus_sources import block, inject, scopes_source, projection_source


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

    def test_source_correspondence_includes_material_and_binding_guards(self):
        scope = scopes_source()
        projection = projection_source()
        self.assertIn('selected.subset_of(ports)', scope)
        self.assertIn('self.binding == requested.binding', scope)
        self.assertIn('common.domain_id != uuid_text(binding.domain_id)', projection)
        self.assertIn('source_address: ip_text(source)', projection)
        self.assertNotIn('/* PRODUCTION_', projection)


if __name__ == "__main__":
    unittest.main()
