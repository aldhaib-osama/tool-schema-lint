import unittest

from tool_schema_lint import lint_schema


def issues(findings):
    return [f["issue"] for f in findings]


def tool(props, **kw):
    t = {"name": kw.pop("name", "t"), "description": "d",
         "parameters": {"type": "object", "properties": props,
                        "additionalProperties": False}}
    t.update(kw)
    return {"tools": [t]}


class LintTests(unittest.TestCase):
    def test_tight_schema_no_high_or_medium(self):
        doc = tool({"city": {"type": "string", "enum": ["a", "b"]}})
        findings = lint_schema(doc)
        self.assertFalse([f for f in findings if f["severity"] in ("high", "medium")])

    def test_free_form_string_flagged(self):
        doc = tool({"q": {"type": "string"}})
        self.assertTrue(any("free-form" in i for i in issues(lint_schema(doc))))

    def test_maxlength_satisfies(self):
        doc = tool({"q": {"type": "string", "maxLength": 50}})
        self.assertFalse(any("free-form" in i for i in issues(lint_schema(doc))))

    def test_open_object_flagged(self):
        doc = tool({"opts": {"type": "object"}})
        self.assertTrue(any("arbitrary" in i for i in issues(lint_schema(doc))))

    def test_dangerous_param_name_flagged(self):
        doc = tool({"execute": {"type": "string", "maxLength": 10}})
        self.assertTrue(any("dangerous capability" in i for i in issues(lint_schema(doc))))

    def test_open_top_level_params_flagged(self):
        doc = {"tools": [{"name": "t", "description": "d",
                          "parameters": {"type": "object", "properties": {}}}]}
        self.assertTrue(any("arbitrary" in i for i in issues(lint_schema(doc))))

    def test_single_tool_document_supported(self):
        doc = {"name": "t", "description": "d",
               "parameters": {"type": "object", "additionalProperties": False,
                              "properties": {"q": {"type": "string"}}}}
        self.assertTrue(any("free-form" in i for i in issues(lint_schema(doc))))

    def test_missing_description_low(self):
        doc = {"tools": [{"name": "t", "parameters": {"type": "object",
                          "additionalProperties": False, "properties": {}}}]}
        findings = lint_schema(doc)
        self.assertTrue(any(f["severity"] == "low" for f in findings))

    def test_empty_tools_info(self):
        self.assertEqual(lint_schema({"tools": []})[0]["severity"], "info")


if __name__ == "__main__":
    unittest.main()
