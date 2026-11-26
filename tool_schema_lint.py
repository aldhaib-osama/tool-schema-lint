"""Lint LLM tool/function schemas for design choices that widen the prompt
injection blast radius. Static checks on schema JSON you supply. Passing the
linter does not make a tool safe; it only catches common risky shapes."""
import json
import sys

DANGEROUS_NAMES = ("execute", "shell", "eval", "delete", "drop", "admin", "raw_sql")
SAFE_ENUM_HINT = 8


def lint_parameters(props, required, path, findings):
    if not isinstance(props, dict):
        return
    for name, spec in props.items():
        p = path + "/" + name
        if not isinstance(spec, dict):
            continue
        if name.lower() in DANGEROUS_NAMES:
            findings.append({"severity": "high", "path": p,
                             "issue": "parameter name suggests dangerous capability"})
        if spec.get("type") == "string":
            if "enum" not in spec and "maxLength" not in spec:
                findings.append({"severity": "medium", "path": p,
                                 "issue": "free-form string with no enum or maxLength"})
            if "enum" in spec and len(spec["enum"]) > SAFE_ENUM_HINT:
                findings.append({"severity": "low", "path": p,
                                 "issue": "large enum; confirm every value is intended"})
        if spec.get("type") == "object" and spec.get("additionalProperties") is not False:
            findings.append({"severity": "medium", "path": p,
                             "issue": "object allows arbitrary additional properties"})
        lint_parameters(spec.get("properties"), spec.get("required", []), p, findings)


def lint_tool(tool, findings):
    name = tool.get("name", "<unnamed>")
    base = "/tools/" + name
    if name == "<unnamed>":
        findings.append({"severity": "high", "path": base, "issue": "tool has no name"})
    if not tool.get("description"):
        findings.append({"severity": "low", "path": base + "/description",
                         "issue": "missing description; model has less context to use it safely"})
    if name.lower() in DANGEROUS_NAMES:
        findings.append({"severity": "high", "path": base,
                         "issue": "tool name suggests dangerous capability"})
    params = tool.get("parameters", tool.get("input_schema", {}))
    if isinstance(params, dict):
        if params.get("type") == "object" and params.get("additionalProperties") is not False:
            findings.append({"severity": "medium", "path": base + "/parameters",
                             "issue": "top-level parameters allow arbitrary properties"})
        props = params.get("properties", {})
        if not props:
            findings.append({"severity": "info", "path": base + "/parameters",
                             "issue": "no declared parameters"})
        lint_parameters(props, params.get("required", []), base + "/parameters", findings)


def lint_schema(doc):
    findings = []
    tools = doc.get("tools")
    if tools is None and "name" in doc:
        tools = [doc]
    if not isinstance(tools, list) or not tools:
        return [{"severity": "info", "path": "/tools", "issue": "no tools found"}]
    for tool in tools:
        if isinstance(tool, dict):
            lint_tool(tool, findings)
    return findings


def main(argv):
    if len(argv) != 2:
        print("usage: python tool_schema_lint.py <schema.json>", file=sys.stderr)
        return 2
    with open(argv[1], "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    findings = lint_schema(doc)
    order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 4))
    print(json.dumps({"findings": findings, "count": len(findings)}, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
