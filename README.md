# tool-schema-lint

Static lint for LLM tool/function schemas, for learning how schema design widens or narrows the prompt injection blast radius.

You give it a JSON list of tool schemas. It reports findings as JSON: free-form string parameters with no `enum` or `maxLength`, objects that allow arbitrary additional properties, dangerous-looking tool or parameter names, missing descriptions, and oversized enums.

## What it is

- An offline educational linter. It reads one file and prints findings.
- A checklist for least-privilege tool design before a schema reaches a model.

## What it is NOT

- Not a safety guarantee. A schema that passes can still be abused.
- It does not call a model or test the tool's behavior.
- Severity labels are heuristics, not a standard.

## Usage

```
python tool_schema_lint.py example.json
```

`example.json` is fictional: one tight tool and one loose tool, so you can see both outcomes.

## Tests

```
python -m unittest -v
```

[VERIFY: run the tests yourself before citing the count in an interview.]

## Provenance

Initial code was AI-assisted. [TO FILL: Dahoba's own review notes.]
