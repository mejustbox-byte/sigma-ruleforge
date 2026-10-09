"""Bounded YAML input, condition AST and shared predicate semantics."""

import fnmatch
import re
import uuid
from dataclasses import dataclass
from pathlib import Path

import yaml

MAX_BYTES = 1_048_576
MAX_NODES = 20_000
MAX_DEPTH = 40
MODIFIERS = {"contains", "startswith", "endswith", "all", "exists"}


class RuleError(ValueError):
    def __init__(self, code, message, line=None, column=None):
        super().__init__(message)
        self.code, self.line, self.column = code, line, column

    def diagnostic(self):
        return {"code": self.code, "message": str(self), "line": self.line, "column": self.column}


def fail(code, message, node=None):
    mark = getattr(node, "start_mark", None)
    raise RuleError(
        code, message, mark.line + 1 if mark else None, mark.column + 1 if mark else None
    )


class Loader(yaml.SafeLoader):
    def construct_mapping(self, node, deep=False):
        result = {}
        for key, value in node.value:
            if not isinstance(key, yaml.ScalarNode) or key.tag != "tag:yaml.org,2002:str":
                fail("YAML_KEY", "Mapping keys must be strings", key)
            name = self.construct_object(key, deep=deep)
            if name in result:
                fail("YAML_DUPLICATE", f"Duplicate key: {name}", key)
            result[name] = self.construct_object(value, deep=deep)
        return result


def read_bytes(path):
    with Path(path).open("rb") as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        fail("INPUT_LIMIT", "Input exceeds 1 MiB")
    return data


def load_yaml(path):
    raw = read_bytes(path)
    try:
        text = raw.decode("utf-8")
        depth = 0
        for count, token in enumerate(yaml.scan(text, Loader=Loader), 1):
            if isinstance(
                token, (yaml.tokens.AnchorToken, yaml.tokens.AliasToken, yaml.tokens.TagToken)
            ):
                fail("YAML_FEATURE", "Anchors, aliases and explicit tags are unsupported", token)
            if isinstance(
                token,
                (
                    yaml.tokens.BlockMappingStartToken,
                    yaml.tokens.BlockSequenceStartToken,
                    yaml.tokens.FlowMappingStartToken,
                    yaml.tokens.FlowSequenceStartToken,
                ),
            ):
                depth += 1
            elif isinstance(
                token,
                (
                    yaml.tokens.BlockEndToken,
                    yaml.tokens.FlowMappingEndToken,
                    yaml.tokens.FlowSequenceEndToken,
                ),
            ):
                depth -= 1
            if depth > MAX_DEPTH or count > MAX_NODES:
                fail("INPUT_LIMIT", "YAML depth or token limit exceeded", token)
        return yaml.load(text, Loader=Loader)
    except (yaml.YAMLError, UnicodeError) as exc:
        mark = getattr(exc, "problem_mark", None)
        raise RuleError(
            "YAML_SYNTAX",
            str(exc),
            mark.line + 1 if mark else None,
            mark.column + 1 if mark else None,
        ) from exc


@dataclass
class Rule:
    metadata: dict
    selectors: dict
    ast: tuple
    warnings: list


class Condition:
    def __init__(self, text, selectors):
        self.tokens = re.findall(r"[A-Za-z_][A-Za-z_0-9*?]*|[0-9]+|[()]", text)
        if re.sub(r"\s+", "", text) != "".join(self.tokens):
            fail("CONDITION", "Unsupported condition syntax")
        if len(self.tokens) > 512:
            fail("INPUT_LIMIT", "Condition exceeds 512 tokens")
        self.pos, self.selectors, self.depth = 0, selectors, 0

    def peek(self):
        return self.tokens[self.pos] if self.pos < len(self.tokens) else None

    def take(self):
        value = self.peek()
        self.pos += 1
        return value

    def parse(self):
        result = self.expression()
        if self.peek() is not None:
            fail("CONDITION", "Unexpected condition token")
        return result

    def expression(self):
        result = self.conjunction()
        while self.peek() == "or":
            self.take()
            result = ("or", result, self.conjunction())
        return result

    def conjunction(self):
        result = self.atom()
        while self.peek() == "and":
            self.take()
            result = ("and", result, self.atom())
        return result

    def atom(self):
        self.depth += 1
        if self.depth > 40:
            fail("INPUT_LIMIT", "Condition nesting exceeds 40")
        try:
            token = self.take()
            if token == "not":
                return ("not", self.atom())
            if token == "(":
                result = self.expression()
                if self.take() != ")":
                    fail("CONDITION", "Missing closing parenthesis")
                return result
            if token in ("1", "all"):
                if self.take() != "of":
                    fail("CONDITION", "Expected 'of'")
                pattern = self.take()
                names = (
                    sorted(self.selectors)
                    if pattern == "them"
                    else [
                        name
                        for name in sorted(self.selectors)
                        if pattern and fnmatch.fnmatchcase(name, pattern)
                    ]
                )
                if not names:
                    fail("CONDITION", "Selector pattern matches nothing")
                result = ("selector", names[0])
                for name in names[1:]:
                    result = ("or" if token == "1" else "and", result, ("selector", name))
                return result
            if token not in self.selectors:
                fail("CONDITION", f"Unknown selector: {token}")
            return ("selector", token)
        finally:
            self.depth -= 1


def validate(path):
    data = load_yaml(path)
    if not isinstance(data, dict):
        fail("SCHEMA", "Rule must be a mapping")
    if any(key in data for key in ("correlation", "filter")):
        fail("UNSUPPORTED", "Correlation and filter rules are unsupported")
    if data.get("taxonomy", "sigma") != "sigma":
        fail("UNSUPPORTED", "Only sigma taxonomy is supported")
    title = data.get("title")
    if not isinstance(title, str) or not title.strip() or len(title) > 256:
        fail("SCHEMA", "title must contain 1..256 characters")
    try:
        data["id"] = str(uuid.UUID(data["id"]))
    except (KeyError, ValueError, TypeError, AttributeError):
        fail("SCHEMA", "RuleForge profile requires a UUID id")
    source = data.get("logsource")
    if (
        not isinstance(source, dict)
        or not source
        or not all(isinstance(v, str) and v for v in source.values())
    ):
        fail("SCHEMA", "logsource must be a nonempty string mapping")
    for key, allowed in {
        "status": {"stable", "test", "experimental", "deprecated", "unsupported"},
        "level": {"informational", "low", "medium", "high", "critical"},
    }.items():
        if key in data and (not isinstance(data[key], str) or data[key] not in allowed):
            fail("SCHEMA", f"Invalid {key}")
    for key in ("tags", "references", "fields", "falsepositives"):
        if key in data and (
            not isinstance(data[key], list) or not all(isinstance(v, str) for v in data[key])
        ):
            fail("SCHEMA", f"{key} must be a string list")
    detection = data.get("detection")
    if not isinstance(detection, dict) or not isinstance(detection.get("condition"), str):
        fail("SCHEMA", "detection.condition must be a string")
    selectors = {k: v for k, v in detection.items() if k != "condition"}
    if not selectors or len(selectors) > 128:
        fail("SCHEMA", "Expected 1..128 selectors")
    for name, selector in selectors.items():
        if not re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", name) or name in {
            "and",
            "or",
            "not",
            "all",
            "of",
            "them",
        }:
            fail("SCHEMA", f"Invalid selector name: {name}")
        if not isinstance(selector, dict) or not selector:
            fail("UNSUPPORTED", "Only nonempty map selectors are supported")
        for key, value in selector.items():
            field, *mods = key.split("|")
            if not field or any(m not in MODIFIERS for m in mods) or len(set(mods)) != len(mods):
                fail("MODIFIER", f"Unsupported field/modifier: {key}")
            transforms = set(mods) - {"all"}
            if len(transforms) > 1 or ("exists" in mods and mods != ["exists"]):
                fail("MODIFIER", "Modifier combination is unsupported")
            values = value if isinstance(value, list) else [value]
            if not values or len(values) > 128:
                fail("SCHEMA", "Value lists must contain 1..128 values")
            for item in values:
                if item is not None and type(item) not in (str, int, bool):
                    fail("UNSUPPORTED", "Only strings, integers, booleans and null are supported")
                if mods and "exists" not in mods and not isinstance(item, str):
                    fail("MODIFIER", "String modifiers require string values")
                if "exists" in mods and type(value) is not bool:
                    fail("MODIFIER", "exists requires a scalar boolean")
    ast = Condition(detection["condition"], selectors).parse()
    known = {
        "title",
        "id",
        "logsource",
        "detection",
        "status",
        "level",
        "tags",
        "references",
        "fields",
        "falsepositives",
        "description",
        "author",
        "date",
        "modified",
        "license",
        "related",
        "name",
        "taxonomy",
        "scope",
    }
    warnings = [f"Unknown metadata preserved: {key}" for key in data if key not in known]
    return Rule(data, selectors, ast, warnings)


def scalar(value):
    return str(value).lower() if isinstance(value, bool) else str(value)


def pattern(value, mods):
    text = scalar(value)
    result, pos = "", 0
    while pos < len(text):
        char = text[pos]
        if char == "\\" and pos + 1 < len(text) and text[pos + 1] in "*?\\":
            pos += 1
            result += re.escape(text[pos])
        elif char == "*":
            result += ".*"
        elif char == "?":
            result += "."
        else:
            result += re.escape(char)
        pos += 1
    return (
        "(?i)"
        + ("" if "contains" in mods or "endswith" in mods else "\\A")
        + result
        + ("" if "contains" in mods or "startswith" in mods else "\\z")
    )


def walk(ast, selector, combine):
    op = ast[0]
    if op == "selector":
        return selector(ast[1])
    return combine(op, [walk(child, selector, combine) for child in ast[1:]])


def matches(rule, event):
    if not isinstance(event, dict) or any(isinstance(v, (dict, list)) for v in event.values()):
        fail("EVENT", "Synthetic events must be flat scalar mappings")

    def selection(name):
        checks = []
        for key, value in rule.selectors[name].items():
            field, *mods = key.split("|")
            actual = event.get(field)
            if "exists" in mods:
                checks.append((actual is not None) == value)
                continue
            values = value if isinstance(value, list) else [value]
            results = [
                actual is None
                if item is None
                else actual is not None
                and re.search(pattern(item, mods).replace("\\z", "\\Z"), scalar(actual), re.DOTALL)
                is not None
                for item in values
            ]
            checks.append(all(results) if "all" in mods else any(results))
        return all(checks)

    return walk(
        rule.ast,
        selection,
        lambda op, values: (
            not values[0] if op == "not" else all(values) if op == "and" else any(values)
        ),
    )


def convert(rule, pipeline):
    if (
        not isinstance(pipeline, dict)
        or type(pipeline.get("version")) is not int
        or pipeline.get("version") != 1
    ):
        fail("PIPELINE", "Pipeline requires version: 1")
    if pipeline.get("logsource") != rule.metadata["logsource"]:
        fail("PIPELINE", "Pipeline logsource must exactly match the rule")
    fields = pipeline.get("fields")
    if not isinstance(fields, dict) or not all(
        isinstance(k, str) and isinstance(v, str) and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*", v)
        for k, v in fields.items()
    ):
        fail("PIPELINE", "fields must map Sigma fields to safe Splunk identifiers")
    scope = pipeline.get("scope")
    if (
        not isinstance(scope, dict)
        or not scope
        or any(k not in {"index", "sourcetype", "source", "host"} for k in scope)
    ):
        fail("PIPELINE", "scope must define index/sourcetype/source/host")
    if not all(isinstance(v, str) and re.fullmatch(r"[A-Za-z_0-9.:-]+", v) for v in scope.values()):
        fail("PIPELINE", "Scope values require literal safe identifiers")

    def quote(text):
        return (
            '"'
            + text.replace("\\", "\\\\")
            .replace('"', '\\"')
            .replace("\n", "\\n")
            .replace("\r", "\\r")
            .replace("\t", "\\t")
            + '"'
        )

    def selection(name):
        checks = []
        for key, value in rule.selectors[name].items():
            field, *mods = key.split("|")
            if field not in fields:
                fail("PIPELINE", f"Missing field mapping: {field}")
            target = fields[field]
            if "exists" in mods:
                checks.append(f"{'isnotnull' if value else 'isnull'}('{target}')")
                continue
            values = value if isinstance(value, list) else [value]
            predicates = [
                f"isnull('{target}')"
                if item is None
                else f"coalesce(match('{target}', {quote(pattern(item, mods).replace('(?i)', '(?is)', 1))}), false())"
                for item in values
            ]
            checks.append("(" + (" AND " if "all" in mods else " OR ").join(predicates) + ")")
        return "(" + " AND ".join(checks) + ")"

    expression = walk(
        rule.ast,
        selection,
        lambda op, args: (
            "(NOT " + args[0] + ")"
            if op == "not"
            else "(" + (" AND " if op == "and" else " OR ").join(args) + ")"
        ),
    )
    return (
        "search "
        + " ".join(f"{k}={quote(v)}" for k, v in sorted(scope.items()))
        + " | where "
        + expression
    )
