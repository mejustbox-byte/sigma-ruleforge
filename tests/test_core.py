import json
from pathlib import Path

import pytest

from ruleforge.cli import main
from ruleforge.cli import test_manifest as run_manifest
from ruleforge.core import RuleError, convert, load_yaml, matches, validate

ROOT = Path(__file__).resolve().parents[1]
BASE = (ROOT / "examples/process_creation.yml").read_text()


def rule(tmp_path, text=BASE):
    path = tmp_path / "rule.yml"
    path.write_text(text, encoding="utf-8")
    return path


@pytest.mark.parametrize(
    "tail,code",
    [
        ("\ntitle: duplicate\n", "YAML_DUPLICATE"),
        ("\nx: &anchor value\n", "YAML_FEATURE"),
        ("\nx: !!python/object:os.system {}\n", "YAML_FEATURE"),
        ("\n---\nx: 1\n", "YAML_SYNTAX"),
    ],
)
def test_unsafe_yaml(tmp_path, tail, code):
    with pytest.raises(RuleError) as exc:
        validate(rule(tmp_path, BASE + tail))
    assert exc.value.code == code
    assert exc.value.line


@pytest.mark.parametrize(
    "old,new,code",
    [
        ("selection and not filter", "selection and absent", "CONDITION"),
        ("selection and not filter", "selection | count() > 1", "CONDITION"),
        ("Image|endswith", "Image|re", "MODIFIER"),
        ("7b79be24-6d8a-4c31-bd15-df297b38e8b3", "invalid", "SCHEMA"),
        ("level: medium", "level: [high]", "SCHEMA"),
        ("selection and not filter", "(" * 41 + "selection" + ")" * 41, "INPUT_LIMIT"),
    ],
)
def test_invalid_profile(tmp_path, old, new, code):
    with pytest.raises(RuleError) as exc:
        validate(rule(tmp_path, BASE.replace(old, new)))
    assert exc.value.code == code


@pytest.mark.parametrize(
    "condition,expected",
    [
        ("selection", True),
        ("selection and not filter", True),
        ("not selection", False),
        ("1 of them", True),
        ("all of them", False),
        ("all of sel*", True),
        ("filter or selection and not filter", True),
        ("(filter or selection) and filter", False),
    ],
)
def test_conditions(tmp_path, condition, expected):
    parsed = validate(rule(tmp_path, BASE.replace("selection and not filter", condition)))
    assert matches(parsed, {"Image": "C:\\cmd.exe", "CommandLine": "WHOAMI"}) is expected


@pytest.mark.parametrize(
    "value,event,expected",
    [
        ("null", {}, True),
        ("null", {"Field": ""}, False),
        ("'a*b?'", {"Field": "AXXBY"}, True),
        ("'a\\*b'", {"Field": "a*b"}, True),
        ("'a\\*b'", {"Field": "axxb"}, False),
        ("false", {"Field": False}, True),
        ("42", {"Field": "42"}, True),
    ],
)
def test_values(tmp_path, value, event, expected):
    text = f"title: Test\nid: 7b79be24-6d8a-4c31-bd15-df297b38e8b3\nlogsource:\n  product: test\ndetection:\n  selection:\n    Field: {value}\n  condition: selection\n"
    assert matches(validate(rule(tmp_path, text)), event) is expected


def test_pipeline(tmp_path):
    parsed = validate(rule(tmp_path))
    pipeline = load_yaml(ROOT / "examples/splunk.yml")
    query = convert(parsed, pipeline)
    assert "coalesce(match(" in query and "(NOT " in query
    del pipeline["fields"]["Image"]
    with pytest.raises(RuleError, match="Missing field mapping"):
        convert(parsed, pipeline)
    pipeline["fields"]["Image"] = "Image) | delete"
    with pytest.raises(RuleError):
        convert(parsed, pipeline)


def test_manifest_golden():
    assert all(c["passed"] for c in run_manifest(ROOT / "examples/manifest.json"))


def test_output_and_exit_codes(tmp_path, capsys):
    path = rule(tmp_path)
    target = tmp_path / "query.spl"
    args = [
        "convert",
        str(path),
        "--pipeline",
        str(ROOT / "examples/splunk.yml"),
        "--output",
        str(target),
    ]
    assert main(args) == 0
    original = target.read_text()
    assert main(args) == 3
    assert target.read_text() == original
    assert main(args + ["--overwrite"]) == 0
    assert main(["validate", str(tmp_path / "absent.yml"), "--format", "json"]) == 3
    capsys.readouterr()
    assert main(["backends", "--format", "json"]) == 0
    assert json.loads(capsys.readouterr().out)[0]["name"] == "splunk"


def test_batch_duplicate_and_strict(tmp_path):
    rule(tmp_path)
    (tmp_path / "second.yml").write_text(BASE)
    assert main(["validate", str(tmp_path)]) == 1
    (tmp_path / "second.yml").unlink()
    rule(tmp_path, BASE + "\ncustom: value\n")
    assert main(["validate", str(tmp_path), "--strict"]) == 1


def test_limits(tmp_path):
    with pytest.raises(RuleError) as exc:
        validate(rule(tmp_path, "x" * 1_048_577))
    assert exc.value.code == "INPUT_LIMIT"
    with pytest.raises(RuleError):
        load_yaml(rule(tmp_path, "[" * 41 + "0" + "]" * 41))


def test_attack_snapshot(tmp_path, capsys):
    dataset = tmp_path / "attack.json"
    dataset.write_text(
        json.dumps(
            {
                "type": "bundle",
                "objects": [
                    {
                        "type": "attack-pattern",
                        "name": "Windows Command Shell",
                        "external_references": [
                            {"source_name": "mitre-attack", "external_id": "T1059.003"}
                        ],
                    }
                ],
            }
        )
    )
    assert (
        main(["attack-map", str(rule(tmp_path)), "--dataset", str(dataset), "--format", "json"])
        == 0
    )
    assert json.loads(capsys.readouterr().out)[0]["attack"][0]["status"] == "active"
    dataset.write_text('{"type":"bundle","objects":[]}')
    assert (
        main(["attack-map", str(tmp_path / "rule.yml"), "--dataset", str(dataset), "--strict"]) == 1
    )


@pytest.mark.parametrize(
    "key,value,event,expected",
    [
        ("Field|exists", "true", {}, False),
        ("Field|exists", "false", {}, True),
        ("Field|contains|all", "['one', 'two']", {"Field": "ONE and TWO"}, True),
        ("Field|contains|all", "['one', 'two']", {"Field": "one"}, False),
        ("Field|startswith", "'foo'", {"Field": "foobar"}, True),
        ("Field|startswith", "'foo'", {"Field": "afoo"}, False),
        ("Field", "''", {"Field": ""}, True),
        ("Field", "''", {}, False),
    ],
)
def test_modifiers(tmp_path, key, value, event, expected):
    text = f"title: Test\nid: 7b79be24-6d8a-4c31-bd15-df297b38e8b3\nlogsource:\n  product: test\ndetection:\n  selection:\n    {key}: {value}\n  condition: selection\n"
    assert matches(validate(rule(tmp_path, text)), event) is expected


def test_uuid_normalization(tmp_path):
    path = rule(tmp_path)
    (tmp_path / "second.yml").write_text(
        BASE.replace(
            "7b79be24-6d8a-4c31-bd15-df297b38e8b3", "{7b79be24-6d8a-4c31-bd15-df297b38e8b3}"
        )
    )
    assert main(["validate", str(tmp_path)]) == 1
    assert validate(path).metadata["id"] == "7b79be24-6d8a-4c31-bd15-df297b38e8b3"
