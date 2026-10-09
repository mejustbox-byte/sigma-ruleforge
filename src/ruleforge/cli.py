"""Offline command line interface."""

import argparse
import hashlib
import json
import os
import tempfile
from pathlib import Path

from . import __version__
from .core import RuleError, convert, fail, load_json, load_yaml, matches, read_bytes, validate


def paths(value):
    root = Path(value)
    if root.is_dir():
        result = sorted(p for p in root.rglob("*") if p.suffix.lower() in (".yml", ".yaml"))
        if not result:
            fail("INPUT", "Directory contains no YAML rules")
        return result
    return [root]


def attack_index(dataset):
    if (
        not isinstance(dataset, dict)
        or dataset.get("type") != "bundle"
        or not isinstance(dataset.get("objects"), list)
    ):
        fail("DATASET", "Expected a local ATT&CK STIX bundle")
    ids = {}
    for obj in dataset["objects"]:
        if not isinstance(obj, dict):
            fail("DATASET", "Invalid STIX object")
        if obj.get("type") not in ("attack-pattern", "x-mitre-tactic"):
            continue
        references = obj.get("external_references", [])
        if not isinstance(references, list) or not all(isinstance(ref, dict) for ref in references):
            fail("DATASET", "Invalid external_references")
        keys = []
        for ref in references:
            if ref.get("source_name") == "mitre-attack" and isinstance(ref.get("external_id"), str):
                keys.append(ref["external_id"].lower())
        if obj.get("type") == "x-mitre-tactic" and isinstance(obj.get("x_mitre_shortname"), str):
            keys.append(obj["x_mitre_shortname"].lower())
        for key in keys:
            if key in ids:
                fail("DATASET", f"Ambiguous ATT&CK identifier: {key}")
            ids[key] = obj
    return ids


def attack_map(rule, ids):
    output = []
    for tag in rule.metadata.get("tags", []):
        if tag.lower().startswith("attack."):
            identifier = tag[7:].lower()
            obj = ids.get(identifier)
            if obj is None:
                output.append({"tag": tag, "status": "unknown"})
            else:
                output.append(
                    {
                        "tag": tag,
                        "name": obj.get("name"),
                        "type": obj["type"],
                        "domains": obj.get("x_mitre_domains", []),
                        "status": "revoked"
                        if obj.get("revoked")
                        else "deprecated"
                        if obj.get("x_mitre_deprecated")
                        else "active",
                    }
                )
    return output


def test_manifest(path):
    root = Path(path).resolve().parent
    manifest = load_json(path)
    if (
        not isinstance(manifest, dict)
        or not isinstance(manifest.get("cases"), list)
        or not manifest["cases"]
    ):
        fail("MANIFEST", "Manifest requires a nonempty cases list")
    results = []
    for case in manifest["cases"]:
        rule = validate(root / case["rule"])
        checks = []
        for fixture in case.get("events", []):
            if type(fixture.get("match")) is not bool:
                fail("MANIFEST", "Event expectations require boolean match")
            checks.append(matches(rule, fixture["event"]) == fixture["match"])
        if "pipeline" in case:
            query = convert(rule, load_yaml(root / case["pipeline"]))
            checks.append(query + "\n" == read_bytes(root / case["golden"]).decode("utf-8"))
        if not checks:
            fail("MANIFEST", "Case has no event or golden checks")
        results.append({"rule": case["rule"], "checks": len(checks), "passed": all(checks)})
    return results


def write_output(path, content, overwrite):
    target = Path(path)
    # Exclusive creation prevents accidental overwrite; replace is atomic when requested.
    if not overwrite:
        with target.open("x", encoding="utf-8") as stream:
            stream.write(content)
        return
    fd, name = tempfile.mkstemp(dir=target.parent, prefix=".ruleforge-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(content)
        os.replace(name, target)
    finally:
        Path(name).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline Sigma supported-profile toolkit")
    parser.add_argument("--version", action="version", version=__version__)
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("validate", "convert", "attack-map"):
        sub = commands.add_parser(command)
        sub.add_argument("path")
        sub.add_argument("--format", choices=("text", "json"), default="text")
        sub.add_argument("--strict", action="store_true")
        if command == "convert":
            sub.add_argument("--backend", choices=("splunk",), default="splunk")
            sub.add_argument("--pipeline", required=True)
            sub.add_argument("--output")
            sub.add_argument("--overwrite", action="store_true")
        elif command == "attack-map":
            sub.add_argument("--dataset", required=True)
    sub = commands.add_parser("test")
    sub.add_argument("--manifest", required=True)
    sub.add_argument("--format", choices=("text", "json"), default="text")
    sub = commands.add_parser("backends")
    sub.add_argument("--format", choices=("text", "json"), default="text")
    args = parser.parse_args(argv)
    code, output = 0, []
    try:
        if args.command == "backends":
            output = [
                {
                    "name": "splunk",
                    "dialect": "SPL1 where/match",
                    "version": __version__,
                    "modifiers": ["contains", "startswith", "endswith", "all", "exists"],
                    "conditions": ["and", "or", "not", "1 of", "all of"],
                }
            ]
        elif args.command == "test":
            output = test_manifest(args.manifest)
            code = 0 if all(item["passed"] for item in output) else 1
        else:
            pipeline = load_yaml(args.pipeline) if args.command == "convert" else None
            dataset = (
                attack_index(load_json(args.dataset, dataset=True))
                if args.command == "attack-map"
                else None
            )
            pipeline_digest = (
                hashlib.sha256(read_bytes(args.pipeline)).hexdigest()
                if pipeline is not None
                else None
            )
            dataset_digest = (
                hashlib.sha256(read_bytes(args.dataset, 128 * 1_048_576)).hexdigest()
                if dataset is not None
                else None
            )
            seen = set()
            for path in paths(args.path):
                try:
                    rule = validate(path)
                    identifier = rule.metadata["id"].lower()
                    if identifier in seen:
                        fail("DUPLICATE_ID", "Duplicate rule id in batch")
                    seen.add(identifier)
                    item = {
                        "file": path.name,
                        "id": identifier,
                        "valid": True,
                        "warnings": rule.warnings,
                    }
                    if args.command == "convert":
                        item["query"] = convert(rule, pipeline)
                        item["manifest"] = {
                            "tool": __version__,
                            "sigma_specification": "2.1.0",
                            "input_sha256": hashlib.sha256(read_bytes(path)).hexdigest(),
                            "pipeline_sha256": pipeline_digest,
                        }
                    elif args.command == "attack-map":
                        item["attack"] = attack_map(rule, dataset)
                        item["dataset_sha256"] = dataset_digest
                        item["warnings"] += [
                            f"{v['tag']}: {v['status']}"
                            for v in item["attack"]
                            if v["status"] != "active"
                        ]
                    if args.strict and item["warnings"]:
                        item["valid"] = False
                        code = 1
                    output.append(item)
                except RuleError as exc:
                    code = 1
                    output.append({"file": path.name, "valid": False, "error": exc.diagnostic()})
            if args.command == "convert" and args.output and code == 0:
                if len(output) != 1:
                    fail("OUTPUT", "--output requires exactly one rule")
                write_output(args.output, output[0]["query"] + "\n", args.overwrite)
    except RuleError as exc:
        output, code = [{"error": exc.diagnostic()}], 1
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        output, code = [{"error": {"code": "CONFIG", "message": str(exc)}}], 2
    except OSError as exc:
        output, code = [{"error": {"code": "IO", "message": str(exc)}}], 3
    if args.format == "json":
        print(json.dumps(output, ensure_ascii=False, indent=2))
    else:
        for item in output:
            print(
                item["query"]
                if "query" in item and code == 0
                else json.dumps(item, ensure_ascii=False)
            )
    return code


if __name__ == "__main__":
    raise SystemExit(main())
