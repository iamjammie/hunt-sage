#!/usr/bin/env python3
"""Validate Sigma rules in research/sigma/.

Checks (offline, no network needed):
  * YAML parses and pySigma accepts the rule (no parse errors)
  * required metadata is present and ids are unique UUIDs
  * ATT&CK tags are well formed and the filename technique matches a tag
  * the rule converts with the Splunk and Kusto backends (when installed)
  * every rule file is listed in research/sigma/index.md

Usage: python scripts/validate_rules.py
"""
import re
import sys
import uuid
from pathlib import Path

import yaml
from sigma.collection import SigmaCollection

ROOT = Path(__file__).resolve().parent.parent
RULE_DIR = ROOT / "research" / "sigma"
REQUIRED = ["title", "id", "status", "description", "references", "author", "date",
            "logsource", "detection", "falsepositives", "level", "tags"]
STATUSES = {"experimental", "test", "stable", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
TACTICS = {"initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
           "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
           "exfiltration", "impact", "resource_development", "reconnaissance"}
TECH_RE = re.compile(r"^attack\.t\d{4}(\.\d{3})?$")


def backends():
    out = []
    try:
        from sigma.backends.splunk import SplunkBackend
        from sigma.pipelines.windows import windows_logsource_pipeline
        out.append(("splunk", lambda: SplunkBackend(windows_logsource_pipeline())))
    except ImportError:
        print("note: splunk backend not installed; skipping conversion check")
    try:
        from sigma.backends.kusto import KustoBackend
        from sigma.pipelines.windows import windows_logsource_pipeline
        out.append(("kusto", lambda: KustoBackend(windows_logsource_pipeline())))
    except ImportError:
        print("note: kusto backend not installed; skipping conversion check")
    return out


def main() -> int:
    errors: list[str] = []
    ids: dict[str, str] = {}
    index_text = (RULE_DIR / "index.md").read_text(encoding="utf-8")
    conv = backends()
    files = sorted(RULE_DIR.glob("*.yml"))
    if not files:
        errors.append("no rule files found")

    for path in files:
        name = path.name
        text = path.read_text(encoding="utf-8")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            errors.append(f"{name}: invalid YAML: {exc}")
            continue

        for key in REQUIRED:
            if key not in data:
                errors.append(f"{name}: missing required key '{key}'")

        rid = str(data.get("id", ""))
        try:
            uuid.UUID(rid)
        except ValueError:
            errors.append(f"{name}: id '{rid}' is not a UUID")
        if rid in ids:
            errors.append(f"{name}: duplicate id (also {ids[rid]})")
        ids[rid] = name

        if data.get("status") not in STATUSES:
            errors.append(f"{name}: bad status {data.get('status')!r}")
        if data.get("level") not in LEVELS:
            errors.append(f"{name}: bad level {data.get('level')!r}")

        tags = data.get("tags") or []
        techs = [t for t in tags if t.startswith("attack.t")]
        tacs = [t for t in tags if t.startswith("attack.") and not t.startswith("attack.t")]
        if not techs:
            errors.append(f"{name}: no ATT&CK technique tag")
        for t in techs:
            if not TECH_RE.match(t):
                errors.append(f"{name}: malformed technique tag {t}")
        for t in tacs:
            if t.split(".", 1)[1] not in TACTICS:
                errors.append(f"{name}: unknown tactic tag {t}")
        m = re.match(r"^(T\d{4}(?:\.\d{3})?)-", name)
        if not m:
            errors.append(f"{name}: filename should start with the technique id (e.g. T1059.001-...)")
        elif f"attack.{m.group(1).lower()}" not in tags:
            errors.append(f"{name}: filename technique {m.group(1)} not present in tags")

        try:
            coll = SigmaCollection.from_yaml(text)
            for rule in coll.rules:
                for err in rule.errors:
                    errors.append(f"{name}: pySigma: {err}")
            for label, factory in conv:
                try:
                    factory().convert(coll)
                except Exception as exc:  # noqa: BLE001 - report any conversion failure
                    errors.append(f"{name}: {label} conversion failed: {type(exc).__name__}: {str(exc)[:120]}")
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: pySigma rejected rule: {type(exc).__name__}: {str(exc)[:160]}")

        if name not in index_text:
            errors.append(f"{name}: not listed in research/sigma/index.md")

    if errors:
        print(f"FAILED: {len(errors)} problem(s)")
        for e in errors:
            print("  -", e)
        return 1
    print(f"OK: {len(files)} rules validated")
    return 0


if __name__ == "__main__":
    sys.exit(main())
