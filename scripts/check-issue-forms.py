#!/usr/bin/env python3
"""Checks .github/ISSUE_TEMPLATE/*.yml against GitHub's issue-form rules.

actionlint does not read issue forms, and GitHub reports a broken form only by
not offering it. This checks what GitHub documents for issue forms and for the
template chooser (config.yml):

  forms:  name, description and a non-empty body are required; top-level keys
          are limited to the documented ones; every body element has a known
          type; markdown has attributes.value; the others have attributes.label;
          ids and labels are unique, ids use [A-Za-z0-9_-]; dropdowns have a
          non-empty list of unique options; checkboxes have options with a
          label; validations.required is a boolean; at least one element is
          not markdown.
  config: blank_issues_enabled is a boolean; each contact link has name, url
          (https) and about.

YAML is read with PyYAML when it is installed, otherwise with Ruby's YAML
library (macOS and the CI images have one of the two).

Usage: scripts/check-issue-forms.py [DIR]   (default .github/ISSUE_TEMPLATE)
"""

import json
import pathlib
import re
import subprocess
import sys

FORM_KEYS = {"name", "description", "body", "title", "labels", "assignees", "projects", "type"}
TYPES = {"markdown", "input", "textarea", "dropdown", "checkboxes"}
ID_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def load(path):
    try:
        import yaml  # type: ignore

        with open(path, encoding="utf-8") as f:
            return yaml.safe_load(f)
    except ImportError:
        out = subprocess.run(
            ["ruby", "-ryaml", "-rjson", "-e", "puts JSON.dump(YAML.safe_load_file(ARGV[0]))", str(path)],
            capture_output=True,
            text=True,
        )
        if out.returncode != 0:
            raise ValueError(out.stderr.strip().splitlines()[0] if out.stderr.strip() else "ruby failed")
        return json.loads(out.stdout)


def check_form(doc, err):
    if not isinstance(doc, dict):
        return err("the file is not a mapping")
    for key in ("name", "description"):
        if not isinstance(doc.get(key), str) or not doc[key].strip():
            err(f"'{key}' is required and must be a non-empty string")
    for key in doc:
        if key not in FORM_KEYS:
            err(f"unknown top-level key '{key}'")
    labels = doc.get("labels")
    if labels is not None and not (isinstance(labels, list) and all(isinstance(x, str) for x in labels)):
        err("'labels' must be a list of strings")
    body = doc.get("body")
    if not isinstance(body, list) or not body:
        return err("'body' is required and must be a non-empty list")
    ids, field_labels, fields = set(), set(), 0
    for i, el in enumerate(body):
        where = f"body[{i}]"
        if not isinstance(el, dict):
            err(f"{where}: not a mapping")
            continue
        t = el.get("type")
        if t not in TYPES:
            err(f"{where}: unknown type {t!r}")
            continue
        attrs = el.get("attributes")
        if not isinstance(attrs, dict):
            err(f"{where} ({t}): 'attributes' is required")
            continue
        for key in el:
            if key not in {"type", "id", "attributes", "validations"}:
                err(f"{where}: unknown key '{key}'")
        if "id" in el:
            eid = el["id"]
            if not isinstance(eid, str) or not ID_RE.match(eid):
                err(f"{where}: id {eid!r} must match [A-Za-z0-9_-]+")
            elif eid in ids:
                err(f"{where}: duplicate id '{eid}'")
            ids.add(eid)
        if t == "markdown":
            if not isinstance(attrs.get("value"), str) or not attrs["value"].strip():
                err(f"{where} (markdown): attributes.value is required")
            if "validations" in el:
                err(f"{where} (markdown): markdown takes no validations")
            continue
        fields += 1
        label = attrs.get("label")
        if not isinstance(label, str) or not label.strip():
            err(f"{where} ({t}): attributes.label is required")
        elif label in field_labels:
            err(f"{where}: duplicate label '{label}'")
        else:
            field_labels.add(label)
        if t == "dropdown":
            opts = attrs.get("options")
            if not isinstance(opts, list) or not opts or not all(isinstance(o, str) and o for o in opts):
                err(f"{where} (dropdown): attributes.options must be a non-empty list of strings")
            elif len(set(opts)) != len(opts):
                err(f"{where} (dropdown): options must be unique")
        if t == "checkboxes":
            opts = attrs.get("options")
            if not isinstance(opts, list) or not opts:
                err(f"{where} (checkboxes): attributes.options must be a non-empty list")
            else:
                for j, o in enumerate(opts):
                    if not isinstance(o, dict) or not isinstance(o.get("label"), str) or not o["label"]:
                        err(f"{where} (checkboxes): options[{j}] needs a label")
                    elif "required" in o and not isinstance(o["required"], bool):
                        err(f"{where} (checkboxes): options[{j}].required must be a boolean")
        v = el.get("validations")
        if v is not None:
            if not isinstance(v, dict) or set(v) - {"required"}:
                err(f"{where}: validations may only hold 'required'")
            elif "required" in v and not isinstance(v["required"], bool):
                err(f"{where}: validations.required must be a boolean")
    if fields == 0:
        err("the body needs at least one element that is not markdown")


def check_config(doc, err):
    if not isinstance(doc, dict):
        return err("the file is not a mapping")
    for key in doc:
        if key not in {"blank_issues_enabled", "contact_links"}:
            err(f"unknown key '{key}'")
    if "blank_issues_enabled" in doc and not isinstance(doc["blank_issues_enabled"], bool):
        err("blank_issues_enabled must be a boolean")
    for i, link in enumerate(doc.get("contact_links") or []):
        if not isinstance(link, dict):
            err(f"contact_links[{i}]: not a mapping")
            continue
        for key in ("name", "url", "about"):
            if not isinstance(link.get(key), str) or not link[key].strip():
                err(f"contact_links[{i}]: '{key}' is required")
        if isinstance(link.get("url"), str) and not link["url"].startswith("https://"):
            err(f"contact_links[{i}]: url must be https")


def main():
    root = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else ".github/ISSUE_TEMPLATE")
    files = sorted(root.glob("*.yml")) + sorted(root.glob("*.yaml"))
    if not files:
        print(f"check-issue-forms: no .yml files in {root}", file=sys.stderr)
        return 1
    failed = 0
    for path in files:
        problems = []
        try:
            doc = load(path)
        except Exception as e:  # a YAML syntax error: GitHub would not offer the form
            print(f"{path}: not valid YAML: {e}", file=sys.stderr)
            failed += 1
            continue
        (check_config if path.stem == "config" else check_form)(doc, problems.append)
        for p in problems:
            print(f"{path}: {p}", file=sys.stderr)
        failed += bool(problems)
        if not problems:
            print(f"ok: {path}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
