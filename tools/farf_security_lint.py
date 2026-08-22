#!/usr/bin/env python3
"""
FARF Security Lint (VAST-style automated check)
======================================================================
Delivered as part of Tier 2 hardening (see RISK_APPENDIX.md Part E).
VAST (Visual, Agile, Simple Threat modeling) is about scale and process
integration, not deep one-time manual analysis -- the recommendation
this script acts on is "turn this codebase's manual review process into
a repeatable, automated gate a CI pipeline can run on every change."

This is a lightweight, dependency-free TEXT scan (regex over source
files), deliberately NOT a full AST-based static analyzer. That's a
conscious trade-off: this script is simple enough to read top to bottom
and audit by eye in a few minutes, at the cost of being foolable by
sufficiently unusual code style (e.g. a send() call constructed via
**kwargs unpacking, or an action_type built from string concatenation
rather than a literal). Treat HIGH CONFIDENCE findings as real; treat
LOW CONFIDENCE findings as "look at this by hand," not as ground truth.

Checks implemented:

  1. HIGH CONFIDENCE -- orphaned action_type. Every literal action_type
     string passed to a .send()/.sign_and_send() call must have a
     corresponding entry in orchestration.DEFAULT_ACTION_SCHEMAS.
     orchestration.py's own _schema_violation() docstring documents
     what happens if it doesn't: "no schema registered for this
     action_type" silently returns "no violation" -- that action_type
     gets ZERO schema enforcement. This is exactly the class of
     regression a careless future change (add a new action_type,
     forget to register its schema) would introduce silently.

  2. LOW CONFIDENCE / heuristic -- raw .send(...) calls with no
     `signature=` argument nearby, in a file that never sets
     `require_message_signatures=False` anywhere. Several existing
     pentest scripts (PT-07, PT-09's Sybil-triggering loop, etc.)
     legitimately call raw send() because they're deliberately testing
     with signing disabled to isolate a different layer -- this check
     tries to exclude those (by checking for the opt-out string
     anywhere in the file) but this is a rough proxy, not a real
     per-bus-instance analysis, hence "low confidence."

Usage:
    python tools/farf_security_lint.py
    # exit code 0: no HIGH CONFIDENCE findings (heuristic findings alone don't fail the build)
    # exit code 1: at least one HIGH CONFIDENCE finding
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SEND_CALL_ACTION_TYPE = re.compile(
    r'\.(?:send|sign_and_send)\(\s*[^,()]+,\s*[^,()]+,\s*[^,()]+,\s*[^,()]+,\s*"([a-zA-Z0-9_]+)"'
)
RAW_SEND_CALL = re.compile(r'\bbus\w*\.send\(')


def _iter_py_files():
    for path in ROOT.rglob("*.py"):
        if "tools" in path.relative_to(ROOT).parts:
            continue
        yield path


def find_registered_action_types() -> set:
    text = (ROOT / "orchestration.py").read_text(errors="ignore")
    m = re.search(r"DEFAULT_ACTION_SCHEMAS[^=]*=\s*\{(.*?)\n\}", text, re.DOTALL)
    if not m:
        return set()
    return set(re.findall(r'"([a-zA-Z0-9_]+)"\s*:', m.group(1)))


def check_orphaned_action_types() -> list:
    registered = find_registered_action_types()
    findings = []
    for path in _iter_py_files():
        text = path.read_text(errors="ignore")
        for m in SEND_CALL_ACTION_TYPE.finditer(text):
            action_type = m.group(1)
            if action_type not in registered:
                line_no = text[:m.start()].count("\n") + 1
                rel = path.relative_to(ROOT)
                findings.append(
                    f"{rel}:{line_no}: action_type '{action_type}' used in a send() call but has NO "
                    f"entry in orchestration.DEFAULT_ACTION_SCHEMAS -- it will receive ZERO schema "
                    f"enforcement (see orchestration.py's _schema_violation() docstring)."
                )
    return findings


def check_unsigned_send_heuristic() -> list:
    findings = []
    for path in _iter_py_files():
        if path.name == "federation_bus.py":
            continue  # the trusted core itself, not a call site
        text = path.read_text(errors="ignore")
        opts_out = "require_message_signatures=False" in text
        # tests/*.py share a fixture (conftest.py) that constructs the
        # bus -- the opt-out can live there instead of in the test file
        # itself. Check the sibling conftest.py too, or this heuristic
        # would wrongly flag every test that relies on that fixture.
        conftest = path.parent / "conftest.py"
        if not opts_out and conftest.exists() and conftest != path:
            opts_out = "require_message_signatures=False" in conftest.read_text(errors="ignore")
        if opts_out:
            continue
        for m in RAW_SEND_CALL.finditer(text):
            window = text[m.end():m.end() + 400]
            if "signature=" in window:
                continue  # looks like a properly-signed raw call (e.g. pt14's race test)
            line_no = text[:m.start()].count("\n") + 1
            rel = path.relative_to(ROOT)
            findings.append(
                f"{rel}:{line_no}: raw .send(...) call with no 'signature=' nearby and no "
                f"'require_message_signatures=False' anywhere in this file or its conftest.py -- "
                f"confirm this is intentional, or use sign_and_send() instead."
            )
    return findings


def main() -> int:
    orphaned = check_orphaned_action_types()
    unsigned = check_unsigned_send_heuristic()

    print(f"FARF Security Lint -- {len(orphaned)} HIGH CONFIDENCE finding(s), "
          f"{len(unsigned)} LOW CONFIDENCE/heuristic finding(s)\n")

    if orphaned:
        print("=== Orphaned action_type (HIGH CONFIDENCE -- fails the build) ===")
        for f in orphaned:
            print(" -", f)
        print()

    if unsigned:
        print("=== Unsigned send() heuristic (LOW CONFIDENCE -- review manually, does not fail the build) ===")
        for f in unsigned:
            print(" -", f)
        print()

    if not orphaned and not unsigned:
        print("No findings.")

    return 1 if orphaned else 0


if __name__ == "__main__":
    sys.exit(main())
