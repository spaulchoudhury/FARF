"""Fallback for `git apply`: applies the rev6 re-seed-guard edits by anchored text replacement.

Safe by design: every edit checks that its anchor exists exactly once (and that the edit is not already applied);
if anything is missing it stops BEFORE writing any file. Preserves each file's line endings (LF or CRLF).
Run from the repo root:  python tools/apply_rev6_patch.py            (add --check to only verify)

rev 6.2: experiments/check_scope_reseeding.py is no longer patched by anchored edits (a local copy that differs
from the Oct 7 file made the anchors fail). It is REPLACED by _bundle6/replacements/check_scope_reseeding.py; the old file
is kept as check_scope_reseeding.py.bak_rev6. All failing anchors are reported at once, nothing is written on failure.
"""
import sys
from pathlib import Path

EDITS = {
"closed_loop.py": [(
'    hop_cap: int | None = None\n\n    def __post_init__(self):\n        if self.scope not in ("global", "scoped"):',
'''    hop_cap: int | None = None
    # v7.9.11 rev6 (G9/L15): opt-in incident-root re-seed guard. An org that was quarantined as COLLATERAL
    # of another org's incident (hop >= 1 inside an active scope) is remembered for `reseed_memory_s`
    # (default 6 x the scope decay). If it is quarantined again after that scope has decayed, it does NOT
    # become a fresh root and does not extend a new scope: its retry is read as a continuation of the
    # original incident. Default False keeps every earlier result reproducible.
    reseed_guard: bool = False
    reseed_memory_s: float | None = None

    def __post_init__(self):
        if self.scope not in ("global", "scoped"):''')],
"federation_bus.py": [(
'        self._incident_hop: dict[str, int] = {}        # org -> hop distance from its nearest active root\n',
'        self._incident_hop: dict[str, int] = {}        # org -> hop distance from its nearest active root\n'
'        self._collateral_marks: dict[str, float] = {}  # org -> last time it was quarantined as collateral (reseed_guard)\n'),
(
'        fb = self.fars_feedback\n        if fb.require_cold and not cold:\n            return\n        now = self._clock()\n        org_hop = self._incident_hop.get(org, 0)',
'''        fb = self.fars_feedback
        if fb.reseed_guard:
            # incident-root re-seed guard (opt-in; see FarsFeedback.reseed_guard)
            now_g = self._clock()
            in_scope = self._org_in_incident_scope(org)
            if in_scope and self._incident_hop.get(org, 0) >= 1:
                self._collateral_marks[org] = now_g       # quarantined as collateral of another org's incident
            elif not in_scope:
                mark = self._collateral_marks.get(org)
                decay = fb.decay_s if fb.decay_s is not None else self.reinstatement_policy.cooling_off_s
                memory = fb.reseed_memory_s if fb.reseed_memory_s is not None else 6.0 * decay
                if mark is not None and (now_g - mark) < memory:
                    self.closed_loop_events.append({"event": "reseed_suppressed", "org": org,
                                                    "since_collateral_s": round(now_g - mark, 3)})
                    return
        if fb.require_cold and not cold:
            return
        now = self._clock()
        org_hop = self._incident_hop.get(org, 0)''')],
"pentest_cloud/bus_service.py": [(
'        for env, key in (("FARF_FB_BETA", "beta"),',
'''        if os.environ.get("FARF_FB_RESEED_GUARD", "").strip() == "1":
            fk["reseed_guard"] = True
        if os.environ.get("FARF_FB_RESEED_MEMORY_S", "").strip():
            fk["reseed_memory_s"] = _env_float("FARF_FB_RESEED_MEMORY_S", 0.0)
        for env, key in (("FARF_FB_BETA", "beta"),''')],
"tools/local_profiles.py": [(
'        "hopcap": (8305, {**LOOP, "FARF_FB_HOP_CAP": "1"}, ["loop"]),\n',
'        "hopcap": (8305, {**LOOP, "FARF_FB_HOP_CAP": "1"}, ["loop"]),\n'
'        "reseedguard": (8307, {**LOOP, "FARF_FB_RESEED_GUARD": "1"}, ["loop"]),\n')],
}
MAIN_OLD = 'if __name__ == "__main__":'


REPLACE = {  # whole-file replacements (old copy kept as .bak_rev6)
    "experiments/check_scope_reseeding.py": "_bundle6/replacements/check_scope_reseeding.py",
}


def main():
    check_only = "--check" in sys.argv
    root = Path.cwd()
    staged, problems = {}, []
    for rel, edits in EDITS.items():
        p = root / rel
        if not p.exists():
            problems.append(f"{rel} not found (run from the repo root)")
            continue
        raw = p.read_bytes().decode("utf-8")
        crlf = "\r\n" in raw
        text = raw.replace("\r\n", "\n")
        if "reseed_guard" in text or "FARF_FB_RESEED_GUARD" in text:
            print(f"skip    {rel}: already patched")
            continue
        for old, new in edits:
            if text.count(old) != 1:
                problems.append(f"{rel}: anchor found {text.count(old)}x (need exactly 1): {old[:70]!r}")
            else:
                text = text.replace(old, new)
        staged[p] = text.replace("\n", "\r\n") if crlf else text
    repl = {}
    for rel, src in REPLACE.items():
        sp = root / src
        if not sp.exists():
            problems.append(f"replacement file missing: {src} (extract the bundle to .\\_bundle6 first)")
            continue
        new_raw = sp.read_bytes().decode("utf-8").replace("\r\n", "\n")
        p = root / rel
        if p.exists() and "reseed_guard" in p.read_bytes().decode("utf-8"):
            print(f"skip    {rel}: already replaced")
            continue
        crlf = p.exists() and b"\r\n" in p.read_bytes()
        repl[p] = new_raw.replace("\n", "\r\n") if crlf else new_raw
    if problems:
        print("STOP - nothing was written:")
        for q in problems:
            print("  -", q)
        sys.exit(1)
    if check_only:
        names = [str(k.relative_to(root)) for k in list(staged) + list(repl)]
        print("check OK:", ", ".join(names) or "nothing to do")
        return
    for p, text in staged.items():
        p.write_bytes(text.encode("utf-8"))
        print("patched ", p.relative_to(root))
    for p, text in repl.items():
        if p.exists():
            bak = p.with_name(p.name + ".bak_rev6")
            if not bak.exists():
                bak.write_bytes(p.read_bytes())
        p.write_bytes(text.encode("utf-8"))
        print("replaced", p.relative_to(root), "(old copy kept as .bak_rev6)")


if __name__ == "__main__":
    main()
