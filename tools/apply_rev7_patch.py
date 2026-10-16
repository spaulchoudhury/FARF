"""rev 7 patcher (15 Oct 2026): adds three profiles and one scenario to tools/local_profiles.py.
    scale-default      taint source unset (default setting), 30 senders x 40 messages        -> scale     (closes the open half of G5, run list T6)
    patient            behaviour_gated bus, real clock                                       -> patient   (run list T5)
    patient-identity   identity bus, real clock                                              -> patient   (run list T5)
Same rules as apply_rev6_patch.py: idempotent, keeps the file's line endings (CRLF stays CRLF), writes nothing unless every anchor is found.
    python tools/apply_rev7_patch.py --check     # reports; writes nothing
    python tools/apply_rev7_patch.py             # applies
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TARGET = os.path.join(ROOT, "tools", "local_profiles.py")

EDITS = [
    # (marker that proves the edit is already in, anchor line to find, text inserted AFTER the anchor line)
    ("scale-default",
     '        "reseedguard": (8307, {**LOOP, "FARF_FB_RESEED_GUARD": "1"}, ["loop"]),\n',
     '        "scale-default": (8309, {}, ["scale"]),\n'
     '        "patient": (8310, dict(gated), ["patient"]),\n'
     '        "patient-identity": (8311, {}, ["patient"]),\n'),
    ("v11_collusion_patient_cloud.py",
     '        "collusion": [py, os.path.join(PC, "v11_collusion_cloud.py"), "--url", url, "--cooling-off", str(cool), "--witnesses", "4"],\n',
     '        "patient": [py, os.path.join(PC, "v11_collusion_patient_cloud.py"), "--url", url, "--cooling-off", str(cool),\n'
     '                    "--horizon", os.environ.get("FARF_PATIENT_HORIZON", "120")],\n'),
    ("taint_source unset (the shipped default)",
     '  hopcap    scoped loop with hop_cap=1                                         -> loop\n',
     '  scale-default  taint_source unset (the shipped default)                      -> benign-scale (30 senders x 40 msgs)\n'
     '  patient   behaviour_gated, real clock (minority + patient attacker)          -> patient\n'
     '  patient-identity  identity mode, real clock                                  -> patient\n'),
]


def main() -> int:
    check = "--check" in sys.argv
    with open(TARGET, "rb") as fh:
        raw = fh.read().decode("utf-8")
    crlf = "\r\n" in raw
    text = raw.replace("\r\n", "\n")
    problems, todo = [], []
    for marker, anchor, add in EDITS:
        if marker in text:
            continue
        if text.count(anchor) != 1:
            problems.append(anchor.strip()[:90])
        else:
            todo.append((anchor, add))
    if problems:
        print("STOP - nothing was written. These anchor lines were not found exactly once in tools/local_profiles.py:")
        for p in problems:
            print("  -", p)
        return 1
    if not todo:
        print("already patched: nothing to do")
        return 0
    if check:
        print(f"check OK: {len(todo)} edit(s) would be applied to tools/local_profiles.py")
        return 0
    for anchor, add in todo:
        text = text.replace(anchor, anchor + add, 1)
    out = text.replace("\n", "\r\n") if crlf else text
    with open(TARGET, "wb") as f:
        f.write(out.encode("utf-8"))
    print(f"patched tools/local_profiles.py ({len(todo)} edit(s), line endings {'CRLF' if crlf else 'LF'} kept)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
