"""Start a LOCAL bus_service.py with a named configuration profile, run the HTTP scenario scripts against it, stop the bus.
Python replacement for the extra localbus profiles (no PowerShell quoting involved).
    python tools/local_profiles.py --profile full3 [--cooling-off 20] [--out <dir>]
Profiles (bus env -> scenarios):
  full      gated reinstatement + scoped-cold FARS loop                       -> gated, loop, personas, collusion, adaptive
  full3     full + taint_source=content (the three-way configuration)         -> gated, loop, content, adaptive
  personas  behaviour_gated                                                    -> personas (dormant, benign_fp), collusion
  collusion-identity  identity mode (the v7.9.10 path)                         -> collusion (documents the weakness)
  scale     taint_source=content                                               -> benign-scale (30 senders x 40 msgs)
  hopcap    scoped loop with hop_cap=1                                         -> loop
  scale-default  taint_source unset (the shipped default)                      -> benign-scale (30 senders x 40 msgs)
  patient   behaviour_gated, real clock (minority + patient attacker)          -> patient
  patient-identity  identity mode, real clock                                  -> patient
Content-related environment you set in your PowerShell session (FARF_OVERRIDE_POLICY, FARF_OVERRIDE_CLASSIFIER_THRESHOLD, FARF_CLASSIFIER_FLOOR)
is inherited by the bus. Exit code 0 only if every scenario printed its PASS line."""
from __future__ import annotations

import argparse, os, re, subprocess, sys, tempfile, time, urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PC = os.path.join(ROOT, "pentest_cloud")
LOOP = {"FARF_FARS_FEEDBACK": "1", "FARF_FB_BETA": "20", "FARF_FB_MAXMULT": "3", "FARF_FB_DECAY_S": "600", "FARF_FB_SCOPE": "scoped", "FARF_FB_REQUIRE_COLD": "1"}


def profiles(cool):
    gated = {"FARF_REINSTATE_MODE": "behaviour_gated", "FARF_COOLING_OFF_S": str(cool), "FARF_PROBATION_MSGS": "5"}
    return {
        "full": (8301, {**gated, **LOOP}, ["gated", "loop", "personas", "collusion", "adaptive"]),
        "full3": (8302, {**gated, **LOOP, "FARF_TAINT_SOURCE": "content"}, ["gated", "loop", "content", "adaptive"]),
        "personas": (8303, dict(gated), ["personas", "collusion"]),
        "collusion-identity": (8306, {}, ["collusion"]),
        "scale": (8304, {"FARF_TAINT_SOURCE": "content"}, ["scale"]),
        "hopcap": (8305, {**LOOP, "FARF_FB_HOP_CAP": "1"}, ["loop"]),
        "reseedguard": (8307, {**LOOP, "FARF_FB_RESEED_GUARD": "1"}, ["loop"]),
        "scale-default": (8309, {}, ["scale"]),
        "patient": (8310, dict(gated), ["patient"]),
        "patient-identity": (8311, {}, ["patient"]),
    }


def scenario_cmd(name, url, cool, texts):
    py = sys.executable
    return {
        "gated": [py, os.path.join(PC, "v11_gated_reinstatement_cloud.py"), "--url", url, "--cooling-off", str(cool)],
        "loop": [py, os.path.join(PC, "v11_fars_loop_cloud.py"), "--url", url],
        "adaptive": [py, os.path.join(PC, "v11_adaptive_attacker_cloud.py"), "--url", url, "--n", "200"],
        "content": [py, os.path.join(PC, "v11_content_taint_cloud.py"), "--url", url],
        "personas": [py, os.path.join(PC, "v11_personas_cloud.py"), "--url", url, "--cooling-off", str(cool), "--persona", "both"],
        "collusion": [py, os.path.join(PC, "v11_collusion_cloud.py"), "--url", url, "--cooling-off", str(cool), "--witnesses", "4"],
        "patient": [py, os.path.join(PC, "v11_collusion_patient_cloud.py"), "--url", url, "--cooling-off", str(cool),
                    "--horizon", os.environ.get("FARF_PATIENT_HORIZON", "120")],
        "scale": [py, os.path.join(PC, "v11_content_benign_scale.py"), "--url", url] + (["--texts", texts] if texts else []),
    }[name]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--profile", required=True, choices=sorted(profiles(20)))
    ap.add_argument("--cooling-off", type=float, default=20.0)
    ap.add_argument("--texts", help="benign phrase file for the scale profile (e.g. data/heldout/D_benign.txt)")
    ap.add_argument("--out", help="directory for per-scenario logs")
    a = ap.parse_args()
    # the scenario scripts run with cwd=pentest_cloud, so every path they receive must be absolute
    a.texts = os.path.abspath(a.texts) if a.texts else None
    if a.texts and not os.path.isfile(a.texts):
        print(f"[FAIL] --texts file not found: {a.texts}")
        return 2
    cool = int(a.cooling_off) if a.cooling_off == int(a.cooling_off) else a.cooling_off
    port, env_extra, scenarios = profiles(cool)[a.profile]
    env = dict(os.environ, PYTHONUTF8="1", FARF_PENTEST_MODE="1", PORT=str(port), **env_extra,
               FARF_AUDIT_DB=os.path.join(tempfile.gettempdir(), f"farf_prof_{a.profile}_{os.getpid()}.db"))
    if a.out:
        os.makedirs(a.out, exist_ok=True)
    proc = subprocess.Popen([sys.executable, os.path.join(PC, "bus_service.py")], env=env, cwd=ROOT,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    url = f"http://127.0.0.1:{port}"
    try:
        for _ in range(40):
            try:
                if b'"ok"' in urllib.request.urlopen(url + "/health", timeout=3).read():
                    break
            except Exception:  # noqa: BLE001
                time.sleep(1)
        else:
            print("[FAIL] local bus did not come up")
            return 1
        print(f"profile {a.profile} on {url}: " + urllib.request.urlopen(url + "/config", timeout=5).read().decode()[:400])
        failures = 0
        for s in scenarios:
            r = subprocess.run(scenario_cmd(s, url, cool, a.texts), env=env, cwd=PC, capture_output=True, text=True, encoding="utf-8", errors="replace", check=False)
            out = r.stdout + r.stderr
            print(out)
            if a.out:
                with open(os.path.join(a.out, f"{a.profile}_{s}.txt"), "w", encoding="utf-8") as lf:
                    lf.write(out)
            ok = bool(re.search(r"RESULT [^\n]*: PASS", out)) and r.returncode == 0
            print(f"[{'PASS' if ok else 'FAIL'}] [{a.profile}] {s} scenario")
            failures += not ok
        print(f"\nRESULT profile {a.profile}: {'PASS' if not failures else 'FAIL'}")
        return 1 if failures else 0
    finally:
        proc.terminate()


if __name__ == "__main__":
    raise SystemExit(main())
