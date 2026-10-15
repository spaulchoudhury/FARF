"""G12 / L16 / F20: colluding minority and a silence-adaptive ("patient") attacker against reinstatement.

Part A  liveness  A benign false-positive organisation OrgA asks to be reinstated while k witnesses
                  withhold their votes (a colluding minority blocking a legitimate recovery).
                  Reports the largest k the federation tolerates, next to the prediction N - q
                  (the accused's own vote counts under the ledger rules).
Part B  safety    A persistent hostile organisation transmits while c colluding witnesses vote for its
                  reinstatement and everyone else abstains. c = q-1 is a colluding minority below
                  quorum; c = q is the unanimous-collusion case already reported in Chapter 4.
Part C  patient   An attacker that stays silent exactly until it is reinstated, behaves cleanly through
                  probation, then resumes. Compared across policies over a fixed horizon:
                  identity-only, behaviour-gated with a patient attacker, behaviour-gated with an
                  impatient attacker (relapses inside probation). Metric: hostile messages delivered.

Local, deterministic (FakeClock). Usage:
    python -m experiments.run_collusion_patient [--out experiments/results_collusion_patient] [--horizon 1200]
"""
from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import random

from closed_loop import ReinstatementPolicy
from experiments.common import BENIGN_TEXTS, FakeClock, close_bus, make_bus, readmit_org
from main import build_federation

logging.disable(logging.CRITICAL)

GATED = ReinstatementPolicy(mode="behaviour_gated", cooling_off_s=30.0, probation_messages=10,
                            probation_sensitivity=2.0, strike_backoff=2.0)
IDENTITY = ReinstatementPolicy(mode="identity")


def _hostile(bus, agents, rng):
    adv, exe = agents["OrgA"]["advisor"], agents["OrgA"]["executor"]
    return bus.send(adv.agent_id, "OrgA", exe.agent_id, "OrgA", "memory_recall_forward",
                    {"requested_privilege": 0.1, "attempts_system_override": False,
                     "instruction": rng.choice(BENIGN_TEXTS)}, taint_delta=0.05)


def _benign(bus, agents, rng):
    adv, exe = agents["OrgA"]["advisor"], agents["OrgA"]["executor"]
    return bus.send(adv.agent_id, "OrgA", exe.agent_id, "OrgA", "benign_plan_forward",
                    {"requested_privilege": 0.1, "attempts_system_override": False,
                     "instruction": rng.choice(BENIGN_TEXTS)}, taint_delta=rng.uniform(0.0, 0.006))


def _quarantine_orgA(bus, agents, rng):
    n = 0
    while "OrgA" not in bus.federation_wide_quarantined and n < 80:
        _hostile(bus, agents, rng)
        n += 1
    assert "OrgA" in bus.federation_wide_quarantined, "setup failed: OrgA not quarantined"
    return n


# ---------------------------------------------------------------- Part A
def liveness_trial(n_orgs: int, k_withhold: int, policy, accused_votes: bool = True, t_max: int = 400) -> dict:
    rng, clock = random.Random(7), FakeClock()
    bus = make_bus(policy=policy, clock=clock, quorum_mode="pbft_dynamic")
    try:
        agents = build_federation(bus, n_orgs=n_orgs)
        orgs = list(agents)
        _quarantine_orgA(bus, agents, rng)
        t_q = clock()
        q = bus.ledger.quorum_required
        withheld = set(orgs[-k_withhold:]) if k_withhold else set()
        voters = [o for o in orgs if o not in withheld and (accused_votes or o != "OrgA")]
        pid = bus.propose_federation_reinstatement("OrgA")["proposal_id"]
        done = None
        for tick in range(t_max):
            clock.advance(1.0)
            if tick % 5 == 4:
                for v in voters:
                    if bus.sign_and_witness_federation_reinstatement(pid, v).get("committed"):
                        done = clock() - t_q
                        break
                if done is not None:
                    break
        return {"n_orgs": n_orgs, "k_withhold": k_withhold, "quorum": q, "voters": len(voters),
                "reinstated": done is not None, "mttr_s": done if done is not None else float("nan")}
    finally:
        close_bus(bus)


# ---------------------------------------------------------------- Part B
def collusion_trial(n_orgs: int, colluders: int, policy, t_max: int = 200) -> dict:
    rng, clock = random.Random(11), FakeClock()
    bus = make_bus(policy=policy, clock=clock, quorum_mode="pbft_dynamic")
    try:
        agents = build_federation(bus, n_orgs=n_orgs)
        orgs = [o for o in agents if o != "OrgA"]
        _quarantine_orgA(bus, agents, rng)
        q = bus.ledger.quorum_required
        voters = orgs[:colluders]
        pid = bus.propose_federation_reinstatement("OrgA")["proposal_id"]
        reinstated, refusals = False, 0
        for tick in range(t_max):
            clock.advance(1.0)
            if tick % 2 == 0:
                _hostile(bus, agents, rng)                        # the attacker keeps transmitting
            if tick % 5 == 4:
                for v in voters:
                    w = bus.sign_and_witness_federation_reinstatement(pid, v)
                    refusals += 1 if w.get("accepted") is False else 0
                    if w.get("committed"):
                        reinstated = True
                        break
            if reinstated:
                break
        return {"n_orgs": n_orgs, "colluders": colluders, "quorum": q, "reinstated": reinstated,
                "vote_refusals": refusals}
    finally:
        close_bus(bus)


# ---------------------------------------------------------------- Part C
def patient_trial(policy, mode: str, horizon: int) -> dict:
    """mode: 'immediate' (resume right after reinstatement), 'patient' (clean through probation first)."""
    rng, clock = random.Random(23), FakeClock()
    bus = make_bus(policy=policy, clock=clock, quorum_mode="pbft_dynamic")
    try:
        agents = build_federation(bus, n_orgs=4)
        voters = ("OrgB", "OrgC", "OrgD")
        t0 = clock()
        delivered = cycles = relapses = 0
        state, probation_left, pid, tick = "attack", 0, None, 0
        while clock() - t0 < horizon:
            clock.advance(1.0)
            tick += 1
            if state == "attack":
                r = _hostile(bus, agents, rng)
                if r["decision"] == "allow":
                    delivered += 1
                if r["decision"] == "quarantine" and "OrgA" in bus.federation_wide_quarantined:
                    state, pid = "wait", bus.propose_federation_reinstatement("OrgA")["proposal_id"]
                    if cycles:                                         # a quarantine right after a reinstatement
                        relapses += 1
            elif state == "wait":                                      # silent: any attempt would restart the clock
                if tick % 5 == 4:
                    for v in voters:
                        if bus.sign_and_witness_federation_reinstatement(pid, v).get("committed"):
                            readmit_org(bus, agents, "OrgA")
                            cycles += 1
                            state = "clean" if mode == "patient" else "attack"
                            probation_left = policy.probation_messages if policy.gated else 0
                            break
            elif state == "clean":
                _benign(bus, agents, rng)
                probation_left -= 1
                if probation_left <= 0:
                    state = "attack"
        return {"policy": policy.mode, "attacker": mode, "horizon_s": horizon, "hostile_delivered": delivered,
                "reinstatements": cycles, "delivered_per_100s": round(100.0 * delivered / horizon, 2),
                "relapses": relapses}
    finally:
        close_bus(bus)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="experiments/results_collusion_patient")
    ap.add_argument("--horizon", type=int, default=1200)
    args = ap.parse_args()
    os.makedirs(args.out, exist_ok=True)
    rep = {"liveness": [], "safety": [], "patient": []}

    print("PART A  liveness: benign OrgA, k witnesses withhold (gated policy; accused's own vote counts)")
    print(f"{'N':>3s} {'q':>3s} {'f':>3s} {'predicted max k (N-q)':>22s} {'observed max k':>15s}  per-k outcome")
    for n in (4, 7, 10, 13):
        res, q = [], None
        for k in range(0, n):
            r = liveness_trial(n, k, GATED)
            q = r["quorum"]
            res.append(r)
            rep["liveness"].append(r)
            if not r["reinstated"] and k > n - q + 1:
                break
        ok_ks = [r["k_withhold"] for r in res if r["reinstated"]]
        obs = max(ok_ks) if ok_ks else -1
        f = (n - 1) // 3
        print(f"{n:3d} {q:3.0f} {f:3d} {n - q:22.0f} {obs:15d}  "
              + " ".join(f"k{r['k_withhold']}={'Y' if r['reinstated'] else 'n'}" for r in res))

    print("\nPART B  safety: persistent hostile OrgA transmits; c colluding witnesses vote for it, all others abstain")
    print(f"{'N':>3s} {'q':>3s} {'c':>3s} {'policy':16s} {'reinstated':>10s} {'vote refusals':>14s}")
    for n in (7, 10):
        for c_label, c_fn in (("q-1", lambda q: int(q) - 1), ("q", lambda q: int(q))):
            for pol in (IDENTITY, GATED):
                probe = collusion_trial(n, 0, pol, t_max=1)
                c = c_fn(probe["quorum"])
                r = collusion_trial(n, c, pol)
                rep["safety"].append(dict(r, policy=pol.mode, c_label=c_label))
                print(f"{n:3d} {r['quorum']:3.0f} {c:3d} {pol.mode:16s} {str(r['reinstated']):>10s} {r['vote_refusals']:14d}")

    print(f"\nPART C  patient attacker over {args.horizon} s (1 hostile message per second while allowed)")
    print(f"{'policy':16s} {'attacker':10s} {'delivered':>9s} {'per 100 s':>9s} {'reinst.':>8s} {'relapses':>9s}")
    rows = []
    for pol, mode in ((IDENTITY, "immediate"), (GATED, "immediate"), (GATED, "patient")):
        r = patient_trial(pol, mode, args.horizon)
        rows.append(r)
        rep["patient"].append(r)
        print(f"{r['policy']:16s} {r['attacker']:10s} {r['hostile_delivered']:9d} {r['delivered_per_100s']:9.2f} "
              f"{r['reinstatements']:8d} {r['relapses']:9d}")
    base = rows[0]["hostile_delivered"] or 1
    print("\nattacker throughput relative to identity-only:",
          ", ".join(f"{r['policy']}/{r['attacker']}={r['hostile_delivered'] / base:.2f}x" for r in rows))
    with open(os.path.join(args.out, "collusion_patient.json"), "w") as f:
        json.dump(rep, f, indent=2)
    with open(os.path.join(args.out, "liveness.csv"), "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rep["liveness"][0]))
        w.writeheader()
        w.writerows(rep["liveness"])
    print("saved to", args.out)


if __name__ == "__main__":
    main()
