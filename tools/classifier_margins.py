"""Print this environment's content-taint classifier margins against the configured CLASSIFIER_FLOOR.
    python tools/classifier_margins.py
Shows library versions, p / margin-to-floor / delta for the benign fixtures and the two attack styles, the benign-vs-attack gap,
and the worst case: how fast a sender repeating ONLY the benign sentence closest to the floor gets refused."""
import logging
import os
import platform
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))   # repo root, so this runs from tools\
logging.disable(logging.CRITICAL)
import numpy  # noqa: E402
import scipy  # noqa: E402
import sklearn  # noqa: E402

import content_taint as ct  # noqa: E402
from content_taint_classifier import classifier_score  # noqa: E402
from experiments.common import BENIGN_TEXTS, ATTACK_TEXT, close_bus, make_bus  # noqa: E402
from experiments.run_content_taint import CLASSIC_OVERRIDE_TEXT  # noqa: E402
from main import build_federation  # noqa: E402

print(f"python {platform.python_version()}  scikit-learn {sklearn.__version__}  numpy {numpy.__version__}  scipy {scipy.__version__}")
F = ct.CLASSIFIER_FLOOR
print(f"CLASSIFIER_FLOOR={F}  CLASSIFIER_WEIGHT={ct.CLASSIFIER_WEIGHT}\n")
rows = []
for name, t in [(f"BENIGN{i}", x) for i, x in enumerate(BENIGN_TEXTS)] + [("E4_ATTACK", ATTACK_TEXT), ("CLASSIC", CLASSIC_OVERRIDE_TEXT)]:
    p = classifier_score(t)
    d = ct.analyse_payload({"instruction": t})["delta"]
    rows.append((name, p, d, t))
    print(f"{name:10s} p={p:.4f}  margin_to_floor={F - p:+.4f}  delta={d:.4f}")
ben = [r for r in rows if r[0].startswith("BENIGN")]
worst = max(ben, key=lambda r: r[1])
e4 = [r for r in rows if r[0] == "E4_ATTACK"][0]
print(f"\nclosest benign to the floor: {worst[0]} (p={worst[1]:.4f}); E4 attack p={e4[1]:.4f}; benign-vs-E4 gap = {e4[1] - worst[1]:+.4f}")
if worst[2] > 0:
    print("  -> a benign sentence is ABOVE the floor on this build (floor margin has gone negative).")
elif F - worst[1] < 0.05:
    print("  -> thin margin (< 0.05): a small change to the floor or the training corpus would put a benign sentence above it. See experiments/run_floor_sweep.py.")
else:
    print("  -> comfortable margin on this build.")

bus = make_bus(taint_source="content")
try:
    ag = build_federation(bus, n_orgs=5)
    o = list(ag)
    first = None
    for i in range(80):
        dest = o[1 + i % 4]
        r = bus.send(ag[o[0]]["advisor"].agent_id, o[0], ag[dest]["advisor"].agent_id, dest, "memory_recall_forward",
                     {"requested_privilege": 0.1, "attempts_system_override": False, "instruction": worst[3]}, taint_delta=0.0)
        if r["decision"] != "allow" and first is None:
            first = i + 1
finally:
    close_bus(bus)
print(f"worst case (80 x '{worst[3][:40]}...'): first refusal at message {first}")
sys.exit(0)
