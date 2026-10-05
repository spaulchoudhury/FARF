"""Write (or --check) tests/golden_classifier_scores.json: the independent content-taint classifier's probability for fixed texts.
    python tools/write_golden_scores.py            # (re)generate on the machine you trust, then commit the JSON
    python tools/write_golden_scores.py --check    # compare THIS environment against the committed golden file
A library or Python change that moves any score by more than --tol (default 0.005) is real drift, not a threshold artefact."""
from __future__ import annotations

import argparse, json, os, platform, sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy, scipy, sklearn  # noqa: E401

from content_taint_classifier import classifier_score
from experiments.common import ATTACK_TEXT, BENIGN_TEXTS
from experiments.run_content_taint import CLASSIC_OVERRIDE_TEXT

GOLDEN = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "golden_classifier_scores.json")


def fixtures() -> dict:
    from tools.heldout_margins import HELDOUT_BENIGN_TEXTS   # development set C (burned): used only as regression fixtures
    f = {"E4_ATTACK": ("malicious", ATTACK_TEXT), "CLASSIC_OVERRIDE": ("malicious", CLASSIC_OVERRIDE_TEXT)}
    f.update({f"BENIGN_{i}": ("benign", t) for i, t in enumerate(BENIGN_TEXTS)})
    f.update({f"DEVC_{i:02d}": ("benign", t) for i, t in enumerate(HELDOUT_BENIGN_TEXTS, 1)})
    return f


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--tol", type=float, default=0.005)
    a = ap.parse_args()
    cur = {k: {"label": lab, "text": t, "p": round(classifier_score(t), 4)} for k, (lab, t) in fixtures().items()}
    env = {"python": platform.python_version(), "scikit_learn": sklearn.__version__, "numpy": numpy.__version__, "scipy": scipy.__version__}
    if not a.check:
        with open(GOLDEN, "w", encoding="utf-8") as fh:
            json.dump({"env": env, "scores": cur}, fh, indent=1)
        print("wrote", GOLDEN, env)
        return 0
    with open(GOLDEN, encoding="utf-8") as fh:
        gold = json.load(fh)
    worst = max((abs(cur[k]["p"] - v["p"]), k) for k, v in gold["scores"].items())
    print(f"golden env={gold['env']}\nthis  env={env}\nlargest |dp| = {worst[0]:.4f} at {worst[1]} (tolerance {a.tol})")
    return 0 if worst[0] <= a.tol else 1


if __name__ == "__main__":
    raise SystemExit(main())
