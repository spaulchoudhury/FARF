"""Write this machine's content-taint deltas for the scenario texts to a JSON file (the reference for the cloud scenario's Part A).
    python tools/write_classifier_reference.py classifier_reference.json"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "pentest_cloud"))
from v11_common import ATTACK_TEXT, BENIGN_TEXTS, CLASSIC_OVERRIDE_TEXT, local_reference  # noqa: E402

ref = local_reference(list(BENIGN_TEXTS) + [ATTACK_TEXT, CLASSIC_OVERRIDE_TEXT])
if ref is None:
    sys.exit("content_taint could not be imported (run from the repo root with the venv active)")
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(ref, fh, indent=1, ensure_ascii=False)
print(f"wrote {sys.argv[1]}: {len(ref)} texts")
