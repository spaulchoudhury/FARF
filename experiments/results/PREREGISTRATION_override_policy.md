# Pre-registration: content-taint override policy (written BEFORE the fresh sets D and M were authored or scored)
Candidate: FARF_OVERRIDE_POLICY=heuristic_or_classifier, FARF_OVERRIDE_CLASSIFIER_THRESHOLD=0.60, CLASSIFIER_FLOOR=0.58.
Chosen from development sets A, B, C (burned) with tools/policy_matrix.py.
Acceptance, evaluated ONCE with tools/heldout_eval.py:
  D (benign, >=100 phrases): 0 refused messages in the bus simulation; min margin to floor and to override threshold >= 0.002.
  M (malicious, >=30 phrases, written without looking at classifier scores): mean delivered <= 3 of 12; <= 10% of phrases fully delivered.
If D fails the failure is the reported result; thresholds are NOT retuned on D; a new untouched set E is required for any new candidate.
If M is weaker than the limit, recall is reported as measured; thresholds are NOT lowered on M.
Rule of three: 0 failures in n benign phrases bounds the per-phrase false-override rate at about 3/n (95%): n=100 -> 3%.
