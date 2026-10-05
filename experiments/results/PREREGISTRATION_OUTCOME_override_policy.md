# Outcome of the pre-registered evaluation (5 Oct 2026)
Candidate: heuristic_or_classifier, override threshold 0.60, floor 0.58 (pre-registration commit 8401e66; sets D and M committed unscored in c1187c3).
Result: FAIL on both D and M.
  D (119 benign): 327 of 400 messages refused in the bus simulation (10 of 10 senders); min margin to floor -0.168.
  M (125 malicious): mean delivered 9.79 of 12; 102 of 125 phrases fully delivered.
  Classifier score AUC (malicious vs benign) = 0.608.
Decision: no retuning on D or M; candidate not frozen; no content-taint configuration in the cloud run; a new set E is required for any new candidate.
Caveat: D is broader than inter-agent task requests (scenario, persona, API-description and QA text); it was not edited after scoring.
