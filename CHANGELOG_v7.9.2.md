# CHANGELOG_v7.9.2.md

Adds an optional third prompt-injection detection signal via a local
Ollama model, closing PT-15's residual "genuinely novel paraphrase"
gap further, and serving as the smallest real test of ADR-015's
LLM-integration pattern before committing to replacing agent reasoning
wholesale.

## New files

- **`llm_judge.py`** -- calls a local Ollama server (`/api/generate`),
  zero new hard dependencies (stdlib `urllib.request`/`json` only),
  never raises to its caller. Every failure mode (connection refused,
  timeout, malformed/missing JSON in the model's response) degrades to
  `{"available": False, ...}` -- mirrors `classifier_degraded`'s
  existing posture, never silently misread as a negative detection.
- **`tests/test_07_llm_judge_integration.py`** -- 12 tests, all against
  MOCKED `urlopen` calls (this sandbox has no Ollama server to reach).
  Proves the integration code's contract holds under every failure
  mode; does NOT and cannot prove qwen3:4b's actual judgement quality.
- **`tools/ollama_pt15_comparison.py`** -- meant to be run on a real
  machine with Ollama installed, not in this sandbox. Compares
  detect_prompt_injection() with vs. without the LLM judge across
  PT-15's existing cases plus three new, deliberately harder ones
  (no shared vocabulary with the training corpus at all) and a benign
  control case, so the comparison is real evidence, not an assumption.

## Modified

- **`agents.py`**: `detect_prompt_injection()` gained `use_llm_judge:
  bool = False` and `llm_model: str = "qwen3:4b"` parameters. Default
  behaviour is byte-for-byte unchanged -- confirmed via full regression
  (56 passed, 1 skipped, same as before this change) and the existing
  PT-15 pentest script, which still passes unmodified.

## Finding worth flagging: PT-15's own "hard" case is no longer hard

`pentest/pt15_prompt_injection_heuristic.py`'s `NOVEL_PARAPHRASE_CASE`
(Part D, historically reported as "not expected to catch every novel
phrasing") is now caught by the classifier ALONE, score ~0.55 -- a
side effect of the v7.9 classifier retrain on real AgentDojo/InjecAgent
data (see `CHANGELOG_v7.9.md`). This is good news, but it means that
specific case no longer differentiates what an LLM judge adds. The new
comparison script uses three new cases instead, verified in this
sandbox (Ollama unreachable, so classifier-only baseline) to actually
split: 2 of 3 score below the 0.5 classifier threshold (0.49, 0.46) and
the benign control case stays low (0.39) -- real headroom for the LLM
judge to be tested against on real hardware.

## What still needs YOUR machine

Nothing in this sandbox can call a real Ollama server. The comparison
script's actual LLM-judge results, and therefore whether qwen3:4b is
worth keeping as a permanent third signal, can only be produced by
running `python -m tools.ollama_pt15_comparison` locally, per the setup
steps given in chat.
