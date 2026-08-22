# CHANGELOG_v7.9.5.md

Fixes a real bug found from the user's first genuine Ollama-backed run of
`tools/ollama_pt15_comparison.py` (GTX 1650, 4GB VRAM, qwen3:4b): 0 of 7
LLM-judge calls returned a usable judgement. Root cause identified and
fixed, not worked around by tuning test cases.

## Root cause

The model pulled for `qwen3:4b` on the user's machine is the **Qwen3 4B
"Thinking" variant** (confirmed in the Ollama server log: `general.name
= Qwen3 4B Thinking 2507`, `general.finetune = Thinking`). Per Ollama
0.12+'s documented behaviour, `*-thinking` model variants **auto-enable
chain-of-thought reasoning whenever the request's `think` field is
omitted** — which `llm_judge.py`'s payload always did.

Effect: the model spent its generation budget on a hidden reasoning
trace (returned in a separate `thinking` field) instead of the
`"format": "json"`-constrained final answer. When the call ended (either
the model's own stop condition or `llm_judge.py`'s client-side timeout),
`response` was empty. `json.loads("")` raises `JSONDecodeError:
Expecting value: line 1 column 1 (char 0)` — exactly what the user's run
showed on 6 of 7 calls, even on calls the Ollama server log shows
completed normally (HTTP 200, real `print_timing` output). The 7th call
(the very first, coincident with model cold-load) hit the 15-second
client-side timeout before the server's own 15.05s round trip finished
(`DEFAULT_TIMEOUT_SECONDS` left no margin for cold-start).

Separately, 3 of the 7 server-side calls logged `got exception:
std::bad_alloc` — the user's machine had only ~300MB free system RAM
and ~3.2GB free VRAM against qwen3:4b's ~3GB footprint (26/37 layers fit
on GPU) at the time of the run. This is a genuine host-resource
constraint, not a `llm_judge.py` bug — flagged, not silently absorbed
into the "fixed" claim below.

## Fix (`llm_judge.py`)

- Added `"think": False` as a **top-level** field in the `/api/generate`
  payload (confirmed via Ollama's own docs this must be top-level, not
  nested under `"options"`, or it's silently ignored). This is safe for
  non-thinking models too — Ollama ignores the field for models that
  don't support it.
- `DEFAULT_TIMEOUT_SECONDS` raised from 15.0 → 30.0, giving real margin
  for a cold model load plus first generation on constrained hardware.
- Added a targeted diagnostic: if a response ever comes back with an
  empty `response` field but non-empty `thinking` content (i.e. `think`
  somehow got ignored), the failure reason now says so explicitly
  instead of surfacing a bare, hard-to-diagnose `JSONDecodeError` on an
  empty string.

**Not changed:** `judge_injection()`'s return contract, its
degrade-not-raise behaviour, or `detect_prompt_injection()`'s default
(`use_llm_judge=False`) call path. Full regression: 57 passed, 0
skipped (unchanged). Lint: unchanged, 0 high-confidence findings.

## What this does and doesn't tell us about the classifier

The user also flagged the TF-IDF+LogReg **classifier**'s scores as
"going low" on the genuinely-hard test cases (0.51, 0.49, 0.46, 0.39 —
two of four below the 0.5 threshold). That part is **not a bug** — it's
the documented, expected residual gap `tools/ollama_pt15_comparison.py`
exists to probe: those four cases were deliberately written with zero
shared vocabulary with the training corpus, specifically to find where
a bag-of-n-grams classifier runs out of signal. The classifier missing
2 of 4 there is exactly what CHANGELOG_v7.9.md's own numbers predict.

What's actually still unknown, because the LLM judge never successfully
ran even once in that session: **whether qwen3:4b actually closes any of
those classifier misses.** The reported "0 of 4 genuinely-hard cases
improved" is not evidence the LLM judge doesn't help — it's null data,
because zero calls produced a real judgement. The user needs to re-run
`python -m tools.ollama_pt15_comparison` with this fix before that
question has an answer either way.

## Still needs the user's machine to actually answer

- Re-run `python -m tools.ollama_pt15_comparison` with the `think:
  false` fix in place — this is the actual test of whether qwen3:4b adds
  a real third signal, still not yet measured.
- If `std::bad_alloc` recurs even with `think: false` (which should cut
  per-call token volume and total compute substantially), that's a
  genuine hardware-headroom issue on this specific laptop, not a code
  fix — closing other applications to free system RAM, or trying a
  smaller already-pulled model (`qwen2.5:3b`, `llama3.2:3b`) as a
  fallback comparison, are the practical next steps, not something this
  codebase can engineer around.
