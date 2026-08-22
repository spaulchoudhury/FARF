# CHANGELOG_v7.9.6.md

Two real, user-reported issues fixed. Session also re-verified the full
build against a clean environment before making changes (see "Build
status re-verified" below) and re-synced `ARCHITECTURE_DECISIONS_1.md`
in the same pass, per that file's own "Keeping this file in sync"
protocol.

## Fix 1: `llm_model` switch had no effect (`agents.py`, `llm_judge.py`)

**User report:** on the user's local machine, `qwen3:4b` intermittently
fails to allocate a CUDA host buffer (`std::bad_alloc`, first flagged in
`CHANGELOG_v7.9.5.md`), so the user needs to switch the LLM judge to
`deepseek-r1:1.5b`. Doing so had no effect.

**Root cause:** two independent hardcoded defaults where the design
intended one source of truth:

```python
# llm_judge.py
DEFAULT_MODEL = "qwen3:4b"

# agents.py
def detect_prompt_injection(instruction: str, use_llm_judge: bool = False,
                             llm_model: str = "qwen3:4b") -> Dict:
```

`agents.py`'s own hardcoded default shadowed `llm_judge.DEFAULT_MODEL`
for every caller that didn't pass `llm_model=` explicitly on every
single call — which is every caller in this codebase
(`tools/ollama_pt15_comparison.py` included). Editing `DEFAULT_MODEL`
alone therefore did nothing observable.

**Fix:**

- `llm_judge.DEFAULT_MODEL` now reads `FARF_LLM_JUDGE_MODEL` from the
  environment, defaulting to `"qwen3:4b"` unchanged:
  `DEFAULT_MODEL = os.environ.get("FARF_LLM_JUDGE_MODEL", "qwen3:4b")`.
  `OLLAMA_HOST` similarly reads `FARF_OLLAMA_HOST`.
- `agents.detect_prompt_injection()`'s `llm_model` parameter now
  defaults to `None` and is resolved against `llm_judge.DEFAULT_MODEL`
  **at call time**, inside the function body, not baked into the
  signature:
  ```python
  def detect_prompt_injection(instruction: str, use_llm_judge: bool = False,
                               llm_model: Optional[str] = None) -> Dict:
      ...
      if use_llm_judge:
          from llm_judge import judge_injection, DEFAULT_MODEL
          resolved_model = llm_model if llm_model is not None else DEFAULT_MODEL
          judgement = judge_injection(instruction, model=resolved_model)
  ```
  An explicit `llm_model="..."` at the call site still overrides
  per-call, same as before — only the *default* now traces back to one
  place instead of two.
- The result dict gained a new `llm_judge_model` key (the model that
  actually produced this verdict), so logs/callers can tell which model
  was in play once this can vary run-to-run.
- `tools/ollama_pt15_comparison.py` updated to import and print
  `llm_judge.DEFAULT_MODEL` rather than hardcoding its own `"qwen3:4b"`
  strings in its docstring, setup instructions, reachability check, and
  summary line — it now automatically follows whatever
  `FARF_LLM_JUDGE_MODEL` is set to.

**Switching models now (Windows PowerShell, matching the user's dev
environment):**

```powershell
$env:FARF_LLM_JUDGE_MODEL = "deepseek-r1:1.5b"
ollama pull deepseek-r1:1.5b
python -m tools.ollama_pt15_comparison
```

**Verified end-to-end, not just by inspection:** patched
`urllib.request.urlopen` to capture the actual `model` field sent in the
outgoing HTTP payload with `FARF_LLM_JUDGE_MODEL=deepseek-r1:1.5b` set,
and confirmed it was `"deepseek-r1:1.5b"` — the fix reaches the real
call, not just the default argument's own repr. Full regression: 57
passed, 0 skipped, unchanged. `tests/test_07_llm_judge_integration.py`:
12/12 unchanged (asserts the contract's shape and degrade-not-raise
behaviour, not a specific model literal, so genuinely unaffected by this
change, not coincidentally passing).

**Not changed:** the default model itself (`"qwen3:4b"`, when the env
var is unset), `judge_injection()`'s return contract, or
`detect_prompt_injection()`'s own default (`use_llm_judge=False`) call
path.

## Fix 2: hardcoded `/tmp/*.db` paths — not OS-agnostic

**Problem:** 23 files (22 `pentest/pt*.py` exploit scripts + 3
`tests/*.py` files: `test_04_statistical_validation.py`,
`test_06_tab78_evaluation_metrics.py`,
`evaluation_metrics_tab78_repeated.py`) constructed SQLite database
paths as literal strings, e.g.:

```python
bus = FederationBus(db_path="/tmp/pt01.db")
...
os.remove("/tmp/pt01.db")
```

`/tmp` doesn't exist on Windows — the user's own stated development
target (README.md: "Intel Core i5 · 8 GB RAM · NVIDIA GTX 1650 (4GB
VRAM) · Windows 11"). Any of these 23 files would raise
`FileNotFoundError` (or silently write to a stray `C:\tmp\` if that
happened to exist) run natively on Windows outside of WSL/Git-Bash.

**Fix:** every occurrence replaced with
`os.path.join(tempfile.gettempdir(), "<name>.db")` (or the f-string
equivalent for the few dynamically-named paths — `pt14`'s
`{'unlocked'/'locked'}` variants, `pt17`'s `{n_orgs}`-parameterised
scale-test paths, `test_04`'s `{seed}_{farf_enabled}`,
`test_06`/`evaluation_metrics_tab78_repeated`'s
`{uuid.uuid4().hex}`-suffixed paths). `import tempfile` added to each
file (all already imported `os` in some form). `tempfile.gettempdir()`
resolves correctly on Windows (`%TEMP%`), Linux/macOS (`/tmp` or
`$TMPDIR`), and any other platform Python itself supports — no
per-platform branching needed anywhere in this codebase now.

**Deliberately NOT changed:** two `"/tmp/..."` strings inside
`agents.py`'s illustrative prompt-injection training corpus (around
lines 155 and 193). These are example attacker-supplied instruction
TEXT the classifier trains its vocabulary on (a fictional path
*mentioned inside a malicious prompt*, like `"...convert the audio at
'/tmp/crime.mp4'..."`) — not a real filesystem path this codebase reads
or writes. Rewriting the corpus text would not fix a portability bug
(there isn't one there) and would needlessly touch a hand-curated
training set for no benefit.

**Verified end-to-end:** all 22/22 `pentest/pt*.py` scripts re-run
individually post-fix and still exit 0 (same pass/fail posture as
before this change — this was a portability fix, not a behaviour
change). Full suite: 57 passed, 0 skipped, unchanged.
`grep -rn "/tmp/" --include="*.py" .` (excluding `agents.py`) now
returns zero matches.

## Build status re-verified this session (clean environment, not re-read from prior CHANGELOGs)

- `python -m pytest tests/ -v` → **57 passed, 0 skipped** — matches
  `CHANGELOG_v7.9.3.md`'s claim.
- `python tools/farf_security_lint.py` → **0 high-confidence, 3
  low-confidence findings** (same 3 pre-existing ones) — matches.
- All **22/22** `pentest/pt*.py` scripts exit 0, both before and after
  this session's changes.
- `python main.py --scenario all` → runs end-to-end, exits 0, produces
  a FARS score (`70.45` this run — expect natural run-to-run variation,
  the scenario isn't seeded), no unhandled exceptions.

## Documentation sync (per `ARCHITECTURE_DECISIONS_1.md`'s own protocol)

- `ARCHITECTURE_DECISIONS_1.md`'s `## Summary: gap → decision → cloud
  mechanism` table updated: ADR-012 row now notes the new
  `llm_judge.model`/`FARF_LLM_JUDGE_MODEL` schema entry; ADR-015 row
  now records this session's model-switch bug fix alongside v7.9.5's
  `think: false` fix.
- ADR-012's illustrative `farf_runtime_config.yaml` block gained an
  `llm_judge:` section (`model`, `host`), following the same
  env-var-is-the-real-mechanism comment pattern already used by its
  `logging:` section. A new paragraph in ADR-012 makes explicit that
  this YAML file is a documented, not-yet-implemented schema — the
  `os.environ`-based mechanism is Phase 1/2's real config surface today
  (see `ARCHITECTURE_DECISIONS_1.md` for the full reasoning on why this
  is the right call for now, not a gap).
- A new Internal Audit entry ("Closed in v7.9.6") records both fixes
  with evidence, following the file's existing per-version format.
- A new "Documentation gap found this session" note flags that
  `CLOUD_PROVIDER_COMPARISON.md` — cited repeatedly throughout
  `ARCHITECTURE_DECISIONS_1.md` as the source of the pricing/provider
  figures — does not actually exist in this delivered package. Flagged,
  not silently worked around; the cost table in ADR-011 should be read
  as directionally reasoned until that source document is located or
  regenerated.
