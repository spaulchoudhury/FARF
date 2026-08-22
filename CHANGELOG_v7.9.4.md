# CHANGELOG_v7.9.4.md

Documentation-only session: full cloud-readiness status review, live
re-verification of the build against a clean environment (not just
re-reading prior CHANGELOGs), and a doc-sync fix for a real staleness
gap found in `ARCHITECTURE_DECISIONS_1.md`. No production code changed.

## Staleness found and fixed

`ARCHITECTURE_DECISIONS_1.md`'s "Summary: gap → decision → cloud
mechanism" table and Internal Audit section were last synced at
v7.9/v7.9.1. `CHANGELOG_v7.9.2.md` (the `llm_judge.py` Ollama signal)
and `CHANGELOG_v7.9.3.md` (the test-suite regression fix) had shipped
without a matching update to that file, so its "last reviewed" line
still said "v7.9 build" and the ADR-015 row didn't mention that a first
real test of its LLM-integration pattern had already shipped.

Fixed in `ARCHITECTURE_DECISIONS_1.md`:
- "Last reviewed" line updated to v7.9.3.
- New "Closed in v7.9.2" / "Closed in v7.9.3" subsections added to the
  Internal Audit, evidenced (not just restated from the CHANGELOGs).
- ADR-015's Summary-table row updated to note the `llm_judge.py`
  integration-pattern test, with the honest caveat that the real
  Ollama-server-backed comparison (`tools/ollama_pt15_comparison.py`)
  still hasn't been run on real hardware.

## Live re-verification this session (clean environment, not asserted from prior docs)

- `python -m pytest tests/ -v` → 57 passed, 0 skipped (matches
  `CHANGELOG_v7.9.3.md`).
- `python tools/farf_security_lint.py` → 0 high-confidence, 3
  low-confidence findings (matches, same 3 pre-existing).
- All 22/22 `pentest/pt*.py` scripts exit 0.
- `python main.py --scenario all` → runs end-to-end, produces a FARS
  score, no unhandled exceptions.
- `llm_judge.py`'s `check_ollama_reachable()`/`judge_injection()` tested
  against a genuinely unreachable Ollama server (this sandbox has none
  running) — degrades cleanly to `available=False`, does not raise.
  This is a real-condition check, not just the mocked test suite.

## On the reported local crash

The user reported their previous local session crashed while testing
the Ollama integration (`tools/ollama_pt15_comparison.py` /
`llm_judge.py` against a real local Ollama server). Nothing in this
sandbox's log (`logs/farf.log`) or the code itself shows a code-side
crash — `llm_judge.py` is designed to degrade, not raise, on every
Ollama failure mode, and that contract held under a genuinely
unreachable server in this session's testing. No root cause identified
from the delivered files; if the user has a traceback or terminal
output from the crash, that would let this be diagnosed properly
instead of assumed.

## Still open (unchanged by this session)

Same three genuine cloud-build blockers as `CHANGELOG_v7.9.1.md`:
ADR-003's real KMS wiring, ADR-006's real multi-node cross-cloud ledger,
and actual AWS+Azure(/GCP) accounts and IAM. See
`ARCHITECTURE_DECISIONS_1.md`'s Internal Audit section for the full,
evidenced list.
