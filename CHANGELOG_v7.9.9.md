# CHANGELOG_v7.9.9.md

Two real code changes this session, both user-requested and both
re-verified end-to-end against the actual shipped code, not just
reasoned about. A third item (ADR-006 multi-process witness nodes) was
requested as an open question, not an implementation — see the
pros/cons write-up at the end; **nothing was implemented for it this
session**, per the user's explicit "don't assume and progress" instruction.

## 1. `main.py` — top-level exception handler (closes the gap flagged in `PHASE1_GAP_REPORT_v7.6.md` §6)

Previously, any unhandled exception inside `main()` — a malformed
`--db` path, a genuine bug in a scenario function, anything the
per-scenario `finally: bus.close()` blocks (v7.6) didn't already catch
— surfaced as a raw Python traceback: no scenario context, no
consistent exit code, no `farf.log` entry.

**Fix:** the `if __name__ == "__main__":` block now wraps `main()` in a
top-level `try/except` that:
- Catches `KeyboardInterrupt` separately — clean one-line message, exit
  code 130 (standard SIGINT convention), no error-level log noise for
  an operator-initiated Ctrl-C.
- Catches every other `Exception`, logs it at ERROR level via
  `farf_logging.get_logger("farf.main")` (`exc_info=True`, so the full
  traceback lands in `logs/farf.log` even when the console doesn't show
  it), prints a clean one-line `[FARF] FATAL: <type>: <message>`, and
  exits 1.
- `FARF_DEBUG=1` prints the full traceback to the console too, for
  local debugging — off by default to keep the default failure mode
  readable.

**Does NOT change:** the v7.6 per-scenario `finally: bus.close()`
blocks already guaranteed no dangling SQLite handle and no lost
audit-buffer flush on a mid-run failure — this handler only changes
what the *operator sees on exit*, not the federation/audit state
itself, exactly as scoped in the original gap report.

**Verified, not just inspected:**
- Normal run (`--scenario composite`): unaffected, exit 0, identical
  output to before.
- Forced failure (bad `--db` path to a nonexistent directory): clean
  `[FARF] FATAL: OperationalError: unable to open database file`,
  `logs/farf.log` gained the ERROR entry, exit code 1.
- Same forced failure with `FARF_DEBUG=1`: full traceback printed in
  addition to the clean message.
- `Ctrl-C` path verified by code inspection of the `KeyboardInterrupt`
  branch (not separately re-triggered live this session — the logic is
  a direct, un-branching `sys.exit(130)`, low risk).
- Full regression: 57/57 pre-existing tests still pass, lint unchanged
  (0 high-confidence), all 22/22 pentest scripts still exit 0.

## 2. `runtime_config.py` (new) — makes `farf_runtime_config.yml` a real, loadable file

ADR-012 was explicit that no module in this codebase parsed YAML and
that the runtime-config schema shown there was illustrative only. This
closes that gap **honestly** — every field in the file the researcher
actually supplied is parsed and classified as either:

- **APPLIED** — wired to a real code parameter, takes effect this run.
- **PARSED_ONLY** — validated and stored on the returned `RuntimeConfig`,
  but nothing in this codebase consumes it yet. Never silently dropped:
  every `PARSED_ONLY` field is named, with a specific reason, in
  `runtime_config.PARSED_ONLY_REASONS` and surfaced by `RuntimeConfig.summarise()`.

### What's actually APPLIED

| Field | What it does |
|---|---|
| `federation.orgs` | Builds a real federation (via `federation_config.build_federation_from_config`) with exactly these org names — verified end-to-end against the real 3-org `["org_a","org_b","org_c"]` file, not a synthetic fixture only |
| `logging.level` | Sets `FARF_LOG_LEVEL` (via `os.environ.setdefault` — an operator-set env var still wins, same precedence pattern as `FARF_LLM_JUDGE_MODEL`) |
| `logging.sink: "json_stdout"` | Sets `FARF_LOG_FORMAT=json`. Any other `sink` value (`cloudwatch`/`stackdriver`/`azure_monitor`) is `PARSED_ONLY` with an explicit warning — those are ADR-007's still-open cloud-build sinks, not shipped here; falls back to the existing local rotating-file sink rather than silently no-op'ing or crashing |

### What's PARSED_ONLY, and why (full detail in `runtime_config.py`'s `PARSED_ONLY_REASONS` dict)

- **`federation.quorum_threshold` (0.6)** — the real quorum resolver
  (`federation_config.resolve_quorum`) takes a count or the string
  `"pbft_proportional"`, not a fraction of orgs. Converting 0.6 into a
  count needs a decision (see options below) — this module does not
  guess; the safe `"pbft_proportional"` default applies instead.
- **`attack_mode.*`** — no runtime attack-injection engine exists;
  `--scenario` selects a hardcoded function, there's no config-driven
  way to vary `injection_variants`/`intensity` against a live federation.
- **`risk_tiering.*` / `cost_ceilings.*`** — no code path classifies
  actions into risk tiers or tracks token spend; same "no Phase 1
  equivalent" status ADR-012 already gave these blocks.
- **`detection_thresholds.cusum_slack`** — no CUSUM detector exists
  anywhere in this codebase (`adaptive_detection.py` is a rolling-window
  calibrated cap, a different algorithm family).
- **`detection_thresholds.volume_cap_mode` / `static_volume_cap`** —
  the real analogue (`AdaptiveOrgVolumeDetector.fallback_cap`, default
  0.35) is a *fraction* of calibrated baseline traffic; `static_volume_cap: 50`
  reads as an *absolute message count* — a real unit mismatch, not a
  naming difference.
- **`fail_safe_defaults.*`** (all four sub-fields) — each depends on a
  mechanism that doesn't exist yet: real KMS calls (ADR-003, still an
  open cloud-build blocker), a taint tri-state, a FARS staleness clock.

### Integration

- `main.py` gained `--runtime-config <path>`. When supplied, it loads
  and applies the config, prints the `summarise()` report, and does a
  **real dry-run federation build** from `federation.orgs` (via
  `build_federation_from_config` — the same function the rest of the
  codebase already trusts, not a parallel code path) to prove that
  field is genuinely wired, not just parsed. If the configured org
  names don't match the demo's `OrgA`/`OrgB`/`OrgC` convention (the
  real file's `org_a`/`org_b`/`org_c` don't), it prints an explicit
  warning and the bundled E1–E4 scenarios still run against the
  standard 3-org demo federation, not the configured one.
- **Deliberately not done:** refactoring `scenario_prompt_injection`/
  `scenario_toctou`/`scenario_trust_boundary_violation`/
  `scenario_memory_manipulation` to take an arbitrary org list instead
  of hardcoding `"OrgA"`/`"OrgB"`/`"OrgC"` by name. This is a real
  design decision (see pros/cons below), not folded into this pass.
- `requirements.txt` gained `PyYAML>=6.0` as a real (not test-only)
  dependency.

### Verified end-to-end (not just unit-tested)

- `python runtime_config.py farf_runtime_config.yml` — standalone CLI
  entry point, run against the researcher's actual file, produces the
  correct APPLIED/PARSED_ONLY report.
- `python main.py --scenario composite --runtime-config farf_runtime_config.yml`
  — full integration: loads the real file, dry-run builds a 3-org
  federation from `org_a`/`org_b`/`org_c` (resolved quorum = 3.0,
  matching `recommended_quorum_for_pbft(3)`'s documented unanimity-at-N=3
  reasoning), prints the naming-convention warning, then runs the
  composite scenario normally against the standard demo federation.
- Two forced-error paths (`--runtime-config` pointing at a nonexistent
  file; a `federation.orgs` field that isn't a list) both surface as
  the new clean `[FARF] FATAL: RuntimeConfigError: ...` message via
  item 1's exception handler, exit code 1 — proves the two changes
  this session compose correctly, not just individually.
- Default runs with no `--runtime-config` flag at all (`--scenario all`)
  — byte-identical behaviour to before this session, confirming the new
  flag is additive, not a breaking change to the existing CLI.
- New test file `tests/test_08_runtime_config.py` — 20 tests: every
  field-classification claim above, the missing-file/malformed-YAML/
  malformed-orgs error paths, env-var precedence (config file vs. an
  explicit operator env var), idempotent re-application, and the real
  `build_federation_from_config()` integration against the actual file
  shape (not a hand-picked simplified fixture).
- Full regression after both changes: **77 passed** (57 pre-existing +
  20 new), 0 skipped; lint unchanged (0 high-confidence, same 3
  low-confidence); all 22/22 pentest scripts still exit 0.

## 3. ADR-006 — parallel-process witness nodes: NOT implemented, pros/cons only

The user asked whether splitting `FederationLedger`'s witness nodes
across two real OS processes (rather than all running in one process,
as today) would reveal any benefit for "the quorum math" specifically,
and explicitly asked for a pros/cons writeup rather than a unilateral
implementation. Delivered in the chat reply, not here — summary:
**the quorum arithmetic itself (`recommended_quorum_for_pbft`) is a
pure static function, unaffected by process boundaries; a multi-process
split would exercise IPC/concurrency/message-ordering robustness, not
the math.** Full reasoning, options, and trade-offs in the reply;
nothing committed to code this session.

## Documentation sync

- `ARCHITECTURE_DECISIONS_1.md`: Summary table's ADR-006 "Code status"
  cell and ADR-012 row both updated (see next commit in this session);
  new "Closed in v7.9.9" Internal Audit block added; `main.py`'s
  top-level exception handler removed from the "correctly deferred, not
  a blocker" list (it's now done, not deferred); ADR-012's schema
  section gains a cross-reference to `runtime_config.py` as the first
  REAL (non-illustrative) implementation of a subset of that schema.
