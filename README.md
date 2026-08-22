# FARF Prototype — Local Experimental Implementation

A resource-light, laptop-runnable implementation of the five FARF artefacts
described in *Federated Adversarial Resilience Framework for Cross-Organisational
Multi-Agent Collaboration* (Sections 7.4–7.9). Built for:

**Intel Core i5 · 8 GB RAM · NVIDIA GTX 1650 (4 GB VRAM) · Windows 11**

No GPU load, no Docker, no external LLM calls are required to run the full
pipeline — everything executes on CPU in well under a second per scenario.

---

## 1. Why it looks the way it does (resource-constraint decisions)

| Proposal component | Full-scale tool | What this prototype uses instead | Why |
|---|---|---|---|
| Federated Adversary Model | TLA+ | NetworkX directed graph + path/threshold reasoning | Same structural guarantees for demo-scale federations (2–10 orgs); export `to_dict()` to feed a TLA+ spec later if you need machine-checked proofs |
| Federated Trust Protocol | DID:key + W3C VC + blockchain-free ZK | Ed25519 `did:key` + signed JSON VCs + nonce/TTL replay guard + hash-commitment attestation | `cryptography` is pure CPU, no GPU needed; a real zk-SNARK library (e.g. py_ecc) can be swapped in later without touching the rest of the pipeline |
| Federated Agent Layer (Advisor/Executor) | LangGraph/CrewAI + local quantised LLM (Ollama) | Deterministic rule-based `Agent` class | A 3–4B quantised model on a 4GB-VRAM card is workable but slow for iterative testing; the agent interface (`plan()`/`execute()`) is designed so you can drop in an Ollama call later with zero changes elsewhere |
| Docker-isolated organisations | Docker Compose federation | In-process namespaces (org strings) routed through one `FederationBus` | Avoids Docker Desktop's RAM overhead on an 8GB machine while preserving the "all cross-boundary traffic goes through one mediator" property that matters for the security argument |
| Provenance reasoning | Soufflé Datalog | NetworkX reachability (`descendants`, `all_simple_paths`) | Gives the same "who could this reach" answers instantly; swap in Soufflé later for full first-order-logic rules if your evaluation needs it |
| Audit storage | Enterprise SIEM | SQLite (`farf_audit.db`) | Zero setup, inspectable with any SQLite browser, matches the proposal's "SQLite audit logs" data source |

This lets you validate the **architecture and security logic** now, and swap
in heavier components (Docker, Ollama, Soufflé, TLA+) selectively later for
the full dissertation evaluation without redesigning anything.

---

## 2. File map → FARF artefact → research objective

| File | FARF Artefact | Objective |
|---|---|---|
| `adversary_model.py` | 1. Formal Federated Adversary Model | O1, O2 |
| `trust_protocol.py` | 2. Federated Trust Protocol | O2 |
| `orchestration.py` | 3. Secure Orchestration & Behavioural Governance | O3, O4 |
| `taint_engine.py` | 4. Provenance-aware Taint Propagation Engine | O5 |
| `fars.py` | 5. Federated Adversarial Resilience Score (FARS) | O6 |
| `federation_bus.py` | Integration layer — routes every message through 1→2→3→4→5 in sequence | O3–O5 |
| `federation_ledger.py` | Blockchain-style quorum consensus for federation-wide (org-level) recovery — no single org can unilaterally clear its own quarantine | O3, O4 |
| `memory_store.py` | Hash-chained, per-writer-signed agent memory (ASI06) — poisoning/tampering detection, single-record revocation, delegated writes | O5 |
| `adaptive_detection.py` | Opt-in per-org volume cap calibrated from each org's own baseline traffic, instead of one fixed federation-wide constant | O4 |
| `agents.py` | Federated Agent Layer (Advisor/Executor stand-ins) | supports O7 |
| `main.py` | Experimental driver — the four attack scenarios (E1–E4) | O7 |
| `tools/farf_security_lint.py` | VAST-style automated CI check — catches send()/write_memory() calls that bypass signing, and orphaned action_types with no policy rule | supports O3 |

**v7.6 additions (this version):** audit-write failure handling --
`FederationBus._write_audit_row()` no longer crashes the caller on a
SQLite failure; failed rows buffer in memory and flush automatically
(or via `flush_buffered_audit_rows()`) once the DB recovers, with the
hash chain provably intact across the cycle. See `THREAT_MODEL.md`
Section 21 and `pentest/pt21_audit_write_resilience.py`.

**v3 additions:** `federation_ledger.py` (new), plus
Zero-Trust per-message signing in `federation_bus.py`/`trust_protocol.py`
(`require_message_signatures=True`, `sign_and_send()`). See
`THREAT_MODEL.md` Sections 6–7 and `pentest/pt07_*`, `pentest/pt08_*`.

**v5–v7.4 additions:** revocation registry, `reinstate()` capability
gate, memory/context integrity, cryptographically-accountable
stake-weighted ledger consensus, temporally-adaptive FARS (EWMA +
recovery-time tracking), an independent fan-out detector, combined
detection-latency metrics, chaos/fuzz testing, and a quantified +
fixed O(N²·⁹) FARS performance bottleneck. Full write-up in
`THREAT_MODEL.md` (19 sections) and `RISK_APPENDIX.md` (LINDDUN/OCTAVE/
Trike/PASTA analysis + the VAST lint tool above).

---

## 3. Setup

```bash
python -m venv venv
venv\Scripts\activate          # Windows
pip install -r requirements.txt
```

Only two dependencies: `networkx` and `cryptography`. Both are pure-Python/CPU
wheels on Windows — no build tools required.

## 4. Running the experiments

```bash
# Each of the 4 attack scenarios (E1-E4) run in ISOLATION with a fresh
# federation each time — easiest for inspecting one artefact at a time.
python main.py --scenario all

# All 4 attacks chained through ONE shared federation, to see cumulative,
# federation-wide resilience degradation under a coordinated campaign
# (mirrors Fig 7.9 in the proposal).
python main.py --scenario composite

# Run a single scenario in isolation
python main.py --scenario prompt_injection
python main.py --scenario toctou
python main.py --scenario trust_boundary
python main.py --scenario memory_manipulation
```

Each run prints:
- the Federation Bus decision (`allow` / `block` / `quarantine`) and reason for every message,
- (E3 only) trust protocol verification results including replay/spoof detection,
- (E4 only) blast-radius, reconstructed privilege-propagation paths, and formal adversary-model escalation paths,
- the resulting **FARS** score and its four weighted components.

An SQLite audit trail (`farf_audit.db`, or `farf_audit_<scenario>.db` in
`--scenario all` mode) is written next to the script — open it with any
SQLite browser or:

```bash
python -c "import sqlite3; [print(r) for r in sqlite3.connect('farf_audit.db').execute('SELECT * FROM audit')]"
```

## 5. Inspecting/extending each artefact independently

Every module also has a `if __name__ == "__main__":` self-test at the bottom,
so you can validate one artefact in complete isolation:

```bash
python adversary_model.py
python trust_protocol.py
python orchestration.py
python taint_engine.py
python fars.py
```

This matches the proposal's DSR principle of validating each artefact
independently *before* integration (Fig 7.5).

## 6. Where to extend for the full dissertation evaluation

1. **Statistical validation (Tab 7.9):** run each scenario N times with
   randomised federation topologies (vary `n_orgs`, delegation weights,
   attack timing) and collect `bus.current_fars()` + `orchestration.audit_log`
   into a pandas DataFrame; feed into `scipy.stats.ttest_rel` /
   `wilcoxon` against a "no-FARF" baseline (just skip the orchestration/taint
   steps in `federation_bus.send()`).
2. **50+ synthetic federation topologies (Tab 7.6):** use
   `networkx.gnp_random_graph` or `barabasi_albert_graph` to auto-generate
   delegation graphs of 2–10 orgs and feed them into `FederatedAdversaryModel`.
3. **Public benchmarks (AgentDojo, INJEC, etc.):** these are prompt/response
   datasets — pipe their adversarial instructions into `Agent.plan()` in
   place of the hard-coded strings in `main.py`.
4. **Real LLM reasoning:** once you're happy with the security logic, replace
   `Agent.plan()`/`Agent.execute()` bodies with a call to a local Ollama model
   (`ollama.chat(model="phi3:mini", ...)`), keeping everything else unchanged.
   A smaller, already-implemented version of this pattern exists today for
   the prompt-injection detector specifically — see `llm_judge.py` and
   `tools/ollama_pt15_comparison.py`; the model it calls is configurable
   via the `FARF_LLM_JUDGE_MODEL` env var (default `qwen3:4b`), so if that
   model doesn't fit your VRAM/RAM headroom, set e.g.
   `FARF_LLM_JUDGE_MODEL=deepseek-r1:1.5b` before pulling and running
   rather than editing code.
5. **TLA+ / Soufflé:** export `adversary_model.to_dict()` /
   `taint_engine.flow_graph` and translate into the formal toolchains for the
   subset of results you want machine-checked proofs for.

## 7. Test protocol

A full pytest-based test suite lives in `tests/`, derived directly from
four architecture diagrams (baseline interaction, E1-E3 attacks, E4
memory-manipulation end-to-end, and the statistical validation workflow).

```bash
pip install pytest scipy numpy pandas
python -m pytest tests/ -v
```

**See `TEST_PROTOCOL.md`** for the full diagram-to-test mapping, what each
suite checks, and two genuine integration gaps this testing found and
fixed in the artefacts themselves (Trust Protocol was isolated from FARS;
FARS's taint-containment score was blind to low-intensity fully-propagated
attacks) -- worth reading before citing FARS numbers in your evaluation
chapter.

## 8. Threat model & pen-test

`THREAT_MODEL.md` has a full STRIDE analysis of all 6 components, backed
by 22 runnable exploit scripts in `pentest/` -- each one attacks the
actual running code, not a theoretical description. All 6 originally
succeeded against the pre-hardening prototype; the code in this delivery
has since been hardened (identity admission control binding the Trust
Protocol to the message bus, fail-closed policy validation, org-level
Sybil detection, re-attestation-gated recovery, a fixed ZK salt leak,
and a tamper-evident audit log) and all 6 now fail as designed.

```bash
python -m pentest.pt01_identity_spoofing
# ...see pentest/README.md for the rest
```

Read `THREAT_MODEL.md` Section 6 in particular before citing any FARS
numbers or containment claims in your dissertation -- it documents two
things the hardening process itself found (a threshold that needed
empirical tuning rather than a guess, and a logging-order bug that
briefly masked a more specific audit reason), which is exactly the kind
of finding an evaluation chapter should surface.

## 9. Known simplifications to disclose in your methodology chapter

- The "Zero-Knowledge Attestation" is a salted hash-commitment scheme, not a
  true zk-SNARK — sufficient to demonstrate the trust-without-disclosure
  property, but not cryptographically equivalent to the proposal's ZK claim.
- Organisations are logical namespaces in one process, not separate Docker
  containers — there is no network-layer isolation between them (acceptable
  for validating security *logic*, not for measuring *deployment* overhead).
- Agents are deterministic rule-based stand-ins, not LLMs — fine for testing
  the security pipeline, but you'll want real LLM-driven agents before
  citing any "attack success rate" figures against genuine prompt-injection
  corpora.
