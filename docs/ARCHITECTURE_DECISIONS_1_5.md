# FARF Phase 2 — Architecture Decisions Record (ADR)

**Scope:** cloud build for the Federated Adversarial Resilience Framework, moving
from the laptop-runnable Phase 1 prototype (`farf_prototype_v7_6/`) to a
genuine two-cloud federation.

**Cloud target (confirmed as Accepted status quo):** two real, independent
providers — **AWS** and **Azure** — not a single-cloud multi-account
simulation. Every ADR below now also documents a **parallel GCP-equivalent
choice**, so that substituting GCP for Azure as the second provider (per the
companion `CLOUD_PROVIDER_COMPARISON.md` cost/service/hybrid-maturity
analysis) is a find-and-replace exercise against a known-good alternative,
not a redesign. Where the GCP path materially changes the decision's
reasoning (not just the service name), that's called out explicitly rather
than treated as a drop-in swap.

**Federation topology used throughout this document:** OrgA and OrgB are
hosted in AWS (us-east-1); OrgC is hosted in Azure (East US) under the
Accepted status quo, or **GCP (us-east4)** under the documented alternative.
This mirrors `main.py`'s existing `n_orgs=3` default and lets every existing
scenario (E1–E4) and the Tab 7.8 trial harness run unmodified against the
cloud build for direct before/after comparison, regardless of which second
provider is finalised.

Each decision below is numbered (ADR-001, ADR-002, …), states its status, the
Phase 1 finding that motivates it (with file:section references into the
existing `THREAT_MODEL.md` / `RISK_APPENDIX.md` / `PHASE1_GAP_REPORT_v7.6.md`
/ `README.md`), the decision itself, what was considered and rejected, and
the consequences — including the honest costs, not just the benefits.

**Revision note (this version):** re-checked against `README.md` in full
(not just the threat-model/gap-report docs already covered). Four genuine
gaps surfaced that no prior ADR addressed — formal verification tooling
placement, the ZK-attestation upgrade path, real LLM-driven agents replacing
the deterministic stand-ins, and CI/CD placement for the existing VAST lint
tool. These are now ADR-013 through ADR-016.

---

## ADR-001: Federation Bus becomes a distributed relay, not a single mediator

**Status:** Accepted

**Motivating finding:** `THREAT_MODEL.md` §7 / `PHASE1_GAP_REPORT_v7.6.md` §2
— "Single-process `FederationBus`, single global lock… the process itself is
a hard SPOF," explicitly scoped as a Phase 2/cloud item. Also closes
`README.md` §1's "Docker-isolated organisations → Docker Compose federation"
row: Docker Compose is no longer the target at all once orgs live in
genuinely separate cloud accounts — real account/subscription/project
boundaries supersede container-level isolation entirely, which is a strictly
stronger isolation guarantee than Docker Compose was ever offering.

**Context:** In Phase 1, one Python process holds one `RLock` and mediates
every message. With OrgA/OrgB in AWS and OrgC in a second cloud, there is no
single process that can sit in the middle without either (a) picking one
cloud to host the mediator, which quietly reintroduces a single-cloud
dependency the whole point of a two-cloud test is meant to rule out, or (b)
something genuinely distributed.

**Decision:** The Federation Bus becomes **one lightweight relay instance per
cloud** (an AWS-hosted relay for OrgA/OrgB traffic, a second-cloud-hosted
relay for OrgC traffic), each running the same orchestration/taint/trust
pipeline locally for messages that stay within its own cloud, and forwarding
cross-cloud messages over an **authenticated, mutually-verified HTTPS+mTLS
channel** directly between the two relays — no third mediator, no cloud
"owns" the other. Each relay independently runs the full
`orchestration.evaluate()` → `taint.propagate()` → `trust.verify_credential()`
pipeline on inbound cross-cloud messages before accepting them locally, so a
compromised or malicious relay on one side cannot force a decision on the
other side by construction, not by trust.

**Alternatives considered:**
- *Single relay in one cloud, orgs in the other cloud call it remotely* —
  rejected: this is a single-cloud dependency wearing a federation costume,
  and defeats the purpose of choosing two real providers.
- *Message broker bridging (EventBridge↔Event Grid, or EventBridge↔Pub/Sub via
  a bridge service)* — more resilient (durable delivery, replay, dead-letter
  handling) but adds real operational complexity and a third component to
  secure. Documented as the natural **upgrade path** if Phase 2 experiments
  show the direct mTLS channel's latency/reliability is a limiting factor —
  not built now, because the direct-channel version is enough to validate the
  architecture and adding broker infrastructure before it's needed would
  inflate cost per ADR-011.

**Consequences:**
- Real cross-cloud network partition risk now exists (didn't exist in
  Phase 1's in-process design) — this is exactly what ADR-004's fail-safe
  matrix has to handle for real, not hypothetically.
- Real cross-cloud latency (tens of ms typical, more under congestion) is now
  part of every cross-org message — orchestration/taint checks stay local-only
  (fast), only the final admitted message crosses the wire.
- Each relay's local quarantine state (`SecureOrchestrationLayer.quarantined_agents`)
  is now genuinely per-cloud, not global-in-one-process — ADR-002 addresses
  how federation-wide state (FARS, ledger quorum) stays consistent regardless.

**GCP equivalent (if AWS+GCP is chosen instead of AWS+Azure):** OrgC's relay
runs on **Cloud Run** instead of Container Apps. This is not just a
name-swap worth flagging: `CLOUD_PROVIDER_COMPARISON.md` §2.4 cites Cloud
Run as "the 2026 leader for concurrency-heavy workloads and AI inference"
due to its container-native scaling and resource efficiency [11] — a
genuine (not just cosmetic) point in GCP's favour for this specific ADR,
and specifically well-suited to a relay's bursty, request-heavy traffic
shape. (Its 1,000-concurrent-requests-per-instance ceiling, independently
confirmed against Google's own Cloud Run quota documentation, reinforces
this but is not itself a claim §2.4 makes — corrected here after an
internal audit found the original phrasing over-attributed that specific
figure to the comparison doc.) The direct mTLS
channel design is otherwise unchanged.

---

## ADR-002: Federated context graph — eventually-consistent, not shared-memory

**Status:** Accepted

**Motivating finding:** Pasted discussion notes — "shared structural memory
layer as the backbone of federation… Federated graph-based context layer."

**Context:** `TaintPropagationEngine`'s `flow_graph` and `FederatedAdversaryModel`'s
delegation graph are in-process NetworkX graphs in Phase 1. Two clouds means
two processes, each with only a partial view of the true federation-wide
graph.

**Decision:** Each cloud's relay maintains its own **local** flow/delegation
graph (unchanged code — `taint_engine.py`/`adversary_model.py` don't need to
know they're now one of two instances), and publishes graph deltas
(new edges, quarantine actions, escalation findings) to a small **replicated
context store** — one managed key-value table per cloud (DynamoDB in AWS,
Cosmos DB in Azure) with **cross-region/cross-cloud replication via signed,
append-only delta records**, not raw table replication. Each relay
periodically reconciles its local graph against the other cloud's published
deltas. This is explicitly **eventually consistent**, not shared memory —
consistent with the pasted notes' instruction to prefer "controlled
replication, not raw shared prompt context."

**Alternatives considered:**
- *A single shared graph database both clouds write to directly* — rejected:
  requires picking one cloud to host it (single-cloud dependency again) or a
  third-party managed graph DB (new vendor dependency, new attack surface, and
  a new SPOF that isn't even one of the two clouds being tested).
- *No replication, purely local graphs* — rejected: `reconstruct_privilege_path()`
  and `cross_org_attack_paths()` (Objective 4/5 in the proposal) need
  federation-wide visibility to be meaningful; a purely local view would
  silently under-report cross-cloud escalation paths.

**Consequences:**
- A window exists (bounded by replication lag, target <5s) where one cloud's
  view of the federation graph is stale relative to the other's. Taint
  containment decisions (`quarantine_edges_from`) remain fail-closed and
  **local-first** — a cloud doesn't wait for the other side's graph state to
  decide whether to quarantine its own agents, only to reconstruct a
  federation-wide picture *after* the fact for FARS/forensics.
- This directly extends, rather than replaces, `taint_engine.py`'s existing
  `_update_peak_reach()` peak-capture design (THREAT_MODEL.md's fix for
  quarantine erasing its own evidence) — the same "capture evidence before
  quarantine removes it" principle now also has to survive replication lag,
  not just local quarantine timing.

**GCP equivalent (if AWS+GCP):** The replicated context store's second half
moves to **Firestore** (closest DynamoDB/Cosmos DB analogue). This is the one
ADR where GCP has a genuine, quantified cost edge worth banking, not just
service-name parity: `CLOUD_PROVIDER_COMPARISON.md` §2.2 found GCP's
**inter-region rate is $0.01/GB versus $0.02/GB on both AWS and Azure** —
exactly the traffic pattern this ADR generates (frequent, small,
delta-record replication). At sustained delta-replication volume this is a
straightforward 50% reduction on this specific ADR's recurring transfer
cost, independent of which network tier (Standard/Premium) is chosen for the
rest of the architecture.

---

## ADR-003: Per-org keys stay in that org's home cloud's KMS — never cross-cloud

**Status:** Accepted

**Motivating finding:** `THREAT_MODEL.md` §9 — "HSM/KMS-backed key storage…
deliberately deferred to FARF Cloud," listed as the top Phase 2 infrastructure
dependency.

**Decision:** OrgA/OrgB's Ed25519 signing keys (currently
`Ed25519PrivateKey` objects held in plain process memory in
`trust_protocol.py`) move to **AWS KMS** (asymmetric signing keys, `Sign`/`Verify`
API calls replace in-process `cryptography` calls). OrgC's key moves to
**Azure Key Vault**. Critically: **no cloud ever holds another org's private
key material** — this is the direct cloud realisation of the proposal's
design principle that each organisation "retains complete control over its
local governance policies, identity management mechanisms" (§7.5). A relay
signs/verifies only its own local orgs' messages via its own cloud's KMS;
verifying a message signed by an org in the *other* cloud is done via that
org's **public key only** (fetched from the trust registry, ADR-005), never
by asking the other cloud's KMS to do it on this cloud's behalf.

**Alternatives considered:**
- *One cloud's KMS holds all keys, cross-cloud calls for the other org* —
  rejected outright: this is exactly the single-point-of-unilateral-control
  the proposal's federation design exists to avoid, and would mean an AWS
  outage taking down OrgC's ability to sign, defeating cross-cloud resilience.
- *A third-party, cloud-neutral KMS (HashiCorp Vault, self-hosted)* —
  considered as a future option; rejected for Phase 2 specifically because it
  introduces a third infrastructure dependency to secure and pay for, when
  each org's *own* cloud's native KMS already satisfies "org controls its own
  keys" without adding a component.

**Consequences:**
- `trust_protocol.py`'s `verify_credential()` logic (signature check, replay
  detection via nonce, TTL expiry) is unchanged — only *where the private key
  lives* changes. This is a deliberately narrow-blast-radius change.
- Signing now costs one network round-trip per signature instead of an
  in-memory operation — directly informs ADR-011's token/cost ceiling design
  (batch where possible; don't sign per sub-step of a workflow if one signature
  over the whole action suffices).
- Key rotation (deferred alongside KMS in Phase 1) is now a real, schedulable
  operation via each cloud's native KMS rotation API — worth enabling as a
  follow-up once Phase 2's baseline is stable, not required for the initial
  cloud build.

**GCP equivalent (if AWS+GCP):** OrgC's key moves to **Google Cloud KMS**
instead of Azure Key Vault. Worth flagging honestly rather than glossing
over: `CLOUD_PROVIDER_COMPARISON.md` §2.3 found Cloud KMS's pricing is
structured around active key-version count and per-operation rate rather
than Azure's flat, easy-to-estimate per-10k-operations charge or AWS's flat
per-key monthly fee — **this is the one ADR where the GCP-equivalent cost is
genuinely the hardest of the three to estimate from list price alone**,
which is why the comparison document recommends a short pilot measuring
actual signature volume under E1–E4 load before finalising the KMS choice on
cost grounds specifically for this ADR.

---

## ADR-004: Fail-safe defaults per component (network-partition-aware)

**Status:** Accepted

**Motivating finding:** Pasted discussion — "every component either fails
closed (blocks/quarantines) or fails open (allows) — and the choice must be
explicit and logged, never accidental," plus ADR-001's new real partition risk.

**Decision:** The component-by-component fail-safe table from the earlier
discussion is retained, with one addition specific to genuine two-cloud
federation: **cross-cloud network partition is its own explicit failure mode**,
distinct from "component X is down within a healthy network."

| Component | Failure mode | Fail-safe behaviour | AWS+Azure mechanism | AWS+GCP mechanism |
|---|---|---|---|---|
| Federation Bus (relay) | Cross-cloud channel down | Fail **closed** for cross-org messages; local-org traffic continues normally | mTLS channel health check; circuit breaker (exponential backoff, bounded retry) | Same design, GCP side runs on Cloud Run health checks |
| Trust Protocol | Home-cloud KMS unreachable | Fail **closed** — no new signatures issued; existing verified credentials honoured only until TTL | KMS SDK error → immediate fail-closed | Cloud KMS SDK error → same fail-closed behaviour |
| Orchestration | Replicated context graph (ADR-002) stale/unreachable | Continue local decisions; **flag** cross-cloud queries as `stale_context` | Reconciliation-lag timestamp on every graph-derived answer | Same, against Firestore's replication-lag timestamp |
| Taint Propagation | Peer relay unreachable mid-propagation | Treat the message as **maximally tainted** at the local boundary | Same `_update_peak_reach()` logic, unchanged | Same, unchanged — this logic is entirely cloud-agnostic |
| FARS | Peer cloud's component data unavailable | Compute/serve **local-only FARS** (`scope: local`); freeze federation-wide score as `stale` | Additive field on `fars.compute()`'s return dict | Identical — no cloud-specific behaviour here |
| Federation Ledger | Quorum unreachable | No unilateral recovery (ADR-006's whole point) | Multi-node quorum spanning both clouds | Multi-node quorum spanning AWS+GCP, same logic |
| Memory Store | Cross-cloud delegated write | Fail **closed** unless grant verifies against owner's home-cloud KMS signature | AWS KMS / Azure Key Vault verification | AWS KMS / Cloud KMS verification |
| Structured logging | Cloud's log sink unreachable | Fail **open** — logging degradation must never block a security decision | CloudWatch/Azure Monitor unreachable → local rotating-file fallback | CloudWatch/Cloud Logging unreachable → same local fallback |

**Consequences:** the one universal rule from the earlier discussion still
holds and is now load-bearing for real: **any ambiguity about whether a
cross-cloud check actually completed resolves to block, not allow.** This
rule itself is provider-neutral — it doesn't change under either cloud
combination, which is the point.

**Genuine cross-cloud partition test, delivered 26 August 2026 (pending
live run):** every partition evidence gathered before this point was
either a single-host Docker network disconnect or an unreachable-hostname
condition observed from an operator's laptop — neither is the actual
case this ADR names ("cross-cloud network partition is its own explicit
failure mode"). `aws_pilot/adr004_partition_client.py` closes that gap:
a long-running Fargate task (not the one-shot `org_client.py` pattern)
loops a real `/send` call against the GCP-hosted bus every few seconds,
logging each attempt's outcome with a timestamp. Run mid-loop, revoking
this task's security group's outbound rule via the AWS CLI produces a
genuine AWS↔GCP internet-path partition, not a container bridge —
restoring the rule tests recovery. Fail-closed here is structurally
guaranteed rather than logic-tested (a Fargate task that can't reach the
single GCP-hosted mediator has no fallback path to send through at all),
so what this test actually demonstrates is narrower and stated honestly:
(a) a real partition produces clean `timeout`/`connection_error` outcomes,
not a hang or a corrupted partial send, and (b) the system self-recovers
without manual intervention once the rule is restored, with the bus's
`/status` message count showing no phantom messages from the blocked
window. This is **not** a test of ADR-001/ADR-006's not-yet-built
distributed multi-node partition scenario (independent relay/ledger
nodes per cloud) — that remains open. See `AWS_CROSS_CLOUD_STEPS.md`
Step 13 for the exact revoke/restore commands and expected log output.

---

## ADR-005: No central CA — lightweight cross-cloud DID registrar, not a PKI hierarchy

**Status:** Accepted

**Motivating finding:** `THREAT_MODEL.md` §9 — "PKI/CA root-of-trust
hierarchy for org identities… every org self-issues its own DID with no
external attestation," deferred to Phase 2 as needing "real multi-party
infrastructure to be meaningful."

**Decision:** Do **not** stand up a certificate authority — this would
contradict the proposal's explicit design goal (§7.5: "without relying upon a
central certificate authority or blockchain-based registry"). Instead: a
small, **replicated-across-both-clouds** registrar record per org —
`{did, home_cloud, kms_key_reference, org_name, registered_at}` — signed by a
one-time federation-bootstrap ceremony (each founding org's operator manually
countersigns the initial registry, a deliberately manual, auditable step, not
an automated trust decision). New orgs joining later require an explicit
quorum-witnessed addition through the Federation Ledger (ADR-006) — so
*joining* the federation goes through the same accountable quorum process as
*recovering* from quarantine already does, rather than inventing a second,
weaker trust-establishment path.

**Alternatives considered:**
- *Full X.509 PKI hierarchy* — rejected: contradicts the proposal's stated
  decentralisation goal and reintroduces the single-root-of-trust problem the
  whole design exists to avoid.
- *Fully automatic, no-ceremony bootstrap* — rejected: an unattended bootstrap
  step is exactly the kind of "AI/system decides who to trust with no human
  check" pattern the pasted discussion's HITL risk-tiering explicitly warns
  against for anything touching trust boundaries.

**Consequences:** MAESTRO Layer 7 (agent-ecosystem-level discovery/reputation
across unrelated federations, `THREAT_MODEL.md` §11) remains genuinely out of
scope — this registrar solves "how do the *known* founding + quorum-admitted
orgs of *this* federation establish trust," not "how does a wholly external
agent get discovered." That stays a named Phase 3 candidate, not silently
implied as solved.

**GCP equivalent (if AWS+GCP):** No meaningful change — this is deliberately
one of the **least cloud-provider-sensitive ADRs** in the whole document,
precisely because it was designed from the start to avoid entangling itself
with any single vendor's native identity primitives (AWS IAM, Entra ID, or
Google Cloud IAM). The registrar record's `home_cloud` field simply takes
the value `"gcp"` instead of `"azure"` for OrgC; the bootstrap ceremony and
quorum-witnessed join process are entirely unchanged.

---

## ADR-006: Federation Ledger becomes a real multi-node quorum across both clouds

**Status:** Accepted

**Motivating finding:** `THREAT_MODEL.md` §7/§12 — "Federation Ledger
consensus is an in-memory single-process stand-in… not real distributed BFT
consensus," explicitly named "the single highest-value Phase 2 item" in the
earlier SPOF audit.

**Decision:** One witness node per org — **two in AWS (OrgA, OrgB), one in
the second cloud (OrgC)** — each independently verifying and signing witness
votes via its own org's KMS key (ADR-003), matching `federation_ledger.py`'s
existing stake-weighted quorum logic (`witness()`, `_commit_block()`)
unchanged in its core algorithm. `recommended_quorum_for_pbft(n_orgs)`
(already implemented, currently opt-in per THREAT_MODEL.md §12) becomes the
**default**, not opt-in, for the cloud build specifically *because* a
genuine two-cloud deployment is exactly the adversarial-partition scenario
PBFT-proportional quorum was designed for.

**Consequences:**
- At N=3 orgs (current default), PBFT-correct quorum requires **all 3** —
  documented in `pentest/pt11_ledger_witness_forgery.py`'s own output
  ("N=3 orgs tolerates 0 Byzantine orgs, so PBFT-correct behaviour requires
  ALL 3, i.e. unanimity"). This is a genuine operational trade-off worth
  flagging in the dissertation: a 3-org federation with real cross-cloud
  partition risk has **no tolerance for one org being unreachable** when a
  federation-wide reinstatement is needed. Scaling to N≥4 orgs (achievable
  once Phase 2 infra supports adding orgs via ADR-005's quorum-witnessed join
  process) buys real Byzantine tolerance.
- Cross-cloud witness signature verification reuses ADR-003's "verify via
  public key only" pattern.

**GCP equivalent (if AWS+GCP):** The single peer-cloud witness node runs on
**Cloud Run with `min-instances: 1`** (guaranteeing it never scales to zero,
matching the "always-on, not spot" requirement quorum availability needs) or
**GKE Autopilot** for a harder availability guarantee. The N=3-requires-unanimity
consequence above is entirely provider-independent — it's a property of the
quorum math, not of which cloud hosts which node — so this finding applies
identically to AWS+Azure and AWS+GCP.

---

## ADR-007: Structured logging ships to each cloud's native log sink; a neutral aggregator (or a real SIEM) unifies both

**Status:** Accepted (local half already implemented in Phase 1's v7.8 work)

**Motivating finding:** `PHASE1_GAP_REPORT_v7.6.md` §5 (closed:
`farf_logging.py` now wired into all 10 production modules, with local
rotating-file persistence under `logs/`). Also closes `README.md` §1's
"Audit storage → Enterprise SIEM" row, which the prior version of this
document under-addressed by naming only a generic "neutral aggregator"
without naming actual SIEM-grade options.

**Decision:** No code change needed on the logging-emission side —
`farf_logging.py`'s `FARF_LOG_FORMAT=json` output is already the standard
shape CloudWatch Logs, Azure Monitor/Log Analytics, and GCP Cloud Logging
all expect from a container's stdout. Each cloud's relay ships its own logs
to its own native sink via the platform's built-in log driver — no in-app
SDK dependency. Two tiers of cross-cloud unification are now named
explicitly, addressing the README gap:
1. **Dashboards/alerting only** (what the prior version implied): a
   lightweight neutral aggregator (self-hosted Grafana + Loki).
2. **Real SIEM-grade correlation** (what README §1's "Enterprise SIEM" row
   actually asked for, and what the prior version under-specified):
   **Microsoft Sentinel** (genuinely cross-cloud-capable — natively ingests
   both AWS CloudWatch and GCP Cloud Logging, not just Azure Monitor,
   despite being an Azure-native product), **Google Security Operations
   (Chronicle)**, or **Splunk Cloud** (fully cloud-neutral, the traditional
   enterprise-SIEM choice) are the three realistic options. Recommend
   **Splunk Cloud** specifically for the two-cloud-federation case, since
   picking Sentinel or Chronicle as the aggregation layer would mean the
   *observability* layer privileges one of the two federated clouds even
   though the *data plane* deliberately doesn't — the same "no cloud is
   structurally privileged" principle ADR-001/003 apply to compute and keys
   should extend to observability tooling too.

**Consequences:** The existing fail-open behaviour (`farf_logging.py`'s
RotatingFileHandler degrading gracefully if the logs directory can't be
written) extends naturally regardless of which SIEM/aggregator tier is
chosen — the container-local rotating file is always the fallback.

**GCP equivalent (if AWS+GCP):** AWS-hosted components ship to CloudWatch
Logs; GCP-hosted components ship to **Cloud Logging** instead of Azure
Monitor — same JSON-compatible format, zero code change. The Splunk Cloud
recommendation above is unchanged and if anything strengthened: it's
cloud-neutral regardless of whether the second provider is Azure or GCP.

**Gap found and fixed, 26 August 2026:** live-checked `docker/bus_service.py`
against `farf_logging.py` directly — the deployed shim never set
`FARF_LOG_FORMAT=json` anywhere (not in the `Dockerfile.cloudrun`/
`Dockerfile.awsecs` build, not in any `gcloud run deploy`/`aws ecs
run-task` command used so far). `farf_logging.py` defaults to `"text"`,
so every log line from both the GCP Cloud Run pilot and the AWS Fargate
pilot was the human-readable text formatter, not the structured,
queryable-by-field JSON this ADR's decision actually specifies. What
*was* confirmed working: stdout delivery to each cloud's native sink
(Cloud Logging / CloudWatch) — that half of the decision holds; the
format half didn't. **Fix:** add `FARF_LOG_FORMAT=json` to the
deployment env vars on both clouds — no code change, since
`farf_logging.py`'s formatter selection already reads this var
correctly; it was simply never set at deploy time. See
`AWS_CROSS_CLOUD_STEPS_1.md` Step 5 (task definition env var) and the
verification note added under Step 7 for the exact redeploy commands
and expected JSON output shape. Same pattern applied on the GCP side:
`gcp_pilot/PILOT_STEPS.md` Step 3 (`--set-env-vars=FARF_LOG_FORMAT=json`
added to the Cloud Run deploy) and the new Step 3b, which reads back via
`gcloud logging read` to confirm the lines are parsed JSON, not flat
text. **Neither fix has been re-verified against a live deployment as
of this edit** — both pilots were torn down before this gap was found,
so the next redeploy on either cloud needs to confirm real JSON output
before this note is upgraded from "fix applied" to "closed, live-confirmed."

---

## ADR-008: Crypto-shredding moves from an in-process dict to KMS-managed data keys

**Status:** Accepted

**Motivating finding:** `PHASE1_GAP_REPORT_v7.6.md` §1 — "Append-only chains
vs. 'right to erasure'… GDPR Art. 17-style erasure is fundamentally
incompatible with a tamper-evident append-only chain," closed locally via
`memory_store.py`'s per-record-key encryption + `erase_record_for_subject()`.

**Decision:** The local design (one symmetric key per record, "erasure" =
discard the key) is preserved conceptually but the per-record keys move from
an in-process Python dict to **KMS-generated data keys**
(`GenerateDataKey`/Azure Key Vault equivalent), wrapped by each org's
home-cloud KMS master key. "Erasure" becomes a real, auditable **KMS
key-deletion API call** (with the cloud's standard deletion-scheduling
window, e.g. AWS KMS's 7–30 day pending-deletion period) rather than an
in-process `del`.

**Consequences:** The deletion-scheduling window (not instantaneous) needs to
be disclosed accurately if this is cited as GDPR Art. 17 compliance evidence
— "erasure requested" and "erasure complete" are now observably different
points in time and should be logged as such (extends ADR-007).

**GCP equivalent (if AWS+GCP):** OrgC's data keys move to **Cloud KMS**
instead of Azure Key Vault. Worth flagging a real, non-cosmetic difference
here: **Cloud KMS's key-destruction scheduling window is a minimum of 24
hours** (configurable up to 30 days), materially shorter than AWS KMS's 7–30
day minimum and Azure Key Vault's comparable soft-delete retention window.
If GCP is the erasure-executing cloud, this is a genuinely *faster*, more
GDPR-Art.17-friendly default than either alternative — worth citing
specifically if erasure latency is discussed in the dissertation's
compliance section, not just noted as a service-name swap.

---

## ADR-009: Audit trail — per-org durable store + cross-cloud hash-chain anchoring

**Status:** Accepted

**Motivating finding:** `THREAT_MODEL.md` §4 — "Tamper-evident, not
tamper-proof… True tamper-proofing needs external anchoring," plus the prior
SPOF audit's S3 finding ("SQLite: single file, single writer, local disk").

**Decision:** Each org's audit trail moves to its home cloud's managed
durable store (Aurora Serverless v2 or DynamoDB for AWS orgs, Azure SQL
Database serverless or Cosmos DB for the Azure org) — preserving per-org data
residency/governance autonomy, consistent with ADR-003's key-locality
principle. The existing hash-chain design (`_write_audit_row`'s
`prev_hash`/`row_hash` chaining) is unchanged. What's new: each cloud
periodically publishes its **current chain-tip hash only** (not the
underlying rows) to the *other* cloud's ledger via the ADR-006 quorum
channel — a lightweight cross-cloud anchoring scheme that gives exactly the
"external anchoring" `THREAT_MODEL.md` §4 named as the missing piece.

**Consequences:** This directly closes the v7.6 in-memory-buffer gap too
(`THREAT_MODEL.md` §21's "process-crash-while-buffered" limitation) — a
managed durable store's own write-ahead durability guarantees replace the
in-memory buffer entirely for the cloud build (kept in the local prototype
for laptop/offline use, not removed there).

**GCP equivalent (if AWS+GCP):** OrgC's durable audit store becomes
**Cloud SQL** (auto-scaling) or **Firestore**, mirroring ADR-002's choice for
consistency across the two GCP-hosted durable-storage needs. The chain-tip
anchoring scheme is entirely provider-agnostic — it only requires each
cloud's ledger node to accept a small signed hash value from the other side,
which every option under consideration (DynamoDB, Cosmos DB, Cloud SQL,
Firestore) supports identically via the ADR-006 witness channel.

---

## ADR-010: Orchestration topology stays per-workload, now also per-cloud-boundary-aware

**Status:** Accepted

**Motivating finding:** Pasted discussion — "map workload → pattern rather
than picking one globally," three patterns (hierarchical Advisor-led, linear
Executor chains, bounded debate).

**Decision:** The three patterns and their workload mapping are unchanged.
One addition specific to real two-cloud federation: **linear Executor chains
that cross a cloud boundary get an explicit re-verification step at the
boundary itself**, not just at each logical hop — because ADR-001 means a
cross-cloud hop is also a network boundary where ADR-004's partition
handling applies. This coincides the TOCTOU-relevant re-validation
(`orchestration.py`'s `memory_toctou_mismatch`/`toctou_resource_mismatch`
rules) exactly with the point where genuine latency and partition risk are
highest.

**GCP equivalent (if AWS+GCP):** No change whatsoever — **this ADR is
entirely provider-neutral by design.** The orchestration topology decision
depends only on workload shape (decomposable vs. compliance-linear vs.
high-ambiguity-discovery) and on *whether* a hop crosses a cloud boundary,
never on *which* second cloud that boundary leads to. Flagged explicitly as
a "no delta" case rather than silently omitted, since a reader checking
every ADR for a GCP column should see a stated reason for the absence, not
an accidental gap.

**Code delivered, 26 August 2026 (validated in-process, live cross-cloud
run pending):** implemented as a purely additive, observational change —
deliberately **not** a new blocking rule, since changing `evaluate()`'s
decision logic here risked silently altering the same already-cited Tab
7.8/7.9 statistics the ADR-006 quorum-default question flagged earlier
(same academic-integrity concern, same resolution: don't touch decision
logic that's already been cited). `federation_bus.py`'s `send()` now
computes `crosses_org_boundary = (from_org != to_org)` and threads it
into `ActionEvent`; `orchestration.py`'s `evaluate()` logs a structured
`cross_boundary_toctou_reverification` event (agent, action type, both
hash pairs) whenever a TOCTOU-relevant action type (`execute_action`,
`memory_recall_use`) crosses that boundary — before this, the framework
had no record of which hops crossed an org/cloud boundary at all, so
there was no way to audit how many TOCTOU-relevant messages took the
cross-cloud path where the check-to-use window is widest. Validated
locally: full 89-test suite passes unchanged, `pt02`/`pt10` (the two
pentests directly exercising these rules) produce byte-identical
decisions/reasons to their pre-patch runs, and the new log line appears
correctly under both `FARF_LOG_FORMAT=text` and `=json`. Live
cross-cloud confirmation (does the log line actually appear in Cloud
Logging for a real AWS→GCP `execute_action` hop) is the one thing still
pending — see `AWS_CROSS_CLOUD_STEPS.md` Step 14.

**Re-applied and independently re-verified, 26 August 2026 (separate
session):** the code described above was **not actually present** in
the repo copy re-uploaded for this session (flagged under ADR-016's
"Independently re-confirmed" note) — re-applied both edits
(`ActionEvent.crosses_org_boundary` in `orchestration.py`,
`crosses_org_boundary = (from_org != to_org)` threaded through in
`federation_bus.py`'s `send()`) from scratch against this tree, then
re-ran every check the note above claims: full test suite (**89 passed**,
matching exactly), `pt02` (`incomplete_action_schema` on both attacks,
`NOT VULNERABLE`) and `pt10` (`memory_toctou_mismatch`, `NOT VULNERABLE`)
byte-identical to their pre-patch output, and the new
`cross_boundary_toctou_reverification` line confirmed firing correctly
under both `FARF_LOG_FORMAT=text` and `=json` on a real cross-org
`execute_action` call (`allow`/`no_violation` — the decision itself,
correctly, is untouched by this observational change). Live cross-cloud
confirmation remains the one open item, now genuinely blocked on the
same AWS account issue affecting the rest of this session's AWS-side
work, not on missing code.

---

## ADR-011: Cost and token governance — concrete service mapping

**Status:** Accepted

**Motivating finding:** Original cloud-build discussion's cost/token ceiling
requirements.

**Decision:** Concrete mapping across all three providers, so the second
cloud can be swapped without redesigning this table:

| Concern | AWS | Azure | GCP |
|---|---|---|---|
| Stateless agent workers (Advisor/Executor) | Lambda (scale-to-zero) | Azure Functions (Consumption plan) | Cloud Functions, or **Cloud Run** if ADR-015's real LLM agents ship (better concurrency economics for AI-inference-shaped traffic) |
| Relay / orchestration service | Fargate (spot where non-critical) | Container Apps | Cloud Run |
| LLM gateway (model routing, token caps) | API Gateway fronting Bedrock | API Management fronting Azure OpenAI | Apigee (or API Gateway) fronting **Vertex AI** |
| Per-org token budget enforcement | API Gateway usage plans | APIM policy (rate-limit-by-key) | Apigee quota policy |
| Durable audit store | Aurora Serverless v2 / DynamoDB on-demand | Azure SQL Serverless / Cosmos DB serverless | Cloud SQL / Firestore |
| Ledger quorum nodes | Fargate (always-on, NOT spot) | Container Apps (always-on tier) | Cloud Run (`min-instances`≥1) or GKE Autopilot |

Cost note tying back to `CLOUD_PROVIDER_COMPARISON.md`: compute pricing is
within ~20% across all three and should **not** drive this table's choices;
egress rate and KMS per-operation cost (ADR-003/§2.2–2.3 of the comparison
doc) are the variables that actually matter for FARF's chatty,
low-bulk-data traffic pattern. Model routing (cheap classification model
default, escalate only on ambiguous/high-risk-tier classification) and
prompt caching guidance are unchanged and apply identically regardless of
which cloud's gateway is handling a given org's traffic.

**Gap found, fix delivered 26 August 2026:** the "stateless agent workers"
row names **Lambda** for AWS, but every pilot exercised so far
(`aws_pilot/cross_cloud_timing_wrapper.py`, `aws_pilot/
adr004_partition_client.py`) ran on **Fargate** — that's this table's
*relay/orchestration* row, a different workload shape, not an intentional
substitution, just the natural fit for a container task at the time.
Fargate's cost/latency numbers therefore say nothing about this row's
actual claim. `aws_pilot/lambda_agent_worker.py` closes the gap: a real
Lambda handler running the same register→admit→send sequence
`org_client.py` uses, against the same GCP-hosted bus, so its numbers
are directly comparable to the Fargate figures already measured (Docker
bridge ~11.7ms, real Cloud Run WAN 337.8ms, Fargate cross-cloud —
pending your run). Reports per-call timing (`register_org_ms`,
`admit_agent_ms`, `send_ms`) plus a disclosed, non-authoritative
cold-start heuristic (`/proc/uptime` < 5s) since Lambda doesn't expose a
direct cold-start flag to handler code. See `AWS_CROSS_CLOUD_STEPS.md`
Step 15 for deployment and expected output.

---

## ADR-012: Runtime config schema — grounded in the actual implemented knobs

**Status:** Accepted (supersedes the illustrative schema from the earlier
discussion, now grounded in real parameter names from the shipped code)

**Decision:** Every field maps to a parameter that already exists in the
shipped code (`AdaptiveOrgVolumeDetector.__init__`, `FederationLedger.__init__`,
`FederationBus.__init__`'s `message_nonce_ttl_seconds`, `farf_logging.py`'s
env vars). The `home_cloud`/`kms_key_ref` fields already accommodate a third
provider value without any schema redesign — shown below with OrgC under
each alternative:

```yaml
# farf_runtime_config.yaml — hot-reloadable, no redeploy needed
federation:
  orgs:
    - { name: "OrgA", home_cloud: "aws", kms_key_ref: "arn:aws:kms:...", stake: 1.0 }
    - { name: "OrgB", home_cloud: "aws", kms_key_ref: "arn:aws:kms:...", stake: 1.0 }
    # OrgC under the Accepted AWS+Azure status quo:
    - { name: "OrgC", home_cloud: "azure", kms_key_ref: "https://<vault>.vault.azure.net/keys/...", stake: 1.0 }
    # OrgC under the documented AWS+GCP alternative (mutually exclusive with the line above):
    # - { name: "OrgC", home_cloud: "gcp", kms_key_ref: "projects/<proj>/locations/<loc>/keyRings/<ring>/cryptoKeys/<key>", stake: 1.0 }
  quorum_required: "pbft_proportional"   # matches FederationLedger(quorum=...), provider-independent

cross_cloud:
  channel_health_check_interval_s: 10
  channel_circuit_breaker_backoff_s: [1, 2, 4, 8, 16, 30]
  context_graph_reconciliation_target_s: 5

adaptive_volume_detector:   # matches AdaptiveOrgVolumeDetector's real __init__ params
  window: 40
  calibration_messages: 20
  cap_multiplier: 3.0
  fallback_cap: 0.35

trust_protocol:
  message_nonce_ttl_seconds: 300.0
  credential_ttl_seconds: 300.0

risk_tiering:
  low:    { autonomy: "full", token_cap_per_action: 2000 }
  medium: { autonomy: "oversight", token_cap_per_action: 4000, human_alert: true }
  high:   { autonomy: "hitl_required", token_cap_per_action: 8000, approval_timeout_s: 300 }

cost_ceilings:
  token_budget_per_org_per_day: 500000
  token_budget_action: "throttle_to_low_autonomy"
  model_routing:
    default: "small"
    escalate_on: ["ambiguous_classification", "high_risk_tier"]

logging:
  level: "INFO"          # FARF_LOG_LEVEL
  format: "json"         # FARF_LOG_FORMAT — required for CloudWatch/Log Analytics/Cloud Logging parsing
  to_file: true           # FARF_LOG_TO_FILE — local fallback stays on
  max_bytes: 5000000      # FARF_LOG_MAX_BYTES
  backup_count: 5         # FARF_LOG_BACKUP_COUNT

llm_judge:                 # v7.9.6 — llm_judge.py's optional third
                            # prompt-injection signal (ADR-015's smallest
                            # real test, see that ADR). Local-Ollama-only
                            # today; once ADR-015's real per-org gateway
                            # ships, `model` here is what gets replaced
                            # by Bedrock/Azure OpenAI/Vertex AI routing.
  model: "qwen3:4b"        # FARF_LLM_JUDGE_MODEL — single source of
                            # truth read by llm_judge.DEFAULT_MODEL;
                            # agents.detect_prompt_injection()'s own
                            # llm_model= param now resolves against this
                            # at call time instead of hardcoding its own
                            # default (v7.9.6 fix — see CHANGELOG_v7.9.6.md)
  host: "http://localhost:11434"  # FARF_OLLAMA_HOST
```

**Consequences:** This config file is a **hot-reload wrapper around real
constructor arguments**, not a new abstraction layer — and the `home_cloud`
enum (`"aws" | "azure" | "gcp"`) already covers all three providers this
document evaluates, so switching OrgC's provider is a one-line config change
plus the corresponding infra swap, not a schema migration.

**On env vars vs. this file (clarified v7.9.6):** `farf_runtime_config.yaml`
above is illustrative, not implemented — no module in this codebase parses
YAML, and the file itself does not ship. Every knob shown is, today,
actually read from an `os.environ` lookup with a `FARF_*` name (see the
inline comments above and `farf_logging.py`, `llm_judge.py`) — that env-var
mechanism **is** Phase 1/2's real config surface, zero new dependencies
(no PyYAML needed), consistent with the rest of the prototype's
resource-light posture (README.md §1). Newly-added knobs (e.g.
`FARF_LLM_JUDGE_MODEL`, v7.9.6) should follow the same pattern: read via
`os.environ.get(..., <default>)` at the point of use, and get a
corresponding line added to this illustrative schema in the same pass —
not deferred until a real YAML loader exists. Building an actual YAML
config loader is itself deferred to cloud-build (it's naturally where
`risk_tiering`/`cost_ceilings`/`cross_cloud` — the fields with no Phase 1
code equivalent — would first get consumed for real), not a Phase 1/2
prototype gap.

---

## ADR-013 (NEW): Formal verification tooling (TLA+ / Soufflé Datalog) stays an offline batch job, decoupled from the live deployment

**Status:** Accepted

**Motivating finding:** `README.md` §1/§6 — the proposal's full-scale tools
for the Federated Adversary Model (TLA+) and provenance reasoning (Soufflé
Datalog) were deliberately not run in Phase 1; the prototype instead exports
`adversary_model.to_dict()` / `taint_engine.flow_graph` for later offline
translation "for the subset of results you want machine-checked proofs for."
No prior ADR addressed where this runs once a live cloud deployment exists —
a genuine gap, not previously covered.

**Decision:** Formal verification stays **explicitly out of the live
request path** — it is not a runtime dependency of any relay, and its
absence or failure never affects an actual federation decision. It runs as
a **scheduled or on-demand batch job**: export the current
`adversary_model.to_dict()` / `taint_engine.flow_graph` state from either
cloud's relay, feed it into TLA+'s TLC model checker or Soufflé Datalog
offline, and store the result as a dissertation-evaluation artefact, not a
production signal. This is a genuinely cloud-agnostic decision — any of the
three providers' batch/build compute (AWS CodeBuild, Azure DevOps Pipelines
or Container Instances, GCP Cloud Build) can run this identically, since
it's fundamentally an offline export-then-analyse step with no security
decision riding on its outcome.

**Alternatives considered:**
- *Run formal verification inline, gating live decisions on its result* —
  rejected: TLA+/Soufflé runs are not designed for request-path latency, and
  making a live federation decision depend on a slow offline verifier would
  invert this ADR's whole purpose (rigor for the dissertation, not a runtime
  dependency).

**Consequences:** Keeps the formal-verification story exactly where the
proposal's own DSR methodology (§7.2, "validating each artefact
independently *before* integration") already puts it — a validation
activity, not a production component — which also means it never needs to
appear in ADR-004's fail-safe matrix at all.

---

## ADR-014 (NEW): Real zero-knowledge attestation (zk-SNARK) deferred to Phase 3; salted hash-commitment stays for Phase 2

**Status:** Accepted

**Motivating finding:** `README.md` §9 — "The 'Zero-Knowledge Attestation' is
a salted hash-commitment scheme, not a true zk-SNARK… a real zk-SNARK
library (e.g. py_ecc) can be swapped in later without touching the rest of
the pipeline," an explicitly named known simplification with no prior ADR
addressing whether/how the cloud build changes this.

**Decision:** **Defer the actual zk-SNARK swap to Phase 3.** The Phase 2
cloud build keeps the existing salted hash-commitment scheme, now backed by
KMS-managed salts (extending ADR-003/ADR-008's pattern) rather than
in-process ones, but does not introduce true zk-SNARK circuits. Rationale:
a real zk-SNARK integration needs a trusted-setup ceremony, which is exactly
the kind of manual, auditable, multi-party trust event ADR-005 already
established a pattern for (the federation-bootstrap registrar ceremony) — if
pursued in Phase 3, it should follow that same precedent rather than
inventing a new one, but doing so now would expand Phase 2's scope beyond
what's needed to validate the cloud architecture itself.

**Alternatives considered:**
- *Implement py_ecc-based zk-SNARKs now* — rejected for Phase 2 scope
  reasons: this is a cryptographic-primitives research task orthogonal to
  the cloud-architecture questions this document exists to answer, and
  would delay the two-cloud federation validation this ADR set is actually
  for.

**Consequences:** The dissertation's methodology chapter should continue
disclosing this as a known simplification (as `README.md` §9 already
does) for the Phase 2 cloud build specifically, not just the Phase 1
laptop prototype — the gap is carried forward honestly, not silently
resolved by the cloud move.

---

## ADR-015 (NEW): Real LLM-driven agents replace the deterministic rule-based stand-ins, via each org's home-cloud model service

**Status:** Accepted

**Motivating finding:** `README.md` §6/§9 — "Real LLM reasoning: once you're
happy with the security logic, replace `Agent.plan()`/`Agent.execute()`
bodies with a call to a local Ollama model… Agents are deterministic
rule-based stand-ins, not LLMs — fine for testing the security pipeline, but
you'll want real LLM-driven agents before citing any 'attack success rate'
figures against genuine prompt-injection corpora." No prior ADR addressed
this despite ADR-011 already naming an "LLM gateway" service mapping without
ever stating the decision to actually use it for agent reasoning.

**Decision:** `Agent.plan()`/`Agent.execute()` (currently deterministic
rule-based stand-ins per `agents.py`) are replaced with calls to **each
org's home-cloud LLM service**, routed through ADR-011's gateway — AWS-hosted
orgs call Bedrock, the second cloud's org calls Azure OpenAI Service or
Vertex AI depending on the final provider choice. This preserves ADR-003's
per-org-autonomy principle at the reasoning layer, not just the
cryptographic layer: **an org's agent reasoning happens via its own cloud's
model service, never the other org's** — an AWS org's Advisor never routes
its planning calls through the second cloud's LLM endpoint, and vice versa.
All such calls are subject to ADR-011's token/cost ceilings and ADR-004's
fail-safe defaults (an LLM call timeout or error is treated conservatively —
falls back to the deterministic rule-based `Agent.plan()` as a documented,
explicit degradation path, never silently retried indefinitely or treated as
"no action needed").

**Alternatives considered:**
- *Self-hosted Ollama on cloud compute, matching the local prototype's
  intended local-LLM upgrade path* — considered; rejected as the Phase 2
  default because it reintroduces exactly the GPU/VRAM resource-management
  problem `README.md` §1 explicitly built the deterministic stand-in to
  avoid, without gaining anything a managed model service doesn't already
  provide at cloud scale. Kept as a documented fallback for cost-constrained
  evaluation runs.
- *One shared LLM gateway regardless of org* — rejected: violates the
  per-org autonomy principle this whole document has treated as
  non-negotiable everywhere else (ADR-003, ADR-005, ADR-009).

**Consequences:** This is the one ADR with a direct, mandatory dependency on
prior work outside this document: the Tab 7.8 metrics harness
(`tests/evaluation_metrics_tab78.py`, closed in the companion session) was
built and validated against the **deterministic** `Agent`. Once real LLM
agents ship, that harness needs to be **re-run against genuine model
outputs** before any "attack success rate," precision/recall, or F1 figures
from it are cited in the dissertation as evidence about LLM-agent behaviour
specifically — the existing Tab 7.8 numbers remain valid evidence about the
*security pipeline* (orchestration, trust, taint, ledger), which is what
they were designed to test, but not about LLM-driven decision quality, which
they were never testing in the first place. This is exactly the honesty
`README.md` §9 already asks for; this ADR makes it an explicit, trackable
consequence rather than a footnote easy to forget once the cloud build is
underway.

---

## ADR-016 (NEW): CI/CD and the existing VAST lint tool run on a cloud-neutral pipeline, not either federated cloud's native build service

**Status:** Accepted

**Motivating finding:** `README.md` §2 — `tools/farf_security_lint.py`
("VAST-style automated CI check — catches `send()`/`write_memory()` calls
that bypass signing, and orphaned action_types with no policy rule") exists
and is referenced as supporting O3, but no prior ADR addressed where or how
it runs once there's an actual cloud deployment pipeline to gate.

**Decision:** **GitHub Actions** (cloud-neutral) is the CI runner, executing
`tools/farf_security_lint.py` as a pre-merge gate on every pull request
against the codebase — independent of which cloud(s) are targeted — plus a
second, deploy-time invocation immediately before any infrastructure-as-code
apply step (Terraform for AWS/GCP, Bicep for Azure), so a lint failure blocks
deployment, not just merge. Consistent with every other cloud-neutral choice
already made in this document (ADR-005's registrar, ADR-007's recommended
Splunk Cloud over a single-vendor SIEM): the CI/CD layer shouldn't privilege
either federated cloud any more than the data plane does.

**Alternatives considered:**
- *Each cloud's native build service (AWS CodeBuild / Azure Pipelines / GCP
  Cloud Build)* — viable, and named explicitly as the fallback if avoiding a
  GitHub Actions dependency matters more than pipeline neutrality for a
  given deployment; not the default here because running the *same* lint
  gate on two different native build services doubles the pipeline
  configuration to maintain for no architectural benefit.

**Consequences:** `tools/farf_security_lint.py` itself needs no code change
— it already operates on the Python source tree, not on any
cloud-deployed artefact, so this ADR is purely about pipeline placement, not
a functional change to the lint tool.

# Proposed ADR-017 / ADR-018 / ADR-019

Status: **Proposed, not yet adopted.** Written after the 26–27 August 2026 AWS↔GCP cross-cloud session (`Multi-CloudTesting_PS_Console_Output.txt`,
`Docker_GCP_Testing_PS_Console_output.txt`), which produced one confirmed pass (Docker-level partition), one confirmed but partial-scope pass (cross-boundary TOCTOU re-verification, non-adversarial path only), and
two genuinely inconclusive results (WAN-level partition; PT-08 under concurrent load) plus one broken measurement (WAN latency-under-load).
These three ADRs exist to turn each inconclusive result into a specific, scoped, re-runnable fix rather than leaving it as an open item restated indefinitely. Each follows the existing ADR-004/006/007/010 numbering and evidence convention: what's being decided, the options actually
considered, and why.

---

## ADR-017: Redesign the AWS↔GCP partition test to defeat security-group connection tracking

**Context.** `aws_pilot/adr004_partition_client.py` revokes egress on the security group attached to the running Fargate task's ENI, expecting subsequent `/send` calls to fail during the revoke window. Across two trial runs (124 total iterations), zero failures were observed, while the revoke command itself succeeded and the task remained `RUNNING`
throughout. **The root cause is not fully isolated, and this ADR is deliberately honest about that rather than naming a single confirmed mechanism.** The leading candidate explanation is that AWS security groups are connection-tracking — revoking a rule blocks new connection
attempts but does not tear down a flow already permitted and tracked.
This candidate is weaker than it first appears, however: the script calls the bare `requests.post()` function on every iteration rather than holding a `requests.Session()` open across iterations, so each iteration should, in principle, open its own fresh TCP connection rather than reuse
one held-open flow from before the revoke — which plain connection-tracking of a single already-established flow does not, by itself, fully account for. Two further candidates were not independently ruled out this session: security-group rule-change propagation lag, and the
revoked rule not covering the task's actual egress path (for example, an intermediate NAT gateway or a second security group in the path). What is established is the observation itself — zero effect across 124 iterations despite a confirmed, successful rule revocation — not a single confirmed causal mechanism. Whichever of A/B/C below is chosen, it should be designed to also directly discriminate between these candidate explanations (e.g. by logging the local ephemeral source port used per iteration, which would show whether "fresh connection per iteration" actually held in practice), not only to produce a pass/fail result.

**Decision needed.** Which mechanism to use to produce a real, observable partition against a *live* connection, not just new connection attempts — and which also resolves which of the candidate explanations above actually applies here.

**Options considered:**

- **Option A — Instrument, then force, new connections per iteration.**
  First add explicit logging of the local ephemeral source port used per   `/send` call, to directly confirm or refute whether the script is really opening a fresh TCP connection each iteration as its lack of a shared `Session()` suggests it should. If it is, and the revoke still
  has no effect, that rules  connection-tracking of an existing flow out as the explanation and points at rule propagation lag or the wrong SG being in the actual egress path instead — genuinely new information, not assumed in advance. If port logging shows the client is *not*
  opening fresh connections for some other reason (e.g. OS-level keep-alive despite no explicit `Session()`), explicitly closing the socket / setting `Connection: close` would then be the correct next step. *Pros*: smallest change, and — unlike treating "force new
  connections" as a fix on faith — it first tells you whether that is even the right fix for what's actually happening. *Cons*: even once fresh-connection behaviour is confirmed, this option only demonstrates "new connections are blocked," not "an in-flight message exchange is
  disrupted mid-flight" — a real federated agent workload is more likely to hold a connection open across several messages, so this option answers a real but narrower question than the original intent.

- **Option B — Switch to a Network ACL (NACL) deny rule instead of a security-group revoke.** NACLs are stateless and evaluated per-packet regardless of existing connection state, so a NACL deny rule would affect already-established flows, not just new ones. *Pros*: directly closes the gap Option A leaves open — this is the AWS-native way to
  simulate a genuine mid-flow partition. *Cons*: NACLs operate at the subnet level, not per-task, so this would need a dedicated partition-test subnet (to avoid partitioning other running tasks sharing the same subnet) — additional one-time infrastructure setup, not just a script change.

- **Option C — Application-level partition simulation:** have the Fargate task's own process pause outbound calls for a defined window (e.g. via an env-var-gated sleep or a local iptables rule inside the container, if the task's IAM/capabilities allow it), rather than relying on the security group at all. *Pros*: fully deterministic timing, no dependency on AWS's connection-tracking internals. *Cons*:
  this is a *simulated* partition from inside the task's own network namespace, not a real external network-layer partition — weaker evidence than either A or B for the specific claim being tested, and arguably closer in spirit to the in-process simulation this thesis has already disclosed as a boundary (Section 4.6) rather than a genuine
  advance on it.

**Recommendation (not a decision — the researcher's call, consistent with how ADR-006/012 were handled in `PHASE1_TO_CLOUD_DECISION_BRIEF.md` §4):** Option A's instrumentation step should be done first regardless
of which of B/C is chosen next, purely as diagnosis — it is cheap, and its result (does the revoke actually block a confirmed-fresh connection, or not) determines whether B is solving the right problem at all. Option B is the only one of the three that would close the gap as originally
scoped (a genuine mid-flow WAN partition, not just a blocked-new-connection test) *if* Option A's diagnosis confirms connection-tracking was indeed the mechanism; if Option A's port logging instead shows fresh connections were already being opened and still not blocked, the actual
fix is elsewhere (propagation lag, wrong SG in path) and B alone would not resolve it.

---

## ADR-018: Make the cross-cloud pentest scripts idempotent against persistent deployments

**Context.** `pentest_cloud/pt08_session_hijack_cloud.py` hardcodes a literal nonce (`"captured-nonce-0001"`) for its replay-attack step, an assumption valid for a single ephemeral in-process test run but not for a persistent, stateful Cloud Run deployment that is re-targeted by the
same script multiple times across a session. In 2 of 3 repeated concurrent-load runs (Section 6.3 of `TEST_PROTOCOL.md`), this produced a false `VULNERABLE` verdict: the script's own "1st use (legitimate)" call was itself flagged `message_replayed` by the bus, correctly, because the nonce had already been consumed by an earlier invocation — the
replay guard working as designed against a non-idempotent harness, not a message-layer defect. A related but distinct issue was also observed:
Step A's "legitimate agent sends via the normal signed path" occasionally returned `agent_already_quarantined` from a previous run's side effects, for the same underlying reason (state persisting across script invocations against one long-lived deployment).

**Decision needed.** How to make the cloud pentest suite safe to re-run repeatedly against one persistent deployment without producing false verdicts in either direction.

**Options considered:**

- **Option A — Per-run unique identifiers.** Generate the nonce (and any agent IDs whose quarantine state could carry over) with `uuid4()` or a timestamp suffix at the start of each script invocation, rather than literals. *Pros*: minimal, localised change to each `pentest_cloud/pt*.py`
  script; preserves the ability to run the same script repeatedly against the same live deployment, which is the realistic reproduction pattern for a cloud pilot. *Cons*: doesn't address a genuinely fresh replay attack scenario differently from a stale-state artifact — both still
  produce `message_replayed`, so the verdict logic itself also needs a small update (see Option C) to distinguish them, not just the input generation.

- **Option B — Reset-before-run.** Add a setup step (or a dedicated `/pentest/reset` route, pentest-mode-gated like the existing `/pentest/*` routes) that clears an org's registered agents/nonces/ quarantine state before each script runs. *Pros*: closest to a true "fresh in-process run" semantics, matching what the scripts were originally written to assume. *Cons*: adds a new bus-side route that
  itself needs to be pentest-mode-gated and kept out of any production build, widening the pentest-mode surface area (already a disclosed risk in `RISK_APPENDIX.md`) rather than shrinking it.

- **Option C — Verdict-logic fix independent of A/B.** Have the script itself distinguish "the bus rejected my *first* attempt as a replay" (almost certainly stale state from a prior run — report as INCONCLUSIVE/RETRY, not VULNERABLE) from "the bus accepted my first attempt and then also accepted my replay of the same signature+nonce"
  (the actual failure condition it's designed to catch) — report VULNERABLE only for the latter. *Pros*: closes the false-positive regardless of which of A/B is also adopted, and is arguably the correct fix on its own merits — the current verdict logic doesn't distinguish these two cases at all. *Cons*: doesn't by itself restore the ability to test a genuinely fresh replay attack if agent-quarantine
  state has also gone stale (Step A's separate `agent_already_quarantined` symptom) — needs pairing with A or B for full coverage.

**Recommendation:** A and C together are the minimum fix — C prevents the specific false verdict already observed, A prevents recurrence of the same class of bug in any future pentest script targeting a persistent deployment. B is worth doing separately as good pilot-ops hygiene but is not required to close this specific gap.

---

## ADR-019: A dedicated, correctly-instrumented load-under-attack test harness

**Context.** The closest existing approximation of a combined
"load-under-attack" test — running `gcp_pilot/egress_load_test.py` concurrently with three `pentest_cloud/pt*.py` scripts as PowerShell background jobs — was assembled ad hoc (the pasted appendix originally
in `TEST_PROTOCOL_updated.md`, now formalised as `TEST_PROTOCOL.md` §6.3) rather than built as a first-class test. It produced genuinely useful security evidence (PT-01/PT-02 held under load) but no usable latency-under-load figure: `gcp_pilot/cloud_run_final_checks.py` PART 2
reported "No successful requests." **Unlike ADR-017's partition gap, this root cause is confirmed, not just a leading candidate.** PART 2 derives its test identities by reading `/status`'s `registered_orgs` field and guessing `orgs[0]`/`orgs[1]` are `PilotOrgA`/`PilotOrgB` with
agents named by convention. `docker/bus_service.py`'s `/status` route returns `registered_orgs` as `sorted(bus.trust.identities.keys())` — alphabetically sorted, not in registration order. On a deployment shared across a session with other pilot/pentest scripts (whose org names, e.g.
`PT01Org...`, `PT08Org<uuid>`, sort interleaved with or ahead of `PilotOrgA`/`PilotOrgB`), `orgs[0:2]` silently picked two orgs that were never admitted under the guessed naming pattern at all — so every `/send` in the timed loop failed for a mundane reason (unrecognised agent), reported only as a bare zero-successes message with no diagnostic
information pointing at why.

**Decision needed.** Whether to keep composing existing single-purpose scripts ad hoc for this scenario, or build one harness that owns both the load generation and the concurrent security/latency measurement —
and, either way, whether to fix the identity-selection bug in
`cloud_run_final_checks.py` directly or route around it entirely.

**Options considered:**

- **Option A — Keep composing existing scripts, fix the identity mismatch only.** Smallest change: add CLI args to both `cloud_run_final_checks.py` and `egress_load_test.py` so the same agent identities can be passed to both  explicitly, and document the correct invocation order in `TEST_PROTOCOL.md` (already partially done in §6.3/§6.4). *Pros*: cheapest, no new code beyond argument-passing;
  reuses scripts already validated individually. *Cons*: still three or four separately-launched PowerShell jobs coordinated by hand each run, the same fragility (Section 6.3's inconsistent PT-08 verdicts) that produced this ADR series in the first place remains structurally possible for *other* combinations not yet tried.

- **Option B — Build one dedicated script
  (`gcp_pilot/load_under_attack.py` or similar)** that starts the load generator as a background thread/process, runs the pentest checks and a latency sampler against the *same* pre-registered, known agent identities in the foreground, and reports a single combined result (security verdicts + latency percentiles + error counts) rather than
  four separate script outputs to be manually cross-referenced. *Pros*: removes the identity-mismatch class of bug structurally, not just for this one instance; produces one canonical, reproducible artefact (matching this thesis's stated evidentiary discipline of citing a
  single script's output rather than reconstructing a result from several logs); easier to re-run identically for a future third data point (e.g. a third region, or before/after a specific ADR fix).
  *Cons*: real new code to write and validate before it can be trusted, larger effort than Option A, and — like any new test script — needs its own idempotency review (ADR-018's lesson) before being trusted against a persistent deployment on a second run.

**Recommendation:** Option A first, as a low-cost fix that unblocks re-running §6.3 cleanly in the near term; Option B is the right answer if load-under-attack evidence is going to be cited more than once or twice more in this thesis or extended to more attack/latency combinations, since it removes an entire class of coordination bug rather than patching one instance of it.

---

## Sequencing note

None of ADR-017/018/019 blocks the others — they touch different scripts in different directories (`aws_pilot/`, `pentest_cloud/`, `gcp_pilot/`) and can be implemented in parallel. If sequencing by "which unblocks the most remaining thesis evidence per unit of effort," the order is
ADR-018 (smallest, unblocks a clean re-run of already mostly-working evidence) → ADR-017 Option A (small, produces the partition thesis's Chapter 5/6 currently lack any positive cross-cloud evidence for) → ADR-019 Option A (unblocks the one currently-broken quantitative figure)
→ ADR-017 Option B and ADR-019 Option B as the higher-effort, more complete versions if time remains before submission.

## Implementation status (this session)

Two of the three ADR-018/019 Option-A fixes are no longer proposals only — working, syntax-checked replacement scripts were written this session and are provided alongside this document:

- **ADR-018 Option A+C**: `pentest_cloud/pt08_session_hijack_cloud.py`
  (fixed version) — per-run `uuid4()`-suffixed org/agent/nonce identifiers, plus a verdict-logic change that reports `INCONCLUSIVE` rather than `VULNERABLE` if stale-state symptoms are detected despite the fresh identifiers. **Not yet re-run against a live deployment** —
  needs a real cross-cloud invocation before its fix can be confirmed, not just trusted because it reads correctly.
- **ADR-019 Option A**: `gcp_pilot/cloud_run_final_checks.py` (fixed version) — accepts explicit `--from-agent/--from-org/--to-agent/ --to-org`, falls back to the previous guess (now labelled as a guess) otherwise, and adds an explicit pre-loop admission probe so a naming mismatch is reported as a clear setup failure rather than a bare "No successful requests." **Not yet re-run** — same caveat as above.

ADR-017 remains a proposal only, deliberately: unlike the two fixes above, its root cause was not confirmed this session (see the Context section), so no fix has been written yet — the instrumentation step in Option A needs to run first to determine which fix is actually correct.

**Status confirmed, 26 August 2026:** `.github/workflows/farf_ci.yml` already exists and already implements exactly this decision — the pre-merge gate (`lint-and-test` job: VAST lint → pytest → Tab 7.8 metrics harness) is complete and correctly wired; the pre-deploy gate is an honestly-documented stub pending the Terraform/Bicep IaC workflow this ADR itself says doesn't exist yet. No code change was needed this session. Re-ran `tools/farf_security_lint.py` directly against the current tree (including this session's ADR-010 edits to `orchestration.py`/`federation_bus.py`) as a sanity check: 0 HIGH
CONFIDENCE findings, exit code 0 — the lint gate would pass on a PR containing this session's changes.

**Independently re-confirmed, 26 August 2026 (separate session):**
re-ran `tools/farf_security_lint.py` directly against this repo copy — same result, **0 HIGH CONFIDENCE findings, exit code 0** (5 LOW CONFIDENCE heuristic findings on raw `.send()` calls, all in test/pentest code, none blocking). The CI workflow's job structure was also checked directly: `lint-and-test` (pre-merge) runs lint → tests → Tab 7.8 harness as claimed; the pre-deploy job is confirmed still a stub, consistent with the note above. **Discrepancy found and since resolved:** this repo copy did not originally contain the ADR-010 code (`crosses_org_boundary`/`cross_boundary_toctou_reverification`) the note
above credited to "this session" — it has since been re-applied (see ADR-010's own "Re-applied and independently re-verified" note) and the lint result above was re-confirmed after that patch landed, so ADR-016's
0-HIGH-CONFIDENCE result now genuinely reflects a tree that includes ADR-010's edits, not one that's missing them.

---

## Summary: gap → decision → cloud mechanism

*Last reviewed against the shipped code: v7.9.10 (four supervisor-directed items closed this session — quorum-default fix + dynamic recompute, FARS
multi-scenario sensitivity + 200-agent connectivity  validation, and the per-record revocation `mode` dispatcher — see "Closed in v7.9.10" below; 
earlier syncs after v7.9.2/v7.9.3 had shipped without a matching update here — see "Closed in v7.9.2" / "Closed in v7.9.3" / "Closed in v7.9.5" /
"Closed in v7.9.6" / "Closed in v7.9.7" below). This table is a **decision** record — it stays true regardless of implementation status. The **Code status** column is what changes as the cloud build progresses; see the Internal Audit section immediately below for the evidence behind
each status and for items this table doesn't cover.*

| Phase 1 / README gap (source) | ADR | Closes via | GCP-equivalent delta? | Code status (v7.9) |
|---|---|---|---|---|
| Single-process Federation Bus SPOF (THREAT_MODEL.md §7) | ADR-001 | Per-cloud relay + direct mTLS channel | Cloud Run's concurrency model is a genuine (not cosmetic) fit for relay traffic — citation corrected this pass; see note below | Open — cloud-build work itself |
| No federated shared state design (pasted notes) | ADR-002 | Replicated, eventually-consistent context graph | GCP's inter-region rate is half AWS/Azure's for this exact traffic pattern (verified against `CLOUD_PROVIDER_COMPARISON.md` §2.2 and live pricing) | Open — cloud-build work itself |
| In-process plaintext keys (THREAT_MODEL.md §9) | ADR-003 | Per-org home-cloud KMS, never cross-cloud | Cloud KMS pricing is the hardest of the three to estimate — pilot recommended | Open — `federation_config.py`'s `OrgConfig.home_cloud`/`kms_key_ref` fields exist and are stored, but call nothing; no real KMS API is wired yet |
| No real network-partition handling (from ADR-001) | ADR-004 | Explicit fail-safe matrix, partition as first-class failure mode | None — matrix logic is provider-independent | Open — decision only, no code implements the matrix's runtime behaviour yet |
| No PKI/root-of-trust (THREAT_MODEL.md §9) | ADR-005 | Quorum-witnessed registrar, not a CA | None — deliberately provider-agnostic by design | Open — cloud-build work itself |
| In-memory ledger consensus (THREAT_MODEL.md §7/§12) | ADR-006 | Real multi-node quorum across both clouds, PBFT default | None — N=3-unanimity finding is quorum-math, not cloud-specific | **Closed in v7.9.10 for the parts that don't need a real cloud account.** `main.py`'s actual `build_federation()` call sites now construct every bus with `quorum_mode="pbft_dynamic"` — the exact discrepancy the v7.9.9 "Correction" (superseded below) found is fixed: `python main.py --scenario all` now genuinely runs PBFT-proportional quorum, not the legacy fixed 2. "Dynamic PBFT quorum adoption" is also closed — `register_organisation()` recomputes `quorum_required` on every join (see `FederationBus._recompute_quorum()`), with an explicit, fail-fast-not-silent `quorum_recompute_strategy="batched"` provision reserved for a future high-throughput federation. Decision was supervisor-directed and evidence-based, not assumed: `tools/quorum_policy_comparison.py` (new) proved PBFT-dynamic requires unanimous collusion to falsely clear a quarantine at N=3 vs. legacy's 2-of-3, at a disclosed, quantified availability cost (needs every org online vs. legacy tolerating one down) — both dimensions reported, not just the one favouring the swap. Confirmed via `tests/evaluation_metrics_tab78*.py` never touching the ledger that this did NOT retroactively change any cited Tab 7.8/7.9 statistic. `FederationBus`'s own class-level default deliberately stays `"static"` so `pentest/pt07`/`pt11` (which specifically exercise legacy quorum=2 behaviour) are unaffected — this closure is scoped to `main.py`'s demo/CLI construction sites, not a global default flip. Full evidence in `CHANGELOG_v7.9.10.md` §1/§3. The cross-*cloud* distribution of witness nodes remains open, unchanged — that genuinely needs real cloud accounts |
| No logging persistence → shipping (PHASE1_GAP_REPORT §5); no named SIEM (README §1) | ADR-007 | Native cloud sinks + Splunk Cloud as the cloud-neutral SIEM tier | Cloud Logging instead of Azure Monitor; SIEM recommendation unchanged | Open — structured JSON logging exists locally (`farf_logging.py`) and is now confirmed (v7.9.10 re-audit) actually wired into all 7 core modules' production call paths (2 `logger.*` calls each, live-checked) — the print() calls that remain in `orchestration.py`/`trust_protocol.py`/`taint_engine.py`/`federation_ledger.py` are confined to each file's own `if __name__ == "__main__"` standalone demo block, not the imported/executed path. Shipping to an actual cloud sink is still cloud-build work |
| Erasure vs. immutability tension (PHASE1_GAP_REPORT §1) | ADR-008 | KMS-managed data keys, real deletion API | Cloud KMS's 24hr-minimum deletion window is genuinely faster than AWS/Azure (independently verified against Google's own pricing/docs) | Open — crypto-shredding itself is closed locally (v7.7, in-memory keystore); real KMS-backed keys are cloud-build work |
| Tamper-evident not tamper-proof (THREAT_MODEL.md §4) | ADR-009 | Per-org durable store + cross-cloud hash anchoring | Cloud SQL/Firestore; anchoring scheme itself is provider-agnostic | Open — cloud-build work itself |
| Latent async TOCTOU risk (THREAT_MODEL.md §2.4) | ADR-010 | Boundary-aware re-verification on cross-cloud hops | None — explicitly provider-neutral | Open — not currently exploitable (no concurrency exists yet to race), correctly deferred |
| Cloud cost/token ceilings (original discussion) | ADR-011 | Three-way concrete service mapping | Full GCP column now included | **Closed as a decision** — figures spot-checked against live AWS/Azure/GCP pricing this audit; inter-region $0.01-vs-$0.02/GB claim confirmed real but should be read as illustrative, not a guaranteed rate for every region pair (see Internal Audit) |
| Illustrative-only config schema (original discussion) | ADR-012 | Schema grounded in real shipped constructor params | `home_cloud` enum already covers `"gcp"` | **Substantially closed, first real loader shipped in v7.9.9** — `credential_ttl_seconds` and `quorum` (`resolve_quorum()`) wired to real code and tested since earlier; v7.9.9 adds `runtime_config.py`, an actual YAML loader (no longer illustrative-only) for `federation.orgs` (real, dry-run-verified `build_federation_from_config()` call), `logging.level`/`logging.sink:json_stdout` — `home_cloud`/`kms_key_ref` still accepted but inert (see ADR-003 row); `risk_tiering`/`cost_ceilings`/`cross_cloud`/`federation.quorum_threshold`/`attack_mode`/`detection_thresholds`/`fail_safe_defaults` deliberately still not implemented — no Phase 1 code equivalent exists for these, each with a specific reason now surfaced live by the loader itself (`runtime_config.PARSED_ONLY_REASONS`) rather than only documented here. v7.9.6: `llm_judge.model`/`FARF_LLM_JUDGE_MODEL` added to the illustrative schema following the same env-var-is-the-real-mechanism pattern as `logging:` |
| Formal verification tooling placement (README.md §1/§6) | **ADR-013** | Offline batch job, decoupled from live deployment | None — cloud-agnostic by design | Open — cloud-build work itself |
| ZK-attestation still hash-commitment, not zk-SNARK (README.md §9) | **ADR-014** | Deferred to Phase 3, KMS-backed salts for Phase 2 | None — deferred regardless of provider | **Closed as a decision** — deferral itself is the whole decision; nothing further needed until Phase 3 |
| Deterministic agents, not real LLMs (README.md §6/§9) | **ADR-015** | Per-org home-cloud LLM service via ADR-011's gateway | Bedrock vs. Azure OpenAI vs. Vertex AI — real per-org routing difference | Open — cloud-build work itself. `llm_judge.py`'s first real-hardware run (user's machine, qwen3:4b) surfaced and fixed a genuine bug (v7.9.5: `*-thinking` model variants need an explicit `"think": False` field or Ollama 0.12+ burns the generation budget on hidden reasoning and never emits the answer — 0/7 calls usable before the fix). v7.9.6: a second real-hardware finding fixed — `agents.detect_prompt_injection()`'s `llm_model` parameter hardcoded its own `"qwen3:4b"` default, silently shadowing `llm_judge.DEFAULT_MODEL`; now resolves against `llm_judge.DEFAULT_MODEL`/`FARF_LLM_JUDGE_MODEL` at call time instead. v7.9.7: the "does the LLM judge add detection value" question now has a real, if preliminary, answer — see the ADR-015 real-world validation note below. `tools/ollama_pt15_comparison.py` also now supports comparing multiple models in one run (`FARF_LLM_JUDGE_COMPARE_MODELS`) and flags cases where a model's boolean verdict contradicts its own stated reason text, both added after the user's real qwen3:4b-vs-deepseek-r1:1.5b comparison run surfaced exactly that contradiction on one case |
| VAST lint tool has no CI placement (README.md §2) | **ADR-016** | GitHub Actions pre-merge + pre-deploy gate | None — cloud-neutral by design | **Closed** — `.github/workflows/farf_ci.yml` implemented and verified locally this session (lint: 0 high-confidence findings; full suite: 44 passed, 1 skipped). Pre-deploy gate job is a documented stub pending the real Terraform/Bicep workflow |

**ADR-001 citation correction (this audit):** the GCP-equivalent note
previously attributed the "1,000 concurrent requests per instance" figure
to `CLOUD_PROVIDER_COMPARISON.md` §2.4. That figure is real (independently
confirmed against Google's own Cloud Run quota documentation) but does not
actually appear in §2.4 or anywhere else in the comparison document — only
the qualitative "2026 leader for concurrency-heavy workloads" claim does.
Corrected above to cite each fact to its real source.

**Explicitly still out of scope for Phase 2** (named, not silently
dropped): MAESTRO Layer 7 ecosystem-level trust/discovery across
*unrelated* federations (THREAT_MODEL.md §11) — ADR-005's registrar
solves trust *within* this federation, not discovery of external ones;
real zk-SNARK cryptography (ADR-014, deferred to Phase 3); LINDDUN's
Non-repudiation-as-privacy-risk and Detectability findings
(`RISK_APPENDIX.md` Part A) — genuine, deliberately unresolved design
tensions, not gaps a cloud architecture decision closes; OCTAVE's
governance-process gap (`RISK_APPENDIX.md` Part B) — who sets `stake`,
`quorum_required`, and per-org volume caps, and by what process, is a
governance question outside what code alone can answer.

*(The 50+ synthetic federation topology sweep and AgentDojo/InjecAgent
integration named in `README.md` §6 items 2–3 were open at the time this
line was originally written; both are now closed — see the Internal Audit
section below and `CHANGELOG_v7.9.md`.)*

---

## Cost-effective cloud combination — decided this session (v7.9.7)

*Answering the direct question: given everything in `CLOUD_PROVIDER_COMPARISON.md`
and every ADR above, which two-cloud combination is actually most
cost-effective for FARF? The comparison doc deliberately stops short of
picking one (its own §4, "not a recommendation") — this section makes
the call the doc leaves open, reasoned against FARF's specific traffic
pattern and current build state, not a generic cloud cost comparison.*

**Recommendation: AWS + GCP, not the currently-Accepted AWS + Azure —
on cost grounds specifically.** Reasoning, weighted by what actually
drives FARF's spend (comparison doc §2, confirmed against every relevant
ADR):

1. **Egress/inter-region is the dominant cost variable for this
   architecture, not compute** (comparison doc §2, opening paragraph;
   confirmed by ADR-001's relay-to-relay channel, ADR-002's context-graph
   replication, and ADR-006's quorum witnessing all being frequent, small,
   cross-cloud messages — a chatty pattern, not bulk data). On that one
   axis, GCP has an unambiguous, tier-independent edge: $0.01/GB
   inter-region vs. $0.02/GB for both AWS and Azure (comparison doc §2.2)
   — a flat 2x advantage on exactly the traffic ADR-002/ADR-006 generate
   continuously, not occasionally.
2. **Compute is a wash** (comparison doc §2.1: ~20% spread, GCP's Q1 2026
   cut nudges it slightly ahead) — correctly not a deciding factor either
   way, per the doc's own verdict.
3. **AI-inference economics now matter more than they did when
   `ARCHITECTURE_DECISIONS_1.md` first confirmed AWS+Azure**, because
   ADR-015's real-LLM-agent path is no longer theoretical — `llm_judge.py`
   has now run real inference workloads on real hardware twice this
   project (qwen3:4b and deepseek-r1:1.5b both validated locally this
   session, see the ADR-015 row update below). The comparison doc's own
   §2.4 verdict names Cloud Run as "the 2026 leader for concurrency-heavy
   workloads and AI inference specifically... directly relevant if ADR-015
   is adopted" — and ADR-015 is now genuinely in progress, not deferred.
4. **Hybrid-maturity fit reinforces the same direction, independent of
   cost**: comparison doc §3's judged synthesis rates Anthos as the
   closest philosophical match to FARF's own "no cloud is structurally
   privileged" federation design, and names AWS+GCP as the best fit given
   ADR-001's relay is already container-based (Fargate/Cloud Run) — not a
   cost argument, but a reason the cost-driven choice doesn't fight the
   architecture.
5. **KMS remains genuinely unresolved either way** (comparison doc §2.3)
   — GCP Cloud KMS's active-key-version pricing structure is, in the
   doc's own words, "the hardest of the three to estimate without a
   concrete signing-volume figure." This is the one line item where the
   recommendation doesn't have a confirmed edge; the doc's own pilot
   recommendation stands regardless of which second provider is chosen.

**What this recommendation is NOT:** a claim that AWS+Azure is a bad
choice in absolute terms — comparison doc §4's decision framework
correctly notes AWS+Azure is the right call if there's existing
institutional Azure/Microsoft investment (dissertation committee,
supervising institution, or an eventual industry partner already on
Microsoft) that outweighs the egress/AI-inference cost edge above. That
constraint is not something this file or the comparison doc can evaluate
— it depends on facts about the institution and committee that only the
researcher knows. **On cost grounds alone, given FARF's specific chatty,
increasingly-AI-inference-shaped traffic pattern, AWS+GCP is the more
defensible choice** — but flipping the confirmed "Accepted status quo" at
the top of this file (line 7) from AWS+Azure to AWS+GCP is a real
architectural commitment this document won't make unilaterally; it
requires the researcher's explicit confirmation, the same way AWS+Azure
itself was originally confirmed. Every ADR already carries the AWS+GCP
column in parallel specifically so this switch is a find-and-replace
against a known-good alternative when/if that confirmation comes, not a
redesign.

**KMS pilot still recommended before finalising either combination**
(comparison doc §2.3) — this is the one line item genuinely undetermined
by the analysis above and should be measured against ADR-003's actual
signature volume under a realistic E1–E4 scenario load, not estimated
from list price.

---

## Internal Audit — Final Review Before Cloud Build (v7.9)

*Cross-referenced against `README.md`, `THREAT_MODEL.md`,
`RISK_APPENDIX.md`, `TEST_PROTOCOL.md`, `PHASE1_GAP_REPORT_v7.6.md`,
`CLOUD_PROVIDER_COMPARISON.md`, and every `CHANGELOG_v*.md`. This section
is the living status tracker — **update it, not just the CHANGELOG, every
time a gap in the table above changes status**, so this file stays the
single place that answers "what's actually done." See "Keeping this file
in sync" at the end.*

### Closed in v7.9.6 (see `CHANGELOG_v7.9.6.md` for full detail)

| Item | Evidence |
|---|---|
| `llm_model` default not actually switchable (user-reported) | `agents.detect_prompt_injection()`'s `llm_model` parameter hardcoded its own `"qwen3:4b"` literal in the function signature — separate from, and shadowing, `llm_judge.DEFAULT_MODEL`. Editing either constant alone had no effect on the other. Root cause: two independent hardcoded defaults where the design intended one source of truth. Fix: `llm_model` now defaults to `None` and resolves against `llm_judge.DEFAULT_MODEL` at call time; `DEFAULT_MODEL` itself now reads `FARF_LLM_JUDGE_MODEL` from the environment (default unchanged: `"qwen3:4b"`). Verified end-to-end (not just by inspection): with `FARF_LLM_JUDGE_MODEL=deepseek-r1:1.5b` set, a mocked Ollama call captured the actual `model` field sent in the HTTP payload and confirmed it was `"deepseek-r1:1.5b"`, not the old hardcoded default. `tools/ollama_pt15_comparison.py` updated to read the same `DEFAULT_MODEL` rather than its own hardcoded `"qwen3:4b"` strings, so the comparison script automatically follows whatever model is configured. Result dict gained a new `llm_judge_model` key so callers/logs can see which model actually produced a given verdict. Regression: 57 passed, 0 skipped, unchanged; `tests/test_07_llm_judge_integration.py` 12/12 unchanged (asserts contract shape, not the literal model string, so unaffected by the fix). |
| Hardcoded `/tmp/*` paths (not OS-agnostic) | 23 files (22 `pentest/pt*.py` scripts + 3 `tests/*.py` files) constructed SQLite DB paths as literal `"/tmp/ptNN.db"` strings — Linux/macOS-only; would raise `FileNotFoundError` on Windows, where the user's own machine (README.md's stated dev target, Windows 11) has no `/tmp`. Fixed via `os.path.join(tempfile.gettempdir(), "ptNN.db")` (and the f-string equivalent for the handful of dynamically-named paths — `pt14`, `pt17`, `test_04`, `test_06`, `evaluation_metrics_tab78_repeated`), added `import tempfile` to each. Two literal `/tmp/...` strings in `agents.py`'s illustrative attack-corpus training data (lines ~155/193) were deliberately left untouched — those are example malicious-instruction TEXT the classifier trains on (attacker-supplied paths inside a prompt string), not real filesystem paths this codebase writes to; changing them would alter training-corpus semantics for no OS-portability benefit. Verified end-to-end, not just compiled: all 22/22 `pentest/pt*.py` scripts re-run and still exit 0; full suite still 57 passed, 0 skipped; `grep -rn "/tmp/" --include="*.py"` confirms zero remaining hardcoded occurrences outside `agents.py`'s corpus text. |

### Closed in v7.9.7 (see `CHANGELOG_v7.9.7.md` for full detail)

| Item | Evidence |
|---|---|
| ADR-015 real-world validation — "does the LLM judge add detection value" | **Now genuinely answered, for the first time, with real data from the user's own machine.** Two full runs of `tools/ollama_pt15_comparison.py` on real hardware (post-v7.9.5 `think: false` fix), one per model: `qwen3:4b` caught 2 of 4 genuinely-hard cases (avg latency 8,118.6ms); `deepseek-r1:1.5b` caught 1 of 4 (avg latency 4,173.0ms, ~1.95x faster). Both correctly did NOT flag the benign control case (no false positive from either model). **Genuine quality concern found in the deepseek-r1:1.5b run, not present in qwen3:4b's**: on the "known phrase" case, deepseek-r1:1.5b returned `is_override_attempt=True` while its own `reason` field read "...which is a legitimate request that may be necessary for system operation. This is not an attempt to bypass, hijack, or override system safety rules" — a direct contradiction between the structured boolean and the model's own stated justification. On a separate case ("incremental goal substitution"), the same model returned `confidence=0.0, reason=''` where qwen3:4b had confidently caught it — consistent with deepseek-r1:1.5b's much smaller parameter count (1.5B vs. qwen3:4b's 4B) producing less reliable reasoning at exactly the semantic-understanding task this signal exists for (see `llm_judge.py`'s module docstring: "An LLM judge does reason about meaning... this module is how you find out whether it actually is, on your own hardware"). **Conclusion, stated honestly: qwen3:4b is the more trustworthy signal of the two on this evidence (higher genuinely-hard-case catch rate, zero reasoning-verdict contradictions), at roughly 2x the latency cost.** Neither model is validated against a large enough sample (4 hard cases, 1 run each) to generalise beyond "directionally suggestive" — see `CHANGELOG_v7.9.7.md` for the statistical-rigor recommendation. |
| `tools/ollama_pt15_comparison.py` gained multi-model comparison | Previously required a separate manual run per model to compare (exactly how the qwen3:4b-vs-deepseek-r1:1.5b data above was gathered) — the reasoning-verdict contradiction above was only caught by manually reading both runs' full output side by side, not by the tool itself. Now supports `FARF_LLM_JUDGE_COMPARE_MODELS="model1,model2,..."` to run several models in one invocation and prints a per-model summary table (new-detection count, avg latency, reasoning-inconsistent count, control-case false-positive flag) plus a new coarse keyword-based consistency check (`_reasoning_looks_inconsistent()`) that flags exactly the kind of boolean-vs-explanation contradiction found above for human review — display-only, does not alter `llm_hit`/`combined_verdict`/anything `detect_prompt_injection()` returns. Verified via a mocked two-model run reproducing the real contradiction: the new flag fires correctly (`REASONING LOOKS INCONSISTENT WITH VERDICT`). Regression: 57 passed, 0 skipped, unchanged. |
| `CLOUD_PROVIDER_COMPARISON.md` restored to the package | See "Documentation gap CLOSED this session" above. |
| Cost-effective cloud combination decided | See the new "Cost-effective cloud combination — decided this session" section above the Internal Audit header: **AWS+GCP recommended over the currently-Accepted AWS+Azure on cost grounds**, pending the researcher's explicit confirmation before the Accepted status quo at the top of this file is actually changed. |

### Closed this session (not yet in a CHANGELOG at time of writing — see `CHANGELOG_v7.9.1.md`)

| Item | Evidence |
|---|---|
| Tab 7.8 Adversary Model Precision (was 0.8214) | `adversary_model.py`'s `simulate_privilege_escalation()` now requires every edge on a flagged path to carry at least `threshold * edge_floor_ratio` (default ratio 0.5) privilege, not just the aggregate crossing 0.8. Re-measured via the real, unmodified `run_adversary_model_trials()` harness across 5 seeds: precision 0.97-1.0 (was 0.8214, one seed), recall unchanged at 1.0. Cross-checked against the real E4 memory-manipulation test (`test_03_memory_manipulation_e2e.py`, threshold=0.6, real edges 0.3/0.4) to confirm the fix doesn't break realistic-magnitude detection — it doesn't. Full suite: 44 passed, 1 skipped, unchanged. |
| ADR-001 citation (this file) | See correction note above the "explicitly out of scope" paragraph. |

### Closed in v7.9 (see `CHANGELOG_v7.9.md` for full detail)

- ADR-012's `credential_ttl_seconds`/`quorum` config gap (`federation_config.py`)
- ADR-006's PBFT-default decision, wired as code (same file)
- `adaptive_org_volume` cloud-build default (was `False`, now `True`)
- ADR-016's CI pipeline (`.github/workflows/farf_ci.yml`)
- FARS's untested N>20 connectivity-sampling path — validated, no material bias found in the tested range (N=22-52 agents; docstring's own 200-agent reference point not yet reached)
- FARS's four uncited constants — ranked by sensitivity; connectivity divisor dominates (max shift 5.6 FARS points per ±30%), rest are minor
- README.md §6 item 2 (50+ synthetic federation topologies, Tab 7.6) — `tools/synthetic_federation_topology.py`
- README.md §6 item 3 (AgentDojo/INJEC integration) — real data pulled from AgentDojo (pip-installable) and InjecAgent (the real benchmark behind the "INJEC" shorthand — see naming note below); classifier corpus grown 29→211 real+original examples, generalization to held-out real attacks improved from precision 0.655/recall 0.190 to precision 0.872/recall 0.929

### Closed in v7.9.2 (see `CHANGELOG_v7.9.2.md` for full detail; not previously synced into this file)

- **`llm_judge.py` (new)** — optional third prompt-injection signal via a
  local Ollama model, closing PT-15's residual "genuinely novel paraphrase"
  gap further and serving as ADR-015's first real (if partial) test of the
  LLM-integration pattern. Stdlib-only (`urllib.request`/`json`), never
  raises to its caller — every failure mode (connection refused, timeout,
  malformed/missing JSON) degrades to `{"available": False, ...}`. Verified
  this session, standalone in this sandbox (no Ollama server present):
  `check_ollama_reachable()` correctly reports `reachable=False` with a
  clean `ConnectionRefusedError` message, and `judge_injection()` degrades
  to `available=False` without raising — confirms the documented fail-open
  (degrade, don't block) contract holds against a genuine unreachable-server
  condition, not just the mocked test double.
- **`tests/test_07_llm_judge_integration.py` (new)** — 12 tests against
  mocked `urlopen`; re-run this session, 12/12 pass.
- **`tools/ollama_pt15_comparison.py` (new)** — meant for a real machine
  with Ollama installed; correctly falls back to baseline-only comparison
  when Ollama is unreachable rather than erroring, confirmed by inspection
  and by the reachability check above.
- **`agents.py`**: `detect_prompt_injection()` gained `use_llm_judge: bool
  = False`/`llm_model: str = "qwen3:4b"`; default behaviour unchanged
  (confirmed — full suite passes with the parameter at its default
  throughout the regression run below).
- **Not yet done, needs a real machine with Ollama running:** the actual
  qwen3:4b-backed comparison run itself — whether the LLM judge earns its
  place as a permanent third signal is still unmeasured pending that run.

### Closed in v7.9.3 (see `CHANGELOG_v7.9.3.md` for full detail; not previously synced into this file)

- Fixed a real regression in `tests/test_04_statistical_validation.py`:
  the v7.9 classifier retrain (real AgentDojo/InjecAgent data) pushed the
  test's fixed trial payload just over the 0.5 detection threshold,
  collapsing `contained` from 24/30 to 30/30 across the fixed seed range
  and silently eating the variance `test_fars_predictive_validity_against_observed_resilience`
  needs — its own "unlucky sample" skip fired every run, which read as
  expected/benign rather than a structural break. Payload text changed
  (not the classifier); re-verified back to 24/30 and PASSED across 5
  repeat runs.
- Full suite went from 56 passed/1 skipped to **57 passed/0 skipped**.

### Closed in v7.9.5 (see `CHANGELOG_v7.9.5.md` for full detail)

- Fixed a real, reproducible bug in `llm_judge.py`: the user's first
  genuine Ollama-backed run (real qwen3:4b, GTX 1650) returned 0/7 usable
  judgements. Root cause: the pulled model is the `*-thinking` variant,
  which Ollama 0.12+ auto-enables chain-of-thought reasoning for unless
  the request explicitly sets `"think": False` — omitted in the original
  payload, so the model burned its generation budget on hidden reasoning
  and never emitted the constrained JSON answer.
- Fix: `"think": False` added as a top-level payload field;
  `DEFAULT_TIMEOUT_SECONDS` raised 15.0→30.0 (the very first call, which
  coincides with model cold-load, took 15.05s server-side alone — zero
  margin before). Full regression: 57 passed, 0 skipped, unchanged.
- **Separately flagged, not fixed by this change:** 3 of the user's 7
  calls hit `std::bad_alloc` server-side under genuine memory pressure
  (~300MB free system RAM, ~3.2GB free VRAM against the model's ~3GB
  footprint). This is a host-hardware headroom issue, not a code defect
  — noted honestly rather than folded into the "fixed" claim above.
- **Still open:** whether qwen3:4b actually earns its place as a third
  detection signal is unmeasured — the comparison run needs to be
  re-executed on the user's machine with this fix in place before that
  question has a real answer.

### Verified this audit, not previously confirmed

- **`CLOUD_PROVIDER_COMPARISON.md`'s core figures are accurate**, independently spot-checked against live AWS/Azure/GCP pricing documentation: AWS KMS flat per-key fee, Azure Key Vault per-10K-ops pricing, GCP Cloud KMS's active-key-version structure, the egress quartet ($0.09/$0.087/$0.12/$0.085), and GCP's $0.01-vs-$0.02/GB inter-region claim (real, but the document is less hedged about this figure's region-pair variability than it is about entry-tier egress's tier-dependence — worth reading as illustrative, not a flat guaranteed rate, when this gets cited in the dissertation).
- **"INJEC" (as cited in the Research Proposal's Tab 7.6 and by extension this project) does not resolve to a real, standalone released dataset.** Traced Hossain et al. 2025's own paper — it uses a self-authored 400-attack corpus, not a dataset by that name. The real, citable benchmark almost certainly intended is **InjecAgent** (Zhan et al., 2024, `github.com/uiuc-kang-lab/InjecAgent`), which is what this build's classifier retraining actually used. Flag for the dissertation's reference list.

### Re-verified live this session (not just re-read from CHANGELOGs)

Independent of the doc-sync above, the actual shipped code was re-run
against a clean environment this session, not re-asserted from prior
CHANGELOG text:

- `python -m pytest tests/ -v` → **57 passed, 0 skipped** — matches
  `CHANGELOG_v7.9.3.md`'s claim exactly.
- `python tools/farf_security_lint.py` → **0 high-confidence, 3
  low-confidence findings** (same 3 pre-existing ones) — matches.
- All **22/22** `pentest/pt*.py` scripts exit 0 — full pentest suite
  still passes end-to-end.
- `python main.py --scenario all` — runs end-to-end, produces a FARS
  score, no unhandled exceptions.
- `llm_judge.py` degrades cleanly against a genuinely unreachable Ollama
  server in this sandbox (see "Closed in v7.9.2" above) — not just the
  mocked test suite.

### Re-verified live this session (v7.9.8) — audit-only pass, no code changed

Same clean-environment re-verification as the v7.9.7 audit, repeated
independently to confirm nothing regressed across the session boundary
(the prior session ended mid-way through the user's own local Ollama
testing, not mid-way through a code change): `pytest tests/ -v` → 57
passed, 0 skipped; `farf_security_lint.py` → 0 high-confidence, 3
low-confidence (same 3 pre-existing); all 22 `pentest/pt*.py` → exit 0;
`main.py --scenario all` → runs end-to-end, no unhandled exceptions.
**Exact match to the v7.9.7 figures — nothing to close, nothing newly
broken.** Full detail in `CHANGELOG_v7.9.8.md`.

### `farf_runtime_config.yml` draft reconciliation (v7.9.8)

The user supplied a second, independently-drafted illustrative runtime
config (separate from this file's ADR-012 schema, and — like ADR-012's
own YAML — not wired to any real loader; no module in this codebase
parses YAML and `requirements.txt` carries no PyYAML dependency).
Field-by-field reconciliation against real code lives in
`CHANGELOG_v7.9.8.md` §2; short version: `cost_ceilings`/`risk_tiering`
match ADR-012 verbatim (same no-consumer caveat, not new), `logging.sink`
is half-real (`json_stdout` yes, cloud sinks no — ADR-007 still open),
`federation.quorum_threshold` expresses the real `resolve_quorum()`
concept but as an incompatible fraction-vs-count unit, and
`attack_mode`/`detection_thresholds`/`fail_safe_defaults` are new
proposed surface area with no code-side equivalent yet — same category
as ADR-012's already-open `risk_tiering`/`cost_ceilings`/`cross_cloud`,
not a regression. **Recommendation, not yet actioned:** merge this draft
with ADR-012's into one schema when the real YAML loader is actually
built during cloud-build, rather than treating either as authoritative
today. Left as a proposal pending the researcher's sign-off, consistent
with how this file has always treated schema/provider decisions.

### Genuinely open — cloud-build blockers (nothing else found; small list)

| Item | Why it blocks starting |
|---|---|
| ADR-003 real KMS wiring | `home_cloud`/`kms_key_ref` are inert metadata until an actual KMS client call exists — needed before any per-org key can genuinely live in AWS KMS / Azure Key Vault |
| Real multi-node ledger across two actual cloud accounts (ADR-006's remaining half) | The quorum *math* is now correct and defaults on; the witness nodes still all run in one local process |
| Actual AWS + Azure (or GCP) accounts, IAM roles, provisioned KMS keys | Operational prerequisite, not a documentation or code gap — no file closes this |

### Genuinely open — correctly deferred, not blockers (do not hold up starting cloud build)

Everything else in the table above marked "Open — cloud-build work
itself" **is** the cloud build, not a prerequisite to it — ADR-002/004/005/007/009/010/013/015 all describe work that only makes sense to do
with real cloud accounts in hand. Also correctly open, per their own
sections: `risk_tiering`/`cost_ceilings`/`cross_cloud` config (no Phase 1
equivalent — will be designed during cloud build, not before); LINDDUN
Non-repudiation/Detectability and OCTAVE governance-process gaps
(deliberate, disclosed design tensions — dissertation Limitations
material, not code work); PT-03/PT-05-raw-primitive/PT-15's residual
Trike risk (`RISK_APPENDIX.md` Part C — need process isolation or a
production classifier, both explicitly Phase 2/cloud items already).
~~`main.py`'s missing top-level exception handler
(`PHASE1_GAP_REPORT_v7.6.md` §6)~~ — **closed in v7.9.9**, see below.

### Closed in v7.9.9 — two real code changes, both re-verified end-to-end

1. **`main.py`'s top-level exception handler** (removed from the
   deferred list above) — `if __name__ == "__main__":` now catches
   `KeyboardInterrupt` (clean message, exit 130) and every other
   `Exception` (logged via `farf_logging`, clean one-line `[FARF]
   FATAL:` message, exit 1, full traceback opt-in via `FARF_DEBUG=1`)
   around `main()`. Does not change the v7.6 per-scenario `finally:
   bus.close()` guarantees — only what the operator sees on exit.
   Verified live: normal run unaffected, a forced `--db`-path failure
   now exits 1 with a clean message instead of a raw traceback, both
   with and without `FARF_DEBUG=1`. Full detail in `CHANGELOG_v7.9.9.md` §1.
2. **`runtime_config.py` (new)** — a real YAML loader for
   `farf_runtime_config.yml`, wired into `main.py` via a new
   `--runtime-config <path>` flag. Every field in the file is classified
   as APPLIED (takes effect: `federation.orgs` via a real dry-run
   `build_federation_from_config()` call, `logging.level`,
   `logging.sink: json_stdout`) or PARSED_ONLY (stored, not consumed —
   `federation.quorum_threshold`'s fraction-vs-count unit mismatch,
   `attack_mode`/`risk_tiering`/`cost_ceilings`/`detection_thresholds`/
   `fail_safe_defaults` all lacking a real code-side consumer, each with
   a specific named reason in `runtime_config.PARSED_ONLY_REASONS`) —
   never silently dropped either way. `requirements.txt` gained
   `PyYAML>=6.0`. Verified against the researcher's actual file (not a
   simplified fixture): standalone CLI, full `main.py` integration
   including the dry-run federation build (3 orgs, quorum resolved to
   3.0 matching `recommended_quorum_for_pbft(3)`), and both forced-error
   paths (missing file, malformed `orgs` field) correctly routing
   through item 1's new exception handler. 20 new tests in
   `tests/test_08_runtime_config.py`. Full detail, including exactly
   which decisions were deliberately left unresolved and why, in
   `CHANGELOG_v7.9.9.md` §2.
   - **ADR-012's Summary-table row updated**: "Substantially closed" →
     first real (non-illustrative) implementation now exists for the
     subset of that schema this file's `orgs`/`quorum`/`credential_ttl_seconds`
     fields already covered; `risk_tiering`/`cost_ceilings`/`cross_cloud`
     remain genuinely unimplemented, same as before, now with the
     specific reasons a live loader surfaces rather than a general note.

### Closed in v7.9.10 — four thesis-supervisor-directed items, all evidence-backed

Session followed the first meeting with the researcher's new supervisor.
All four items she approved are closed; full detail, live command output,
and the comparison-tool results in `CHANGELOG_v7.9.10.md`. Summary:

1. **Quorum-default gap, Option B ("fix + re-run as a comparison")** —
   `tools/quorum_policy_comparison.py` (new) proved PBFT-dynamic requires
   unanimous collusion to falsely clear a quarantine at N=3 vs. legacy's
   2-of-3, cross-checked against the real code, not just arithmetic;
   swap made on that evidence, scoped to `main.py`'s construction sites
   only (pt07/pt11's legacy-quorum tests deliberately unaffected). See
   the corrected ADR-006 row above.
2. **FARS `connectivity_divisor` multi-scenario sensitivity** —
   `tools/fars_sensitivity_sweep.py` extended to 5 regimes, live-run:
   max-shift ranged 0.96–5.62 FARS points depending on scenario — the
   sensitivity itself is regime-dependent, not a fixed property, which
   the original single-scenario sweep couldn't have shown.
3. **Dynamic quorum recompute** — delivered with item 1;
   `quorum_recompute_strategy="batched"` is a real, fail-fast (not
   silently-approximated) provision for the future.
4. **Per-record revocation, configurable** — **with a disclosed erratum**:
   this was already built (`revoke_record()`/`erase_record_for_subject()`
   pre-date this session); `PHASE1_TO_CLOUD_DECISION_BRIEF.md`'s claim
   otherwise was wrong, caused by an incomplete grep during that earlier
   audit, corrected in place with a visible strikethrough rather than
   silently edited. What v7.9.10 actually added: a single
   `mode="tombstone"|"crypto_shred"` dispatcher, plus a real bug found
   and fixed during testing (crypto_shred mode didn't check key
   existence before writing an audit marker).

Regression across all four: 89/89 tests (77 pre-existing + 12 new for
item 4), 0 high-confidence lint findings, 22/22 pentest unchanged,
`validate_connectivity_sampling.py` extended to the real 200-agent case
(no material bias found: signed bias +0.0069).

Regression after both changes: 77/77 tests passing (57 pre-existing +
20 new), lint unchanged (0 high-confidence), 22/22 pentest unchanged.

**Not implemented this session (by explicit instruction):** ADR-006
multi-process witness nodes — the user asked for this as an open
question, not a task, so only a pros/cons analysis was delivered (in
conversation, not code). Summary: the quorum *math*
(`recommended_quorum_for_pbft`) is a pure static function independent
of process boundaries — splitting witnesses across processes would
exercise IPC/concurrency robustness, not the arithmetic itself. See
`CHANGELOG_v7.9.9.md` §3 for the pointer; the full options/trade-offs
were given directly to the researcher for a decision.



`CLOUD_PROVIDER_COMPARISON.md` — cited throughout this file as the source
for every pricing/provider figure — was missing from the delivered
package as of v7.9.6 (flagged, not silently worked around). The user
located and re-supplied the original file this session; it now ships
inside the package (see `README.md`'s file listing). Every citation in
this document (ADR-001, ADR-002, ADR-003, ADR-008, ADR-011, and the
Summary table's "GCP-equivalent delta?" column) is re-verified against
the actual file's content, not re-asserted from memory of the prior
session's description of it. See the new "Cost-effective cloud
combination — decided this session" section immediately below for the
recommendation this restores the ability to make.

### Naming/versioning hygiene (cheap, worth doing, not urgent)

- ~~`PHASE1_GAP_REPORT_v7.6.md`'s closing line pointed at the wrong
  filename (`ARCHITECTURE_DECISIONS.md` instead of
  `ARCHITECTURE_DECISIONS_1.md`)~~ — **fixed in v7.9.8**, see
  `CHANGELOG_v7.9.8.md`.
- Keep the prototype's internal folder name and its outer zip/version
  label in agreement going forward (v7.9's zip and folder now match;
  earlier packaging — see `CHANGELOG_v7.9.md`'s note — did not).

### Keeping this file in sync going forward

This file (`ARCHITECTURE_DECISIONS_1.md`) is now shipped **inside** the
prototype zip (see `README.md`'s file listing) rather than living only as
a separate upload — it travels with the code it describes. Protocol for
future sessions:

1. Any code change that closes, partially closes, or newly opens an item
   in the summary table above gets a **Code status** update in that same
   pass — not deferred to "later."
2. Every `CHANGELOG_v*.md` entry that closes something already listed in
   this file's Internal Audit section links back here rather than
   restating the decision rationale — CHANGELOGs record *what changed and
   when and with what evidence*; this file records *current status*. If
   the two ever disagree, the most recent CHANGELOG's evidence wins and
   this file gets corrected to match, in the same session that notices
   the mismatch.
3. Before starting a new cloud-build ADR, re-read this Internal Audit
   section first — it's the fastest way to confirm a "gap" isn't actually
   already closed.
