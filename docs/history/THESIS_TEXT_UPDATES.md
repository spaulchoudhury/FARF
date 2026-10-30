# Thesis text updates from the 20-21 September 2026 re-verification run

Drafts for you to edit into your own voice. Every number below is taken from a file in `evidence_20260921\`
or from the pasted screen output; the "Evidence" line after each block names it. Paragraph numbers refer to
the .docx files you uploaded (Chapter 5 v3, Chapter 6 v2). Nothing here should be pasted in without
checking that it still matches what you did.

Two facts you must decide before you use the ADR-010 text (block D): see the note at the end of that block.

---------------------------------------------------------------------------------------------------

## A. What the new evidence changes (one-screen summary)

| Item | Old status (Ch5 27-28 Aug) | New status |
|---|---|---|
| WAN partition (ADR-017) | inconclusive, 0/124 failures, cause = "leading hypothesis: connection tracking" | **Observed and recovered** in two independent runs; earlier null result explained by an incomplete revoke (all-traffic rule left in place) |
| Cross-boundary TOCTOU, adversarial path (ADR-010) | not exercised | **Exercised**: allow/no_violation and block/toctou_resource_mismatch, both logged in Cloud Run's own log stream (see the vantage-point note in block D) |
| PT-08 verdict inconsistency (ADR-018) | 2 of 3 runs false VULNERABLE (harness defect) | **Fixed and verified**: NOT VULNERABLE under load, and on an immediate re-run, with a stable org count |
| Latency under load (ADR-019) | no figure (script defect) | **Measured**: N=200, 0 errors, mean 111.3 ms (laptop to Cloud Run) |
| AWS-to-GCP latency | none | **Measured**: 92 clean attempts, mean 22.4 ms, p50 21.3 ms, p95 27.0 ms (Fargate to Cloud Run) |
| Quorum over Cloud Run | reproduced at N=3 | Re-confirmed on a fresh revision: 3.0 required at 3 orgs, commit exactly at 3.0 |

---------------------------------------------------------------------------------------------------

## B. Chapter 5, heading of Section 5.11.3

Suggested heading (adds the re-verification dates):

> 5.11.3 Cross-Cloud (AWS↔GCP) Deployment Verification: Partition, Boundary Re-verification and Load-Under-Attack (27–28 August 2026, with re-verification on 20–21 September 2026)

Add one sentence at the end of paragraph [167]:

> Items that were inconclusive or defective in the first session (27–28 August) were re-run on 20–21 September 2026 after the specific defect in each had been identified and corrected; both the original and the re-run results are reported, and each finding states which session it belongs to.

---------------------------------------------------------------------------------------------------

## C. Section 5.11.3.1 (Network Partition and Quorum-Witnessed Recovery)

**Keep paragraph [169] unchanged** (the Docker-level test). **Replace paragraph [170]** with the three paragraphs below.

> The harder question — whether a real network partition between two independent cloud providers is observable and recoverable at the WAN boundary — was attempted twice in the first session (27–28 August) without a usable result, and was resolved in a second session (20–21 September 2026). The first attempt revoked egress on the AWS security group attached to the running Fargate task's network interface and later restored it, across two trial windows (24 and 100 iterations); every iteration of the client loop reported success (zero timeouts, zero connection errors) although the revoke command itself succeeded. That session recorded connection tracking of an already-established flow as the leading candidate explanation, while noting that it fitted poorly because the client issued a new request on each iteration. A third attempt on 28 August is recorded as invalid rather than as a result: the client was run from the author's workstation, which no AWS security group governs, and every request, including the pre-revoke baseline, returned HTTP 500 because the client had never admitted its agents to the bus (an unadmitted sender raises a KeyError inside the bus's signing step, which the service surfaced as an unhandled 500).

> Inspection of the security-group configuration in the second session identified the cause of the first session's null result without needing the connection-tracking hypothesis. Both pilot security groups carried an all-traffic egress rule (protocol -1, 0.0.0.0/0) in addition to the TCP-443 rule. The first session's procedure revoked only the TCP-443 rule. AWS security-group rules are permit-only and additive, so the surviving all-traffic rule continued to allow every outbound connection, which by itself accounts for zero failures in 124 iterations. The connection-tracking explanation is therefore not needed and is not supported by the later evidence, in which fresh connections failed once both rules had been removed.

> The corrected test (aws_pilot/adr004_partition_client_v5.py) runs inside a Fargate task, admits its agents before starting, refuses to begin unless a pre-flight request returns HTTP 200 with decision=allow, opens a new TCP connection for every attempt and records the operating-system-assigned source port (49 distinct ports for 49 connecting attempts in the first run, 45 for 45 in the second, confirming no connection reuse), and re-admits its agents periodically because the bus's admission credential lifetime is 300 s. Egress was revoked on an otherwise unused security group (sg-0f5755cb8a65a398c) whose two rules were saved beforehand as JSON and restored from that file; a describe call during the window returned an empty rule list. In run 1 (per-attempt timeout 8 s; revoke at 19:03:32Z, restore at 19:05:35Z, 123 s) the first attempt after the revoke began 4 s later and failed after 64.0 s with "Network is unreachable", the next attempt stalled for 31.3 s and completed 5.4 s after the restore, and no request succeeded for 129 s in total; all 37 later attempts succeeded at about 22 ms. In run 2 (timeout 2 s; revoke 19:26:59Z, restore 19:29:02Z, 123 s) five consecutive attempts failed, each after 16.0 s, one further attempt stalled for 15.1 s and completed 2.2 s after the restore, no request succeeded for 125 s, and all 31 later attempts succeeded. A failed attempt lasts exactly eight times the configured timeout in both runs (64.0 s at 8 s, 16.0 s at 2 s), consistent with the client trying each of the eight addresses the service hostname resolves to in turn. The two runs used different tasks and different client timeouts and gave the same qualitative outcome.

> The scope of this result is stated narrowly. It shows that new connections from an AWS task to the GCP-hosted bus fail while the task's egress rules are absent and resume within roughly two to five seconds of restoration, measured at the client. Because only five to six attempts fall inside each 123 s window (each blocked attempt occupies the client for many seconds), it is reported as a timeline of observed attempts, not as a rate or a statistical estimate. It does not show what happens to an already-established connection (AWS retains state for tracked flows, which is documented behaviour but was not tested here), it does not exercise the quorum-witnessed recovery mechanism across the WAN partition (that property rests on the Docker-level test of the preceding paragraph), and one log line from run 2 (iteration 12) is absent from the exported CloudWatch log although the client's own summary counts it, most probably a log-delivery gap during the blackout. A network-ACL variant that would also affect established flows (ADR-017 Option B) is carried forward as future work.

Evidence: `evidence_20260921\*_partition_cloudwatch_export.txt` (both runs), `*_partition_analysis.txt`, `egress_saved.json`
(the two rules), `sg_during_revoke.json` (`[]`), and the client's own `loop_complete` line for run 2.

**Latency finding to add at the end of 5.11.3.1** (or as a new short paragraph):

> The clean attempts from Fargate (ap-south-1) to Cloud Run (asia-south1), including TCP and TLS setup on every attempt, gave a mean of 22.4 ms (p50 21.3 ms, p95 27.0 ms, N = 92 across the two runs; run 1: mean 22.7 ms, N = 48; run 2: mean 22.2 ms, N = 44). This is the first latency measurement available to this thesis for the actual AWS-to-GCP path, as distinct from the workstation-to-Cloud-Run figures of Section 5.11.2.

---------------------------------------------------------------------------------------------------

## D. Section 5.11.3.2 (Cross-Boundary TOCTOU Re-verification Logging)

**Replace** the scope sentences at the end of paragraph [172] (from "The scope of this evidence is stated precisely..." to the end) with:

> The adversarial path was exercised in the second session. adr010_boundary_probe_v2.py sent two execute_action requests from organisation PT010Org2 to an agent in PilotOrgA: a non-tampered request (resource_hash_at_check = resource_hash_at_use = "h1"), which the bus allowed with reason no_violation, and a tampered request (check hash "h1_original", use hash "h2_tampered"), which the bus blocked with reason toctou_resource_mismatch — the rule name registered in orchestration.py, not the "toctou_violation" name used in an earlier draft of this thesis's own documentation. Querying the Cloud Run service's own log stream (revision <farf-prototype>-bus-00011-2vl) returned exactly two cross_boundary_toctou_reverification events, one carrying each hash pair, 0.1 s apart at 18:35:31Z. The event is logged for every cross-boundary action of this type whether or not it is blocked and does not itself record the decision, so the two are correlated by hash pair and time; the allow or block decision comes from the response.

> Two limitations apply. First, both hashes are supplied by the client in the request payload, so this evidence shows that the mismatch rule fires and is logged across the provider boundary, not that the bus independently recomputes a resource hash. Second, the second-session probe was run from the author's Windows workstation against the Cloud Run service, i.e. from a client outside Google Cloud, whereas the first session's matching-hash run was executed from an AWS ECS task; the adversarial case has therefore been shown across a network boundary to GCP but not yet from the AWS task.

**Decision for you before you write this block.** If you want the sentence to read "from an AWS task", the probe must be
run from Fargate (about 5 minutes, a few paise of Cloud Run time; I can build a `-Step adr010-aws` step). Otherwise keep the
second limitation as written. Do not delete that limitation and leave the probe running from your laptop.

Evidence: `evidence_20260921\*_adr010_probe.txt`, `*_adr010_gcp_log_events.txt`.

---------------------------------------------------------------------------------------------------

## E. Section 5.11.3.3 (Load-Under-Attack)

Keep [174] and [175] (they correctly record the first session). **Replace [176]** and add one paragraph after it:

> The latency-under-load measurement that failed in the first session (an agent-identity mismatch between the two scripts) was re-run in the second session after cloud_run_final_checks.py was corrected to take explicit sender and receiver identities and a --skip-quorum option, so that the latency probe does not change organisation state while the pentest scripts run. In a concurrent mixed workload — a 1000-message load generator (completed in 116.0 s with 0 errors, about 8.6 messages per second from a single client), PT-01, PT-02, PT-08 and a 200-request latency probe running as five simultaneous jobs — PT-01 and PT-02 again returned NOT VULNERABLE (PT-02's two attacks were both blocked with reason incomplete_action_schema), and PT-08 returned NOT VULNERABLE both under load and on an immediate second run. The measured latency under load was a mean of 111.3 ms (sd 12.2 ms, p50 108.0 ms, p95 133.7 ms, N = 200, 0 errors), compared with 119.6 ms (sd 17.0 ms, p50 117.0 ms, p95 148.9 ms, N = 200, 0 errors) unloaded, both measured from the author's workstation to Cloud Run about 30 minutes apart, and both including per-request connection setup.

> These figures support "no measurable degradation at this offered load", not a claim that load improves latency: the unloaded measurement was taken first and the difference is within the variation expected between two measurement windows. The load is light (a single client), so this is a concurrent mixed workload and should not be described as a stress test. The two measurements are comparable with each other because they share a vantage point; neither should be compared with the AWS-to-GCP figure of Section 5.11.3.1.

> The PT-08 defect recorded in [175] was corrected in two stages. Run-scoped identifiers (a random suffix on organisation, agent identities and nonce) removed the false verdict, but registering a new organisation on every run was found to grow the deployment's organisation set permanently and, under the pbft_dynamic quorum policy, to move the required quorum (measured: 3.0 at three organisations, 5.0 at seven), which would silently change the quorum figure reported elsewhere. The final version therefore fixes the organisation name and makes only the agent identities and nonce run-scoped; on the second run the registered-organisation count was unchanged (7 before and after). Because the quorum requirement depends on the organisation count, every quorum figure in this thesis should be reported with the organisation count at which it was measured (3.0 at N = 3 in the second session). At N = 3 the pbft_dynamic requirement equals unanimity, so this measurement confirms the dynamic threshold but cannot by itself demonstrate tolerance of a faulty organisation, which requires N of 4 or more.

Evidence: `*_load_egress.txt`, `*_load_latency.txt`, `*_load_pt01.txt`, `*_load_pt02.txt`, `*_load_pt08.txt`,
`*_load_pt08_second_run.txt`, `*_quorum_final-checks.txt`.

---------------------------------------------------------------------------------------------------

## F. Table 5.9 (summary table): suggested rows

| Finding | Session | Status | Note |
|---|---|---|---|
| Docker-level partition and quorum | 27-28 Aug | Confirmed pass | unchanged |
| WAN partition, first attempts | 27-28 Aug | Inconclusive; **cause identified** | only tcp/443 revoked; all-traffic rule left in place |
| WAN partition, corrected client | 20-21 Sep | **Confirmed (connection level)** | 2 runs; blackout 125-129 s; recovery 2.2-5.4 s; established flows and quorum-over-WAN not tested |
| TOCTOU, matching hashes | 27-28 Aug | Confirmed pass | from an AWS task |
| TOCTOU, adversarial mismatch | 20-21 Sep | **Confirmed (logged and blocked)** | client-supplied hashes; run from workstation (or AWS task, if you run block D's option) |
| PT-01, PT-02 under load | both | Confirmed pass | mixed workload |
| PT-08 under load | 27-28 Aug | Harness defect (false VULNERABLE) | nonce/agent state persisted across runs |
| PT-08 under load, fixed | 20-21 Sep | **Confirmed pass** | run-scoped agents and nonce; org count stable |
| Latency under load | 27-28 Aug | Broken measurement | identity mismatch |
| Latency under load, re-run | 20-21 Sep | **Measured** | mean 111.3 ms vs 119.6 ms unloaded (workstation vantage) |
| AWS-to-GCP latency | 20-21 Sep | **Measured** | mean 22.4 ms, N = 92 |

**Replace paragraph [178]** (the closing paragraph of 5.11.3) with:

> Of the three items left incomplete by the first session, all three were closed in the second by identifying and correcting a defect in the measurement apparatus, not by changing the system under test: the WAN partition attempt (an incomplete rule revocation), the untested adversarial boundary-re-verification path (now exercised), and the broken load-latency measurement (an identity mismatch, now measured). The bus image was unchanged between sessions (federation-bus:v4-adr010). What remains open is stated in Section 6.7.

---------------------------------------------------------------------------------------------------

## G. Chapter 6, Section 6.5.1 (Cloud Deployment Latency): addition

Your section names "a genuine same-region control" as unfinished work. The AWS-to-GCP run is close to one. Add after paragraph [40]:

> A near-same-metro control was subsequently obtained in the second session: Fargate tasks in ap-south-1 (Mumbai) sending to the asia-south1 (Mumbai) Cloud Run deployment measured a mean /send round trip of 22.4 ms (N = 92, p95 27.0 ms), including TCP and TLS setup on every request, against 111–120 ms from the author's workstation to the same service (110.9 ms in Section 5.11.2, 119.6 ms unloaded and 111.3 ms under load in Section 5.11.3.3). Two consequences follow. First, most of the workstation figure is network path from the author's location, which supports the reading that network distance dominated the earlier measurements. Second, it places an upper bound of roughly 22 ms on /send's own processing floor plus connection setup, which weakens the preceding paragraph's inference that the request-handling floor is the larger cost at short distance: the KMS figure of 69.6 ms was also measured from the workstation, so the two are not comparable, and a KMS measurement from a same-metro vantage has not been made. The ordering of /send and KMS latency at short distance therefore remains unresolved, and the ADR-003 batching rationale in the preceding paragraph should be read as unproven.

Note: this is a genuine change to a conclusion in your chapter, so read it against paragraphs [39] and [40]
and soften those two accordingly.

---------------------------------------------------------------------------------------------------

## H. Chapter 6, Section 6.7 (What This Evidence Does Not Establish)

In paragraph [49] replace "**under real network partition**" with:

> beyond a connection-level network partition (Section 5.11.3.1: new connections from an AWS task to the GCP-hosted bus fail while egress is revoked and resume within seconds of restoration, but established connections, asymmetric or longer partitions, and the quorum-witnessed recovery mechanism across a WAN partition were not tested)

Add to the same paragraph's list of open items: fault tolerance of the dynamic quorum at N of 4 or more over a real deployment; a KMS
latency measurement from a same-metro vantage; the AWS-hosted execution of the adversarial ADR-010 case (delete this item if you run it).

Note: your Chapter 6 v2 has no Section 6.5.2, although earlier working notes referred to one. The sections that exist are 6.5, 6.5.1,
6.6 and 6.7, so the edits above go to 6.5.1 and 6.7.

---------------------------------------------------------------------------------------------------

## I. ARCHITECTURE_DECISIONS: outcomes for the three proposed ADRs

**ADR-017 (partition test).** Context correction: replace "root cause: connection tracking" with "root cause: the revoke procedure
removed only the tcp/443 rule and left an all-traffic egress rule; SG rules are additive". Decision adopted: Option A (fresh
connection per attempt, ground-truth source port) plus a complete revoke of every egress rule on a dedicated unused SG, with the
client running inside the task, a preflight gate and a timestamp-based analyzer. Option B (network ACL) not needed for the claim
made; retained as future work for established-flow behaviour. Option C rejected (simulated from inside the task).

**ADR-018 (pentest idempotency).** Adopted: A (run-scoped identifiers) in a narrowed form (agents and nonce only; the organisation
is fixed, because per-run organisations shift the quorum), and C (verdict logic distinguishes stale state from a genuine replay
failure). B (reset route) not adopted: a new Cloud Run revision already provides a clean state without widening the pentest-mode
surface. PT-01 and PT-02 re-ran cleanly without change, so the fix was not applied to them.

**ADR-019 (load-under-attack harness).** Adopted: A (explicit identities passed to cloud_run_final_checks.py, plus --skip-quorum
so the latency probe does not change state during the pentests), executed by one driver script (farf_run.ps1) that records
evidence per step. B (a dedicated harness) deferred: the composed run was reproducible without it.

**New note for all three ADRs.** The bus admits each agent with a credential valid for 300 s; every long-running client must
re-admit periodically (the v5 partition client does), and the latency probe must be run within 300 s of admission.

---------------------------------------------------------------------------------------------------

## J. Evidence index (put this in an appendix)

| Claim | Evidence file (in `evidence_20260921\` unless stated) |
|---|---|
| Bus image, env vars, revisions | `*_bus-env_deploy.txt`, `*_warm_update.txt`, `*_cool_update.txt`; image digest `sha256:617eee4e...` for the partition client |
| Quorum 3.0 at 3 orgs; unloaded latency | `*_quorum_final-checks.txt`, `*_quorum_readmit.txt` |
| ADR-010 adversarial path | `*_adr010_probe.txt`, `*_adr010_gcp_log_events.txt` |
| Load-under-attack | `*_load_*.txt` |
| Partition runs 1 and 2 | `*_partition_cloudwatch_export.txt` (x2), `*_partition_analysis.txt` (x2), `egress_saved.json`, `sg_during_revoke.json` |
| Inventory before the runs | `precheck_2026...` folders (contain your AWS account and project identifiers: do not publish) |
| Code that produced the results | git commit of the repository (make it now, see the teardown checklist); files `farf_run.ps1`, `aws_pilot/adr004_partition_client_v5.py`, `aws_pilot/analyze_partition_log.py`, `pentest_cloud/pt08_session_hijack_cloud.py` (v2), `gcp_pilot/cloud_run_final_checks_FIXED.py` (with --skip-quorum) |

---------------------------------------------------------------------------------------------------

## K. Do not claim

- "100% of requests failed during the partition" (5 to 6 attempts per window; report the timeline).
- That connection tracking was refuted in general (only that it is not needed to explain the earlier result and was not supported later).
- That the bus is faster under load (unloaded and loaded measurements are 30 minutes apart, single runs).
- That the AWS-to-GCP figure and the workstation figures are comparable.
- That the quorum result shows Byzantine tolerance (N = 3 is unanimity).
- That the ADR-010 adversarial test ran from AWS, unless you run it from Fargate.
