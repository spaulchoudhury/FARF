# Next steps: run the verification, one command per step

Everything is driven by one script, `farf_run.ps1`. Run it from the repo root
(`farf_prototype_v7_9_7`) in the VS Code PowerShell terminal with `.venv` active.
Each step prints **EXPECT** lines first, then `[PASS]` / `[FAIL]` lines, and saves all output to
`evidence_<date>\` in the repo folder. **If any line says `[FAIL]`, stop and paste the screen output.**
`[WARN]` lines are things to look at, not blockers.

## 0. One-time file placement (from your Downloads folder)

```powershell
$dl = "$HOME\Downloads"
Copy-Item $dl\farf_run.ps1 .
Copy-Item $dl\cloud_run_final_checks_FIXED.py .\gcp_pilot\        # NEWER copy: adds --skip-quorum
Remove-Item .\build_and_deploy.ps1 -ErrorAction SilentlyContinue   # replaced by farf_run.ps1
```
Everything else you already copied last time (v5 client, analyzer, adr010 v2, task def, pt08 v2, bus-env.yaml).
Windows may block a downloaded .ps1: if you see "running scripts is disabled", run once in this terminal:
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`

## The order

| # | Command | Time | Costs money? | Changes anything? |
|---|---------|------|--------------|-------------------|
| 1 | `.\farf_run.ps1 -Step check` | 1 min | no | no (read-only) |
| 2 | `.\farf_run.ps1 -Step bus-env` | 2 min | no (min 0) | Cloud Run: new revision with both env vars |
| 3 | `.\farf_run.ps1 -Step aws-image` | 5-10 min | pennies | ECR image + task definition |
| | *(stop here if you are not ready to test now)* | | | |
| 4 | `.\farf_run.ps1 -Step warm` | 2 min | **meter starts, about INR 1.3/hour** | bus ON, clean state |
| 5 | `.\farf_run.ps1 -Step quorum` | 1-2 min | | adds a third org |
| 6 | `.\farf_run.ps1 -Step adr010` | 2 min | | |
| 7 | `.\farf_run.ps1 -Step load` | 3-6 min | | adds pentest orgs |
| 8 | `.\farf_run.ps1 -Step partition` | 8-10 min | | briefly cuts one SG's outbound |
| 9 | `.\farf_run.ps1 -Step cool` | 1 min | **meter stops** | bus OFF |

Run 4 to 9 in one sitting (about 30-40 minutes, roughly INR 1). **Step 5 must come before 7**: every pentest adds
an org and changes the quorum number you will cite in Chapter 6. `.\farf_run.ps1 -Step status` shows at any time
what is on (read-only).

## What each step should look like

**1 check**: all `[PASS]`. Acceptable `[WARN]`s: none expected. A WARN naming project `<farf-prototype>-2026` means a
second GCP project has a Cloud Run service: check its `minScale` (it may be costing money).
Fixes for FAILs: Docker not running: start Docker Desktop. AWS login: run `aws login`. `--skip-quorum` missing:
re-copy `cloud_run_final_checks_FIXED.py`.

**2 bus-env**: gcloud ends with `Service URL: https://<farf-prototype>-bus-...run.app`, then
`[PASS] FARF_PENTEST_MODE=1`, `[PASS] FARF_LOG_FORMAT=json`, `[PASS] image tag is v4-adr010`,
`[PASS] max instances = 1`, `[PASS] min instances = 0`. No Docker build happens (the bus code did not change).

**3 aws-image**: `Login Succeeded`, a docker build (first time several minutes), a push, then the container listing
`adr004_partition_client_v5.py` / `---` / `NO_AWS_KEY_FOUND`, then `[PASS] ECR has tag v5-partition` and
`[PASS] task definition registered ...<farf-prototype>-partition-test-v5:1`.

**4 warm**: `[PASS] bus /health returns ok`, `[PASS] smoke message: decision=allow`, env vars present, min instances = 1,
then `[WARN] COST METER IS RUNNING` (expected). First request after a cold start can take 10-30 s.

**5 quorum** (real output, local sample; your latency will be tens of ms because it crosses the internet):
```
Registered PilotOrgC: {'quorum_required': 3.0, ...}
quorum_required: 3.0 for 3 orgs
Witness 3/3 (PilotOrgC): {'accepted': True, 'committed': True, ...}
... PART 1 PASSED.
=== Real WAN /send latency, Cloud Run (N=200, errors=0) ===
  mean = ... ms   sd = ... ms   p50 = ... ms   p95 = ... ms
```
`[PASS] PART 1 quorum passed`, `[PASS] PART 2 latency: N=200, errors=0`. Write down the two `NOTE` lines: quorum 3.0 at
3 orgs, and the **unloaded** latency. If PART 2 says `FAIL (setup error)`, run `warm` again.

**6 adr010**: `Case 1 ... PASS` (allow / no_violation), `Case 2 ... PASS` (block / toctou_resource_mismatch),
`CROSS-CLOUD TOCTOU RE-VERIFICATION: CONFIRMED`, then `[PASS] Cloud Logging shows >= 2 ... events` and
`[PASS] both hash pairs present`. It retries up to 6 times (about 2 minutes) for the log lines to appear. Found 0 events
means `FARF_LOG_FORMAT=json` is missing: re-run `bus-env`, then `warm`.
Chapter note: both hashes are supplied by the client, so this proves the rule fires across the cloud boundary, not
that the bus recomputes the hash itself.

**7 load**: five background jobs. After they finish you see each one's output, then `[PASS]` for: load generator
`Done in ...s, 0 errors` (1000 messages), PT-01 `PASSED`, PT-02 `NOT VULNERABLE`, PT-08 `NOT VULNERABLE`, loaded
latency `N=200, errors=0`, then PT-08 re-run alone `NOT VULNERABLE` with `[org-count check] before=X after=X`
(equal numbers; on the FIRST PT-08 run above it grows by exactly one, once, which is expected). Note the
**loaded** latency line separately from the unloaded one. `INCONCLUSIVE` from PT-08 = stale state, not a finding;
a plain `VULNERABLE` needs one re-run before you believe it.

**8 partition**: pre-flight `[PASS]` lines (nothing is touched until all pass), then a Fargate task starts
(1-3 min), `[PASS] task baseline is clean`, about 45 s later the revoke, `[PASS] SG egress is EMPTY during the window`,
`PARTITION WINDOW: holding for 120 s`, `RESTORED at ...`, `[PASS] SG rules are back to 2`, then the analyzer. Success:
```
VERDICT: PARTITION OBSERVED AND RECOVERED -- clean baseline, NN% network failures during the revoke window, clean recovery.
```
Other verdicts are real results, not script errors: `NO EFFECT`, `PARTIAL / LAG`, `NO CLEAN RECOVERY`,
`INVALID BASELINE`. Paste them and we interpret together. If `RESTORED` never appears, the script prints the exact
restore command for the SG. Keep `egress_saved.json`, `sg_during_revoke.json` and the evidence folder.

**9 cool**: `[PASS] min instances is 0`, `[PASS] no ECS tasks running`, `[PASS] partition SG has its 2 rules`.

## If something fails

- AWS commands say token/expired: run `aws login`, re-run the step.
- A step stopped half-way: run `.\farf_run.ps1 -Step status`, then `cool` if the bus is on.
- Do not run later steps after a `[FAIL]`; paste the screen text (not screenshots) to Claude.

## After the run

Save `evidence_<date>\` before teardown. Send me: the screen output of steps 5-8 and the partition
`cloudwatch_export` and `analysis` files, and I will help update Chapter 5 Section 5.11.3.1 and Chapter 6
Sections 6.5.2 and 6.7. Teardown (delete Cloud Run service, ECS/ECR, log groups, KMS keys, old GCP project) comes
after that, and I will give you the exact list.
