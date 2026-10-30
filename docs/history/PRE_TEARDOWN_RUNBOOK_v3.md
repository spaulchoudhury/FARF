# Pre-Teardown Runbook v3: ADR-017/018/019 (+ ADR-010 v2) Fix Verification

Supersedes v2. Written 2026-09-20 after re-checking every fix against the real
`pentest_cloud/bus_service.py` locally. **Only the code paths were verified
locally; nothing here has yet been run against AWS or GCP.** The PowerShell
driver in Section 5 was read, not executed.

## A. What changed from v2, and why

1. **The 28 Aug log (`partition_v2_log.jsonl`) is not evidence about the SG.**
   40/40 HTTP 500 including the baseline. Cause (reproduced): `/send` for an
   agent that was never admitted raises `KeyError` in `TrustProtocol.sign_message()`
   -> Flask 500. v2/v3 never admitted agents. v4/v5 do.
2. **v2's Step 0 curl was a false alarm.** It used an unadmitted `healthcheck`
   agent, which returns 500 by design. Use `GET /health` plus the v5 PREFLIGHT gate.
3. **The audit-log-write explanation for the 500s is stale.** Closed in v7.6
   (THREAT_MODEL Section 21). `TEST_PROTOCOL` Section 4(e) needs correcting.
4. **Security-group facts (from your describe output).** `<farf-prototype>-sg`
   (`sg-03a05b9bf6769eb23`) and `<farf-prototype>-sg-2` (`sg-0f5755cb8a65a398c`) each have
   egress "All traffic 0.0.0.0/0" AND "TCP 443 0.0.0.0/0". The `default` SG
   (`sg-01ef62a6de2b53734`) also allows all egress. Your earlier ECS tasks used
   `<farf-prototype>-sg` only. The v1 revoke removed `tcp/443` but left the all-traffic
   rule, which by itself explains 0/124 failures (SG rules are additive). Revoking
   ONLY the all-traffic rule would also fail: `tcp/443` still reaches Cloud Run.
   Both rules must go. Multiple SGs on one ENI are additive too.
5. **v4 outlived the bus's 300 s admission TTL** (`/admit_agent` hardcodes 300 s;
   ~358 s run). v5 re-admits every 100 s. Re-admission is idempotent (verified).
6. **PT-08 v1 fix grew the org set per run**, moving `quorum_required`
   (measured: 5 orgs -> 3.0, 8 orgs -> 5.0). Use `pt08_session_hijack_cloud_FIXED_v2.py`
   (fixed org, run-scoped agent ids + nonce).
7. **Never use `gcloud run deploy --set-env-vars`** on this service; it replaces all
   variables (this is why `FARF_PENTEST_MODE` kept vanishing). Use `--update-env-vars`.

## B. Files to place first

- `adr004_partition_client_v5.py`, `analyze_partition_log.py`, `adr010_boundary_probe_v2.py` -> `aws_pilot/`
- `pt08_session_hijack_cloud_FIXED_v2.py` -> `pentest_cloud/` (rename to `pt08_session_hijack_cloud.py`)
- `cloud_run_final_checks_FIXED.py` -> `gcp_pilot/`
- Rebuild + push the image as tag `v5-partition` (Dockerfile does `COPY . /app`, so the
  old image does not contain v5). Then register `task-def-partition-v5.json`.

## 0. Stop the cost meter (now)

At list prices (assuming default 1 vCPU / 0.5 GiB, before free tier/credits) the
idle min-instance costs about INR 1.3/hour (about INR 31/day, about INR 930/30 days).

```powershell
gcloud run services update <farf-prototype>-bus --region asia-south1 --min-instances=0
aws ecs list-tasks --cluster <farf-prototype>-cluster --desired-status RUNNING --region ap-south-1   # stop any leftovers
```

## 1. Start a clean, warm session (a new revision resets all in-memory state)

Keep `--max-instances=1`: state is in memory, so more than one instance breaks admission.

Preferred (env vars come from `bus-env.yaml`, the single source of truth; needs `build_and_deploy.ps1`
dot-sourced and the image tag shown by `precheck_inventory.ps1` section G2):
```powershell
. .\build_and_deploy.ps1
Deploy-Bus -Tag <tag-from-G2> -MinInstances 1
```
Equivalent without the helper:
```powershell
gcloud run services update <farf-prototype>-bus --region asia-south1 --min-instances=1 --update-env-vars "FARF_PENTEST_MODE=1,FARF_LOG_FORMAT=json"
gcloud run services describe <farf-prototype>-bus --region asia-south1 --format="value(spec.template.spec.containers[0].env)"
curl "$url/health"
```

## 2. Quorum + UNLOADED latency (before any pentest adds orgs)

```powershell
python .\gcp_pilot\egress_load_test.py --url $url --n-messages 1
python .\gcp_pilot\cloud_run_final_checks_FIXED.py --url $url --n-latency-trials 200 `
  --from-agent PilotOrgA-executor --from-org PilotOrgA --to-agent PilotOrgB-advisor --to-org PilotOrgB
```
Record org count and `quorum_required` next to the result (N<4: quorum=N; N>=4: 2*floor((N-1)/3)+1).

## 3. ADR-010 v2

```powershell
$env:FARF_BUS_URL=$url; $env:FARF_ORG="PT010Org2"
python .\aws_pilot\adr010_boundary_probe_v2.py
gcloud logging read "resource.type=cloud_run_revision AND jsonPayload.event=cross_boundary_toctou_reverification" --limit 10 --format json --freshness=10m
```
Expect two entries: hashes `h1`/`h1` and `h1_original`/`h2_tampered`.
Caveat for the write-up: both hashes are client-supplied in the payload; this shows the
rule fires across the boundary, not that the bus independently recomputes the hash.

## 4. ADR-018 / ADR-019 under load

Re-admit immediately before (300 s TTL): `egress_load_test.py --n-messages 1`.
Then run the load as a background job with the pentests and the loaded latency check
concurrently:

```powershell
$egressJob = Start-Job { Set-Location $using:PWD; python .\gcp_pilot\egress_load_test.py --url $using:url --n-messages 2000 } -Name egress
Start-Sleep 2
Start-Job { Set-Location $using:PWD; python .\pentest_cloud\pt01_identity_spoofing_cloud.py --url $using:url } -Name pt01
Start-Job { Set-Location $using:PWD; python .\pentest_cloud\pt02_field_omission_bypass_cloud.py --url $using:url } -Name pt02
Start-Job { Set-Location $using:PWD; python .\pentest_cloud\pt08_session_hijack_cloud.py --url $using:url } -Name pt08
Start-Job { Set-Location $using:PWD; python .\gcp_pilot\cloud_run_final_checks_FIXED.py --url $using:url --n-latency-trials 200 --from-agent PilotOrgA-executor --from-org PilotOrgA --to-agent PilotOrgB-advisor --to-org PilotOrgB } -Name latency-loaded
Get-Job | Receive-Job -Wait
```
Then run PT-08 a second time on its own. Expect `NOT VULNERABLE` both times and no growth in
`registered_orgs` after the first run. `INCONCLUSIVE` = stale state; a plain `VULNERABLE`
needs one rerun before it counts as a finding. Label the latency figures "unloaded"
(Section 2) and "under load" (here).

## 5. ADR-017 partition test (client runs INSIDE Fargate)

Use the existing, unattached `<farf-prototype>-sg-2` (`sg-0f5755cb8a65a398c`) as the partition SG. The 20 Sep
inventory (A4) showed no network interfaces in the VPC, so nothing else uses it, and no
`ec2:CreateSecurityGroup` permission is needed (the `<farf-prototype>` IAM user cannot list IAM objects, so its
permissions are narrow; test with dry runs, do not assume). Launch the task with this SG ONLY (never together
with `<farf-prototype>-sg`; SG rules are additive). Save its exact rules so the restore is identical:

```powershell
$region="ap-south-1"; $subnet="subnet-05607578f1909b49f"; $sg="sg-0f5755cb8a65a398c"
aws sts get-caller-identity
aws ec2 describe-security-groups --group-ids $sg --region $region --query "SecurityGroups[0].IpPermissionsEgress" --output json | Set-Content egress_saved.json -Encoding ascii
aws ec2 revoke-security-group-egress    --group-id $sg --ip-permissions file://egress_saved.json --dry-run --region $region
aws ec2 authorize-security-group-egress --group-id $sg --ip-permissions file://egress_saved.json --dry-run --region $region
aws logs filter-log-events --log-group-name /ecs/<farf-prototype>-partition-test --limit 1 --region $region
```
Both dry runs must report `DryRunOperation ... would have succeeded`. On 27 Aug an authorize call returned
`UnauthorizedOperation`; do not start if either dry run fails, or you may be unable to restore.
`egress_saved.json` must contain BOTH rules (`-1` and `tcp/443`).
If the driver dies while the rules are revoked, restore by hand:
`aws ec2 authorize-security-group-egress --group-id $sg --ip-permissions file://egress_saved.json --region $region`
Your CLI credentials are session-type (`aws configure list` showed type "login"); run
`aws sts get-caller-identity` right before the driver so they cannot lapse between revoke and restore.

Driver (timing is by wall clock and the restore is in `finally`; markers are not usable in Fargate):

```powershell
$cluster="<farf-prototype>-cluster"; $lg="/ecs/<farf-prototype>-partition-test"
$start=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
$taskArn = aws ecs run-task --cluster $cluster --task-definition <farf-prototype>-partition-test-v5 --launch-type FARGATE --network-configuration "awsvpcConfiguration={subnets=[$subnet],securityGroups=[$sg],assignPublicIp=ENABLED}" --region $region --query "tasks[0].taskArn" --output text
try {
  $pre=$null
  for($i=0;$i -lt 60 -and -not $pre;$i++){ Start-Sleep 5
    $pre = aws logs filter-log-events --log-group-name $lg --start-time $start --filter-pattern "?PREFLIGHT ?PREFLIGHT_FAILED" --region $region --query "events[].message" --output text }
  if(-not $pre -or $pre -match "PREFLIGHT_FAILED"){ throw "Baseline not clean: $pre" }
  Start-Sleep 45
  $tRevoke=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  aws ec2 revoke-security-group-egress --group-id $sg --ip-permissions file://egress_saved.json --region $region
  aws ec2 describe-security-groups --group-ids $sg --region $region --query "SecurityGroups[0].IpPermissionsEgress" > sg_during_revoke.json   # expect []
  Start-Sleep 120
} finally {
  $tRestore=(Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  aws ec2 authorize-security-group-egress --group-id $sg --ip-permissions file://egress_saved.json --region $region
}
do { Start-Sleep 10; $st = aws ecs describe-tasks --cluster $cluster --tasks $taskArn --region $region --query "tasks[0].lastStatus" --output text } while ($st -ne "STOPPED")
(aws logs filter-log-events --log-group-name $lg --start-time $start --region $region --output json | ConvertFrom-Json).events | ForEach-Object { $_.message } | Set-Content partition_v5_cloudwatch.jsonl -Encoding utf8
python .\aws_pilot\analyze_partition_log.py --log partition_v5_cloudwatch.jsonl --revoke-utc $tRevoke --restore-utc $tRestore
```

Analyzer exit codes: 0 partition observed and recovered; 10 invalid baseline (fix the app first);
11 no effect; 12 partial/lag; 13 no clean recovery (`unadmitted_identity` = TTL lapse).
If the exit is 11: compare the source IP in Cloud Run request logs
(`httpRequest.remoteIp`) with the task's public IP, and check that `sg_during_revoke.json` is `[]`.
Escalate to ADR-017 Option B (NACL) only if the IPs match AND the revoke provably landed.
Scope to state honestly: this tests that NEW connections are blocked and recover; it does not
disrupt an already-established flow (only a NACL would), which suits a stateless request/response bus.
Afterwards confirm `describe-security-groups` on `$sg` shows both egress rules again.

## 6. Save before teardown

CloudWatch export, `sg_during_revoke.json`, `egress_saved.json`, every script's stdout,
the Cloud Run source-IP query result, and org count + `quorum_required` for Section 2.

## 7. Documentation corrections

- `TEST_PROTOCOL` Section 4(e): stale (closed v7.6).
- ADR-017 Context: the connection-tracking root cause is unproven; the incomplete revoke
  (all-traffic rule left in place) is sufficient to explain the result.
- Chapter 5 Section 5.11.3.1 / Chapter 6 Sections 6.5.2 and 6.7: update only from the v5 result.
- Chapter 6 quorum figure: state the org count it was measured at.

## 8. Still open, not blockers

- 4(d): CUSUM cannot fire before the sliding-window detector under current calibration
  (THREAT_MODEL Section 19).
- Section 4 remains valid only for what was actually run; nothing above is a result until executed.

## 9. Teardown

After Section 6: delete the Cloud Run service, ECS tasks/cluster, the dedicated SG, ECR images, and
CloudWatch log groups. Then re-check the billing consoles for both clouds; AWS charges are not
covered by the pricing CSV.
