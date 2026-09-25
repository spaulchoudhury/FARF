$region = "ap-south-1"
$cluster = "<farf-prototype>-cluster"
$taskDefinition = "<farf-prototype>-partition-test"
$subnet = "subnet-05607578f1909b49f"
$sg = "sg-03a05b9bf6769eb23"
$busUrl = "https://<farf-prototype>-bus-<GCP_PROJECT_NUMBER>.asia-south1.run.app"
$project = "<farf-prototype>-2026b"# True Cross-Cloud Pilot + Cross-Cloud Pentest — GCP + AWS Walkthrough

Extends the earlier single-cloud ADR-006 pilot into a genuine two-cloud
federation: **Federation Bus + OrgA stay on GCP Cloud Run** (already
proven working), **OrgB moves to AWS Fargate** with its own real AWS KMS
Ed25519 key, sending real cross-cloud `/send` traffic to the GCP-hosted
bus. This is the first test in the project that actually spans two cloud
providers, matching ADR-003/ADR-005/ADR-006's original architecture
rather than a single-cloud approximation of it. **Steps 9-10 then layer
the cross-cloud pentest set (`pentest_cloud/`, pt01/pt02/pt08) on top of
this same infrastructure** — validated locally and on single-cloud Cloud
Run already; this walkthrough is what gets them validated against the
real two-cloud topology.

**Budget note — now two clouds, two guardrails.** Set a budget alert in
*both* consoles before starting (GCP Billing → Budgets, and AWS Billing →
Budgets), not just one. Real 2026 rates: AWS Fargate is
$0.04048/vCPU-hour + $0.004445/GB-hour, billed per-second — a single
short-lived 0.25 vCPU/0.5GB task running a couple of minutes costs a
fraction of a cent. AWS KMS is the same structure as GCP's: ~$1/month per
key (prorated hourly) plus negligible per-operation cost. **The one AWS
cost trap worth naming explicitly: a NAT Gateway costs ~$32/month if left
running** — this walkthrough avoids it entirely by running the Fargate
task in a public subnet with a public IP (fine for a short-lived,
torn-down-immediately pilot task; not something to do for anything
longer-lived).

## Step 0 — Redeploy the GCP side

The earlier pilot's project was fully deleted, so this needs a fresh
project (a deleted project ID can't be reused for roughly 30 days — use a
new name, e.g. `<farf-prototype>-2026b`). Repeat `gcp_pilot/PILOT_STEPS.md`
Steps 0–3 (project create, enable APIs, build+push, deploy to Cloud Run
with `--min-instances=1 --max-instances=1`) — everything is identical
except the project ID. **Also repeat Step 2** (create the Ed25519 KMS key
and grant yourself `roles/cloudkms.signerVerifier`) if you want a second
GCP KMS latency reading for comparison, though it's optional this time —
the number is already documented from the first pilot.

Confirm it's up and note the URL:
```powershell
curl https://YOUR-NEW-SERVICE-URL/health -UseBasicParsing
```

## Step 1 — Install and configure the AWS CLI

```powershell
winget install --id Amazon.AWSCLI -e
```
**Expect:** same pattern as the `gcloud` install — close and reopen your
terminal afterwards for PATH changes to take effect. Verify:
```powershell
aws --version
```

**Create a dedicated IAM user for this pilot** rather than using root
account keys (same least-privilege posture as everything else in this
project): AWS Console → IAM → Users → Create user → attach
`AmazonEC2ContainerRegistryFullAccess`, `AmazonECS_FullAccess`, and
`AWSKeyManagementServicePowerUser` (broad for a quick pilot; tighten if
this becomes a longer-lived setup) → Security credentials → Create access
key → choose "Command Line Interface (CLI)".

```powershell
aws configure
```
**Expect:** four prompts — Access Key ID, Secret Access Key, default
region (use `us-east-1`, matching the earlier pricing figures and a
reasonable geographic pairing for `us-central1`), default output format
(`json`). No confirmation message beyond returning to the prompt — verify
with:
```powershell
aws sts get-caller-identity
```
**Expect:** a JSON block with your `UserId`, `Account`, and `Arn` — this
confirms credentials work before anything else.

## Step 2 — Create the AWS KMS Ed25519 key

```powershell
aws kms create-key --key-spec ECC_NIST_EDWARDS25519 --key-usage SIGN_VERIFY --description "FARF pilot OrgB Ed25519 key" --region us-east-1
```
**Expect:** a JSON block with `"KeySpec": "ECC_NIST_EDWARDS25519"` and a
`KeyId` (a UUID) — copy this, needed below.

```powershell
aws kms create-alias --alias-name alias/<farf-prototype>-org-b-key --target-key-id YOUR_KEY_ID --region us-east-1
```
**Expect:** no output on success — aliases let you reference the key by
name instead of the UUID from here on.

## Step 3 — Push the image to ECR

```powershell
aws ecr create-repository --repository-name <farf-prototype>-org-b --region us-east-1
```
**Expect:** a JSON block with `repositoryUri` — save it, e.g.
`123456789012.dkr.ecr.us-east-1.amazonaws.com/<farf-prototype>-org-b`.

```powershell
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker build -f aws_pilot/Dockerfile.awsecs -t 123456789012.dkr.ecr.us-east-1.amazonaws.com/<farf-prototype>-org-b:v1 .
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/<farf-prototype>-org-b:v1
```
**Expect:** `Login Succeeded`, then a normal Docker build (same base image
you've built twice before, now with the `aws_pilot/` files copied in too
since the build context is `.`), then a push progress bar.

## Step 4 — Minimal networking (public subnet, no NAT)

```powershell
$vpc = aws ec2 describe-vpcs --filters "Name=is-default,Values=true" --query "Vpcs[0].VpcId" --output text
$subnet = aws ec2 describe-subnets --filters "Name=vpc-id,Values=$vpc" --query "Subnets[0].SubnetId" --output text
$sg = aws ec2 create-security-group --group-name <farf-prototype>-sg --description "FARF pilot outbound only" --vpc-id $vpc --query "GroupId" --output text
```
**Expect:** each command returns an ID (`vpc-...`, `subnet-...`,
`sg-...`) — the default VPC already has an internet gateway attached and
its default subnets auto-assign public IPs, which is exactly what avoids
needing a NAT Gateway here. No inbound rule is needed — the task only
makes outbound calls to the GCP bus.

## Step 5 — ECS cluster and task definition

```powershell
aws ecs create-cluster --cluster-name <farf-prototype>-cluster --region us-east-1
```

Create a task execution role (lets Fargate pull from ECR and write logs;
this is boilerplate, not FARF-specific):
```powershell
aws iam create-role --role-name farfPilotTaskExecutionRole --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"ecs-tasks.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}'
aws iam attach-role-policy --role-name farfPilotTaskExecutionRole --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
```

Create a log group:
```powershell
aws logs create-log-group --log-group-name /ecs/<farf-prototype>-org-b --region us-east-1
```

Register the task definition — save this as `aws_pilot/task-def.json`
first (replace `123456789012` with your account ID and
`YOUR-GCP-SERVICE-URL` with Step 0's URL):
```json
{
  "family": "<farf-prototype>-org-b",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::123456789012:role/farfPilotTaskExecutionRole",
  "containerDefinitions": [{
    "name": "org-b",
    "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/<farf-prototype>-org-b:v1",
    "environment": [
      {"name": "FARF_BUS_URL", "value": "https://YOUR-GCP-SERVICE-URL"},
      {"name": "FARF_ORG", "value": "PilotOrgB"},
      {"name": "FARF_PEER_ORG", "value": "PilotOrgA"},
      {"name": "FARF_N_LATENCY_TRIALS", "value": "50"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/<farf-prototype>-org-b",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "org-b"
      }
    }
  }]
}
```
```powershell
aws ecs register-task-definition --cli-input-json file://aws_pilot/task-def.json --region us-east-1
```
**Expect:** a JSON block confirming registration, `"status": "ACTIVE"`.

**Important — register PilotOrgA on the GCP side first**, if not already
present (the timing wrapper needs a peer org to send to):
```powershell
curl -X POST https://YOUR-GCP-SERVICE-URL/register_org -H "Content-Type: application/json" -d '{\"org\":\"PilotOrgA\"}' -UseBasicParsing
curl -X POST https://YOUR-GCP-SERVICE-URL/admit_agent -H "Content-Type: application/json" -d '{\"agent_id\":\"PilotOrgA-advisor\",\"org\":\"PilotOrgA\",\"role\":\"advisor\"}' -UseBasicParsing
```

## Step 6 — Run the cross-cloud task

```powershell
aws ecs run-task `
    --cluster <farf-prototype>-cluster `
    --task-definition <farf-prototype>-org-b `
    --launch-type FARGATE `
    --network-configuration "awsvpcConfiguration={subnets=[$subnet],securityGroups=[$sg],assignPublicIp=ENABLED}" `
    --region us-east-1
```
**Expect:** a JSON block with a `taskArn` — the task starts, runs
`cross_cloud_timing_wrapper.py`, and exits (it's one-shot, like
`org_client.py`). Wait ~30-60s, then check it finished:
```powershell
aws ecs describe-tasks --cluster <farf-prototype>-cluster --tasks YOUR_TASK_ARN --region us-east-1 --query "tasks[0].lastStatus"
```
**Expect:** `"STOPPED"` once done.

## Step 7 — Fetch the cross-cloud latency results from CloudWatch

```powershell
aws logs tail /ecs/<farf-prototype>-org-b --region us-east-1 --since 10m
```
**Expect:** the full stdout from `cross_cloud_timing_wrapper.py` —
`[PilotOrgB] federation-bus reachable...`, registration/admit
confirmations with AWS→GCP timing, then the 50-trial cross-cloud `/send`
latency block ending in a five-point comparison against every prior
latency figure in this project.

## Step 8 — AWS KMS latency probe (from your laptop, like the GCP one)

```powershell
pip install boto3
python aws_pilot\aws_kms_latency_probe.py --key-id alias/<farf-prototype>-org-b-key --region us-east-1 --n-trials 100
```
**Expect:** the same style of output as the GCP KMS probe — warm-up call,
100 timed calls, then a five-point comparison table with the real number
filled in.

## Step 9 — Deploy the pentest-enabled bus and run the cross-cloud pentest set

Everything above used the plain `bus_service.py`. This step redeploys
using `pentest_cloud/bus_service.py` instead (adds the three gated
`/pentest/*` routes) with `FARF_PENTEST_MODE=1` set, then runs pt01, pt02,
and pt08 against the real cross-cloud topology — genuinely new evidence,
since these were only validated locally (Flask test client) and via
single-cloud Cloud Run before now.

**Redeploy the GCP bus with the pentest routes enabled** (same service,
new revision — traffic switches automatically):
```powershell
docker build -f docker/Dockerfile.cloudrun -t us-central1-docker.pkg.dev/<farf-prototype>-2026b/<farf-prototype>/federation-bus:v2-pentest .
```
Before building, copy `pentest_cloud/bus_service.py` over
`docker/bus_service.py` in your local copy — same one-line-CMD pattern as
before, this file already has the three `/pentest/*` routes added.
```powershell
docker push us-central1-docker.pkg.dev/<farf-prototype>-2026b/<farf-prototype>/federation-bus:v2-pentest
gcloud run deploy <farf-prototype>-bus `
    --image=us-central1-docker.pkg.dev/<farf-prototype>-2026b/<farf-prototype>/federation-bus:v2-pentest `
    --region=us-central1 `
    --set-env-vars=FARF_PENTEST_MODE=1
```
**Expect:** the same deploy sequence as Step 0, ending in the same
`Service URL:` line — the URL doesn't change, only the running revision
does. `--min-instances`/`--max-instances`/`--port` carry forward from the
existing service automatically.

**Confirm the gate is actually open** before running anything:
```powershell
curl -X POST https://YOUR-GCP-SERVICE-URL/pentest/register_agent_structural -H "Content-Type: application/json" -d '{\"agent_id\":\"gate-check\",\"org\":\"PT01OrgA\"}' -UseBasicParsing
```
**Expect:** `200`, not `404`. If you get `404`, the `FARF_PENTEST_MODE=1`
env var didn't take — re-check the `--set-env-vars` flag on the deploy
command above.

**Run the three cross-cloud pentest scripts**, each against the real
GCP-hosted bus (these test the bus itself, not the AWS side — OrgB's
presence on AWS doesn't change what pt01/pt02/pt08 are checking, but
having it there means the bus is genuinely handling real cross-cloud
production traffic from Step 6 *at the same time* as being pentested,
which is closer to a realistic deployment than testing an idle service):
```powershell
python pentest_cloud\pt01_identity_spoofing_cloud.py --url https://YOUR-GCP-SERVICE-URL
python pentest_cloud\pt02_field_omission_bypass_cloud.py --url https://YOUR-GCP-SERVICE-URL
python pentest_cloud\pt08_session_hijack_cloud.py --url https://YOUR-GCP-SERVICE-URL
```
**Expect:** each ends in either `PASSED`/`NOT VULNERABLE` (exit code 0)
or `VULNERABLE` (exit code 1, and worth stopping to investigate
immediately if this happens) — see `pentest_cloud/README.md` for the
exact expected `decision`/`reason` values each step should produce,
already validated once via Flask test client before this walkthrough was
written.

## Step 10 — What else this established setup can measure

With the cross-cloud infra and the pentest routes both live at the same
time, a few more things become measurable cheaply, worth doing before
tearing down rather than redeploying later for each one individually:

- **Pentest-under-load timing.** Re-run pt01/pt02/pt08 *while* the AWS
  Fargate task (Step 6) is mid-flight sending its 50 `/send` calls, and
  compare pass/fail results and response times against running them on
  an idle bus. Confirms the security gates hold under concurrent real
  traffic, not just in isolation — a cheap way to combine two things this
  session already built rather than run them as separate, disconnected
  exercises.
- **Cross-cloud egress with realistic mixed traffic.** `egress_load_test.py`
  (from the earlier single-cloud pilot) only sent uniform `/send` calls;
  re-running it now, with the AWS task and pentest scripts also hitting
  the same bus, gives an egress figure closer to what mixed
  production-and-security-testing traffic would actually cost, rather
  than a single clean traffic pattern.
- **Pentest routes' own latency.** `/pentest/sign_only` performs a real
  signing operation server-side (bus-side Ed25519, not KMS) — timing it
  under both idle and loaded conditions is a free fourth data point
  alongside the in-process/Docker-bridge/Cloud-Run-WAN numbers already
  documented, this time specifically for the bus's own signing path
  rather than an external KMS call.
- **AWS-side pentest equivalent (not built this session, worth naming as
  a future option, not assumed complete)**: the three adapted pentest
  scripts test the GCP-hosted bus's own logic, which is deployment-
  location-independent by the same Reason-1 argument in
  `pentest_cloud/README.md` — running them "from AWS" instead of your
  laptop wouldn't change the verdict, only the network path latency
  component already captured by `cross_cloud_timing_wrapper.py`. Not
  worth building unless the specific question is "does pentest
  verdict-latency change based on attacker origin," which nothing in this
  project has asked yet.

## Step 12 — ADR-007 fix: turn on structured JSON logging

Live-checking `docker/bus_service.py` against `farf_logging.py` found
that `FARF_LOG_FORMAT` was never actually set on either cloud's deploy —
`farf_logging.py` defaults to `"text"`, so every log line produced by
every pilot so far (Step 0's GCP deploy, Step 5's Fargate task) was
human-readable text, not the structured, per-field-queryable JSON this
ADR's decision actually specifies. Delivery to each cloud's native sink
was already confirmed working — only the format was wrong.

**GCP side** — redeploy with the env var added (no image rebuild
needed, this is a config-only redeploy):
```powershell
gcloud run deploy <farf-prototype>-bus `
    --image=us-central1-docker.pkg.dev/<farf-prototype>-2026b/<farf-prototype>/federation-bus:v2-pentest `
    --region=us-central1 `
    --update-env-vars=FARF_LOG_FORMAT=json
```
**Expect:** same deploy sequence as before, new revision serving traffic.

**AWS side** — add the env var to `aws_pilot/task-def.json`'s
`environment` array (`{"name": "FARF_LOG_FORMAT", "value": "json"}`),
then re-register:
```powershell
aws ecs register-task-definition --cli-input-json file://aws_pilot/task-def.json --region us-east-1
```

**Confirm the fix** by triggering one real message, then reading the raw
log line:
```powershell
curl -X POST https://YOUR-GCP-SERVICE-URL/send -H "Content-Type: application/json" -d '{\"from_agent\":\"PilotOrgA-advisor\",\"from_org\":\"PilotOrgA\",\"to_agent\":\"PilotOrgA-advisor\",\"to_org\":\"PilotOrgA\",\"action_type\":\"plan_forward\",\"payload\":{\"requested_privilege\":0.1,\"attempts_system_override\":false}}' -UseBasicParsing
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=<farf-prototype>-bus" --limit 5 --format json --project <farf-prototype>-2026b
```
**Expect:** each `textPayload` field from before is now a `jsonPayload`
object with `timestamp`/`level`/`component`/`message` keys parsed as
structured fields, not one opaque string — this is the actual, queryable
difference ADR-007's decision was about. Compare against a log line from
before this step (still in Cloud Logging's history) to see the shape
change directly.

## Step 13 — ADR-004 fix: a genuine cross-cloud partition test

Every partition test run so far was either a single-host Docker network
disconnect (ADR-004's original Docker verification) or an unreachable-
hostname condition — neither is a real AWS↔GCP internet-path partition.
This step deploys a long-running Fargate task that loops real `/send`
calls, so revoking this task's security group's outbound rule mid-loop
(from your laptop, via the AWS CLI) produces a genuine, timestamped
partition window in CloudWatch.

Save as `aws_pilot/task-def-partition.json` (same pattern as Step 5's
task def, different family/image command):
```json
{
  "family": "<farf-prototype>-partition-test",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "256",
  "memory": "512",
  "executionRoleArn": "arn:aws:iam::123456789012:role/farfPilotTaskExecutionRole",
  "containerDefinitions": [{
    "name": "partition-test",
    "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/<farf-prototype>-org-b:v1",
    "command": ["python", "aws_pilot/adr004_partition_client.py"],
    "environment": [
      {"name": "FARF_BUS_URL", "value": "https://YOUR-GCP-SERVICE-URL"},
      {"name": "FARF_ORG", "value": "PilotOrgB-Partition"},
      {"name": "FARF_PEER_ORG", "value": "PilotOrgA"},
      {"name": "FARF_LOOP_INTERVAL_SECONDS", "value": "5"},
      {"name": "FARF_LOOP_ITERATIONS", "value": "24"}
    ],
    "logConfiguration": {
      "logDriver": "awslogs",
      "options": {
        "awslogs-group": "/ecs/<farf-prototype>-partition-test",
        "awslogs-region": "us-east-1",
        "awslogs-stream-prefix": "partition-test"
      }
    }
  }]
}
```
```powershell
aws logs create-log-group --log-group-name /ecs/<farf-prototype>-partition-test --region us-east-1
aws ecs register-task-definition --cli-input-json file://aws_pilot/task-def-partition.json --region us-east-1
```
The default 24 iterations × 5s interval gives a 2-minute window — long
enough to comfortably fit the revoke/wait/restore sequence below in the
middle without rushing.

**Run it:**
```powershell
aws ecs run-task `
    --cluster <farf-prototype>-cluster `
    --task-definition <farf-prototype>-partition-test `
    --launch-type FARGATE `
    --network-configuration "awsvpcConfiguration={subnets=[$subnet],securityGroups=[$sg],assignPublicIp=ENABLED}" `
    --region us-east-1
```
**Expect:** a `taskArn` — note it, you'll want `aws ecs describe-tasks`
to confirm `"STOPPED"` in about 2 minutes, same as Step 6.

**About 30-40 seconds in** (roughly iteration 6-8 of 24 — no need to be
precise, the loop's own timestamped logs will show exactly which
iterations were affected regardless of your timing), revoke the task's
outbound internet access:
```powershell
aws ec2 revoke-security-group-egress --group-id $sg --protocol tcp --port 443 --cidr 0.0.0.0/0 --region us-east-1
```
**Expect:** no output on success. This blocks HTTPS egress for every
task using this security group — since the partition-test task is the
only thing running against `$sg` right now, this is safe to do without
affecting anything else.

**Wait about 20-30 seconds** (4-6 more loop iterations), then restore:
```powershell
aws ec2 authorize-security-group-egress --group-id $sg --protocol tcp --port 443 --cidr 0.0.0.0/0 --region us-east-1
```
**Expect:** no output on success — this is exactly reversing the revoke
command above (the default security group created in Step 4 already had
this rule; you're just re-adding what was removed).

**Fetch the full log once the task shows `STOPPED`:**
```powershell
aws logs tail /ecs/<farf-prototype>-partition-test --region us-east-1 --since 10m
```
**Expect:** a clean sequence of JSON log lines — `success` outcomes
before your revoke command, then `timeout` or `connection_error`
outcomes (both are correct fail-closed behaviour — which one you see
depends on exactly when the TCP connection was in flight when the rule
changed) for the iterations during the blocked window, then `success`
again after your restore command, ending in a `loop_complete` line whose
`outcomes` object should show `other_error: 0`. If `other_error` is
anything but 0, that's a genuine bug worth investigating, not expected
partition behaviour — everything else is expected and is the actual
evidence this step exists to produce.

**Confirm no phantom messages landed during the blocked window:**
```powershell
curl https://YOUR-GCP-SERVICE-URL/status -UseBasicParsing
```
**Expect:** `total_messages` should equal exactly the number of
`success` outcomes in the log (not the full 24 — the blocked-window
attempts genuinely never reached the bus at all, which is the fail-
closed property this test is verifying).

## Step 14 — ADR-010 fix: confirm the boundary re-verification log line

This closes a code gap, not an infrastructure gap — `federation_bus.py`
and `orchestration.py` were patched to flag and log every TOCTOU-
relevant action type (`execute_action`, `memory_recall_use`) that
crosses an org/cloud boundary, validated locally (89/89 tests pass
unchanged, `pt02`/`pt10` byte-identical decisions) but not yet confirmed
against a real cross-cloud hop. Requires redeploying the GCP bus with
the patched files.

**Copy the two patched files into your local repo**, replacing the
versions currently there, then rebuild and redeploy exactly as in Step
9's `docker build`/`push`/`gcloud run deploy` sequence (bump the image
tag, e.g. `:v3-adr010`).

**Trigger a real cross-cloud `execute_action`** — from the AWS side, so
`from_org` genuinely differs from the bus's own `to_org` in a way that
crossed the actual AWS→GCP path (a curl from your laptop would set the
flag correctly too, but wouldn't exercise the AWS-hosted org at all):
```powershell
curl -X POST https://YOUR-GCP-SERVICE-URL/send -H "Content-Type: application/json" -d '{\"from_agent\":\"PilotOrgB-executor\",\"from_org\":\"PilotOrgB\",\"to_agent\":\"PilotOrgA-advisor\",\"to_org\":\"PilotOrgA\",\"action_type\":\"execute_action\",\"payload\":{\"resource_hash_at_check\":\"h1\",\"resource_hash_at_use\":\"h1\"}}' -UseBasicParsing
```
(If `PilotOrgB-executor` isn't currently admitted on this fresh
revision, run Step 5's `/admit_agent` call for it first — same pattern
as `PilotOrgA-advisor` earlier in this file.)

**Fetch the log:**
```powershell
gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=<farf-prototype>-bus AND jsonPayload.message=cross_boundary_toctou_reverification" --limit 5 --format json --project <farf-prototype>-2026b
```
**Expect:** one matching entry with `agent_id: PilotOrgB-executor`,
`action_type: execute_action`, and both hash fields populated — this is
the live confirmation that was pending after the code was written; if
`FARF_LOG_FORMAT=json` from Step 12 is also active on this revision, the
query above works directly on structured fields rather than needing a
text-log grep.

## Step 15 — ADR-011 fix: the Lambda agent-worker row, for real

The pilot's OrgB ran on Fargate throughout, which is ADR-011's
*relay/orchestration* row — this step exercises the row ADR-011 actually
names for "stateless agent workers": Lambda.

**Package the function** (Lambda's Python runtime doesn't include
`requests`, so it needs to be bundled into the deployment zip):
```powershell
mkdir lambda_build
pip install requests -t lambda_build --quiet
Copy-Item aws_pilot\lambda_agent_worker.py lambda_build\
Compress-Archive -Path lambda_build\* -DestinationPath lambda_function.zip -Force
```

**Create an execution role** (Lambda needs its own, distinct from the
Fargate task execution role from Step 5 — no VPC/network permissions
needed since this function doesn't run inside your VPC):
```powershell
aws iam create-role --role-name farfPilotLambdaRole --assume-role-policy-document '{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"lambda.amazonaws.com\"},\"Action\":\"sts:AssumeRole\"}]}'
aws iam attach-role-policy --role-name farfPilotLambdaRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
```
**Expect:** `AWSLambdaBasicExecutionRole` covers writing to CloudWatch
Logs — the only permission this function needs beyond outbound internet
access, which Lambda has by default outside a VPC.

**Create the function:**
```powershell
aws lambda create-function `
    --function-name <farf-prototype>-agent-worker `
    --runtime python3.12 `
    --role arn:aws:iam::123456789012:role/farfPilotLambdaRole `
    --handler lambda_agent_worker.handler `
    --zip-file fileb://lambda_function.zip `
    --timeout 30 `
    --environment "Variables={FARF_BUS_URL=https://YOUR-GCP-SERVICE-URL,FARF_ORG=PilotOrgB-Lambda,FARF_PEER_ORG=PilotOrgA}" `
    --region us-east-1
```
**Expect:** a JSON block with `"State": "Active"` (or `"Pending"` briefly
first — re-run `aws lambda get-function --function-name
<farf-prototype>-agent-worker --region us-east-1` if so).

**Invoke it twice** — once cold, once warm, to get both numbers:
```powershell
aws lambda invoke --function-name <farf-prototype>-agent-worker --region us-east-1 out1.json
Get-Content out1.json
aws lambda invoke --function-name <farf-prototype>-agent-worker --region us-east-1 out2.json
Get-Content out2.json
```
**Expect:** both calls return `"StatusCode": 200`, and each `out*.json`
contains the `timings_ms` breakdown (`register_org_ms`, `admit_agent_ms`,
`send_ms`, `total_wall_clock_ms`) plus `likely_cold_start` — the first
invocation should show `likely_cold_start: true` and a noticeably higher
`total_wall_clock_ms` than the second (Lambda's cold-start penalty,
which Fargate's always-running-once-started model doesn't have in the
same way). This is the number ADR-011's table was missing.

## Step 16 — Teardown, all deployments

**AWS side** — now three task-definition families and one Lambda
function to clean up, not just one:
```powershell
aws lambda delete-function --function-name <farf-prototype>-agent-worker --region us-east-1
aws iam detach-role-policy --role-name farfPilotLambdaRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole
aws iam delete-role --role-name farfPilotLambdaRole

aws ecs delete-cluster --cluster <farf-prototype>-cluster --region us-east-1
aws ecs deregister-task-definition --task-definition <farf-prototype>-org-b:1 --region us-east-1
aws ecs deregister-task-definition --task-definition <farf-prototype>-partition-test:1 --region us-east-1
aws ecr delete-repository --repository-name <farf-prototype>-org-b --force --region us-east-1
aws kms schedule-key-deletion --key-id alias/<farf-prototype>-org-b-key --pending-window-in-days 7 --region us-east-1
aws logs delete-log-group --log-group-name /ecs/<farf-prototype>-org-b --region us-east-1
aws logs delete-log-group --log-group-name /ecs/<farf-prototype>-partition-test --region us-east-1
aws logs delete-log-group --log-group-name /aws/lambda/<farf-prototype>-agent-worker --region us-east-1
aws ec2 delete-security-group --group-id $sg --region us-east-1
aws iam detach-role-policy --role-name farfPilotTaskExecutionRole --policy-arn arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy
aws iam delete-role --role-name farfPilotTaskExecutionRole
```
**Expect:** each command returns quietly on success. `schedule-key-deletion`
requires a minimum 7-day pending window (AWS's equivalent safety net to
GCP's mandatory pending-destroy — cannot be made instant). **Double-check
the security group's egress rule is back to normal before deleting it**
(`aws ec2 describe-security-groups --group-ids $sg --region us-east-1`)
— if Step 13's revoke command never got restored for some reason, delete
still works fine (deleting the whole group makes the individual rule
moot), but it's worth a 5-second glance so you're not left thinking a
rule is still blocking something after teardown.

**GCP side** — same as before, but note the project deleting the whole
service also removes `FARF_PENTEST_MODE`, so there's no separate step
needed to "turn the pentest routes back off" — deletion handles it:
```powershell
gcloud run services delete <farf-prototype>-bus --region=us-central1 --quiet
gcloud kms keys versions destroy 1 --key=<farf-prototype>-org-a-key --keyring=<farf-prototype>-keyring --location=us-central1
gcloud projects delete <farf-prototype>-2026b
```

## What to send back

**From the original cross-cloud + pentest pass (Steps 0-10):** the full
CloudWatch log output from Step 7 (registration timings + the
cross-cloud latency table), the AWS KMS probe output from Step 8, the
console output from all three pentest scripts in Step 9
(PASSED/VULNERABLE verdicts and the full decision/reason JSON for each
step), and anything from Step 10 you chose to run.

**From this five-ADR fix pass (Steps 12-15):**
- Step 12 — the before/after log line comparison (text vs. JSON shape)
  from both `gcloud logging read` and (if you also redeployed the
  Fargate task with the env var) `aws logs tail`.
- Step 13 — the full `aws logs tail` output for the partition test,
  especially the `loop_complete` line's `outcomes` object, and the
  `/status` message-count cross-check.
- Step 14 — the `gcloud logging read` result confirming the
  `cross_boundary_toctou_reverification` entry appeared with the
  expected fields.
- Step 15 — both `out1.json`/`out2.json` contents from the cold/warm
  Lambda invocations.

**Plus confirmation all deployments (Step 16) were torn down** — AWS
(cluster, both task-definition families, Lambda function, ECR repo, KMS
key, log groups, security group, IAM roles) and GCP (Cloud Run service,
KMS key version, project).

Once you paste these back, I'll fold the real numbers into
`ARCHITECTURE_DECISIONS_1.md` (the four "pending live cross-cloud run"
notes added this session for ADR-007/004/010/011, plus ADR-003/005/006
from the earlier pass), `PHASE1_TO_CLOUD_DECISION_BRIEF.md`, and
`pentest_cloud/README.md` (moving pt01/pt02/pt08 from "validated
locally" to "validated live, cross-cloud") — the same pattern as every
prior phase of this project: nothing gets marked verified without a real
run behind it.
