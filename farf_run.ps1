# farf_run.ps1  --  ONE command per step. Replaces build_and_deploy.ps1 (delete that file).
#
# Run from the repo root (farf_prototype_v7_9_7), in the VS Code PowerShell terminal, .venv active:
#     .\farf_run.ps1 -Step check
#     .\farf_run.ps1 -Step bus-env
#     ... one step at a time, in the order in NEXT_STEPS_GUIDE.md
#
# Every step: (1) prints what to EXPECT, (2) runs, (3) prints [PASS]/[FAIL] lines,
#             (4) saves all output under .\evidence_<date>\  (share those files when asked).
# If any line says [FAIL], STOP and paste the screen output; do not run the next step.
# Written for Windows PowerShell 5.1 (no PowerShell-7-only syntax).

param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('check', 'bus-env', 'aws-image', 'warm', 'quorum', 'adr010', 'adr010-aws', 'orgs8', 'latency-pair', 'load', 'recover', 'lambda-adr011', 'bus-fix', 'partition', 'evidence', 'cool', 'status')]
  [string]$Step,
  [string]$FixTag = "v5-recovery-fix",       # image tag for -Step bus-fix
  [string]$Since = "2026-09-20T17:30:00Z",   # start of the test session (UTC); used by -Step evidence
  [int]$FreshnessDays = 3,                   # how far back Cloud Logging is read by -Step evidence
  [double]$SleepScale = 1.0                  # test hook only; leave at 1
)

$ErrorActionPreference = 'Continue'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------------ settings
$Project   = "<farf-prototype>-26aug"
$Region    = "asia-south1"
$Service   = "<farf-prototype>-bus"
$BusTag    = "v4-adr010"                      # image already deployed; the bus code has not changed
$GcpRepo   = "asia-south1-docker.pkg.dev/$Project/<farf-prototype>-27aug"
$AwsAcct   = "<AWS_ACCOUNT_ID>"
$AwsRegion = "ap-south-1"
$EcrHost   = "$AwsAcct.dkr.ecr.$AwsRegion.amazonaws.com"
$EcrRepo   = "$EcrHost/<farf-prototype>-org-b"
$PartTag   = "v5-partition"
$Cluster   = "<farf-prototype>-cluster"
$LogGroup  = "/ecs/<farf-prototype>-partition-test"
$Subnet    = "subnet-05607578f1909b49f"
$PartSg    = "sg-0f5755cb8a65a398c"           # <farf-prototype>-sg-2, attached to nothing
$Evidence  = Join-Path $PWD ("evidence_" + (Get-Date -Format "yyyyMMdd"))
$script:Results = @()
$script:LastExit = 0

# ------------------------------------------------------------------ helpers
function Head([string]$t) { Write-Host ""; Write-Host "=== $t" -ForegroundColor Cyan }
function Expect([string[]]$lines) {
  Write-Host "EXPECT:" -ForegroundColor Yellow
  foreach ($l in $lines) { Write-Host "  - $l" -ForegroundColor Yellow }
  Write-Host ""
}
function Nap([double]$s) { Start-Sleep -Milliseconds ([int]($s * 1000 * $SleepScale)) }
function Check([string]$Name, [bool]$Ok, [string]$Detail = "") {
  if ($Ok) { $tag = "[PASS]"; $color = "Green" } else { $tag = "[FAIL]"; $color = "Red" }
  Write-Host ("{0} {1}  {2}" -f $tag, $Name, $Detail) -ForegroundColor $color
  $script:Results += [pscustomobject]@{ Name = $Name; Ok = $Ok }
}
function Warn([string]$Name, [string]$Detail = "") {
  Write-Host ("[WARN] {0}  {1}" -f $Name, $Detail) -ForegroundColor Yellow
}
function AnyFail { return (@($script:Results | Where-Object { -not $_.Ok }).Count -gt 0) }
function Finish {
  Write-Host ""
  if (AnyFail) {
    Write-Host "RESULT: at least one check FAILED. Stop here and paste this screen output to Claude." -ForegroundColor Red
  } else {
    Write-Host "RESULT: all checks passed for step '$Step'. Safe to run the next step." -ForegroundColor Green
  }
  Write-Host "Evidence saved in: $Evidence"
}
function Log-Path([string]$name) {
  if (-not (Test-Path $Evidence)) { New-Item -ItemType Directory -Path $Evidence | Out-Null }
  return (Join-Path $Evidence ("{0}_{1}_{2}.txt" -f (Get-Date -Format "HHmmss"), $Step, $name))
}
# Runs a script block, shows the output live, saves it to the evidence folder, returns it as text.
function Run-Logged([string]$RunName__, [scriptblock]$Block__) {
  # Internal names end in "__" on purpose: the script block runs in a child scope of this function
  # and must not see (and be confused by) ordinary names such as $file or $lines used by callers.
  $lf__ = Log-Path $RunName__
  $acc__ = New-Object System.Collections.ArrayList
  & $Block__ 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -ne "System.Management.Automation.RemoteException" } | ForEach-Object {
    Write-Host $_
    Add-Content -Path $lf__ -Value $_ -Encoding UTF8
    [void]$acc__.Add($_)
  }
  $script:LastExit = $LASTEXITCODE
  return ($acc__ -join "`n")
}
function Get-BusUrl {
  $u = (gcloud run services describe $Service --project $Project --region $Region --format "value(status.url)" 2>$null | Out-String).Trim()
  if (-not $u) { throw "Could not read the bus URL. Are you logged in to gcloud? (gcloud auth login)" }
  return $u
}
function Get-BusJson {
  $j = (gcloud run services describe $Service --project $Project --region $Region --format=json 2>$null | Out-String)
  return ($j | ConvertFrom-Json)
}
# Windows PowerShell 5.1 returns a JSON ARRAY from ConvertFrom-Json as ONE object (PowerShell 7 unrolls it),
# so @($json | ConvertFrom-Json).Count is 1 for a 2-element array. This helper always returns the elements.
function ConvertFrom-JsonArray([string]$Text) {
  if ((-not $Text) -or (-not $Text.Trim())) { return @() }
  $parsed = $Text | ConvertFrom-Json
  $acc = New-Object System.Collections.ArrayList
  foreach ($x in @($parsed)) {
    if ($x -is [System.Array]) { foreach ($y in $x) { [void]$acc.Add($y) } } else { [void]$acc.Add($x) }
  }
  return $acc.ToArray()
}
function Get-Ann($svc, [string]$key) {
  $ann = $svc.spec.template.metadata.annotations
  if (-not $ann) { return $null }
  $p = $ann.PSObject.Properties[$key]
  if ($p) { return [string]$p.Value } else { return $null }
}
function Post-Json([string]$Base, [string]$Path, $Obj) {
  return (Invoke-RestMethod -Method Post -Uri "$Base$Path" -ContentType "application/json" `
            -Body ($Obj | ConvertTo-Json -Depth 5 -Compress) -TimeoutSec 30)
}
function Show-Status {
  $svc = Get-BusJson
  $env_ = @($svc.spec.template.spec.containers[0].env | ForEach-Object { "{0}={1}" -f $_.name, $_.value })
  $min = Get-Ann $svc "autoscaling.knative.dev/minScale"
  if (-not $min) { $min = "0 (not set)" }
  Write-Host "Bus image:        $($svc.spec.template.spec.containers[0].image)"
  Write-Host "Bus env vars:     $($env_ -join ', ')"
  Write-Host "Bus min/max inst: $min / $(Get-Ann $svc 'autoscaling.knative.dev/maxScale')   (min 1 = costs about INR 1.3/hour)"
  $running = (aws ecs list-tasks --cluster $Cluster --desired-status RUNNING --region $AwsRegion --query "length(taskArns)" --output text 2>$null | Out-String).Trim()
  Write-Host "Running ECS tasks: $running"
  $n = (aws ec2 describe-security-groups --group-ids $PartSg --region $AwsRegion --query "length(SecurityGroups[0].IpPermissionsEgress)" --output text 2>$null | Out-String).Trim()
  Write-Host "Partition SG egress rules: $n   (must be 2 when no test is running)"
  return @{ Svc = $svc; Min = $min; Running = $running; SgRules = $n }
}

# ================================================================== STEPS
if ($Step -eq 'check') {
  Head "check: is this laptop and are both clouds ready? (read-only, free, ~1 min)"
  Expect @(
    "Every line [PASS] except possibly [WARN] lines, which are things to look at, not blockers.",
    "A [WARN] about project '<farf-prototype>-2026' means a second GCP project may be costing money."
  )
  $null = docker info --format "{{.ServerVersion}}" 2>$null
  Check "Docker Desktop is running" ($LASTEXITCODE -eq 0) "(if FAIL: start Docker Desktop and wait for the whale icon to stop animating)"
  Check ".dockerignore exists in this folder" (Test-Path ".dockerignore")
  foreach ($f in @("aws_pilot\adr004_partition_client_v5.py", "aws_pilot\analyze_partition_log.py",
                   "aws_pilot\adr010_boundary_probe_v2.py", "aws_pilot\task-def-partition-v5.json",
                   "gcp_pilot\cloud_run_final_checks_FIXED.py", "gcp_pilot\egress_load_test.py",
                   "pentest_cloud\pt01_identity_spoofing_cloud.py", "pentest_cloud\pt02_field_omission_bypass_cloud.py",
                   "pentest_cloud\pt08_session_hijack_cloud.py", "bus-env.yaml")) {
    Check "file present: $f" (Test-Path $f)
  }
  $hasSkip = $false
  if (Test-Path "gcp_pilot\cloud_run_final_checks_FIXED.py") {
    $hasSkip = [bool](Select-String -Path "gcp_pilot\cloud_run_final_checks_FIXED.py" -Pattern "--skip-quorum" -Quiet)
  }
  Check "cloud_run_final_checks_FIXED.py is the newest copy (has --skip-quorum)" $hasSkip "(if FAIL: re-copy it from the delivered files)"
  $pt8 = $false
  if (Test-Path "pentest_cloud\pt08_session_hijack_cloud.py") {
    $pt8 = [bool](Select-String -Path "pentest_cloud\pt08_session_hijack_cloud.py" -Pattern 'PT08Org' -Quiet)
  }
  Check "pt08 is the v2 fix (fixed org, run-scoped agents)" $pt8 "(if FAIL: copy pt08_session_hijack_cloud_FIXED_v2.py over pt08_session_hijack_cloud.py)"
  $null = python -c "import requests" 2>$null
  Check "python can import 'requests'" ($LASTEXITCODE -eq 0) "(if FAIL: pip install requests)"
  $arn = (aws sts get-caller-identity --query Arn --output text 2>$null | Out-String).Trim()
  Check "AWS login works as user <farf-prototype>" ($arn -match "user/<farf-prototype>") "$arn   (if FAIL: run: aws login)"
  $proj = (gcloud config get-value project 2>$null | Out-String).Trim()
  Check "gcloud project is $Project" ($proj -eq $Project) "$proj"
  if (Test-Path "$HOME\.aws\credentials") { Warn "static AWS keys file exists" "$HOME\.aws\credentials - delete old keys from it" }
  else { Check "no static AWS key file on disk" $true }
  $projects = @(gcloud projects list --format "value(projectId)" 2>$null)
  if ($projects -contains "<farf-prototype>-2026") {
    $svcs = @(gcloud run services list --project <farf-prototype>-2026 --format "value(metadata.name)" 2>$null)
    if ($svcs.Count -gt 0) { Warn "OLD GCP project <farf-prototype>-2026 has Cloud Run service(s): $($svcs -join ', ')" "check min-instances there; it may be costing money" }
    else { Check "old project <farf-prototype>-2026: no Cloud Run services" $true }
  } else { Check "old project <farf-prototype>-2026 not present in your account" $true }
  $nk = (aws kms list-keys --region $AwsRegion --query "length(Keys)" --output text 2>$null | Out-String).Trim()
  if ($nk -eq "1") { Check "exactly one AWS KMS key" $true } else { Warn "AWS KMS key count is '$nk' (expected 1)" "extra keys cost about USD 1/month each" }
  $rt = (aws ecs list-tasks --cluster $Cluster --desired-status RUNNING --region $AwsRegion --query "length(taskArns)" --output text 2>$null | Out-String).Trim()
  Check "no ECS tasks running" ($rt -eq "0") "running=$rt"
  $st = Show-Status
  Finish
}

if ($Step -eq 'bus-env') {
  Head "bus-env: redeploy the SAME bus image with the correct env vars, at zero idle cost (~2 min)"
  Expect @(
    "gcloud prints 'Deploying container...' and ends with 'Service URL: https://<farf-prototype>-bus-...run.app'.",
    "[PASS] lines: both FARF_PENTEST_MODE and FARF_LOG_FORMAT=json set, image $BusTag, max 1, min 0.",
    "No Docker build happens in this step; nothing is pushed."
  )
  $null = Run-Logged "deploy" {
    gcloud run deploy $Service --project $Project --region $Region --image "$GcpRepo/federation-bus:$BusTag" `
      --min-instances 0 --max-instances 1 --port 8080 --allow-unauthenticated --env-vars-file .\bus-env.yaml
  }
  Check "gcloud deploy exited cleanly" ($script:LastExit -eq 0)
  $svc = Get-BusJson
  $vars = @{}
  foreach ($e in @($svc.spec.template.spec.containers[0].env)) { $vars[$e.name] = $e.value }
  Check "FARF_PENTEST_MODE=1" ($vars["FARF_PENTEST_MODE"] -eq "1")
  Check "FARF_LOG_FORMAT=json" ($vars["FARF_LOG_FORMAT"] -eq "json")
  Check "image tag is $BusTag" ($svc.spec.template.spec.containers[0].image -like "*:$BusTag")
  Check "max instances = 1" ((Get-Ann $svc "autoscaling.knative.dev/maxScale") -eq "1")
  $min = Get-Ann $svc "autoscaling.knative.dev/minScale"
  Check "min instances = 0 (no idle cost)" ((-not $min) -or ($min -eq "0")) "minScale=$min"
  Finish
}

if ($Step -eq 'aws-image') {
  Head "aws-image: build the partition-test image, push to ECR, register the task definition (~5-10 min)"
  Expect @(
    "'Login Succeeded', a Docker build (first build downloads a lot; later builds are cached), then a push.",
    "The container listing shows adr004_partition_client_v5.py and then NO_AWS_KEY_FOUND.",
    "[PASS] lines for: image in ECR with tag $PartTag, task definition <farf-prototype>-partition-test-v5 ACTIVE."
  )
  $img = "${EcrRepo}:$PartTag"
  $null = docker info --format "{{.ServerVersion}}" 2>$null
  Check "Docker Desktop is running" ($LASTEXITCODE -eq 0)
  Check "v5 client is in aws_pilot\" (Test-Path "aws_pilot\adr004_partition_client_v5.py")
  if (AnyFail) { Finish; exit 1 }
  $t = Run-Logged "ecr-login" { aws ecr get-login-password --region $AwsRegion | docker login --username AWS --password-stdin $EcrHost }
  Check "ECR login" ($t -match "Login Succeeded")
  if (AnyFail) { Finish; exit 1 }
  $null = Run-Logged "build" { docker build -f .\docker\Dockerfile.awsecs -t $img . }
  Check "docker build" ($script:LastExit -eq 0)
  if (AnyFail) { Finish; exit 1 }
  $null = Run-Logged "push" { docker push $img }
  Check "docker push" ($script:LastExit -eq 0)
  $t = Run-Logged "image-contents" { docker run --rm --entrypoint sh $img -c "ls /app/aws_pilot; echo ---; grep -rIlE 'AKIA[0-9A-Z]{16}' /app || echo NO_AWS_KEY_FOUND" }
  Check "image contains the v5 client" ($t -match "adr004_partition_client_v5.py")
  Check "no AWS key pattern inside the image" ($t -match "NO_AWS_KEY_FOUND")
  $tags = (aws ecr describe-images --repository-name <farf-prototype>-org-b --image-ids "imageTag=$PartTag" --region $AwsRegion --query "imageDetails[0].imageTags" --output text 2>$null | Out-String).Trim()
  Check "ECR has tag $PartTag" ($tags -match $PartTag) $tags
  $arn = (aws ecs register-task-definition --cli-input-json file://aws_pilot/task-def-partition-v5.json --region $AwsRegion --query "taskDefinition.taskDefinitionArn" --output text 2>&1 | Out-String).Trim()
  Check "task definition registered" ($arn -match "task-definition/<farf-prototype>-partition-test-v5:") $arn
  Finish
}

if ($Step -eq 'warm') {
  Head "warm: switch the bus ON (min-instances=1) and prove it answers. COST METER STARTS: about INR 1.3/hour (~2 min)"
  Expect @(
    "'Done' from gcloud, then [PASS] for /health = ok and a smoke message returning decision=allow.",
    "It also creates a NEW revision, so bus memory (orgs, admissions) starts clean. That is intended.",
    "Run '-Step cool' when you finish testing, or the meter keeps running."
  )
  $null = Run-Logged "update" { gcloud run services update $Service --project $Project --region $Region --min-instances 1 }
  Check "gcloud update exited cleanly" ($script:LastExit -eq 0)
  $url = Get-BusUrl
  Write-Host "Bus URL: $url"
  $ok = $false
  for ($i = 0; $i -lt 18 -and -not $ok; $i++) {
    try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 10; if ($h.status -eq "ok") { $ok = $true } }
    catch { Nap 5 }
  }
  Check "bus /health returns ok" $ok
  if (-not $ok) { Finish; exit 1 }
  $null = Post-Json $url "/register_org" @{ org = "PilotOrgA" }
  $null = Post-Json $url "/register_org" @{ org = "PilotOrgB" }
  $null = Post-Json $url "/admit_agent" @{ agent_id = "PilotOrgA-executor"; org = "PilotOrgA"; role = "executor"; base_privilege = 0.1 }
  $null = Post-Json $url "/admit_agent" @{ agent_id = "PilotOrgB-advisor"; org = "PilotOrgB"; role = "advisor"; base_privilege = 0.1 }
  $r = Post-Json $url "/send" @{ from_agent = "PilotOrgA-executor"; from_org = "PilotOrgA"; to_agent = "PilotOrgB-advisor"; to_org = "PilotOrgB";
                                 action_type = "smoke_test"; payload = @{ probe = $true }; taint_delta = 0.0 }
  Check "smoke message: decision=allow" ($r.decision -eq "allow") "decision=$($r.decision) reason=$($r.reason)"
  $svc = Get-BusJson
  $vars = @{}
  foreach ($e in @($svc.spec.template.spec.containers[0].env)) { $vars[$e.name] = $e.value }
  Check "env vars present (PENTEST_MODE=1 and LOG_FORMAT=json)" (($vars["FARF_PENTEST_MODE"] -eq "1") -and ($vars["FARF_LOG_FORMAT"] -eq "json"))
  Check "min instances = 1" ((Get-Ann $svc "autoscaling.knative.dev/minScale") -eq "1")
  Set-Content -Path (Log-Path "bus_url") -Value $url -Encoding UTF8
  Write-Host "Letting the new revision settle for 20s before anything hits it with load..."
  Nap 20
  try {
    $warmup = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 20
    Check "post-settle health check" ($warmup.status -eq "ok")
  } catch {
    Check "post-settle health check" $false "(the revision may still be cold -- wait another 20s and run -Step status to confirm before -Step quorum)"
  }
  Warn "COST METER IS RUNNING" "run: .\farf_run.ps1 -Step cool   when you are done"
  Finish
}

if ($Step -eq 'quorum') {
  Head "quorum: quorum check + UNLOADED latency (run FIRST, before any pentest script) (~1-2 min)"
  Expect @(
    "PART 1: 'Registered PilotOrgC ... quorum_required: 3.0 for 3 orgs' then 'Witness 3/3 ... committed: True' then 'PART 1 PASSED'.",
    "PART 2: '=== Real WAN /send latency, Cloud Run (N=200, errors=0) ===' with mean/sd/p50/p95 in milliseconds.",
    "Real WAN mean should be tens of ms (a laptop to Mumbai), not 2 ms. Write the org count (3) and quorum (3.0) in your notes.",
    "If PART 2 says 'FAIL (setup error)', the agents were not admitted: run '-Step warm' again."
  )
  $url = Get-BusUrl
  $null = Run-Logged "readmit" { python gcp_pilot\egress_load_test.py --url $url --n-messages 1 }
  $t = Run-Logged "final-checks" {
    python gcp_pilot\cloud_run_final_checks_FIXED.py --url $url --n-latency-trials 200 `
      --from-agent PilotOrgA-executor --from-org PilotOrgA --to-agent PilotOrgB-advisor --to-org PilotOrgB
  }
  Check "PART 1 quorum passed" ($t -match "PART 1 PASSED")
  Check "PART 2 latency: N=200, errors=0" ($t -match "N=200, errors=0")
  $m = [regex]::Match($t, "quorum_required: ([0-9.]+) for (\d+) orgs")
  if ($m.Success) { Write-Host "NOTE for Chapter 6: quorum_required=$($m.Groups[1].Value) at $($m.Groups[2].Value) orgs" }
  $m2 = [regex]::Match($t, "mean = ([0-9.]+) ms\s+sd = ([0-9.]+) ms\s+p50 = ([0-9.]+) ms\s+p95 = ([0-9.]+) ms")
  if ($m2.Success) { Write-Host "NOTE unloaded WAN latency: mean=$($m2.Groups[1].Value) ms p50=$($m2.Groups[3].Value) ms p95=$($m2.Groups[4].Value) ms" }
  Finish
}

if ($Step -eq 'adr010') {
  Head "adr010: cross-cloud TOCTOU probe + confirm the events appear in Cloud Run's own log (~2 min)"
  Expect @(
    "'Case 1 ... PASS' (allow / no_violation) and 'Case 2 ... PASS' (block / toctou_resource_mismatch).",
    "'CROSS-CLOUD TOCTOU RE-VERIFICATION: CONFIRMED ...'.",
    "Then [PASS] when Cloud Logging shows 2 events (hash pairs h1/h1 and h1_original/h2_tampered).",
    "Log lines can take up to ~2 minutes to appear; the script retries 6 times. 0 events means LOG_FORMAT=json is missing."
  )
  $url = Get-BusUrl
  $env:FARF_BUS_URL = $url
  $env:FARF_ORG = "PT010Org2"
  $t = Run-Logged "probe" { python aws_pilot\adr010_boundary_probe_v2.py }
  Check "Case 1 (no tamper) PASS" ($t -match "Case 1 .*PASS")
  Check "Case 2 (tamper) PASS" ($t -match "Case 2 .*PASS")
  $items = @(); $json = ""
  for ($i = 0; $i -lt 6; $i++) {
    $json = (gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$Service AND jsonPayload.event=cross_boundary_toctou_reverification" `
              --project $Project --limit 10 --freshness=20m --format json 2>$null | Out-String)
    $items = @(ConvertFrom-JsonArray $json)
    if ($items.Count -ge 2) { break }
    Write-Host "  waiting for log ingestion (attempt $($i + 1)/6)..."
    Nap 20
  }
  Set-Content -Path (Log-Path "gcp_log_events") -Value $json -Encoding UTF8
  Check "Cloud Logging shows >= 2 cross_boundary_toctou_reverification events" ($items.Count -ge 2) "found $($items.Count)"
  Check "both hash pairs present (h1/h1 and h1_original/h2_tampered)" (($json -match "h2_tampered") -and ($json -match "h1_original"))
  Write-Host "NOTE for the chapter: both hashes come from the client payload. This proves the rule fires across the cloud boundary, not that the bus recomputes the hash itself."
  Finish
}

if ($Step -eq 'load') {
  Head "load: pentests + loaded latency running AT THE SAME TIME as a 1000-message load (~3-6 min)"
  Expect @(
    "Five background jobs start together; their output appears after they finish.",
    "load: 'Done in ...s, 0 errors'.   pt01: 'PT-01 (cloud) PASSED'.   pt02: 'NOT VULNERABLE'.   pt08: 'NOT VULNERABLE'.",
    "latency: 'N=200, errors=0' (this is the UNDER LOAD figure; keep it separate from the unloaded one).",
    "Then PT-08 runs a second time alone: 'NOT VULNERABLE' and '[org-count check] ... before=X after=X' (equal numbers).",
    "'INCONCLUSIVE' from pt08 = stale state, not a finding. A plain 'VULNERABLE' needs one re-run before you believe it."
  )
  $url = Get-BusUrl
  $wd = $PWD.Path
  $null = Run-Logged "readmit" { python gcp_pilot\egress_load_test.py --url $url --n-messages 1 }
  $jobs = @{}
  $jobs["egress"] = Start-Job -Name egress -ScriptBlock { Set-Location $using:wd; python gcp_pilot\egress_load_test.py --url $using:url --n-messages 1000 2>&1 | Out-String }
  Nap 2
  $jobs["pt01"] = Start-Job -Name pt01 -ScriptBlock { Set-Location $using:wd; python pentest_cloud\pt01_identity_spoofing_cloud.py --url $using:url 2>&1 | Out-String }
  $jobs["pt02"] = Start-Job -Name pt02 -ScriptBlock { Set-Location $using:wd; python pentest_cloud\pt02_field_omission_bypass_cloud.py --url $using:url 2>&1 | Out-String }
  $jobs["pt08"] = Start-Job -Name pt08 -ScriptBlock { Set-Location $using:wd; python pentest_cloud\pt08_session_hijack_cloud.py --url $using:url 2>&1 | Out-String }
  $jobs["latency"] = Start-Job -Name latency -ScriptBlock {
    Set-Location $using:wd
    python gcp_pilot\cloud_run_final_checks_FIXED.py --url $using:url --n-latency-trials 200 --skip-quorum `
      --from-agent PilotOrgA-executor --from-org PilotOrgA --to-agent PilotOrgB-advisor --to-org PilotOrgB 2>&1 | Out-String
  }
  Write-Host "Waiting for jobs (up to 10 minutes)..."
  $null = Wait-Job -Job @($jobs.Values) -Timeout 600
  $out = @{}
  foreach ($k in $jobs.Keys) {
    $out[$k] = (Receive-Job -Job $jobs[$k] -ErrorAction SilentlyContinue | Out-String)
    Set-Content -Path (Log-Path $k) -Value $out[$k] -Encoding UTF8
    Write-Host ""; Write-Host "----- $k -----"; Write-Host $out[$k]
  }
  Remove-Job -Job @($jobs.Values) -Force -ErrorAction SilentlyContinue
  Check "load generator finished with 0 errors" ($out["egress"] -match "Done in .*, 0 errors")
  Check "PT-01 passed" ($out["pt01"] -match "PT-01 \(cloud\) PASSED")
  Check "PT-02 not vulnerable" ($out["pt02"] -match "NOT VULNERABLE")
  Check "PT-08 (under load) not vulnerable" ($out["pt08"] -match "NOT VULNERABLE")
  Check "loaded latency N=200, errors=0" ($out["latency"] -match "N=200, errors=0")
  $m2 = [regex]::Match($out["latency"], "mean = ([0-9.]+) ms\s+sd = ([0-9.]+) ms\s+p50 = ([0-9.]+) ms\s+p95 = ([0-9.]+) ms")
  if ($m2.Success) { Write-Host "NOTE loaded WAN latency: mean=$($m2.Groups[1].Value) ms p50=$($m2.Groups[3].Value) ms p95=$($m2.Groups[4].Value) ms" }
  Write-Host ""; Write-Host "--- PT-08 second run, alone (idempotency check)"
  $t = Run-Logged "pt08_second_run" { python pentest_cloud\pt08_session_hijack_cloud.py --url $url }
  Check "PT-08 second run not vulnerable" ($t -match "NOT VULNERABLE")
  $mm = [regex]::Match($t, "before=(\d+) after=(\d+)")
  Check "org count did not grow on the re-run" ($mm.Success -and ($mm.Groups[1].Value -eq $mm.Groups[2].Value)) $mm.Value
  Finish
}


if ($Step -eq 'recover') {
  Head "recover: quorum-witnessed reinstatement of the quarantined PT08Org on the LIVE bus, then PT-08 v3 twice on a fresh organisation (~2 min)"
  Expect @(
    "Use this after the load step left PT08Org quarantined (org_wide_behavioural_drift). Needs the bus still warm and its state unchanged.",
    "The probe prints 'reinstatement committed at witness 7 of 10 (quorum 7)' (the number follows the org count), then 'quarantined agents ... after the commit: 0'.",
    "It then re-admits a fresh agent pair and sends 3 messages. On the deployed code (v4-adr010) the FIRST message is expected to be quarantined again",
    "(org_wide_behavioural_drift): that is a documented FINDING, shown as a [WARN], not a failure of the step.",
    "Finally PT-08 v3 runs twice on a fresh organisation (PT08OrgV3): both 'NOT VULNERABLE'. Adds ONE organisation to the bus."
  )
  $url = Get-BusUrl
  $healthy = $false
  try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 15; $healthy = ($h.status -eq "ok") } catch { }
  Check "bus is up (/health ok)" $healthy "(if FAIL: the bus was cooled; its quarantine state is gone: nothing left to recover)"
  Check "recovery probe present" (Test-Path "aws_pilot\recovery_probe.py")
  Check "PT-08 v3 present" (Test-Path "pentest_cloud\pt08_session_hijack_cloud_FIXED_v3.py")
  if (AnyFail) { Finish; exit 1 }
  $t = Run-Logged "recovery_probe" { python aws_pilot\recovery_probe.py --url $url --org PT08Org }
  $rc = $script:LastExit
  if ($rc -eq 5) { Warn "PT08Org has no quarantined agents" "nothing to reinstate (state already clean)" }
  else {
    Check "reinstatement committed at exactly the quorum-th witness and the quarantine was lifted" ($rc -eq 0)
    if ($t -match "durability:\s+DURABLE") { Check "recovery is durable (the org can send again)" $true }
    else { Warn "recovery is NOT durable on this code" "the org-level detector window is not reset on reinstatement: finding F1 in AUDIT_AND_NEXT_STEPS.md; a 6-line fix and a regression test are provided" }
  }
  $a1 = Run-Logged "pt08_v3_first" { python pentest_cloud\pt08_session_hijack_cloud_FIXED_v3.py --url $url --org PT08OrgV3 }
  Check "PT-08 v3 first run (fresh org) NOT VULNERABLE" ($a1 -match "NOT VULNERABLE")
  $a2 = Run-Logged "pt08_v3_second" { python pentest_cloud\pt08_session_hijack_cloud_FIXED_v3.py --url $url --org PT08OrgV3 }
  Check "PT-08 v3 second run NOT VULNERABLE" ($a2 -match "NOT VULNERABLE")
  $m = [regex]::Match($a2, "before=(\d+) after=(\d+)")
  Check "org count stable on the second run" ($m.Success -and ($m.Groups[1].Value -eq $m.Groups[2].Value)) $m.Value
  try { $f = Invoke-RestMethod -Uri "$url/fars" -TimeoutSec 15; Write-Host "NOTE FARS now: $($f.FARS)  (trust_health $($f.components.trust_health))" } catch { }
  Finish
}

# --- add 'lambda-adr011' to the ValidateSet on line 15, alongside the other step names ---

if ($Step -eq 'lambda-adr011') {
  Head "lambda-adr011: ADR-011 Lambda agent-worker, cold + warm invoke against the LIVE bus (~2-3 min)"
  Expect @(
    "If the function does not exist yet, it is created first (role + function), which takes ~15-20s to become Active.",
    "Two invokes: the FIRST should show likely_cold_start=true and a higher total_wall_clock_ms; the SECOND should show likely_cold_start=false.",
    "Both out*.json must show a timings_ms block with register_org_ms/admit_agent_ms/send_ms/total_wall_clock_ms -- if that block is missing, the handler ran but never reached the bus calls: check FARF_BUS_URL."
  )
  $url = Get-BusUrl
  $healthy = $false
  try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 15; $healthy = ($h.status -eq "ok") } catch { }
  Check "bus is up (/health ok)" $healthy "(if FAIL: run -Step warm first)"
  if (AnyFail) { Finish; exit 1 }

  $exists = $false
  try { $null = aws lambda get-function --function-name <farf-prototype>-agent-worker --region $AwsRegion 2>$null; $exists = ($LASTEXITCODE -eq 0) } catch { }

  if (-not $exists) {
    Write-Host "Function not found -- creating it (role, package, function)..."
    if (Test-Path lambda_build) { Remove-Item lambda_build -Recurse -Force }
    $null = Run-Logged "pip_package" { pip install requests -t lambda_build --quiet }
    Copy-Item aws_pilot\lambda_agent_worker.py lambda_build\
    Compress-Archive -Path lambda_build\* -DestinationPath lambda_function.zip -Force

    $roleArn = (aws iam get-role --role-name farfPilotLambdaRole --query "Role.Arn" --output text 2>$null | Out-String).Trim()
    if (-not $roleArn -or $roleArn -notlike "arn:aws:iam::*") {
      $trust = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
      $null = Run-Logged "create_role" { aws iam create-role --role-name farfPilotLambdaRole --assume-role-policy-document $trust }
      $null = Run-Logged "attach_policy" { aws iam attach-role-policy --role-name farfPilotLambdaRole --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole }
      Nap 10   # IAM propagation delay before the role can be assumed
      $roleArn = (aws iam get-role --role-name farfPilotLambdaExecutionRole --query "Role.Arn" --output text 2>$null | Out-String).Trim()
    }
    Check "Lambda execution role exists" ($roleArn -like "arn:aws:iam::*")

    $null = Run-Logged "create_function" {
      aws lambda create-function --function-name <farf-prototype>-agent-worker --runtime python3.12 `
        --role $roleArn --handler lambda_agent_worker.handler --zip-file fileb://lambda_function.zip `
        --timeout 30 --region $AwsRegion `
        --environment ("Variables={{FARF_BUS_URL={0},FARF_ORG=PilotOrgB-Lambda,FARF_PEER_ORG=PilotOrgA}}" -f $url)
    }
    Nap 15
    $exists = ($LASTEXITCODE -eq 0)
  } else {
    Write-Host "Function already exists -- updating its FARF_BUS_URL in case the bus URL changed, then invoking."
    $null = Run-Logged "update_config" {
      aws lambda update-function-configuration --function-name <farf-prototype>-agent-worker --region $AwsRegion `
        --environment ("Variables={{FARF_BUS_URL={0},FARF_ORG=PilotOrgB-Lambda,FARF_PEER_ORG=PilotOrgA}}" -f $url)
    }
    Nap 8
  }
  Check "function exists / created" $exists
  if (-not $exists) { Finish; exit 1 }

  $out1 = Log-Path "lambda_invoke1"
  $null = Run-Logged "invoke1" { aws lambda invoke --function-name <farf-prototype>-agent-worker --region $AwsRegion $out1 }
  $r1 = Get-Content $out1 -Raw
  Write-Host "--- invoke 1 (expected cold) ---"; Write-Host $r1
  Check "invoke 1 succeeded and returned timings_ms" ($r1 -match "timings_ms")

  Nap 3
  $out2 = Log-Path "lambda_invoke2"
  $null = Run-Logged "invoke2" { aws lambda invoke --function-name <farf-prototype>-agent-worker --region $AwsRegion $out2 }
  $r2 = Get-Content $out2 -Raw
  Write-Host "--- invoke 2 (expected warm) ---"; Write-Host $r2
  Check "invoke 2 succeeded and returned timings_ms" ($r2 -match "timings_ms")
  Check "invoke 1 shows a cold start, invoke 2 does not" (($r1 -match '"likely_cold_start":\s*true') -and ($r2 -match '"likely_cold_start":\s*false')) "(if this fails, both may have hit an already-warm container -- wait 10+ min and re-run -Step lambda-adr011 for a clean cold sample)"

  Write-Host "Keep out1.json/out2.json (saved under evidence) -- this closes ADR-011's missing cold-start figure."
  Finish
}

if ($Step -eq 'bus-fix') {
  Head "bus-fix: build+deploy the PATCHED bus image, reproduce the quarantine, confirm the fix LIVE on Cloud Run (~10-12 min)"
  Expect @(
    "Pre-flight: federation_bus.py in this folder must be the patched version, and Docker Desktop must be running.",
    "Docker build + push (a few minutes), then a Cloud Run deploy to a NEW revision, image tag $FixTag. min-instances=1: COST METER STARTS.",
    "PT08Org is deliberately driven back into quarantine (repeated PT-08 runs) to recreate the exact bug scenario on the NEW image.",
    "recovery_probe.py then reinstates it. Expect 'durability: DURABLE' this time -- proves the fix works on live Cloud Run, not just locally.",
    "AFTER THIS: do not run -Step bus-env (it redeploys the OLD image, v4-adr010, and would silently revert the fix). Finish with -Step cool."
  )
  $patched = [bool](Select-String -Path "federation_bus.py" -Pattern "Clear the detector state that CAUSED the quarantine" -Quiet -ErrorAction SilentlyContinue)
  Check "federation_bus.py in this folder is the PATCHED version" $patched "(if FAIL: Copy-Item federation_bus_PATCHED.py federation_bus.py -Force , then re-run this step)"
  $null = docker info --format "{{.ServerVersion}}" 2>$null
  Check "Docker Desktop is running" ($LASTEXITCODE -eq 0)
  Check "pentest_cloud\bus_service.py present" (Test-Path "pentest_cloud\bus_service.py")
  Check "pt08 script present (used to reproduce the quarantine)" (Test-Path "pentest_cloud\pt08_session_hijack_cloud.py")
  Check "recovery probe present" (Test-Path "aws_pilot\recovery_probe.py")
  if (AnyFail) { Write-Host "Nothing was built or deployed."; Finish; exit 1 }

  Copy-Item "pentest_cloud\bus_service.py" "docker\bus_service.py" -Force
  $img = "$GcpRepo/federation-bus:$FixTag"
  $null = Run-Logged "build" { docker build -f .\docker\Dockerfile.cloudrun -t $img . }
  Check "docker build" ($script:LastExit -eq 0)
  if (AnyFail) { Finish; exit 1 }
  $null = Run-Logged "push" { docker push $img }
  Check "docker push" ($script:LastExit -eq 0)
  if (AnyFail) { Finish; exit 1 }

  $null = Run-Logged "deploy" {
    gcloud run deploy $Service --project $Project --region $Region --image $img `
      --min-instances 1 --max-instances 1 --port 8080 --allow-unauthenticated --env-vars-file .\bus-env.yaml
  }
  Check "gcloud deploy exited cleanly" ($script:LastExit -eq 0)
  $url = Get-BusUrl
  $healthy = $false
  for ($i = 0; $i -lt 18 -and -not $healthy; $i++) {
    try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 10; if ($h.status -eq "ok") { $healthy = $true } }
    catch { Nap 5 }
  }
  Check "bus /health returns ok on the new image" $healthy
  $svc = Get-BusJson
  Check "deployed image tag is $FixTag" ($svc.spec.template.spec.containers[0].image -like "*:$FixTag")
  if (AnyFail) { Finish; exit 1 }

  Write-Host "Reproducing the quarantine on the PATCHED deployment (deliberate; this is the bug scenario, not a new failure)..."
  $quarantined = $false
  for ($i = 1; $i -le 8 -and -not $quarantined; $i++) {
    $null = Run-Logged "pt08_repro_$i" { python pentest_cloud\pt08_session_hijack_cloud.py --url $url }
    try {
      $st = Invoke-RestMethod -Uri "$url/status" -TimeoutSec 15
      $quarantined = @($st.quarantined_agents | Where-Object { $_ -like "PT08Org-*" }).Count -gt 0
    } catch { }
    Write-Host "  after repro run $i : PT08Org quarantined = $quarantined"
  }
  Check "PT08Org became quarantined (bug scenario reproduced on the patched image)" $quarantined "(if FAIL after 8 runs: check the detector cap has not changed)"
  if (-not $quarantined) { Finish; exit 1 }

  $t = Run-Logged "recovery_probe_live" { python aws_pilot\recovery_probe.py --url $url --org PT08Org }
  Check "reinstatement committed and the quarantine was lifted" ($script:LastExit -eq 0)
  Check "recovery is DURABLE on the live, patched Cloud Run deployment" ($t -match "durability:\s+DURABLE") "(if FAIL: the deployed image may not actually contain the patch -- check the build log)"
  Warn "COST METER IS RUNNING (new revision, min-instances=1)" "run: .\farf_run.ps1 -Step cool   when done"
  Finish
}

if ($Step -eq 'partition') {
  Head "partition: the AWS->GCP network partition test, ADR-017 (~8-10 min). Briefly cuts the SG's outbound traffic."
  Expect @(
    "Pre-flight [PASS] lines first (rules saved, dry-runs allowed, SG unused, task def active, bus healthy). Any FAIL: nothing is touched.",
    "A Fargate task starts (1-3 min), its PREFLIGHT line shows 'outcome: success', you wait ~45 s, the SG rules are revoked for 120 s, then restored.",
    "The last lines come from the analyzer. Success = 'VERDICT: PARTITION OBSERVED AND RECOVERED'.",
    "'NO EFFECT' or 'PARTIAL / LAG' are real results, not script errors: paste them and we interpret together.",
    "At the end the SG must show 2 egress rules again. If it says otherwise, run the restore command it prints."
  )
  $url = Get-BusUrl
  $arn = (aws sts get-caller-identity --query Arn --output text 2>$null | Out-String).Trim()
  Check "AWS login works right now" ($arn -match "user/<farf-prototype>") "(if FAIL: aws login)"
  $rulesJson = (aws ec2 describe-security-groups --group-ids $PartSg --region $AwsRegion --query "SecurityGroups[0].IpPermissionsEgress" --output json 2>$null | Out-String)
  $rules = @(ConvertFrom-JsonArray $rulesJson)
  Check "partition SG currently has BOTH egress rules (all-traffic + tcp/443)" ($rules.Count -eq 2) "found $($rules.Count)"
  if ($rules.Count -eq 2) { Set-Content -Path "egress_saved.json" -Value $rulesJson -Encoding ASCII }
  $eni = (aws ec2 describe-network-interfaces --filters "Name=group-id,Values=$PartSg" --region $AwsRegion --query "length(NetworkInterfaces)" --output text 2>$null | Out-String).Trim()
  Check "partition SG is attached to nothing" ($eni -eq "0") "attached to $eni interfaces"
  if (Test-Path "egress_saved.json") {
    $dr1 = (aws ec2 revoke-security-group-egress --group-id $PartSg --ip-permissions file://egress_saved.json --dry-run --region $AwsRegion 2>&1 | Out-String)
    Check "IAM allows REVOKE (dry run)" ($dr1 -match "DryRunOperation") $dr1.Trim()
    $dr2 = (aws ec2 authorize-security-group-egress --group-id $PartSg --ip-permissions file://egress_saved.json --dry-run --region $AwsRegion 2>&1 | Out-String)
    Check "IAM allows RESTORE (dry run)" ($dr2 -match "DryRunOperation") $dr2.Trim()
  }
  $lg = (aws logs filter-log-events --log-group-name $LogGroup --limit 1 --region $AwsRegion --query "length(events)" --output text 2>&1 | Out-String).Trim()
  Check "can read CloudWatch logs" ($lg -match "^\d+$") $lg
  $td = (aws ecs describe-task-definition --task-definition <farf-prototype>-partition-test-v5 --region $AwsRegion --query "taskDefinition.status" --output text 2>&1 | Out-String).Trim()
  Check "task definition <farf-prototype>-partition-test-v5 is ACTIVE" ($td -eq "ACTIVE") $td
  $healthy = $false
  try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 15; $healthy = ($h.status -eq "ok") } catch { }
  Check "bus is up (/health ok)" $healthy "(if FAIL: run -Step warm)"
  if (AnyFail) { Write-Host "Nothing was changed."; Finish; exit 1 }

  $start = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $tStartUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $taskArn = (aws ecs run-task --cluster $Cluster --task-definition <farf-prototype>-partition-test-v5 --launch-type FARGATE `
      --network-configuration "awsvpcConfiguration={subnets=[$Subnet],securityGroups=[$PartSg],assignPublicIp=ENABLED}" `
      --region $AwsRegion --query "tasks[0].taskArn" --output text 2>&1 | Out-String).Trim()
  Check "Fargate task started" ($taskArn -like "arn:aws:ecs:*") $taskArn
  if (AnyFail) { Finish; exit 1 }

  $revoked = $false; $tRevoke = $null; $tRestore = $null
  try {
    Write-Host "Waiting for the task's PREFLIGHT line (1-3 minutes: Fargate must start and pull the image)..."
    $pre = ""
    for ($i = 0; $i -lt 60 -and -not $pre; $i++) {
      Nap 5
      $pre = (aws logs filter-log-events --log-group-name $LogGroup --start-time $start --filter-pattern "?PREFLIGHT ?PREFLIGHT_FAILED" `
                --region $AwsRegion --query "events[].message" --output text 2>$null | Out-String).Trim()
    }
    $baselineOk = [bool]($pre -and ($pre -notmatch "PREFLIGHT_FAILED") -and ($pre -match '"outcome": "success"'))
    Check "task baseline is clean (HTTP 200 + allow) BEFORE touching the SG" $baselineOk $pre
    if (-not $baselineOk) { throw "Baseline is not clean. The SG was NOT changed." }
    Write-Host "Baseline clean. Waiting 45 s so the log has a good run of clean attempts before the revoke..."
    Nap 45
    $tRevoke = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
    $null = aws ec2 revoke-security-group-egress --group-id $PartSg --ip-permissions file://egress_saved.json --region $AwsRegion 2>&1
    $revoked = ($LASTEXITCODE -eq 0)
    Check "revoke command succeeded" $revoked
    $during = (aws ec2 describe-security-groups --group-ids $PartSg --region $AwsRegion --query "SecurityGroups[0].IpPermissionsEgress" --output json 2>$null | Out-String)
    Set-Content -Path "sg_during_revoke.json" -Value $during -Encoding ASCII
    $dn = @(ConvertFrom-JsonArray $during)
    Check "SG egress is EMPTY during the window (sg_during_revoke.json)" ($dn.Count -eq 0) "rules=$($dn.Count)"
    Write-Host "PARTITION WINDOW: holding for 120 s (started $tRevoke)..."
    Nap 120
  }
  catch { Write-Host "ABORT: $_" -ForegroundColor Red }
  finally {
    if ($revoked) {
      $tRestore = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
      $null = aws ec2 authorize-security-group-egress --group-id $PartSg --ip-permissions file://egress_saved.json --region $AwsRegion 2>&1
      Write-Host "RESTORED at $tRestore" -ForegroundColor Green
    }
  }
  $after = (aws ec2 describe-security-groups --group-ids $PartSg --region $AwsRegion --query "length(SecurityGroups[0].IpPermissionsEgress)" --output text 2>$null | Out-String).Trim()
  Check "SG rules are back to 2" ($after -eq "2") "rules now=$after   (if not 2 run: aws ec2 authorize-security-group-egress --group-id $PartSg --ip-permissions file://egress_saved.json --region $AwsRegion)"

  Write-Host "Waiting for the task to finish (up to ~7 minutes)..."
  $status = ""
  for ($i = 0; $i -lt 50 -and $status -ne "STOPPED"; $i++) {
    Nap 10
    $status = (aws ecs describe-tasks --cluster $Cluster --tasks $taskArn --region $AwsRegion --query "tasks[0].lastStatus" --output text 2>$null | Out-String).Trim()
  }
  if ($status -ne "STOPPED") { $null = aws ecs stop-task --cluster $Cluster --task $taskArn --region $AwsRegion 2>&1; Warn "task did not finish in time; stopped it" }
  Nap 20
  $file = Log-Path "cloudwatch_export"
  $evj = (aws logs filter-log-events --log-group-name $LogGroup --start-time $start --region $AwsRegion --output json 2>$null | Out-String)
  $ev = $null; if ($evj.Trim()) { $ev = $evj | ConvertFrom-Json }
  $msgs = @(); if ($ev -and $ev.events) { $msgs = @($ev.events | ForEach-Object { $_.message }) }
  Set-Content -Path $file -Value $msgs -Encoding UTF8
  Check "exported task log lines" ($msgs.Count -gt 10) "$($msgs.Count) lines -> $file"
  if ($tRevoke -and $tRestore -and $msgs.Count -gt 0) {
    Write-Host ""; Write-Host "--- analysis"
    $null = Run-Logged "analysis" { python aws_pilot\analyze_partition_log.py --log $file --revoke-utc $tRevoke --restore-utc $tRestore }
    Check "analyzer verdict: PARTITION OBSERVED AND RECOVERED" ($script:LastExit -eq 0) "analyzer exit code $($script:LastExit) (0=success, 10=bad baseline, 11=no effect, 12=partial, 13=no recovery)"
    if ($script:LastExit -eq 11) {
      Write-Host "NO EFFECT: before concluding, compare the source IP in Cloud Run request logs with the task's public IP:"
      Write-Host "  gcloud logging read 'resource.type=cloud_run_revision AND httpRequest.requestUrl:""/send""' --project $Project --limit 5 --freshness=30m --format=""value(timestamp,httpRequest.remoteIp)"""
    }
  }
  if ($tRevoke -and $tRestore) {
    $wline = "partition_run,{0},{1},{2},{3}" -f $tStartUtc, (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $tRevoke, $tRestore
    Set-Content -Path (Log-Path "window_times") -Value @("# name,start,end,revoke,restore (UTC)", $wline) -Encoding UTF8
  }
  Write-Host "Keep: egress_saved.json, sg_during_revoke.json and the evidence folder."
  Finish
}


if ($Step -eq 'adr010-aws') {
  Head "adr010-aws: run the adversarial ADR-010 probe FROM AN AWS FARGATE TASK against the GCP bus (~5 min)"
  Expect @(
    "Pre-flight [PASS] lines (bus up, image in ECR, task definition registered), then a Fargate task starts (1-3 min) and finishes in seconds.",
    "The task's own log shows 'Case 1 ... PASS', 'Case 2 ... PASS' and 'CROSS-CLOUD TOCTOU RE-VERIFICATION: CONFIRMED'.",
    "Then [PASS] when Cloud Logging shows 2 events for organisation PT010OrgAWS (hash pairs h1/h1 and h1_original/h2_tampered).",
    "Needs the bus warm (-Step warm). This adds ONE organisation (PT010OrgAWS) to the bus."
  )
  $url = Get-BusUrl
  $healthy = $false
  try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 15; $healthy = ($h.status -eq "ok") } catch { }
  Check "bus is up (/health ok)" $healthy "(if FAIL: run -Step warm)"
  $tags = (aws ecr describe-images --repository-name <farf-prototype>-org-b --image-ids "imageTag=$PartTag" --region $AwsRegion --query "imageDetails[0].imageTags" --output text 2>$null | Out-String).Trim()
  Check "ECR image $PartTag exists" ($tags -match $PartTag)
  Check "task definition file present" (Test-Path "aws_pilot\task-def-adr010-aws.json")
  if (AnyFail) { Write-Host "Nothing was started."; Finish; exit 1 }
  $arn = (aws ecs register-task-definition --cli-input-json file://aws_pilot/task-def-adr010-aws.json --region $AwsRegion --query "taskDefinition.taskDefinitionArn" --output text 2>&1 | Out-String).Trim()
  Check "task definition registered" ($arn -match "task-definition/<farf-prototype>-adr010-aws:") $arn
  if (AnyFail) { Finish; exit 1 }
  $start = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
  $tStartUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  $taskArn = (aws ecs run-task --cluster $Cluster --task-definition <farf-prototype>-adr010-aws --launch-type FARGATE `
      --network-configuration "awsvpcConfiguration={subnets=[$Subnet],securityGroups=[$PartSg],assignPublicIp=ENABLED}" `
      --region $AwsRegion --query "tasks[0].taskArn" --output text 2>&1 | Out-String).Trim()
  Check "Fargate task started" ($taskArn -like "arn:aws:ecs:*") $taskArn
  if (AnyFail) { Finish; exit 1 }
  Write-Host "Waiting for the task to finish (1-4 minutes)..."
  $status = ""
  for ($i = 0; $i -lt 40 -and $status -ne "STOPPED"; $i++) {
    Nap 10
    $status = (aws ecs describe-tasks --cluster $Cluster --tasks $taskArn --region $AwsRegion --query "tasks[0].lastStatus" --output text 2>$null | Out-String).Trim()
  }
  Check "task finished" ($status -eq "STOPPED") $status
  $exit = (aws ecs describe-tasks --cluster $Cluster --tasks $taskArn --region $AwsRegion --query "tasks[0].containers[0].exitCode" --output text 2>$null | Out-String).Trim()
  Check "container exit code 0 (probe passed)" ($exit -eq "0") "exit code $exit"
  $text = ""
  for ($i = 0; $i -lt 5; $i++) {
    Nap 10
    $j = (aws logs filter-log-events --log-group-name "/ecs/<farf-prototype>-org-b" --log-stream-name-prefix "adr010-aws" --start-time $start --region $AwsRegion --output json 2>$null | Out-String)
    if ($j.Trim()) {
      $o = $j | ConvertFrom-Json
      $text = (@($o.events | ForEach-Object { $_.message }) -join "`n")
    }
    if ($text -match "CONFIRMED|INCOMPLETE") { break }
  }
  Set-Content -Path (Log-Path "task_log") -Value $text -Encoding UTF8
  Write-Host $text
  Check "task log: Case 1 PASS" ($text -match "Case 1 .*PASS")
  Check "task log: Case 2 PASS" ($text -match "Case 2 .*PASS")
  Check "task log: CONFIRMED" ($text -match "CONFIRMED")
  $items = @(); $gj = ""
  for ($i = 0; $i -lt 6; $i++) {
    $gj = (gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$Service AND jsonPayload.event=cross_boundary_toctou_reverification AND jsonPayload.org=PT010OrgAWS" `
             --project $Project --limit 10 --freshness=30m --format json 2>$null | Out-String)
    $items = @(ConvertFrom-JsonArray $gj)
    if ($items.Count -ge 2) { break }
    Write-Host "  waiting for log ingestion (attempt $($i + 1)/6)..."
    Nap 20
  }
  Set-Content -Path (Log-Path "gcp_log_events") -Value $gj -Encoding UTF8
  Check "Cloud Logging shows >= 2 events for PT010OrgAWS" ($items.Count -ge 2) "found $($items.Count)"
  Check "both hash pairs present" (($gj -match "h2_tampered") -and ($gj -match "h1_original"))
  $tEnd = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")
  Set-Content -Path (Log-Path "window_times") -Value @("# name,start,end (UTC)", "adr010_aws,$tStartUtc,$tEnd") -Encoding UTF8
  Write-Host "NOTE for the chapter: the client ran inside an AWS Fargate task (ap-south-1) and the hashes are still client-supplied."
  Finish
}

if ($Step -eq 'orgs8') {
  Head "orgs8: quorum threshold at N = 4, 7 and 8 organisations, and PT-08 at exactly 8 organisations (~3 min)"
  Expect @(
    "Best run right after '-Step warm' (a fresh bus): then you see the whole curve, org count by org count.",
    "'stage N=4: quorum 3 ... committed at witness 3 of 4', 'N=7: quorum 5 ... witness 5 of 7', 'N=8: quorum 5 ... witness 5 of 8'.",
    "PT-08 twice: NOT VULNERABLE both times, with '[org-count check] before=7 after=8' the first time and 'before=8 after=8' the second.",
    "Finally 'QUORUM SWEEP: PASSED'. This registers extra organisations (PilotOrgD..H, PT08Org): a fresh revision (-Step warm) removes them.",
    "Scope: the bus signs /witness votes with its own keys, so this shows threshold arithmetic and enforcement, not independent key custody."
  )
  $url = Get-BusUrl
  $st = Invoke-RestMethod -Uri "$url/status" -TimeoutSec 20
  $n0 = @($st.registered_orgs).Count
  Write-Host "Organisations registered right now: $n0"
  if ($n0 -gt 3) { Warn "the bus is not fresh ($n0 orgs)" "the early part of the curve will be skipped; run -Step warm first for the complete curve" }
  Check "bus has fewer than 8 orgs to start" ($n0 -lt 8) "$n0 orgs"
  if (AnyFail) { Finish; exit 1 }
  $t1 = Run-Logged "sweep_to7" { python aws_pilot\quorum_sweep.py --url $url --stages 4,7 }
  Check "sweep at N=4 and N=7 passed" ($script:LastExit -eq 0)
  $t2 = Run-Logged "pt08_first" { python pentest_cloud\pt08_session_hijack_cloud.py --url $url }
  Check "PT-08 first run NOT VULNERABLE" ($t2 -match "NOT VULNERABLE")
  $m2 = [regex]::Match($t2, "before=(\d+) after=(\d+)")
  Write-Host "PT-08 first run org count: $($m2.Value)"
  $t3 = Run-Logged "pt08_second" { python pentest_cloud\pt08_session_hijack_cloud.py --url $url }
  Check "PT-08 second run NOT VULNERABLE" ($t3 -match "NOT VULNERABLE")
  $m3 = [regex]::Match($t3, "before=(\d+) after=(\d+)")
  Check "org count stable on the second PT-08 run" ($m3.Success -and ($m3.Groups[1].Value -eq $m3.Groups[2].Value)) $m3.Value
  $t4 = Run-Logged "sweep_at8" { python aws_pilot\quorum_sweep.py --url $url --stages 8 }
  Check "sweep at N=8 passed (quorum 5, commit at witness 5 of 8)" (($script:LastExit -eq 0) -and ($t4 -match "N=8 .*quorum=5"))
  $st2 = Invoke-RestMethod -Uri "$url/status" -TimeoutSec 20
  Write-Host "NOTE final state: $(@($st2.registered_orgs).Count) organisations, quorum_required=$($st2.quorum_required)"
  Finish
}

if ($Step -eq 'latency-pair') {
  Head "latency-pair: /send with a FRESH vs a KEPT-ALIVE connection, then Cloud KMS signing, from THIS laptop, back to back (~4 min)"
  Expect @(
    "'=== Paired /send latency (N=200 pairs, errors=0) ===' with two lines (fresh / kept-alive) and the mean connection-setup cost.",
    "Kept-alive should be clearly lower than fresh (the difference is the TCP+TLS handshake). Kept-alive is the fair counterpart of the KMS number.",
    "Then '=== Cloud KMS AsymmetricSign latency (Ed25519, N=100) ===' if google-cloud-kms and your gcloud login are set up; otherwise a [WARN] with the two setup commands.",
    "Purpose: to settle whether /send or KMS is the larger per-message cost (Chapter 6 Section 6.5.1, ADR-003). Needs the bus warm."
  )
  $url = Get-BusUrl
  $t = Run-Logged "send_paired" {
    python gcp_pilot\send_latency_paired.py --url $url --n 200 --from-agent PilotOrgA-executor --from-org PilotOrgA --to-agent PilotOrgB-advisor --to-org PilotOrgB
  }
  Check "paired /send probe ran with errors=0" ($t -match "errors=0")
  $mf = [regex]::Match($t, "fresh connection per request : n=\d+ mean=([0-9.]+) ms .* p50=([0-9.]+)")
  $mk = [regex]::Match($t, "kept-alive connection\s+: n=\d+ mean=([0-9.]+) ms .* p50=([0-9.]+)")
  if ($mf.Success -and $mk.Success) { Write-Host "NOTE /send from this laptop: fresh mean=$($mf.Groups[1].Value) ms p50=$($mf.Groups[2].Value) | kept-alive mean=$($mk.Groups[1].Value) ms p50=$($mk.Groups[2].Value)" }
  $null = python -c "import google.cloud.kms" 2>$null
  if ($LASTEXITCODE -eq 0) {
    $k = Run-Logged "kms" {
      python gcp_pilot\kms_latency_probe.py --project $Project --location $Region --keyring <farf-prototype>-27aug-keyring --key <farf-prototype>-org-a-key --n-trials 100
    }
    $km = [regex]::Match($k, "mean = ([0-9.]+) ms")
    Check "KMS probe produced a mean" $km.Success "(if FAIL: run: gcloud auth application-default login)"
    if ($km.Success -and $mk.Success) {
      Write-Host "NOTE compare like with like: kept-alive /send mean=$($mk.Groups[1].Value) ms vs Cloud KMS AsymmetricSign mean=$($km.Groups[1].Value) ms (same laptop, same session)."
    }
  } else {
    Warn "google-cloud-kms is not installed in this environment" "run: pip install google-cloud-kms   and   gcloud auth application-default login   then repeat this step"
  }
  Finish
}

if ($Step -eq 'evidence') {
  Head "evidence: export CloudWatch, Cloud Run and CloudTrail logs, and checksum everything (read-only, ~3 min, free)"
  Expect @(
    "A folder evidence_<date>\export_<time>\ with CloudWatch exports (3 log groups), Cloud Run logs, CloudTrail lookups, service snapshots, and MANIFEST_sha256.txt.",
    "The Cloud Run request log is summarised per source address: for each partition run, the Fargate address must show a silence covering revoke..restore.",
    "The CloudWatch check says whether the missing line of partition run 2 (iteration 12) is absent from CloudWatch itself.",
    "CloudTrail may be denied to the <farf-prototype> user: that is a [WARN] with console instructions, not a failure.",
    "Run this BEFORE teardown: Cloud Logging keeps about 30 days and deleting the project deletes the logs."
  )
  $dir = Join-Path $Evidence ("export_" + (Get-Date -Format "HHmmss"))
  New-Item -ItemType Directory -Path $dir -Force | Out-Null
  $sinceMs = [int64]([DateTimeOffset]::Parse($Since).ToUnixTimeMilliseconds())
  foreach ($g in @("/ecs/<farf-prototype>-partition-test", "/ecs/<farf-prototype>-org-b", "/aws/lambda/<farf-prototype>-agent-worker")) {
    $f = Join-Path $dir (("cloudwatch" + ($g -replace '[^A-Za-z0-9]+', '_')) + ".json")
    $gStart = $sinceMs
    if ($g -like "/aws/lambda/*") { $gStart = 0 }   # the Lambda test was in late August: export its whole (small) history
    (aws logs filter-log-events --log-group-name $g --start-time $gStart --region $AwsRegion --output json 2>&1 | Out-String) | Set-Content -Path $f -Encoding UTF8
    # --query is applied PER PAGE by the AWS CLI, so the count comes back as several numbers (for example "111" and "0"): add them up
    $nraw = (aws logs filter-log-events --log-group-name $g --start-time $gStart --region $AwsRegion --query "length(events)" --output text 2>$null | Out-String)
    $nums = @($nraw -split "\s+" | Where-Object { $_ -match "^\d+$" })
    $cnt = 0; foreach ($x in $nums) { $cnt += [int]$x }
    Check "CloudWatch export $g" ((Test-Path $f) -and ($nums.Count -gt 0)) "events=$cnt"
  }
  $cwf = Join-Path $dir "cloudwatch_ecs_farf_pilot_partition_test.json"
  if (Test-Path $cwf) { $null = Run-Logged "cloudwatch_completeness" { python aws_pilot\check_cloudwatch_export.py $cwf } }
  $gf = Join-Path $dir "gcp_cloudrun_all.json"
  (gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$Service" --project $Project --freshness="${FreshnessDays}d" --limit 20000 --format json 2>$null | Out-String) | Set-Content -Path $gf -Encoding UTF8
  $sz = 0; if (Test-Path $gf) { $sz = (Get-Item $gf).Length }
  Check "Cloud Run log export (all logs)" ($sz -gt 1000) "$sz bytes"
  # requests only (httpRequest.status>=100 selects Cloud Run's request log): small, so the 20000-entry cap cannot cut off the older runs
  $rf = Join-Path $dir "gcp_cloudrun_requests.json"
  (gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$Service AND httpRequest.status>=100" --project $Project --freshness="${FreshnessDays}d" --limit 20000 --format json 2>$null | Out-String) | Set-Content -Path $rf -Encoding UTF8
  $rsz = 0; if (Test-Path $rf) { $rsz = (Get-Item $rf).Length }
  Check "Cloud Run request-log export" ($rsz -gt 1000) "$rsz bytes"
  if ($rsz -gt 1000) { $gf = $rf; $sz = $rsz }
  $wf = ""
  if (Test-Path ".\partition_run_times.txt") { $wf = ".\partition_run_times.txt" }
  if ($sz -gt 1000) {
    if ($wf) { $null = Run-Logged "bus_request_summary" { python aws_pilot\summarize_bus_requests.py --log $gf --windows $wf --out (Join-Path $dir "source_address_summary_UNMASKED.txt") } }
    else { Warn "partition_run_times.txt not found" "copy it into the repo root to get the per-run silence analysis" }
  }
  foreach ($ev in @("RevokeSecurityGroupEgress", "AuthorizeSecurityGroupEgress", "RunTask")) {
    $ct = (aws cloudtrail lookup-events --lookup-attributes "AttributeKey=EventName,AttributeValue=$ev" --start-time $Since --region $AwsRegion --output json 2>&1 | Out-String)
    Set-Content -Path (Join-Path $dir "cloudtrail_$ev.json") -Value $ct -Encoding UTF8
    if ($ct -match "AccessDenied|not authorized") { Warn "CloudTrail $ev denied for this user" "console: CloudTrail > Event history > Event name = $ev > export; needs an administrator" }
    else { Check "CloudTrail $ev exported" ($ct.Trim().Length -gt 2) }
  }
  (gcloud run revisions list --service $Service --project $Project --region $Region --format=yaml 2>$null | Out-String) | Set-Content -Path (Join-Path $dir "cloudrun_revisions.yaml") -Encoding UTF8
  (gcloud run services describe $Service --project $Project --region $Region --format=yaml 2>$null | Out-String) | Set-Content -Path (Join-Path $dir "cloudrun_service.yaml") -Encoding UTF8
  (aws ecr describe-images --repository-name <farf-prototype>-org-b --region $AwsRegion --output json 2>$null | Out-String) | Set-Content -Path (Join-Path $dir "ecr_images.json") -Encoding UTF8
  (aws ecs list-task-definitions --family-prefix farf --region $AwsRegion --output json 2>$null | Out-String) | Set-Content -Path (Join-Path $dir "ecs_task_definitions.json") -Encoding UTF8
  (aws ec2 describe-security-groups --group-ids $PartSg --region $AwsRegion --output json 2>$null | Out-String) | Set-Content -Path (Join-Path $dir "security_group_now.json") -Encoding UTF8
  $mf = Join-Path $dir "MANIFEST_sha256.txt"
  $rows = Get-ChildItem -Path $dir -File | Where-Object { $_.Name -ne "MANIFEST_sha256.txt" } | ForEach-Object {
    "{0}  {1}  {2} bytes" -f (Get-FileHash $_.FullName -Algorithm SHA256).Hash, $_.Name, $_.Length
  }
  Set-Content -Path $mf -Value (@("# SHA-256 manifest, created " + (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ") + " UTC") + $rows) -Encoding UTF8
  Write-Host ""; Write-Host "Manifest:"; $rows | ForEach-Object { Write-Host "  $_" }
  Write-Host "Files contain your AWS account, project and source IP addresses: keep the folder private."
  Finish
}

if ($Step -eq 'cool') {
  Head "cool: switch the bus OFF (min-instances=0) so the cost meter stops (~1 min)"
  Expect @("gcloud update output, then [PASS] min instances = 0, no ECS tasks running, SG rules = 2.")
  $null = Run-Logged "update" { gcloud run services update $Service --project $Project --region $Region --min-instances 0 }
  Check "gcloud update exited cleanly" ($script:LastExit -eq 0)
  $s = Show-Status
  $minv = $s.Min
  Check "min instances is 0" (($minv -eq "0") -or ($minv -like "0 *"))
  Check "no ECS tasks running" ($s.Running -eq "0")
  Check "partition SG has its 2 rules" ($s.SgRules -eq "2")
  Finish
}

if ($Step -eq 'status') {
  Head "status: what is running right now (read-only)"
  $s = Show-Status
  Finish
}
