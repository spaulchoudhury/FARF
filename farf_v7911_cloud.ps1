# farf_v7911_cloud.ps1 -- CROSS-CLOUD (GCP Cloud Run bus + AWS Lambda origin) test protocol for FARF v7.9.11.
# Standalone: it does NOT modify farf_run.ps1 (which cannot be dot-sourced: it has a mandatory -Step and runs on load).
# Same project / region / account settings as farf_run.ps1. Run from the merged tree root, venv active or via .venv python.
#
# DO FIRST (free):  .\farf_v7911_local.ps1 -Step tests     then     .\farf_v7911_local.ps1 -Step localbus
#                   a scenario that fails locally WILL fail here.
#
# RUN ONE COMMAND PER LINE. Do NOT chain steps with ';' -- in PowerShell every statement must start with a command, so
# "...cloud.ps1 -Step deploy ; -Step run" fails with "'-Step' is not recognized". Each deploy makes a NEW revision (bus state
# starts clean); min-instances=1 => COST METER RUNNING until -Step cool.
#
#   .\farf_v7911_cloud.ps1 -Step prep
#   .\farf_v7911_cloud.ps1 -Step build                                  (~5-10 min, one image for ALL profiles)
#
#   .\farf_v7911_cloud.ps1 -Step deploy     -ProfileName default
#   .\farf_v7911_cloud.ps1 -Step run        -ProfileName default
#   .\farf_v7911_cloud.ps1 -Step regress
#   .\farf_v7911_cloud.ps1 -Step aws-origin -ProfileName default
#
#   .\farf_v7911_cloud.ps1 -Step deploy     -ProfileName gated
#   .\farf_v7911_cloud.ps1 -Step run        -ProfileName gated
#   .\farf_v7911_cloud.ps1 -Step aws-origin -ProfileName gated
#
#   (same three lines for -ProfileName loop-scoped; then loop-global = documented NEGATIVE baseline; then content)
#
#   .\farf_v7911_cloud.ps1 -Step evidence
#   .\farf_v7911_cloud.ps1 -Step cool
# Profiles:  default | content | gated | loop-scoped | loop-global | full (= gated + loop-scoped)
# NOTE: every python child runs with PYTHONUTF8=1 (Windows console encoding).
# WARNING 1: do NOT run farf_run.ps1 -Step bus-env afterwards: it redeploys the OLD image tag (v4-adr010) and silently reverts this.
# WARNING 2: farf_run.ps1 -Step recover (recovery_probe.py) witnesses expecting an immediate commit; on the 'gated'/'full' revision the
#            first votes are REFUSED by design (cooling_off_active), so it would report FAIL. Use -Step run -ProfileName gated instead.
# Written for Windows PowerShell 5.1.

param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('prep', 'build', 'deploy', 'run', 'regress', 'aws-origin', 'evidence', 'cool', 'status')]
  [string]$Step,
  [ValidateSet('default', 'content', 'gated', 'loop-scoped', 'loop-global', 'full')]
  [string]$ProfileName = "default",
  [string]$Tag = "v7-9-11b",                 # NEW image tag, deliberately distinct from v4-adr010 / v5 / v6 so rollback = redeploy the old tag
  [double]$CoolingOff = 20,                 # seconds; baked into the gated/full profiles; the scenario must be told the same number
  [int]$AdaptiveN = 200                     # messages in the adaptive-attacker scenario (WAN ~0.3 s each => ~1 min per 200)
)

$ErrorActionPreference = 'Continue'
$env:PYTHONUTF8 = "1"
$env:PYTHONIOENCODING = "utf-8"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# ------------------------------------------------------------------ settings (copied from farf_run.ps1)
$Project   = "<GCP_PROJECT_ID>"
$Region    = "asia-south1"
$Service   = "<farf-prototype>-bus"
$GcpRepo   = "asia-south1-docker.pkg.dev/$Project/<GCP_REPO_ID>"
$AwsRegion = "ap-south-1"
$Cluster   = "<farf-prototype>-cluster"
$LambdaFn  = "<farf-prototype>-v11-runner"
$BaseLambda = "<farf-prototype>-agent-worker"    # existing function; its execution role is reused
$Evidence  = Join-Path $PWD ("evidence_v7911_cloud_" + (Get-Date -Format "yyyyMMdd"))
$Py        = if (Test-Path ".\.venv\Scripts\python.exe") { ".\.venv\Scripts\python.exe" } else { "python" }
$script:Results = @()
$script:LastExit = 0
# Any terminating script error (e.g. a mistyped function name) is recorded as a FAILED check instead of vanishing into a green summary.
trap {
  Write-Host ("[FAIL] SCRIPT ERROR: " + $_.Exception.Message) -ForegroundColor Red
  $script:Results += [pscustomobject]@{ Name = ("SCRIPT ERROR: " + $_.Exception.Message); Ok = $false }
  continue
}

# ------------------------------------------------------------------ profile table (MUST mirror farf_v7911_local.ps1 -Step localbus)
$ProfileNames = @{
  "default"     = @{ };
  "content"     = @{ FARF_TAINT_SOURCE = "content" };
  "gated"       = @{ FARF_REINSTATE_MODE = "behaviour_gated"; FARF_COOLING_OFF_S = [string]$CoolingOff; FARF_PROBATION_MSGS = "5" };
  "loop-scoped" = @{ FARF_FARS_FEEDBACK = "1"; FARF_FB_BETA = "20"; FARF_FB_MAXMULT = "3"; FARF_FB_DECAY_S = "600"; FARF_FB_SCOPE = "scoped"; FARF_FB_REQUIRE_COLD = "1" };
  "loop-global" = @{ FARF_FARS_FEEDBACK = "1"; FARF_FB_BETA = "20"; FARF_FB_MAXMULT = "3"; FARF_FB_DECAY_S = "600"; FARF_FB_SCOPE = "global" };
  "full"        = @{ FARF_REINSTATE_MODE = "behaviour_gated"; FARF_COOLING_OFF_S = [string]$CoolingOff; FARF_PROBATION_MSGS = "5";
                     FARF_FARS_FEEDBACK = "1"; FARF_FB_BETA = "20"; FARF_FB_MAXMULT = "3"; FARF_FB_DECAY_S = "600"; FARF_FB_SCOPE = "scoped"; FARF_FB_REQUIRE_COLD = "1" }
}
# what each profile exercises, and what /config must report for the run to be meaningful
$Scenarios = @{
  "default"     = @("gated_reinstatement", "fars_loop", "adaptive_attacker", "collusion");
  "content"     = @("content_taint", "adaptive_attacker");
  "gated"       = @("gated_reinstatement", "personas", "collusion");
  "loop-scoped" = @("fars_loop");
  "loop-global" = @("fars_loop");
  "full"        = @("gated_reinstatement", "fars_loop", "personas", "collusion")
}
$Expected = @{
  "default"     = @{ taint_source = "declared"; reinstatement_mode = "identity";        fars_feedback_enabled = $false };
  "content"     = @{ taint_source = "content";  reinstatement_mode = "identity";        fars_feedback_enabled = $false };
  "gated"       = @{ taint_source = "declared"; reinstatement_mode = "behaviour_gated"; fars_feedback_enabled = $false };
  "loop-scoped" = @{ taint_source = "declared"; reinstatement_mode = "identity";        fars_feedback_enabled = $true;  fb_scope = "scoped" };
  "loop-global" = @{ taint_source = "declared"; reinstatement_mode = "identity";        fars_feedback_enabled = $true;  fb_scope = "global" };
  "full"        = @{ taint_source = "declared"; reinstatement_mode = "behaviour_gated"; fars_feedback_enabled = $true;  fb_scope = "scoped" }
}

# ------------------------------------------------------------------ helpers (same conventions as farf_run.ps1)
function Head([string]$t) { Write-Host ""; Write-Host "=== $t" -ForegroundColor Cyan }
function Expect([string[]]$lines) { Write-Host "EXPECT:" -ForegroundColor Yellow; foreach ($l in $lines) { Write-Host "  - $l" -ForegroundColor Yellow }; Write-Host "" }
function Nap([double]$s) { Start-Sleep -Milliseconds ([int]($s * 1000)) }
function Check([string]$Name, [bool]$Ok, [string]$Detail = "") {
  if ($Ok) { $tag = "[PASS]"; $c = "Green" } else { $tag = "[FAIL]"; $c = "Red" }
  Write-Host ("{0} {1}  {2}" -f $tag, $Name, $Detail) -ForegroundColor $c
  $script:Results += [pscustomobject]@{ Name = $Name; Ok = $Ok }
}
function Warn([string]$Name, [string]$Detail = "") { Write-Host ("[WARN] {0}  {1}" -f $Name, $Detail) -ForegroundColor Yellow }
function AnyFail { return (@($script:Results | Where-Object { -not $_.Ok }).Count -gt 0) }
function Finish {
  Write-Host ""
  if (AnyFail) { Write-Host "RESULT: at least one check FAILED. Stop and paste this screen output." -ForegroundColor Red }
  else { Write-Host "RESULT: all checks passed for step '$Step'." -ForegroundColor Green }
  Write-Host "Evidence saved in: $Evidence"
}
function Log-Path([string]$name) {
  if (-not (Test-Path $Evidence)) { New-Item -ItemType Directory -Path $Evidence -Force | Out-Null }
  return (Join-Path $Evidence ("{0}_{1}_{2}.txt" -f (Get-Date -Format "HHmmss"), $Step, $name))
}
function Run-Logged([string]$RunName__, [scriptblock]$Block__) {
  $lf__ = Log-Path $RunName__
  $acc__ = New-Object System.Collections.ArrayList
  & $Block__ 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -ne "System.Management.Automation.RemoteException" } | ForEach-Object {
    Write-Host $_; Add-Content -Path $lf__ -Value $_ -Encoding UTF8; [void]$acc__.Add($_) }
  $script:LastExit = $LASTEXITCODE
  return ($acc__ -join "`n")
}
function Get-BusUrl {
  $u = (gcloud run services describe $Service --project $Project --region $Region --format "value(status.url)" 2>$null | Out-String).Trim()
  if (-not $u) { throw "Could not read the bus URL. Are you logged in to gcloud? (gcloud auth login)" }
  return $u
}
function Get-BusJson { return ((gcloud run services describe $Service --project $Project --region $Region --format=json 2>$null | Out-String) | ConvertFrom-Json) }
function Get-Ann($svc, [string]$key) {
  $ann = $svc.spec.template.metadata.annotations
  if (-not $ann) { return $null }
  $p = $ann.PSObject.Properties[$key]
  if ($p) { return [string]$p.Value } else { return $null }
}
function Wait-Health([string]$url) {
  for ($i = 0; $i -lt 24; $i++) { try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 10; if ($h.status -eq "ok") { return $true } } catch { Nap 5 } }
  return $false
}
# The run is only meaningful if the live revision was started with the profile we think it was.
function Assert-Profile([string]$url, [string]$name) {
  try { $cfg = Invoke-RestMethod -Uri "$url/config" -TimeoutSec 20 } catch { Check "bus exposes /config (is this the v7.9.11 image?)" $false "(if FAIL: -Step deploy first; the old image has no /config)"; return $false }
  $exp = $Expected[$name]
  Set-Content -Path (Log-Path "config_$name") -Value ($cfg | ConvertTo-Json -Depth 6) -Encoding UTF8
  Check "live revision taint_source = $($exp.taint_source)" ($cfg.taint_source -eq $exp.taint_source) "got $($cfg.taint_source)"
  Check "live revision reinstatement_mode = $($exp.reinstatement_mode)" ($cfg.reinstatement_mode -eq $exp.reinstatement_mode) "got $($cfg.reinstatement_mode)"
  Check "live revision fars_feedback_enabled = $($exp.fars_feedback_enabled)" ([bool]$cfg.fars_feedback_enabled -eq $exp.fars_feedback_enabled) "got $($cfg.fars_feedback_enabled)"
  if ($exp.ContainsKey("fb_scope")) {
    # loop-scoped and loop-global differ ONLY in this field; without this check an aws-origin run against the wrong one passes silently.
    $gotScope = $null
    if ($cfg.v7911_active -and $cfg.v7911_active.fars_feedback) { $gotScope = [string]$cfg.v7911_active.fars_feedback.scope }
    Check "live revision FARS scope = $($exp.fb_scope)" ($gotScope -eq $exp.fb_scope) "got $gotScope"
  }
  return (-not (AnyFail))
}
function Scenario-Args([string]$sc) {
  if ($sc -eq "gated_reinstatement" -or $sc -eq "personas" -or $sc -eq "collusion") { return @("--cooling-off", [string]$CoolingOff) }
  if ($sc -eq "adaptive_attacker")   { return @("--n", [string]$AdaptiveN) }
  return @()
}
$ScriptFile = @{ "gated_reinstatement" = "v11_gated_reinstatement_cloud.py"; "fars_loop" = "v11_fars_loop_cloud.py";
                 "adaptive_attacker" = "v11_adaptive_attacker_cloud.py"; "content_taint" = "v11_content_taint_cloud.py";
                 "personas" = "v11_personas_cloud.py"; "collusion" = "v11_collusion_cloud.py" }
$ResultRx   = @{ "gated_reinstatement" = "RESULT reinstatement scenario .*: PASS"; "fars_loop" = "RESULT FARS-loop scenario .*: PASS";
                 "adaptive_attacker" = "RESULT adaptive-attacker scenario .*: PASS"; "content_taint" = "RESULT content-taint scenario: PASS";
                 "personas" = "RESULT personas scenario: PASS"; "collusion" = "RESULT collusion scenario .*: PASS" }

# ================================================================== STEPS
if ($Step -eq 'prep') {
  Head "prep: local gates before ANY cloud spend (read-only, free, ~2 min)"
  Expect @("All [PASS]. If anything fails, nothing has been built or deployed.")
  $null = docker info --format "{{.ServerVersion}}" 2>$null
  Check "Docker Desktop is running" ($LASTEXITCODE -eq 0) "(start it; it is only needed for -Step build)"
  foreach ($f in @("closed_loop.py", "content_taint.py", "docker\bus_service.py", "pentest_cloud\bus_service.py", "pentest_cloud\v11_common.py", "pentest_cloud\v11_gated_reinstatement_cloud.py",
                   "pentest_cloud\v11_fars_loop_cloud.py", "pentest_cloud\v11_adaptive_attacker_cloud.py", "pentest_cloud\v11_content_taint_cloud.py", "pentest_cloud\v11_personas_cloud.py", "pentest_cloud\v11_collusion_cloud.py",
                   "aws_pilot\v11_lambda_runner.py", "tools\make_lambda_zip.py", "tools\write_classifier_reference.py", "aws_pilot\recovery_probe.py", "pentest_cloud\pt08_session_hijack_cloud_FIXED_v3.py")) { Check "present: $f" (Test-Path $f) }
  if (-not (AnyFail)) {
    $same = (Get-FileHash "docker\bus_service.py").Hash -eq (Get-FileHash "pentest_cloud\bus_service.py").Hash
    Check "docker\ and pentest_cloud\ bus_service.py identical" $same
    Check "bus_service.py is the v7.9.11 profile-aware revision (/config route)" ([bool](Select-String -Path "docker\bus_service.py" -Pattern '"/config"' -Quiet))
    $t = Run-Logged "unit_gate" { & $Py -m pytest -q -p no:cacheprovider tests\test_17_reinstatement_is_identity_not_behaviour_gated.py tests\test_18_v7_9_11_contract.py tests\test_19_override_policy.py tests\test_20_golden_scores.py }
    Check "test_17 + test_18 + test_19 + test_20 pass (default path == v7.9.10; v7.9.11 contracts and classifier determinism hold)" ($script:LastExit -eq 0)
  }
  $arn = (aws sts get-caller-identity --query Arn --output text 2>$null | Out-String).Trim()
  Check "AWS login works as user <farf-prototype>" ($arn -match "user/<farf-prototype>") "$arn   (if FAIL: aws login)"
  $proj = (gcloud config get-value project 2>$null | Out-String).Trim()
  Check "gcloud project is $Project" ($proj -eq $Project) $proj
  $rt = (aws ecs list-tasks --cluster $Cluster --desired-status RUNNING --region $AwsRegion --query "length(taskArns)" --output text 2>$null | Out-String).Trim()
  Check "no ECS tasks running" ($rt -eq "0") "running=$rt"
  Finish
}

if ($Step -eq 'build') {
  Head "build: ONE v7.9.11 bus image for every profile; tag $Tag (~5-10 min)"
  Expect @("A Docker build + push to Artifact Registry. The container listing shows closed_loop.py and content_taint.py (Dockerfile does COPY . /app, so they are included),",
           "and 'scikit-learn' prints a version (the content-taint classifier needs it inside the container).",
           "Nothing is deployed in this step, so it costs nothing beyond the push.")
  $img = "$GcpRepo/federation-bus:$Tag"
  $null = docker info --format "{{.ServerVersion}}" 2>$null
  Check "Docker Desktop is running" ($LASTEXITCODE -eq 0)
  Check "docker\bus_service.py is profile-aware" ([bool](Select-String -Path "docker\bus_service.py" -Pattern '"/config"' -Quiet))
  if (AnyFail) { Finish; exit 1 }
  $null = Run-Logged "gar_auth" { gcloud auth configure-docker asia-south1-docker.pkg.dev --quiet }
  $null = Run-Logged "build" { docker build -f .\docker\Dockerfile.cloudrun -t $img . }
  Check "docker build" ($script:LastExit -eq 0)
  if (AnyFail) { Finish; exit 1 }
  $t = Run-Logged "image_contents" { docker run --rm --entrypoint ls $img /app/closed_loop.py /app/content_taint.py /app/pentest_cloud/v11_common.py }
  Check "image contains closed_loop.py and content_taint.py" (($t -match "closed_loop.py") -and ($t -match "content_taint.py"))
  $t2 = Run-Logged "image_sklearn" { docker run --rm --entrypoint python $img -m pip show scikit-learn }
  $m = [regex]::Match($t2, "Version: ([0-9.]+)")
  Check "scikit-learn installed inside the image" $m.Success
  $lap = (& $Py -c "import sklearn; print(sklearn.__version__)" 2>$null | Out-String).Trim()
  if ($m.Success) {
    Write-Host "NOTE container scikit-learn = $($m.Groups[1].Value);  laptop = $lap"
    if ($m.Groups[1].Value -ne $lap) { Warn "scikit-learn differs between the image and your laptop" "classifier scores were identical on 1.8.0 and 1.9.1 when tested, but pin the version for reproducibility (docker\\requirements-docker.txt)." }
  }
  $null = Run-Logged "push" { docker push $img }
  Check "docker push" ($script:LastExit -eq 0)
  Finish
}

if ($Step -eq 'deploy') {
  Head "deploy -ProfileName $ProfileName : new Cloud Run revision from image $Tag with that profile's env vars. COST METER STARTS (~INR 1.3/h) (~2 min)"
  Expect @("gcloud ends with 'Service URL: https://<farf-prototype>-bus-...run.app'. /health returns ok; /config reports exactly this profile's settings.",
           "max-instances=1 is REQUIRED (bus state lives in memory); min-instances=1 keeps it alive across the scenario. New revision => clean state, quorum starts small.",
           "--set-env-vars REPLACES all env vars, so a profile switch can never leave a previous profile's flags behind.")
  $vars = @("FARF_PENTEST_MODE=1", "FARF_LOG_FORMAT=json")
  foreach ($k in ($ProfileNames[$ProfileName].Keys | Sort-Object)) { $vars += ("{0}={1}" -f $k, $ProfileNames[$ProfileName][$k]) }
  $envStr = ($vars -join ",")
  Write-Host "env vars: $envStr"
  $null = Run-Logged "deploy" {
    gcloud run deploy $Service --project $Project --region $Region --image "$GcpRepo/federation-bus:$Tag" `
      --min-instances 1 --max-instances 1 --port 8080 --allow-unauthenticated --set-env-vars $envStr
  }
  Check "gcloud deploy exited cleanly" ($script:LastExit -eq 0)
  if (AnyFail) { Finish; exit 1 }
  $url = Get-BusUrl
  Check "bus /health ok" (Wait-Health $url)
  $svc = Get-BusJson
  Check "image tag is $Tag" ($svc.spec.template.spec.containers[0].image -like "*:$Tag")
  Check "max instances = 1" ((Get-Ann $svc "autoscaling.knative.dev/maxScale") -eq "1")
  Check "min instances = 1" ((Get-Ann $svc "autoscaling.knative.dev/minScale") -eq "1")
  $null = Assert-Profile $url $ProfileName
  Write-Host "Letting the revision settle for 15 s..."; Nap 15
  Warn "COST METER IS RUNNING" "run: .\farf_v7911_cloud.ps1 -Step cool   when you are done"
  Finish
}

if ($Step -eq 'run') {
  Head "run -ProfileName $ProfileName : v7.9.11 scenarios from THIS LAPTOP (WAN) against the live Cloud Run bus (~3-8 min)"
  Expect @("Scenarios for this profile: $($Scenarios[$ProfileName] -join ', ').   Each prints [PASS]/[FAIL] lines and 'RESULT ...: PASS'.",
           "adaptive_attacker: credentials live 300 s; a long run re-authenticates and reports the renewals (a refusal reason of unadmitted_identity is credential expiry, not detection).",
           "default : gated_reinstatement runs in 'identity' mode (commits at the quorum-th vote); fars_loop in 'off' mode; adaptive attacker delivers 100% (documented residual gap).",
           "gated   : immediate vote REFUSED (cooling_off_active); a persistent attacker stays refused; a quiet org is reinstated after ~$($CoolingOff + 3) s.",
           "loop-scoped : 2-hop and isolated bystanders keep sensitivity 1.0 and 0 refusals; loop-global : bystanders ARE boosted (negative baseline, scenario PASSES by reproducing it).",
           "content : Part A deltas match the local reference (else scikit-learn drift); Part B benign senders refused 0 times; Part C1 classic-override lie BLOCKED; Part C2 (E4 style) is informational -- content taint only marginally helps there (documented).")
  $url = Get-BusUrl
  if (-not (Assert-Profile $url $ProfileName)) { Write-Host "The live revision does not match -ProfileName $ProfileName. Run -Step deploy -ProfileName $ProfileName first." -ForegroundColor Red; Finish; exit 1 }
  foreach ($sc in $Scenarios[$ProfileName]) {
    # NB: parenthesise the path. In PowerShell the comma operator binds tighter than '+', so
    # @("dir\" + $x, "--url", $u) would glue everything into ONE string argument.
    $args_ = @(("pentest_cloud\" + $ScriptFile[$sc]), "--url", $url)
    $extra_ = @(Scenario-Args $sc)
    if ($extra_.Count -gt 0) { $args_ += $extra_ }
    $t = Run-Logged $sc { & $Py @args_ }
    Check "scenario $sc reports RESULT: PASS" ($t -match $ResultRx[$sc])
    if ($t -match "\[FAIL\]") { Warn "$sc printed at least one [FAIL] line" "read the transcript above" }
  }
  foreach ($ep in @("closed_loop_status", "resilience_timing", "fars", "status")) {
    try { Set-Content -Path (Log-Path "ep_$ep") -Value (Invoke-RestMethod -Uri "$url/$ep" -TimeoutSec 20 | ConvertTo-Json -Depth 8) -Encoding UTF8 } catch { Warn "could not read /$ep" "" }
  }
  Finish
}

if ($Step -eq 'regress') {
  Head "regress: the existing cloud pentests against the v7.9.11 image, DEFAULT profile (proves the new image did not disturb v7.9.10 behaviour) (~3 min)"
  Expect @("Requires -Step deploy -ProfileName default. PT-01 '(cloud) PASSED', PT-02 'NOT VULNERABLE', PT-08 v3 'NOT VULNERABLE' (fresh org each time; org count stable on the repeat).")
  $url = Get-BusUrl
  if (-not (Assert-Profile $url "default")) { Write-Host "Deploy the default profile first." -ForegroundColor Red; Finish; exit 1 }
  $null = Run-Logged "readmit" { & $Py gcp_pilot\egress_load_test.py --url $url --n-messages 1 }
  $t = Run-Logged "pt01" { & $Py pentest_cloud\pt01_identity_spoofing_cloud.py --url $url };  Check "PT-01 passed" ($t -match "PT-01 \(cloud\) PASSED")
  $t = Run-Logged "pt02" { & $Py pentest_cloud\pt02_field_omission_bypass_cloud.py --url $url }; Check "PT-02 not vulnerable" ($t -match "NOT VULNERABLE")
  $org = "PT08V11" + (Get-Date -Format "HHmmss")
  $a1 = Run-Logged "pt08_first" { & $Py pentest_cloud\pt08_session_hijack_cloud_FIXED_v3.py --url $url --org $org }; Check "PT-08 v3 first run NOT VULNERABLE" ($a1 -match "NOT VULNERABLE")
  $a2 = Run-Logged "pt08_second" { & $Py pentest_cloud\pt08_session_hijack_cloud_FIXED_v3.py --url $url --org $org }; Check "PT-08 v3 second run NOT VULNERABLE" ($a2 -match "NOT VULNERABLE")
  $m = [regex]::Match($a2, "before=(\d+) after=(\d+)"); Check "org count stable on the repeat" ($m.Success -and ($m.Groups[1].Value -eq $m.Groups[2].Value)) $m.Value
  $t = Run-Logged "recovery_probe" { & $Py aws_pilot\recovery_probe.py --url $url --org $org }
  if ($script:LastExit -eq 5) { Warn "no quarantined agents to reinstate" "(PT-08 did not trip the org detector this time -- fine)" }
  else { Check "recovery_probe (identity mode): commit at quorum + lifted + DURABLE" (($script:LastExit -eq 0) -and ($t -match "durability:\s+DURABLE")) }
  Finish
}

if ($Step -eq 'aws-origin') {
  Head "aws-origin -ProfileName $ProfileName : the SAME scenarios executed FROM AWS Lambda ($AwsRegion) against the GCP bus = real cross-cloud origin (~3-10 min)"
  Expect @("First call builds/updates Lambda '$LambdaFn' (reuses the execution role of '$BaseLambda'; zip built with Python so entries use forward slashes).",
           "Each scenario prints 'statusCode 200', origin 'aws-lambda:$AwsRegion', ok=True and the same transcript as -Step run.",
           "Lambda is invoked with --cli-read-timeout 900 (the AWS CLI's default 60 s would abort the gated scenario).")
  $url = Get-BusUrl
  if (-not (Assert-Profile $url $ProfileName)) { Write-Host "Deploy -ProfileName $ProfileName first." -ForegroundColor Red; Finish; exit 1 }
  $roleArn = (aws lambda get-function-configuration --function-name $BaseLambda --region $AwsRegion --query "Role" --output text 2>$null | Out-String).Trim()
  Check "reusable Lambda execution role found" ($roleArn -like "arn:aws:iam::*") $roleArn
  if (AnyFail) { Finish; exit 1 }
  $build = Join-Path $PWD "lambda_build_v11"
  if (Test-Path $build) { Remove-Item $build -Recurse -Force }
  New-Item -ItemType Directory -Path $build | Out-Null
  # Lambda is Linux: fetch LINUX wheels (a plain 'pip install -t' on Windows would vendor Windows .pyd files that Lambda cannot import).
  $null = Run-Logged "pip_package" { & $Py -m pip install requests --target $build --platform manylinux2014_x86_64 --implementation cp --python-version 3.12 --only-binary=:all: --quiet }
  Check "Linux wheels vendored for Lambda" ($script:LastExit -eq 0)
  Copy-Item aws_pilot\v11_lambda_runner.py $build; Copy-Item pentest_cloud\v11_*.py $build
  $null = Run-Logged "zip" { & $Py tools\make_lambda_zip.py --src $build --out lambda_v11_runner.zip }
  Check "zip built" ($script:LastExit -eq 0)
  Remove-Item $build -Recurse -Force -ErrorAction SilentlyContinue   # keep vendored packages out of the tree (ruff would lint them)
  $exists = $false
  $null = aws lambda get-function --function-name $LambdaFn --region $AwsRegion 2>$null
  if ($LASTEXITCODE -eq 0) { $exists = $true }
  if ($exists) {
    $null = Run-Logged "update_code" { aws lambda update-function-code --function-name $LambdaFn --zip-file fileb://lambda_v11_runner.zip --region $AwsRegion }
    Check "function code updated" ($script:LastExit -eq 0)
    Nap 8
  } else {
    $null = Run-Logged "create_fn" { aws lambda create-function --function-name $LambdaFn --runtime python3.12 --role $roleArn --handler v11_lambda_runner.handler `
                                      --zip-file fileb://lambda_v11_runner.zip --timeout 600 --memory-size 256 --region $AwsRegion }
    Check "function created" ($script:LastExit -eq 0)
    Nap 15
  }
  $null = Run-Logged "wait_active" { aws lambda wait function-active-v2 --function-name $LambdaFn --region $AwsRegion }
  foreach ($sc in $Scenarios[$ProfileName]) {
    $params = @{}
    if ($sc -eq "gated_reinstatement" -or $sc -eq "personas" -or $sc -eq "collusion") { $params["cooling_off"] = $CoolingOff }
    if ($sc -eq "adaptive_attacker")   { $params["n"] = [Math]::Min($AdaptiveN, 300) }
    if ($sc -eq "content_taint") {
      # Part A compares the BUS's classifier output with THIS laptop's. Lambda has no repo tree, so ship the laptop's deltas along.
      $rf = Join-Path $env:TEMP "classifier_reference.json"
      $null = & $Py tools\write_classifier_reference.py $rf
      if ($LASTEXITCODE -eq 0) { $params["reference"] = (Get-Content $rf -Raw | ConvertFrom-Json) } else { Warn "could not write classifier reference" "Part A will not be scored from AWS" }
    }
    $payloadObj = @{ scenario = $sc; url = $url; params = $params }
    $pf = Join-Path $env:TEMP ("v11_payload_" + $sc + ".json")
    [IO.File]::WriteAllText($pf, ($payloadObj | ConvertTo-Json -Depth 5 -Compress), (New-Object System.Text.UTF8Encoding($false)))   # no BOM
    $of = Log-Path ("lambda_" + $sc)
    $null = Run-Logged ("invoke_" + $sc) { aws lambda invoke --function-name $LambdaFn --region $AwsRegion --cli-read-timeout 900 --payload ("fileb://" + $pf) $of }
    Check "lambda invoke $sc returned" ($script:LastExit -eq 0)
    $raw = Get-Content $of -Raw
    try { $j = $raw | ConvertFrom-Json } catch { $j = $null }
    if ($j -and $j.transcript) { foreach ($l in $j.transcript) { Write-Host $l } }
    Check "scenario $sc from AWS: statusCode 200 and ok=True" ($j -and ($j.statusCode -eq 200) -and ($j.ok -eq $true)) $(if ($j) { "origin=$($j.origin)" } else { "unparseable: $raw" })
  }
  Write-Host "NOTE: compare the per-message latency lines here (AWS -> GCP) with the laptop's (-Step run): that is your cross-cloud origin latency evidence."
  Finish
}

if ($Step -eq 'evidence') {
  Head "evidence: dump the live bus state + recent Cloud Run logs for the write-up (read-only, free)"
  $url = Get-BusUrl
  foreach ($ep in @("config", "status", "fars", "resilience_timing", "closed_loop_status")) {
    try { Set-Content -Path (Log-Path "ep_$ep") -Value (Invoke-RestMethod -Uri "$url/$ep" -TimeoutSec 20 | ConvertTo-Json -Depth 8) -Encoding UTF8; Check "saved /$ep" $true } catch { Warn "could not read /$ep" "(old image or cooled bus?)" }
  }
  $j = (gcloud logging read "resource.type=cloud_run_revision AND resource.labels.service_name=$Service" --project $Project --limit 300 --freshness=6h --format json 2>$null | Out-String)
  Set-Content -Path (Log-Path "cloud_run_logs") -Value $j -Encoding UTF8
  Check "Cloud Run log export saved" ($j.Length -gt 10) ("{0} bytes" -f $j.Length)
  Write-Host "Zip the folder $Evidence and send it."
  Finish
}

if ($Step -eq 'cool') {
  Head "cool: STOP THE COST METER (min-instances 0)"
  $null = Run-Logged "cool" { gcloud run services update $Service --project $Project --region $Region --min-instances 0 }
  Check "gcloud update exited cleanly" ($script:LastExit -eq 0)
  $svc = Get-BusJson
  $min = Get-Ann $svc "autoscaling.knative.dev/minScale"
  Check "min instances = 0" ((-not $min) -or ($min -eq "0")) "minScale=$min"
  $rt = (aws ecs list-tasks --cluster $Cluster --desired-status RUNNING --region $AwsRegion --query "length(taskArns)" --output text 2>$null | Out-String).Trim()
  Check "no ECS tasks running" ($rt -eq "0") "running=$rt"
  Warn "Lambda $LambdaFn is left in place" "it costs nothing when idle; delete with: aws lambda delete-function --function-name $LambdaFn --region $AwsRegion"
  Finish
}

if ($Step -eq 'status') {
  Head "status (read-only)"
  $svc = Get-BusJson
  Write-Host "Bus image:     $($svc.spec.template.spec.containers[0].image)"
  Write-Host ("Bus env vars:  " + (@($svc.spec.template.spec.containers[0].env | ForEach-Object { "{0}={1}" -f $_.name, $_.value }) -join ", "))
  Write-Host ("min/max inst:  {0} / {1}   (min 1 = costs about INR 1.3/hour)" -f (Get-Ann $svc "autoscaling.knative.dev/minScale"), (Get-Ann $svc "autoscaling.knative.dev/maxScale"))
  try { Invoke-RestMethod -Uri "$(Get-BusUrl)/config" -TimeoutSec 20 | ConvertTo-Json -Depth 6 } catch { Write-Host "/config not reachable (old image, or bus cold)" }
}
