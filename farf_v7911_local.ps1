# farf_v7911_local.ps1 -- LOCAL (laptop-only) test protocol for FARF v7.9.11.  Windows 11, 8 GB RAM, GTX 1650.
# RUN FROM THE ROOT OF YOUR ALREADY-MERGED TREE (the folder that contains federation_bus.py), e.g. ...\LJMU\farf_prototype_v7_9_11
# (or pass -Root <path>).  The 'merge' step is only for building a tree from the two zips and is NOT needed if you merged by hand.
# One step at a time, in this order:
#   additions -> env -> lint -> tests -> pentest -> smoke -> benign -> localbus -> (optional) full -> report
#   .\farf_v7911_local.ps1 -Step additions -Additions .\farf_v7911_additions.zip     (folder or zip; copies the new v7.9.11 files into the tree)
# Written for Windows PowerShell 5.1 (no PS7-only syntax). Does NOT touch farf_run.ps1.
# 8 GB NOTES: nothing here uses the GPU (the GTX 1650 / Ollama is only needed for the optional LLM judge; test_07 mocks it).
#   Peak RAM is a few hundred MB. Close Docker Desktop (it pins ~2 GB via WSL2) for local steps; it is only needed for cloud image builds.
# SAFETY: 'smoke' and 'full' write to a NEW folder (results_rerun_*), never into experiments\results. (The shipped
#   fars_loop_sweep_v2.json has an empty 'chain' section -- almost certainly a partial re-run overwrote it. Do not repeat that.)

param(
  [Parameter(Mandatory = $true)]
  [ValidateSet('merge', 'additions', 'env', 'lint', 'tests', 'pentest', 'smoke', 'benign', 'classifier', 'floor', 'reseed', 'localbus', 'full', 'report')]
  [string]$Step,
  [string]$Root       = (Get-Location).Path,
  [string]$BaseZip    = ".\farf_prototype_v7_9_7_28Sep.zip",
  [string]$OverlayZip = ".\farf_v7_9_11_FINAL.zip",
  [string]$Additions  = ".\farf_v7911_additions.zip",
  [int]$N = 5,
  [switch]$IncludeSweep
)

$ErrorActionPreference = 'Continue'
$env:PYTHONUTF8 = "1"            # pt15 prints a Cyrillic homoglyph; piped stdout would otherwise be cp1252 and crash
$env:PYTHONIOENCODING = "utf-8"
$script:Results = @()
$script:LastExit = 0
$Evidence = Join-Path $Root ("evidence_v7911_local_" + (Get-Date -Format "yyyyMMdd"))
$Py = Join-Path $Root ".venv\Scripts\python.exe"

function Head([string]$t) { Write-Host ""; Write-Host "=== $t" -ForegroundColor Cyan }
function Expect([string[]]$lines) { Write-Host "EXPECT:" -ForegroundColor Yellow; foreach ($l in $lines) { Write-Host "  - $l" -ForegroundColor Yellow }; Write-Host "" }
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
  if (Test-Path $Evidence) { Write-Host "Evidence saved in: $Evidence" }
}
function Get-LogPath([string]$name) {
  if (-not (Test-Path $Evidence)) { New-Item -ItemType Directory -Path $Evidence -Force | Out-Null }
  return (Join-Path $Evidence ("{0}_{1}_{2}.txt" -f (Get-Date -Format "HHmmss"), $Step, $name))
}
# Runs a block, shows output live, saves it, returns it as text. Internal names end in __ so the block cannot see caller variables by accident.
function Invoke-Logged([string]$RunName__, [scriptblock]$Block__) {
  $lf__ = Get-LogPath $RunName__
  $acc__ = New-Object System.Collections.ArrayList
  & $Block__ 2>&1 | ForEach-Object { "$_" } | Where-Object { $_ -ne "System.Management.Automation.RemoteException" } | ForEach-Object {
    Write-Host $_; Add-Content -Path $lf__ -Value $_ -Encoding UTF8; [void]$acc__.Add($_) }
  $script:LastExit = $LASTEXITCODE
  return ($acc__ -join "`n")
}
function Test-RepoTree { if (-not (Test-Path (Join-Path $Root "federation_bus.py"))) { Write-Host "No FARF tree at $Root (federation_bus.py not found). cd into your merged folder, or pass -Root <path>." -ForegroundColor Red; exit 1 } }
function Test-RepoVenv { Test-RepoTree; if (-not (Test-Path $Py)) { Write-Host "No venv. Run -Step env first." -ForegroundColor Red; exit 1 } }


# Copies the delivered additions (folder or .zip) into the tree. Idempotent. Also fixes the 'pt23 ... (1).py' name if present.
function Import-Additions([string]$src) {
  $tmpA = $null
  if ($src -match "\.zip$") {
    if (-not (Test-Path $src)) { Check "additions zip found" $false $src; return }
    $tmpA = Join-Path $env:TEMP ("farf_add_" + (Get-Date -Format "HHmmss"))
    Expand-Archive -Path $src -DestinationPath $tmpA -Force
    $inner = Get-ChildItem $tmpA -Directory | Select-Object -First 1
    if ($inner -and (Test-Path (Join-Path $inner.FullName "bus_service.py"))) { $src = $inner.FullName } else { $src = $tmpA }
  }
  if (-not (Test-Path (Join-Path $src "bus_service.py"))) { Check "additions folder valid (bus_service.py inside)" $false $src; return }
  robocopy $src $Root /E /XF "bus_service.py" /NFL /NDL /NJH /NJS | Out-Null
  Check "additions copied (v11 scenarios, test_18, tools, experiments)" ($LASTEXITCODE -lt 8) "robocopy rc=$LASTEXITCODE"
  foreach ($d in @("docker", "pentest_cloud")) {
    if (Test-Path (Join-Path $Root $d)) { Copy-Item (Join-Path $src "bus_service.py") (Join-Path $Root "$d\bus_service.py") -Force }
  }
  $same = (Get-FileHash (Join-Path $Root "docker\bus_service.py")).Hash -eq (Get-FileHash (Join-Path $Root "pentest_cloud\bus_service.py")).Hash
  Check "docker\ and pentest_cloud\ copies of bus_service.py identical" $same
  Check "bus_service.py is the v7.9.11 profile-aware revision (/config route)" ([bool](Select-String -Path (Join-Path $Root "docker\bus_service.py") -Pattern '"/config"' -Quiet))
  $odd = Get-ChildItem -LiteralPath (Join-Path $Root "pentest") -Filter "pt23*(1).py" -ErrorAction SilentlyContinue
  foreach ($f in $odd) { Move-Item -LiteralPath $f.FullName -Destination (Join-Path $Root "pentest\pt23_threshold_aware_adaptive_attacker.py") -Force; Write-Host "renamed $($f.Name) -> pt23_threshold_aware_adaptive_attacker.py" }
  foreach ($f in @("closed_loop.py", "content_taint.py", "tests\test_18_v7_9_11_contract.py", "pentest_cloud\v11_common.py", "experiments\check_content_taint_benign.py", "tools\compare_results.py",
                   "pentest\pt23_threshold_aware_adaptive_attacker.py", "experiments\run_ablation.py", "experiments\run_fars_loop_sweep_v2.py")) {
    Check "present: $f" (Test-Path (Join-Path $Root $f))
  }
  Check "federation_bus.py is the v7.9.11 one (_locked)" ([bool](Select-String -Path (Join-Path $Root "federation_bus.py") -Pattern "_locked" -Quiet))
  if ($tmpA) { Remove-Item $tmpA -Recurse -Force -ErrorAction SilentlyContinue }
}

if ($Step -eq 'additions') {
  Head "additions: copy the new v7.9.11 files into $Root (seconds)"
  Expect @("All [PASS]: closed_loop.py / content_taint.py (from your manual merge) and the new test_18, v11 scenarios, tools and the profile-aware bus_service.py are in place.",
           "If 'present: closed_loop.py' FAILS, your manual merge did not include the v7.9.11 overlay -- copy the overlay files over the tree first.")
  Test-RepoTree
  Import-Additions $Additions
  Finish
}

# ---------------------------------------------------------------------------------------------------------------
if ($Step -eq 'merge') {
  Head "merge: v7.9.7 base + v7.9.11 overlay (+ additions) -> $Root   (~1 min)"
  Expect @("[PASS] both zips found; pt23 renamed from 'pt23_... (1).py'; the tree contains closed_loop.py, content_taint.py, experiments\run_*.py.",
           "federation_bus.py from the overlay is a superset of v7.9.7's (checked by hand: the 11 removed lines are comment/rewrap only).")
  Check "base zip found" (Test-Path $BaseZip) $BaseZip
  Check "overlay zip found" (Test-Path $OverlayZip) $OverlayZip
  if (AnyFail) { Finish; exit 1 }
  $tmp = Join-Path $env:TEMP ("farf_merge_" + (Get-Date -Format "HHmmss"))
  Expand-Archive -Path $BaseZip -DestinationPath (Join-Path $tmp "base") -Force
  Expand-Archive -Path $OverlayZip -DestinationPath (Join-Path $tmp "over") -Force
  $b = Get-ChildItem (Join-Path $tmp "base") -Directory | Select-Object -First 1
  $o = Get-ChildItem (Join-Path $tmp "over") -Directory | Select-Object -First 1
  if (Test-Path $Root) { Warn "$Root already exists" "merging on top; delete it first for a clean tree" }
  robocopy $b.FullName $Root /E /XD "evidence_*" "precheck_*" ".git" "__pycache__" ".ruff_cache" ".venv" /XF "*.zip" /NFL /NDL /NJH /NJS | Out-Null
  Check "base copied" ($LASTEXITCODE -lt 8) "robocopy rc=$LASTEXITCODE"
  robocopy $o.FullName $Root /E /XD "__pycache__" /NFL /NDL /NJH /NJS | Out-Null
  Check "overlay copied" ($LASTEXITCODE -lt 8) "robocopy rc=$LASTEXITCODE"
  $odd = Get-ChildItem -LiteralPath (Join-Path $Root "pentest") -Filter "pt23*(1).py" -ErrorAction SilentlyContinue
  foreach ($f in $odd) {
    Move-Item -LiteralPath $f.FullName -Destination (Join-Path $Root "pentest\pt23_threshold_aware_adaptive_attacker.py") -Force
    Write-Host "renamed $($f.Name) -> pt23_threshold_aware_adaptive_attacker.py"
  }
  if (Test-Path $Additions) {
    robocopy $Additions $Root /E /NFL /NDL /NJH /NJS | Out-Null
    Check "additions copied (bus_service.py, v11 scenarios, test_18, tools)" ($LASTEXITCODE -lt 8)
    Copy-Item (Join-Path $Root "bus_service.py") (Join-Path $Root "docker\bus_service.py") -Force
    Copy-Item (Join-Path $Root "bus_service.py") (Join-Path $Root "pentest_cloud\bus_service.py") -Force
    Remove-Item (Join-Path $Root "bus_service.py") -Force
    $same = (Get-FileHash (Join-Path $Root "docker\bus_service.py")).Hash -eq (Get-FileHash (Join-Path $Root "pentest_cloud\bus_service.py")).Hash
    Check "docker\ and pentest_cloud\ copies of bus_service.py identical" $same
  } else { Warn "no additions folder at $Additions" "the v7.9.11 cloud profiles and test_18 will be missing" }
  foreach ($f in @("closed_loop.py", "content_taint.py", "federation_bus.py", "orchestration.py", "pentest\pt23_threshold_aware_adaptive_attacker.py", "experiments\run_ablation.py", "experiments\run_recovery.py", "experiments\run_fars_loop_sweep_v2.py")) {
    Check "present: $f" (Test-Path (Join-Path $Root $f))
  }
  Check "federation_bus.py has the v7.9.11 lock (_locked)" ([bool](Select-String -Path (Join-Path $Root "federation_bus.py") -Pattern "_locked" -Quiet))
  Remove-Item $tmp -Recurse -Force -ErrorAction SilentlyContinue
  Finish
}

if ($Step -eq 'env') {
  Head "env: create .venv, install requirements + pytest + ruff (~3-5 min, needs internet)"
  Expect @("pip finishes without ERROR; [PASS] for every import. Python 3.11 matches the Docker images; 3.12 also worked in my run.")
  Test-RepoTree
  Push-Location $Root
  Write-Host ("python on PATH: " + (python --version 2>&1 | Out-String).Trim())
  if (-not (Test-Path ".venv")) { $null = Invoke-Logged "venv" { python -m venv .venv }; Check "venv created" ($script:LastExit -eq 0) }
  $null = Invoke-Logged "pip_upgrade" { & $Py -m pip install --upgrade pip --quiet }
  $null = Invoke-Logged "pip_req" { & $Py -m pip install -r requirements.txt pytest ruff flask requests --quiet }
  Check "pip install exited cleanly" ($script:LastExit -eq 0)
  foreach ($m in @("networkx", "cryptography", "sklearn", "numpy", "scipy", "pandas", "yaml", "flask", "requests", "pytest")) {
    $null = & $Py -c "import $m" 2>$null
    Check "import $m" ($LASTEXITCODE -eq 0)
  }
  Write-Host ("scikit-learn on this laptop: " + (& $Py -c "import sklearn; print(sklearn.__version__)" 2>$null | Out-String).Trim() + "   (content-taint numbers depend on it)")
  Pop-Location
  Finish
}

if ($Step -eq 'lint') {
  Head "lint: ruff check  (I could NOT run ruff in my sandbox -- no network -- so this result is unknown to me)"
  Expect @("'All checks passed!'. If ruff reports findings in closed_loop.py / content_taint.py / experiments\*, paste them.")
  Test-RepoVenv; Push-Location $Root
  $t = Invoke-Logged "ruff" { & $Py -m ruff check . }
  Check "ruff: All checks passed" ($t -match "All checks passed")
  Pop-Location; Finish
}

if ($Step -eq 'tests') {
  Head "tests: the REAL pytest suite (~1-2 min)"
  Expect @("134 passed, 3 skipped (117 original + 11 in test_18 + 6 in test_19; the 3 skipped are test_20, which skips until tools\write_golden_scores.py has been run). This step says "
           "nothing about benign false positives on realistic text: see tools\policy_matrix.py and tools\heldout_eval.py."
           "If test_classifier_is_available_in_this_environment FAILS, scikit-learn is missing from the venv: run -Step env, then re-run.")
  Test-RepoVenv; Push-Location $Root
  $null = & $Py -c "import sklearn" 2>$null
  Check "scikit-learn importable in the venv (else the classifier is silently disabled and content taint is heuristic-only)" ($LASTEXITCODE -eq 0) "(fix: .\farf_v7911_local.ps1 -Step env)"
  if (-not (Test-Path "tests\test_18_v7_9_11_contract.py")) { Warn "test_18 not found" "run -Step additions first; expect 117 passed instead of 124" }
  $t = Invoke-Logged "pytest" { & $Py -m pytest -q -p no:cacheprovider }
  Check "pytest exit code 0" ($script:LastExit -eq 0)
  $m = [regex]::Match($t, "(\d+) passed")
  if ($m.Success) { Write-Host "NOTE passed=$($m.Groups[1].Value)" }
  Check "no failures" (-not ($t -match "\d+ failed"))
  Check "no test errors" (-not ($t -match "\d+ error"))
  Pop-Location; Finish
}

if ($Step -eq 'pentest') {
  Head "pentest: PT-01 .. PT-23 in-process against the merged tree (~1 min)"
  Expect @("PT-01..04,06..11,13,14,16,19 print NOT VULNERABLE; PT-17 prints PASS; PT-12/15/18/20/21/22 print their own 'BEHAVES AS DESIGNED / CONFIRMED' sentence.",
           "PT-05 prints a nuanced verdict containing the word FAIL ('RAW PRIMITIVE NOW FAILS CLOSED'): documented, NOT a failure.",
           "PT-23 reports delivered_fraction 1.0 under the default bus: the documented RESIDUAL GAP, not a regression.")
  Test-RepoVenv; Push-Location $Root
  $notVuln = @("pt01", "pt02", "pt03", "pt04", "pt06", "pt07", "pt08", "pt09", "pt10", "pt11", "pt13", "pt14", "pt16", "pt19")
  $sentence = @{ "pt12" = "ALL TEMPORAL-ADAPTIVITY FEATURES BEHAVE AS DESIGNED"; "pt15" = "PROMPT-INJECTION DETECTION BEHAVES AS DESIGNED"; "pt18" = "METRIC BEHAVES AS DESIGNED";
                 "pt20" = "DEFENCE-IN-DEPTH CONFIRMED"; "pt21" = "AUDIT-WRITE RESILIENCE CONFIRMED"; "pt22" = "CRYPTO-SHREDDING BEHAVES AS DESIGNED"; "pt17" = "PASS";
                 "pt05" = "RAW PRIMITIVE NOW FAILS CLOSED"; "pt23" = "residual gap" }
  foreach ($f in (Get-ChildItem pentest\pt*.py | Sort-Object Name)) {
    $b = [IO.Path]::GetFileNameWithoutExtension($f.Name); $key = $b.Substring(0, 4)
    $out = (& $Py -m "pentest.$b" 2>&1 | Out-String); Set-Content -Path (Get-LogPath $b) -Value $out -Encoding UTF8
    if ($notVuln -contains $key) { Check "$b -> NOT VULNERABLE" (($out -match "NOT VULNERABLE") -and -not ($out -match "(?m)^\s*VULNERABLE")) }
    elseif ($sentence.ContainsKey($key)) { Check "$b -> documented verdict" ($out -match [regex]::Escape($sentence[$key])) }
    else { Check "$b ran" ($out.Length -gt 0) }
  }
  Pop-Location; Finish
}

if ($Step -eq 'smoke') {
  Head "smoke: every v7.9.11 experiment at n=$N into a NEW folder, then compare to the shipped CSVs by seed (~1 min at n=5)"
  Expect @("[PASS] each runner exits 0; ablation, recovery and baseline_comparison rows are IDENTICAL to the shipped CSVs for the same seeds (verified on your tree in my sandbox).",
           "EXPECTED [WARN] content_taint_raw.csv: the shipped file/summary (and README: 100% -> 32.5%) predate the recalibration. Current n=60: classic override 100% -> 0% delivered; E4 style 100% -> 96% (blast 80%).",
           "EXPECTED [WARN]: fars_loop_campaign_raw.csv differs -- the shipped file came from an older revision of run_fars_loop.py (it lacks the",
           "max_incident_hop / n_orgs_touched_by_scope columns). A provenance issue in the package, not a code regression.")
  Test-RepoVenv; Push-Location $Root
  $out = Join-Path $Root ("experiments\results_rerun_" + (Get-Date -Format "yyyyMMdd_HHmm"))
  New-Item -ItemType Directory -Path $out -Force | Out-Null
  foreach ($r in @(@("run_ablation", $N), @("run_recovery", $N), @("run_baseline_comparison", $N), @("run_content_taint", $N), @("run_fars_loop", 3))) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $null = Invoke-Logged $r[0] { & $Py -m "experiments.$($r[0])" --n $r[1] --out $out }
    Check "$($r[0]) exit 0" ($script:LastExit -eq 0) ("{0:N0}s" -f $sw.Elapsed.TotalSeconds)
  }
  $t = Invoke-Logged "compare" { & $Py tools\compare_results.py $out }
  foreach ($f in @("ablation_e4", "ablation_campaign", "ablation_fanout", "ablation_sybil", "recovery", "baseline_comparison_e4", "baseline_comparison_fanout", "baseline_comparison_sybil")) {
    Check "$f rows identical to shipped" ($t -match ("OK\s+" + $f + "_raw.csv"))
  }
  if ($t -match "DIFF\s+content_taint_raw.csv") { Warn "content_taint_raw.csv differs from shipped" "STALE SHIPPED RESULT: it predates the classifier recalibration (no attack_style column). The fresh files in the rerun folder are the current ones; use those." }
  if ($t -match "DIFF\s+fars_loop_campaign_raw.csv") { Warn "fars_loop_campaign_raw.csv differs from shipped" "expected -- see EXPECT above" }
  Write-Host "Fresh results are in: $out"
  Pop-Location; Finish
}

if ($Step -eq 'benign') {
  Head "benign: the measurement v7.9.11 is missing -- does content-derived taint throttle a BENIGN sender? (~2 min)"
  Expect @("declared, content and max: senders refused 0/30 in all three. This uses the five fixture sentences only; it cannot see override false positives on realistic benign text (use local_profiles.py --profile scale --texts <D file>)."
           "If content mode shows refusals here, CLASSIFIER_FLOOR is below some benign text's classifier score -- run -Step floor for the operating curve.")
  Test-RepoVenv; Push-Location $Root
  $out = Join-Path $Root ("experiments\results_rerun_benign_" + (Get-Date -Format "yyyyMMdd_HHmm"))
  $t = Invoke-Logged "benign" { & $Py -m experiments.check_content_taint_benign --n 30 --out $out }
  Check "declared: 0/30 benign senders refused" ($t -match "declared\s+senders refused 0/30")
  Check "content: 0/30 benign senders refused" ($t -match "content\s+senders refused 0/30") "(else: floor too low for this scikit-learn)"
  Check "max: 0/30 benign senders refused" ($t -match "max\s+senders refused 0/30")
  Pop-Location; Finish
}

if ($Step -eq 'classifier') {
  Head "classifier: this machine's content-taint classifier margins and the worst-case benign throttling (~10 s)"
  Expect @("Fixture margins to the 0.49 floor are +0.067 or more with the 349-example classifier, but held-out benign phrases reach p = 0.5712, so a comfortable fixture margin is not evidence of safety.",
           "A sender repeating the current worst fixture was benign margin at 80x . -Step floor shows the trade-off against E4 protection.")
  Test-RepoVenv; Push-Location $Root
  $t = Invoke-Logged "classifier_margins" { & $Py tools\classifier_margins.py }
  Check "diagnostic ran" ($script:LastExit -eq 0)
  if ($t -match "ABOVE the floor") { Warn "a benign sentence is above CLASSIFIER_FLOOR" "run -Step floor and freeze a floor from the operating curve" }
  elseif ($t -match "thin margin") { Warn "thin floor margin" "see -Step floor" }
  $m = [regex]::Match($t, "first refusal at message (\w+)")
  if ($m.Success -and $m.Groups[1].Value -ne "None") { Warn "worst-case repeated benign sentence is refused at message $($m.Groups[1].Value)" "" }
  Pop-Location; Finish
}

if ($Step -eq 'floor') {
  Head "floor: CLASSIFIER_FLOOR operating curve -- benign collateral versus E4 protection (~3-5 min)"
  Expect @("Five fixtures only. E4 is 0.000/0.000 up to floor 0.54 and 0.325/0.000 at 0.58 under the historical agents policy; the held-out phrases"
           " are covered by tools\policy_matrix.py.")
  Test-RepoVenv; Push-Location $Root
  $t = Invoke-Logged "floor_sweep" { & $Py -m experiments.run_floor_sweep --n 60 }
  Check "sweep ran" ($script:LastExit -eq 0)
  Pop-Location; Finish
}

if ($Step -eq 'reseed') {
  Head "reseed: deterministic check of scoped-cold chain creep (FakeClock, ~5 s)"
  Expect @("A) retries within decay_s: O3 untouched (sensitivity 1.0; hops O0=1, O1=0, O2=1).",
           "B) retries AFTER decay_s: O3 BOOSTED to the max multiplier, because the collateral-quarantined O2 is 'cold' again and becomes a new root.",
           "B is a FINDING (closed_loop.py describes it as 'genuinely cold re-detection'), not a test failure: state it in the thesis as a limit of scoped-cold.")
  Test-RepoVenv; Push-Location $Root
  $t = Invoke-Logged "reseed" { & $Py -m experiments.check_scope_reseeding }
  Check "A) retries within decay_s leave O3 untouched" ($t -match "A\)[^\n]*O3 untouched")
  if ($t -match "B\)[^\n]*O3 BOOSTED") { Warn "B) scope re-seeds from a retrying collateral victim after decay_s" "documented design; disclose as a limitation" } else { Check "B) no re-seeding" $true "(behaviour has changed -- re-read closed_loop.py)" }
  Pop-Location; Finish
}

if ($Step -eq 'localbus') {
  Head "localbus: the HTTP cloud scenarios against a LOCAL bus_service.py, once per profile (~6-8 min)"
  Expect @("Exactly what the cloud script does, minus the network: same scripts, same verdict lines. Each profile starts a fresh bus on port 8201+. Per-message latency should be a few ms (a ~2000 ms mean means localhost/IPv6 is still being used).",
           "Do this BEFORE spending cloud money: a scenario that fails here will fail in the cloud.")
  Test-RepoVenv; Push-Location $Root
  $profiles = @(
    @{ Name = "default";     Port = 8201; Env = @{};                                                         Scenarios = @("gated", "loop", "adaptive", "content") },
    @{ Name = "content";     Port = 8202; Env = @{ FARF_TAINT_SOURCE = "content" };                          Scenarios = @("content", "adaptive") },
    @{ Name = "gated";       Port = 8203; Env = @{ FARF_REINSTATE_MODE = "behaviour_gated"; FARF_COOLING_OFF_S = "20"; FARF_PROBATION_MSGS = "5" }; Scenarios = @("gated") },
    @{ Name = "loop-scoped"; Port = 8204; Env = @{ FARF_FARS_FEEDBACK = "1"; FARF_FB_BETA = "20"; FARF_FB_MAXMULT = "3"; FARF_FB_DECAY_S = "600"; FARF_FB_SCOPE = "scoped"; FARF_FB_REQUIRE_COLD = "1" }; Scenarios = @("loop") },
    @{ Name = "loop-global"; Port = 8205; Env = @{ FARF_FARS_FEEDBACK = "1"; FARF_FB_BETA = "20"; FARF_FB_MAXMULT = "3"; FARF_FB_DECAY_S = "600"; FARF_FB_SCOPE = "global" }; Scenarios = @("loop") }
  )
  foreach ($p in $profiles) {
    Write-Host ""; Write-Host "##### profile: $($p.Name)  (port $($p.Port))" -ForegroundColor Magenta
    $dbp = Join-Path $env:TEMP ("farf_v11_" + $p.Name + ".db"); Remove-Item "$dbp*" -Force -ErrorAction SilentlyContinue
    $env:FARF_AUDIT_DB = $dbp; $env:FARF_PENTEST_MODE = "1"; $env:PORT = [string]$p.Port
    foreach ($k in $p.Env.Keys) { Set-Item -Path ("Env:" + $k) -Value $p.Env[$k] }
    $proc = Start-Process -FilePath $Py -ArgumentList "pentest_cloud\bus_service.py" -PassThru -WindowStyle Hidden `
              -RedirectStandardOutput (Join-Path $env:TEMP "bus_$($p.Port).out") -RedirectStandardError (Join-Path $env:TEMP "bus_$($p.Port).err")
    foreach ($k in $p.Env.Keys) { Remove-Item -Path ("Env:" + $k) -ErrorAction SilentlyContinue }
    $url = "http://127.0.0.1:$($p.Port)"; $up = $false   # NOT localhost: on Windows localhost tries IPv6 first and adds ~2 s per request (and made the adaptive scenario outlive its 300 s credential)
    for ($i = 0; $i -lt 30 -and -not $up; $i++) { try { $h = Invoke-RestMethod -Uri "$url/health" -TimeoutSec 3; $up = ($h.status -eq "ok") } catch { Start-Sleep -Seconds 1 } }
    Check "[$($p.Name)] local bus is up" $up
    if ($up) {
      $cfg = Invoke-RestMethod -Uri "$url/config" -TimeoutSec 5
      Write-Host ("config: taint_source={0} reinstatement_mode={1} fars_feedback={2}" -f $cfg.taint_source, $cfg.reinstatement_mode, $cfg.fars_feedback_enabled)
      foreach ($s in $p.Scenarios) {
        if ($s -eq "gated")    { $t = Invoke-Logged "$($p.Name)_gated"    { & $Py pentest_cloud\v11_gated_reinstatement_cloud.py --url $url --cooling-off 20 }; Check "[$($p.Name)] reinstatement scenario" ($t -match "RESULT reinstatement scenario .*: PASS") }
        if ($s -eq "loop")     { $t = Invoke-Logged "$($p.Name)_loop"     { & $Py pentest_cloud\v11_fars_loop_cloud.py --url $url };                          Check "[$($p.Name)] FARS-loop scenario" ($t -match "RESULT FARS-loop scenario .*: PASS") }
        if ($s -eq "adaptive") { $t = Invoke-Logged "$($p.Name)_adaptive" { & $Py pentest_cloud\v11_adaptive_attacker_cloud.py --url $url --n 200 };       Check "[$($p.Name)] adaptive-attacker scenario" ($t -match "RESULT adaptive-attacker scenario .*: PASS") }
        if ($s -eq "content")  { $t = Invoke-Logged "$($p.Name)_content"  { & $Py pentest_cloud\v11_content_taint_cloud.py --url $url };                     Check "[$($p.Name)] content-taint scenario" ($t -match "RESULT content-taint scenario: PASS") }
      }
      try { Set-Content -Path (Get-LogPath "$($p.Name)_closed_loop_status") -Value (Invoke-RestMethod -Uri "$url/closed_loop_status" -TimeoutSec 5 | ConvertTo-Json -Depth 6) -Encoding UTF8 } catch { }
    }
    Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
  }
  Remove-Item Env:FARF_AUDIT_DB, Env:FARF_PENTEST_MODE, Env:PORT -ErrorAction SilentlyContinue
  Pop-Location; Finish
}

if ($Step -eq 'full') {
  Head "full: full-n experiments into a NEW folder (~15-20 min without the sweep; the sweep adds ~30-60+ min on an i5 -- keep the laptop plugged in)"
  Expect @("Runner defaults: ablation 40, recovery 30, baseline 60, content_taint 60, fars_loop 40.",
           "-IncludeSweep adds run_fars_loop_sweep_v2 (n=40, all sections). It is the ONLY source for the README's multiplier / chain-length claims,",
           "and the shipped fars_loop_sweep_v2.json no longer contains the 'chain' section, so this re-run is what regenerates that evidence.",
           "Results land in experiments\results_rerun_full_<stamp>. Nothing in experiments\results is overwritten.")
  Test-RepoVenv; Push-Location $Root
  $out = Join-Path $Root ("experiments\results_rerun_full_" + (Get-Date -Format "yyyyMMdd_HHmm"))
  New-Item -ItemType Directory -Path $out -Force | Out-Null
  $runs = @("run_ablation", "run_recovery", "run_baseline_comparison", "run_content_taint", "run_fars_loop")
  if ($IncludeSweep) {
    if (Test-Path "experiments\run_fars_loop_sweep_v2.py") { $runs += "run_fars_loop_sweep_v2" }
    else { Warn "experiments\run_fars_loop_sweep_v2.py not in this tree" "the v1 sweep is superseded (README: do not cite it). Copy optional_sweep_v2\ over the tree, then re-run." ; $IncludeSweep = $false }
  }
  foreach ($r in $runs) {
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $null = Invoke-Logged $r { & $Py -m "experiments.$r" --out $out }
    Check "$r exit 0" ($script:LastExit -eq 0) ("{0:N1} min" -f $sw.Elapsed.TotalMinutes)
  }
  $null = Invoke-Logged "benign" { & $Py -m experiments.check_content_taint_benign --n 30 --out $out }
  if ($IncludeSweep) {
    $j = Get-Content (Join-Path $out "fars_loop_sweep_v2.json") -Raw | ConvertFrom-Json
    $chainKeys = @($j.chain.PSObject.Properties).Count
    Check "sweep JSON has a populated 'chain' section" ($chainKeys -gt 0) "chain lengths: $chainKeys"
  }
  Write-Host "Results: $out"
  Pop-Location; Finish
}

if ($Step -eq 'report') {
  Head "report: summary of everything saved under the evidence folder"
  Test-RepoTree
  if (-not (Test-Path $Evidence)) { Write-Host "No evidence folder yet ($Evidence)."; exit 1 }
  $files = Get-ChildItem $Evidence -File | Sort-Object Name
  Write-Host ("{0} evidence files in {1}" -f $files.Count, $Evidence)
  $files | Select-Object Name, Length | Format-Table -AutoSize
  $f = Get-ChildItem $Evidence -Filter "*pytest*" | Select-Object -Last 1
  if ($f) { Write-Host "--- last pytest summary line:"; Select-String -Path $f.FullName -Pattern "passed|failed" | Select-Object -Last 1 | ForEach-Object { $_.Line } }
  Write-Host "Zip the whole evidence folder and send it."
}
