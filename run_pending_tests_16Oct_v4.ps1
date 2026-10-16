# FARF v7.9.11 - run list v4 (16 Oct 2026). Adds T4b and T5long and re-runs Preflight on the tagged tree. T3, T4, T5, T6, T7 and FARSrank are already done.
# Usage from the repo root, after unzipping farf_rev7_bundle.zip over the repo:
#   Unblock-File .\run_pending_tests_16Oct_v4.ps1
#   .\run_pending_tests_16Oct_v4.ps1 -Step Patch
# Changes from v2: Patch step added; FARSrank now runs fars_rank_without_connectivity.py (v2 ran the wrong tool);
# one results folder per day (Pack no longer zips an empty folder); skipped/failed steps are reported as such;
# Commit stages an explicit file list instead of git add -A; pytest summary line is no longer suppressed.
param(
  [Parameter(Mandatory=$true)]
  [ValidateSet('Preflight','Patch','T3','T4','T4b','T5','T5long','T6','T7','FARSrank','Commit','Pack')]
  [string]$Step,
  [string]$Root = (Get-Location).Path
)
$ErrorActionPreference = 'Continue'
Set-Location $Root
$day   = Get-Date -Format 'yyyyMMdd'
$out   = Join-Path $Root "results_rerun_$day"
New-Item -ItemType Directory -Force -Path $out | Out-Null
$script:status = 'Done'
function Log($m) { Write-Host "[$((Get-Date).ToString('HH:mm:ss'))] $m" }
function Need($p) { if (-not (Test-Path $p)) { Write-Warning "Missing: $p. Step skipped."; $script:status = 'SKIPPED'; return $false }; return $true }
function Check($name) { if ($LASTEXITCODE -ne 0) { Write-Warning "$name exited with code $LASTEXITCODE"; $script:status = 'FAILED' } }

switch ($Step) {

'Preflight' {
  git rev-parse HEAD      | Tee-Object "$out\git_commit.txt"
  git status --short      | Tee-Object "$out\git_status.txt"
  python --version        | Tee-Object "$out\python_version.txt"
  ruff check .            | Tee-Object "$out\lint.txt"
  # no extra -q: pyproject already sets -q, and a second one removes the "N passed" line. Expect 142 passed, 2 skipped.
  python -m pytest -rs    | Tee-Object "$out\pytest.txt"
}

'Patch' {
  # Adds scale-default, patient, patient-identity profiles to tools\local_profiles.py. Safe to run twice.
  if (Need 'tools\apply_rev7_patch.py') {
    python tools\apply_rev7_patch.py --check; Check 'patch check'
    if ($script:status -eq 'Done') { python tools\apply_rev7_patch.py; Check 'patch' }
  }
}

'T3' {   # about 2-3 min. Guard-evasion; informational (read the cost lines).
  if (Need 'experiments\run_guard_evasion.py') {
    python -m experiments.run_guard_evasion --n 20 --out "$out\T3" 2>&1 | Tee-Object "$out\T3_console.txt"; Check 'T3'
  }
}

'T4' {   # about 10-15 min. PT-23 with jittered thresholds. Control (j=0) must PASS; the rest is the curve.
  if (Need 'pentest\pt23_jitter.py') {
    python pentest\pt23_jitter.py --jitter 0.10,0.20,0.40 --n 30 --out "$out\T4" 2>&1 | Tee-Object "$out\T4_console.txt"; Check 'T4'
  }
}

'T4b' {   # about 6-10 min. Attacker who knows the jitter range and backs off. Informational.
  if (Need 'pentest\pt23_jitter_retreat.py') {
    python pentest\pt23_jitter_retreat.py --jitter 0.10,0.20,0.40 --n 30 --msgs 400 --out "$out\T4b" 2>&1 | Tee-Object "$out\T4b_console.txt"; Check 'T4b'
  }
}

'T5long' {   # about 17 min. Same scenario, 300 s per attacker, for larger counts. Optional.
  if ((Need 'pentest_cloud\v11_collusion_patient_cloud.py') -and (Select-String -Path tools\local_profiles.py -Pattern 'patient-identity' -Quiet)) {
    $env:FARF_PATIENT_HORIZON = '300'
    python tools\local_profiles.py --profile patient          --cooling-off 20 --out "$out\T5long_gated"    2>&1 | Tee-Object "$out\T5long_gated_console.txt";    Check 'T5long gated'
    python tools\local_profiles.py --profile patient-identity --cooling-off 20 --out "$out\T5long_identity" 2>&1 | Tee-Object "$out\T5long_identity_console.txt"; Check 'T5long identity'
    Select-String -Path "$out\T5long_gated_console.txt","$out\T5long_identity_console.txt" -Pattern 'SUMMARY' | ForEach-Object { $_.Line } | Tee-Object "$out\T5long_summary.txt"
  } else { Write-Warning 'Run -Step Patch first.'; $script:status = 'SKIPPED' }
}

'T5' {   # about 8 min. Real clock, cooling-off 20 s, horizon 120 s per attacker.
  if ((Need 'pentest_cloud\v11_collusion_patient_cloud.py') -and (Select-String -Path tools\local_profiles.py -Pattern 'patient-identity' -Quiet)) {
    $env:FARF_PATIENT_HORIZON = '120'
    python tools\local_profiles.py --profile patient          --cooling-off 20 --out "$out\T5_gated"    2>&1 | Tee-Object "$out\T5_gated_console.txt";    Check 'T5 gated'
    python tools\local_profiles.py --profile patient-identity --cooling-off 20 --out "$out\T5_identity" 2>&1 | Tee-Object "$out\T5_identity_console.txt"; Check 'T5 identity'
    Select-String -Path "$out\T5_gated_console.txt","$out\T5_identity_console.txt" -Pattern 'SUMMARY' | ForEach-Object { $_.Line } | Tee-Object "$out\T5_summary.txt"
    # Expected order of delivered: identity/immediate > gated/patient > gated/immediate. No reinstatement below quorum in either mode.
  } else { Write-Warning 'Run -Step Patch first.'; $script:status = 'SKIPPED' }
}

'T6' {   # about 2 min. Default-setting HTTP check (taint source unset).
  if (-not (Select-String -Path tools\local_profiles.py -Pattern 'scale-default' -Quiet)) { Write-Warning 'Run -Step Patch first.'; $script:status = 'SKIPPED'; break }
  python tools\local_profiles.py --profile scale-default --texts data\heldout\D_benign.txt --out "$out\T6" 2>&1 | Tee-Object "$out\T6_console.txt"; Check 'T6'
  # CAUTION for Ch5: 0 of 1,200 refused is expected and is vacuous. With the default (declared) taint source the bus does not inspect
  # message text; the legacy detector runs inside the agent's plan() step (that is where the G10 63% comes from).
  # Write: "Over HTTP at the default setting the bus does not inspect text, so all 1,200 were delivered by construction."
}

'T7' {   # about 3 min. FARS vs an outcome measured from send decisions, 60 topologies.
  if (Need 'experiments\run_fars_topologies.py') {
    python -m experiments.run_fars_topologies --n 60 --out "$out\T7" 2>&1 | Tee-Object "$out\T7_console.txt"; Check 'T7'
  }
}

'FARSrank' {   # connectivity-free re-scoring (the rank check), not the sensitivity sweep
  if (Need 'tools\fars_rank_without_connectivity.py') {
    python tools\fars_rank_without_connectivity.py 2>&1 | Tee-Object "$out\FARSrank_console.txt"; Check 'FARSrank'
  }
}

'Commit' {   # run last, after the steps above. Stages code only; results go in the evidence zip.
  $files = @('pentest/pt23_jitter_retreat.py','run_pending_tests_16Oct_v4.ps1','experiments/run_guard_evasion.py','experiments/run_fars_topologies.py','pentest/pt23_jitter.py',
             'pentest_cloud/v11_collusion_patient_cloud.py','tools/apply_rev7_patch.py','tools/local_profiles.py',
             'run_pending_tests_16Oct_v4.ps1')
  git add -- $files
  git status --short
  Log 'Not staged on purpose: _bundle6/, results_rerun_*/, docker/bus_service.py, tab78_evaluation_report.csv (review those yourself).'
  Log 'If the staged list looks right run:  git commit -m "rev7b: range-aware jitter attacker, run list v4"  ; git tag v7.9.11c   (do not move v7.9.11b)'
}

'Pack' {
  $zip = "evidence_v7911_local_$day.zip"
  $dirs = Get-ChildItem -Directory -Filter "results_rerun_$day*" | ForEach-Object { $_.FullName }
  Compress-Archive -Path $dirs -DestinationPath $zip -Force
  Get-FileHash $zip -Algorithm SHA256 | Tee-Object "$out\SHA256.txt"
  # Redact account IDs and addresses before sharing the archive.
}
}
Log "$($script:status): $Step -> $out"
