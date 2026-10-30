<# day1_resilience.ps1 -- run the numbered blocks below IN ORDER, one at a time, from the repo root with
# your .venv active. This does NOT modify farf_run.ps1; it reuses its config variables and conventions but
# stands alone, so a mistake here cannot silently corrupt your existing runner. Save this file if you like,
# or just paste each numbered block into your terminal.
#
# WHY STANDALONE: I do not have your current farf_run.ps1 in full (it has grown steps -- recover,
# lambda-adr011 -- since the copy I hold). Rather than guess at its internals and risk silently reverting a
# fix (as nearly happened with pentest_cloud/bus_service.py -- see Step 0), every value below is either
# read directly from YOUR file at run time, or asked of you to confirm before anything is deployed.

# ============================================================================================
# STEP 0 (2 min) -- confirm your runner's current deploy config, and that it still matches what
# this plan assumes. Do not skip this: if $BusTag has moved past v4-adr010 since 22 Sep, or the
# project/region differ, everything below needs those values, not mine.
# ============================================================================================
Select-String -Path farf_run.ps1 -Pattern '^\$Project\s*=|^\$Region\s*=|^\$Service\s*=|^\$BusTag\s*=|^\$GcpRepo\s*='
# EXPECT (from the copy of farf_run.ps1 I have; CONFIRM yours matches, don't assume):
#   $Project   = "<GCP_PROJECT_ID>"
#   $Region    = "asia-south1"
#   $Service   = "<farf-prototype>-bus"
#   $BusTag    = "v4-adr010"
#   $GcpRepo   = "asia-south1-docker.pkg.dev/<GCP_PROJECT_ID>/<GCP_REPO_ID>"
# If ANY line differs from what's above, substitute YOUR values everywhere below -- do not proceed on mine.

$Project = "<GCP_PROJECT_ID>"      # <-- overwrite these four with Step 0's real output if different
$Region  = "asia-south1"
$Service = "<farf-prototype>-bus"
$GcpRepo = "asia-south1-docker.pkg.dev/<GCP_PROJECT_ID>/<GCP_REPO_ID>"
$FixTag  = "v6-resilience-mttr"    # a NEW tag, deliberately distinct from v4/v5, so this never collides
                                    # with an existing image and can be rolled back to by re-deploying the old tag

# ============================================================================================
# STEP 1 (5 min) -- apply the three code changes and the two bus_service.py copies together.
# Expand the kit, then verify BOTH copies are identical before building anything (this is the
# exact mistake I found and fixed on my end: the two copies had diverged).
# ============================================================================================
Expand-Archive day1_resilience_artifacts.zip -DestinationPath . -Force
Copy-Item docker\bus_service.py pentest_cloud\bus_service.py -Force
$identical = (Get-FileHash docker\bus_service.py).Hash -eq (Get-FileHash pentest_cloud\bus_service.py).Hash
Write-Host "docker/ and pentest_cloud/ copies of bus_service.py identical: $identical"
# EXPECT: True. If False, stop -- do not build.

python -m pytest -q tests/test_17_reinstatement_is_identity_not_behaviour_gated.py
# EXPECT: 2 passed
ruff check .
# EXPECT: All checks passed!

# ============================================================================================
# STEP 2 (10-12 min) -- your OWN existing -Step bus-fix does exactly this: build, push, deploy
# to a NEW revision, THEN automatically drive PT08Org into quarantine once and recover it once.
# Confirmed against your actual farf_run.ps1: bus-fix is generic (uses $FixTag, not a hardcoded
# historical tag) and its precondition check looks for a DIFFERENT, older fix string in
# federation_bus.py -- unrelated to today's change, so it will still pass. This gives you TRIAL 1
# of 5 for free. min-instances=1: THE COST METER STARTS HERE.
# ============================================================================================
.\farf_run.ps1 -Step bus-fix -FixTag $FixTag
# Passing -FixTag explicitly matters: farf_run.ps1 defaults $FixTag to "v5-recovery-fix" (the SAME tag
# your earlier PT-08 fix session used) if you don't override it. Reusing that name would still work
# (Cloud Run deploys by digest, not tag text) but makes today's build indistinguishable from the old
# one in your evidence logs -- pass a fresh tag so "which build is this" stays traceable.
# EXPECT: same "reinstatement committed at witness N of M" / "lifted: yes" / "DURABLE" sequence
# you've seen before, now on a revision that also serves /resilience_timing. If the pre-flight
# check "federation_bus.py in this folder is the PATCHED version" FAILS, that file itself hasn't
# changed today (only bus_service.py/recovery_probe.py/fars.py did) -- do not touch federation_bus.py
# to "fix" this; send me the exact failure text instead.

$url = Get-BusUrl
Invoke-RestMethod -Uri "$url/resilience_timing" -TimeoutSec 10 | ConvertTo-Json -Compress
# EXPECT: {"count":2,"mean_seconds":X.XXXX,"min_seconds":X.XXXX,"max_seconds":X.XXXX,"completed":[...]}
# count=2 because bus-fix's own quarantine+recovery cycle touches both the org key and its agent key.
# If this 404s, the deploy did not pick up the patched bus_service.py -- stop and check Step 1.
#>
# ============================================================================================
# STEP 3 (~15-20 min) -- FOUR MORE independent reinstatement trials (bus-fix already gave you
# one), to turn Table 6.4's n=2 into n=5 with real Mean-Time-To-Recovery data.
# ============================================================================================
$ev = ".\evidence_$(Get-Date -Format yyyyMMdd)"
New-Item -ItemType Directory -Force -Path $ev | Out-Null
$trials = @()
for ($t = 2; $t -le 5; $t++) {
    Write-Host "=== Trial $t of 5 (trial 1 already ran inside -Step bus-fix above) ==="
    $quarantined = $false
    for ($i = 1; $i -le 8 -and -not $quarantined; $i++) {
        $out = python pentest_cloud\pt08_session_hijack_cloud.py --url $url 2>&1
        $out | Out-File "$ev\day1_trial${t}_pt08_run${i}.txt"
        if ($out -match "org_wide_behavioural_drift") { $quarantined = $true }
    }
    Write-Host "PT08Org quarantined after $i PT-08 runs: $quarantined"
    # EXPECT: True, usually within 1-4 runs (the org's volume window carries over from the previous trial's
    # traffic too, so later trials often quarantine faster than the first).

    Write-Host "--- recovering ---"
    $probeOut = python aws_pilot\recovery_probe.py --url $url --org PT08Org 2>&1
    $probeOut | Out-File "$ev\day1_trial${t}_recovery_probe.txt"
    $probeOut | Select-String "recovery time|committed at witness|lifted:|FARS after"
    # EXPECT per trial: "reinstatement committed at witness N of M (quorum N)", "lifted: yes",
    # "recovery time (quarantine -> reinstatement) for PT08Org: X.XXXXs"

    $timing = Invoke-RestMethod -Uri "$url/resilience_timing" -TimeoutSec 10
    $trials += [pscustomobject]@{ trial = $t; count_so_far = $timing.count; mean_seconds = $timing.mean_seconds
                                  min_seconds = $timing.min_seconds; max_seconds = $timing.max_seconds }
    Start-Sleep 3   # brief pause between trials; not required, just polite to the shared deployment
}
$trials | Format-Table
$trials | Export-Csv "$ev\day1_reinstatement_mttr_trials.csv" -NoTypeInformation
# EXPECT: count climbs 2, 4, 6, 8, 10 (each trial's probe both quarantines and recovers TWO entries: the org
# and its own key -- see the /resilience_timing sample output in the previous message). mean/min/max settle
# once all 5 trials have run. If any trial's "lifted:" says "no", STOP and send me that trial's log --
# that would be a genuine regression, not expected variance.

# ============================================================================================
# STEP 4 (5 min) -- cross-platform evidence aggregation against your REAL evidence folder, not
# my /tmp test. Point it at every evidence_* folder you want summarised, or just today's.
# ============================================================================================
python tools\cross_platform_summary.py --evidence-dir $ev --out "$ev\day1_cross_platform_summary.json"
Get-Content "$ev\day1_cross_platform_summary.json"
# EXPECT: valid JSON. "wan_send_latency" will likely say "no matching latency/load evidence file found" for
# TODAY's folder specifically, since today's evidence is PT-08/recovery transcripts, not a -Step load run --
# that's correct, not a bug. To get a real number here, also point --evidence-dir at your 25 Sep folder:
python tools\cross_platform_summary.py --evidence-dir .\evidence_20260925 --out ".\evidence_20260925\cross_platform_summary.json"
# EXPECT: "lambda_cold_start": {"n": 5, "init_ms_mean": 343.76, ...} -- if this number differs from 343.76,
# your evidence_20260925 folder has files I have not seen; that's fine, just note the new number.

# ============================================================================================
# STEP 5 (15-20 min) -- statefulness audit of PT-01 and PT-02: are they vulnerable to the SAME
# class of defect as PT-08 (fixed identifiers, or reuse across repeated runs against one
# persistent deployment)? This is mostly reading, not running.
# ============================================================================================
Select-String -Path pentest_cloud\pt01_identity_spoofing_cloud.py -Pattern 'uuid|run_id|OrgA"|"PT01Org"' -Context 0,1
Select-String -Path pentest_cloud\pt02_field_omission_bypass_cloud.py -Pattern 'uuid|run_id|OrgA"|"PT02Org"' -Context 0,1
# EXPECT: look for whether agent/org names include a uuid4/run_id suffix (safe, like the fixed PT-08) or are
# hardcoded literals (potentially vulnerable, like the ORIGINAL PT-08 before ADR-018). PT-01 and PT-02 use a
# structural-registration / incomplete-schema attack respectively, neither of which accumulates taint the
# way PT-08's legitimate sends do, so my expectation is BOTH are clean -- but confirm rather than assume.
# Paste me what these two commands print and I'll write the one-paragraph audit finding for Section 5.11.4.

# ============================================================================================
# STEP 6 (2 min) -- stop the cost meter, using your own existing step.
# ============================================================================================
.\farf_run.ps1 -Step cool
# EXPECT: [PASS] min instances is 0, [PASS] no ECS tasks running, [PASS] partition SG has its 2 rules.

Write-Host ""
Write-Host "Send me: $ev\day1_reinstatement_mttr_trials.csv, the cross_platform_summary.json from BOTH"
Write-Host "evidence folders, and Step 5's two Select-String outputs. I will fold all four into Table 6.4"
Write-Host "and Section 5.11.4 as a final pass."
