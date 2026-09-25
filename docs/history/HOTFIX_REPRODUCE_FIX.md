# Reproducing the FARF prototype build

Three levels, cheapest first. Levels 1 and 2 need no cloud account.

## Level 1: local build, tests and gates (about 2 minutes)

```
python -m venv .venv
.venv\Scripts\activate            # Windows;  source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt   # CI uses Python 3.11
python -m pytest                  # expect: 115 passed
ruff check .                      # expect: All checks passed (rules and rationale: pyproject.toml)
python tools/farf_security_lint.py   # expect: 0 HIGH CONFIDENCE findings (6 low-confidence notes are known)
```

Known side effect: `tests/test_06_tab78_evaluation_metrics.py` regenerates `tab78_evaluation_report.csv`
(it is the generator of the cited artefact, and one row is a timing mean that varies per run). After a test run,
`git checkout -- tab78_evaluation_report.csv` unless you mean to refresh the cited value.

## Level 2: containerised federation on one machine

```
docker compose -f docker/docker-compose.yml up --build
```
See `docker/README.md`. The image copies the repository (`COPY . /app`), so `.dockerignore` keeps evidence,
scripts and build output out of it.

## Level 3: cross-cloud pilot (AWS Fargate + GCP Cloud Run; costs money; needs your own accounts)

Driven by `farf_run.ps1` (Windows PowerShell 5.1), one step per invocation, in the order in `NEXT_STEPS_GUIDE.md`.

# Reproducing the FARF prototype build

Three levels, cheapest first. Levels 1 and 2 need no cloud account.

## Level 1: local build, tests and gates (about 2 minutes)

```
python -m venv .venv
.venv\Scripts\activate            # Windows;  source .venv/bin/activate on Linux/macOS
pip install -r requirements.txt   # CI uses Python 3.11
python -m pytest                  # expect: 115 passed
ruff check .                      # expect: All checks passed (rules and rationale: pyproject.toml)
python tools/farf_security_lint.py   # expect: 0 HIGH CONFIDENCE findings (6 low-confidence notes are known)
```

Known side effect: `tests/test_06_tab78_evaluation_metrics.py` regenerates `tab78_evaluation_report.csv`
(it is the generator of the cited artefact, and one row is a timing mean that varies per run). After a test run,
`git checkout -- tab78_evaluation_report.csv` unless you mean to refresh the cited value.

## Level 2: containerised federation on one machine

```
docker compose -f docker/docker-compose.yml up --build
```
See `docker/README.md`. The image copies the repository (`COPY . /app`), so `.dockerignore` keeps evidence,
scripts and build output out of it.

## Level 3: cross-cloud pilot (AWS Fargate + GCP Cloud Run; costs money; needs your own accounts)

Driven by `farf_run.ps1` (Windows PowerShell 5.1), one step per invocation, in the order in `NEXT_STEPS_GUIDE.md`.
See `PILOT_STATUS.md` for which steps are currently confirmed working against the live deployment versus still open.

**Run-order rule (PT-08 budget).** The bus quarantines an organisation whose last 40 messages sum to more than 0.35 taint
(`SlidingWindowVolumeDetector(window=40, cap=0.35)`, the PT-04 Sybil fix). PT-08 sends 2 legitimate 0.05-taint messages per
run from `PT08Org`, so the **4th PT-08 run against one bus revision** quarantines it: Step C's legitimate message comes back
`quarantine / org_wide_behavioural_drift`. That is exhausted bus state, not a defence failure (the script reports it as
`INCONCLUSIVE`, exit 3). `-Step orgs8` uses 2 runs and `-Step load` uses 2, so run `-Step warm` (new revision, clean state)
between them. `-Step orgs8` also needs a fresh bus (fewer than 8 organisations registered) and fails its first check otherwise.
Confirmed on the live deployment on 24 and 25 Sep 2026 (two independent `-Step load` runs, `run_id=a318c663` and
`run_id=6060ede9`/`31f1e9e2`): the exhausted-window case is correctly reported `INCONCLUSIVE (not VULNERABLE)`, and the
runner's own pass check (a case-insensitive match on "not vulnerable") correctly treats that as `[PASS]`.

If `PT08Org` is already quarantined **before your run even starts** (Step A itself comes back `quarantine`, and every
step after it comes back `unadmitted_identity`), that means an earlier session already used up the organisation's
volume budget and never got a fresh bus in between. Run `-Step warm` before repeating `-Step load`, or use
`-Step recover` (below) if you need to keep the current bus state rather than start a new revision.

**Recovering a quarantined `PT08Org` without a fresh revision:** `-Step recover` performs a quorum-witnessed
reinstatement of `PT08Org` on the live bus, then runs PT-08 v3 (which uses a fresh, disposable organisation,
`PT08OrgV3`, precisely so it is not affected by `PT08Org`'s quarantine state) twice to confirm the deployed code
still behaves correctly. **This step needs both** `pentest_cloud/pt08_session_hijack_cloud.py` **and**
`pentest_cloud/pt08_session_hijack_cloud_FIXED_v3.py` **to be present** — losing either one (for example, by hand-deleting
it as an apparent duplicate during a repo clean-up) fails the step's own prerequisite check before it does anything
on the cloud side. Both are tracked in git and neither is matched by any `.gitignore` pattern; if the check still
fails, confirm the file is actually present on disk (`Test-Path pentest_cloud\pt08_session_hijack_cloud_FIXED_v3.py`)
before assuming the check itself is wrong.

The committed scripts carry the identifiers of the original pilot (AWS account, region `ap-south-1`, subnet,
security group, Cloud Run URL). To reproduce with your own accounts, replace them in:
`farf_run.ps1` (config block, top), `aws_pilot/task-def*.json`, `lambda-environment.json`.
`tools/scrub_pilot_ids.py` swaps the original identifiers for placeholders (dry-run by default).

Lambda worker (ADR-011): `aws_pilot/lambda_agent_worker.py`, handler `lambda_agent_worker.handler`, dependency
`requests` only. Build for the Lambda (Linux) target, not the developer machine:
```
pip install requests --platform manylinux2014_x86_64 --only-binary=:all: --target lambda_build
copy aws_pilot\lambda_agent_worker.py lambda_build\        (cp on Linux/macOS)
# zip the CONTENTS of lambda_build/ with forward-slash paths (e.g. `python -m zipfile -c lambda_function.zip lambda_build/*`
# from inside the folder, or 7-Zip); do not use a tool that stores backslash paths.
```
The original zip was built on Windows with Python 3.14 wheels (`win_amd64`), which is not portable.

Shipping a handler-only change without rebuilding the dependencies: `python tools/patch_lambda_zip.py --zip lambda_function.zip
--handler aws_pilot/lambda_agent_worker.py --out build/lambda_function_cold_flag.zip` (every other entry is copied byte for byte),
then `aws lambda update-function-code --function-name <farf-prototype>-agent-worker --zip-file fileb://build/lambda_function_cold_flag.zip`.
Before patching, confirm the local zip is what is deployed: its base64 SHA-256 must equal the function's `CodeSha256`.

**Cold-start evidence.** The handler reports `likely_cold_start` = first invocation served by that execution environment (module-scope
flag). Its `total_wall_clock_ms` starts when the handler starts, so it **excludes Lambda's Init phase**. The cold-start cost is the
`Init Duration` field of the CloudWatch `REPORT` line, present only on a cold start: capture it with
`aws lambda invoke ... --log-type Tail` and cite that figure. The earlier `/proc/uptime < 5 s` proxy never fired and was removed.

**Confirmed (25 Sep 2026), n=5, `evidence_20260925/cold_report_1.txt`–`cold_report_5.txt` paired with `cold_loop_1.json`–`cold_loop_5.json`:**
every sample correctly shows `likely_cold_start: true` / `first_invocation_in_environment: true` on the handler side, with a real
`Init Duration` on the matching CloudWatch report every time (the `update-function-configuration` trick in step 6 above forces a
new execution environment reliably). **Init Duration: mean 343.8 ms, range 291.3–396.7 ms.** Billed Duration ≈ Duration + Init
Duration rounded up (checked on all 5: e.g. sample 1, 330.63 + 366.83 → billed 698 ms), confirming Lambda is billing the cold-start
cost, not just handler time. This is the ADR-011 figure — cite it instead of `container_uptime_seconds`, which is not a cold-start
signal (see the field's own description in the handler's docstring).

**Open issue, not yet fixed:** on a live `-Step lambda-adr011` run (25 Sep 2026), the handler's own two invokes were correct
(`likely_cold_start: true` then `false`), but the step's `[FAIL] invoke 1 shows a cold start, invoke 2 does not` check still fired.
The check's source has not been reviewed — it predates the copy of `farf_run.ps1` in this repository, which has no `lambda-adr011`
step at all — so it most likely still derives cold-vs-warm itself from `container_uptime_seconds` independently of the field the
handler now reports, rather than reading `likely_cold_start`. Until that check is patched, judge this step by the JSON body content,
not by its `[PASS]`/`[FAIL]` line. See `PILOT_STATUS.md`.

**Egress load generator (`gcp_pilot/egress_load_test.py`).** Now retries transient network failures (up to 3 attempts) during its
1000-message loop instead of crashing the whole run on one timeout — see `tests/test_16_egress_load_retry.py` for the
verification against a deliberately flaky fake server. **Not yet confirmed on the live deployment**: the original crash (24-25 Sep
2026, `ReadTimeoutError` during `-Step load`) has not been reproduced against Cloud Run since the fix, because it was intermittent
to begin with. Treat this as fixed-and-unit-tested, not fixed-and-field-confirmed, until a `-Step load` run reports a "Done in
...s, N errors" line where a genuine transient failure occurred (N will be small and nonzero, which is the fix working, not a
new problem).

## Evidence and results

Cloud run output (`evidence_<date>/`, `precheck_*`) is not in git: it contains account ids, source IPs and an
e-mail address. See `evidence/README.md`. Small, cited result files that are safe to publish
(`*_evaluation_report*.csv`, `statistical_validation_report.csv`, `validation/results/*.json`) are committed.

**Run-order rule (PT-08 budget).** The bus quarantines an organisation whose last 40 messages sum to more than 0.35 taint
(`SlidingWindowVolumeDetector(window=40, cap=0.35)`, the PT-04 Sybil fix). PT-08 sends 2 legitimate 0.05-taint messages per
run from `PT08Org`, so the **4th PT-08 run against one bus revision** quarantines it: Step C's legitimate message comes back
`quarantine / org_wide_behavioural_drift`. That is exhausted bus state, not a defence failure (the script reports it as
`INCONCLUSIVE`, exit 3). `-Step orgs8` uses 2 runs and `-Step load` uses 2, so run `-Step warm` (new revision, clean state)
between them. `-Step orgs8` also needs a fresh bus (fewer than 8 organisations registered) and fails its first check otherwise.

The committed scripts carry the identifiers of the original pilot (AWS account, region `ap-south-1`, subnet,
security group, Cloud Run URL). To reproduce with your own accounts, replace them in:
`farf_run.ps1` (config block, top), `aws_pilot/task-def*.json`, `lambda-environment.json`.
`tools/scrub_pilot_ids.py` swaps the original identifiers for placeholders (dry-run by default).

Lambda worker (ADR-011): `aws_pilot/lambda_agent_worker.py`, handler `lambda_agent_worker.handler`, dependency
`requests` only. Build for the Lambda (Linux) target, not the developer machine:
```
pip install requests --platform manylinux2014_x86_64 --only-binary=:all: --target lambda_build
copy aws_pilot\lambda_agent_worker.py lambda_build\        (cp on Linux/macOS)
# zip the CONTENTS of lambda_build/ with forward-slash paths (e.g. `python -m zipfile -c lambda_function.zip lambda_build/*`
# from inside the folder, or 7-Zip); do not use a tool that stores backslash paths.
```
The original zip was built on Windows with Python 3.14 wheels (`win_amd64`), which is not portable.

Shipping a handler-only change without rebuilding the dependencies: `python tools/patch_lambda_zip.py --zip lambda_function.zip
--handler aws_pilot/lambda_agent_worker.py --out build/lambda_function_cold_flag.zip` (every other entry is copied byte for byte),
then `aws lambda update-function-code --function-name <farf-prototype>-agent-worker --zip-file fileb://build/lambda_function_cold_flag.zip`.
Before patching, confirm the local zip is what is deployed: its base64 SHA-256 must equal the function's `CodeSha256`.

**Cold-start evidence.** The handler reports `likely_cold_start` = first invocation served by that execution environment (module-scope
flag). Its `total_wall_clock_ms` starts when the handler starts, so it **excludes Lambda's Init phase**. The cold-start cost is the
`Init Duration` field of the CloudWatch `REPORT` line, present only on a cold start: capture it with
`aws lambda invoke ... --log-type Tail` and cite that figure. The earlier `/proc/uptime < 5 s` proxy never fired and was removed.

## Evidence and results

Cloud run output (`evidence_<date>/`, `precheck_*`) is not in git: it contains account ids, source IPs and an
e-mail address. See `evidence/README.md`. Small, cited result files that are safe to publish
(`*_evaluation_report*.csv`, `statistical_validation_report.csv`, `validation/results/*.json`) are committed.
