# ADR-006 Option 3 Pilot — Cloud Run + Cloud KMS Walkthrough

**This is the first step in this project that spends real money.** Every
previous session (Docker, N_REPEATS, ADR-004) was free — local compute
only. Read the budget section before Step 1.

## What this pilot proves (and doesn't)

Validates `CLOUD_PROVIDER_COMPARISON.md`'s published-rate-card estimates
against real GCP billing for the three things Option 3 named: Cloud Run
always-on cost (`min-instances=1`, satisfying ADR-006's availability
requirement), real Cloud KMS signing latency (Ed25519, matching FARF's
existing DID key algorithm — a like-for-like comparison, not an
approximation), and real egress cost at pilot scale.

**Does not** wire Cloud KMS into `trust_protocol.py`/`FederationBus` —
that's a much larger change (ADR-003's actual scope) than a pilot should
attempt. The KMS probe calls the `AsymmetricSign` API directly and times
it, decoupled from the running federation-bus. **Does not** test
cross-cloud partition behaviour (ADR-004's Docker tests already covered
the quorum-logic side of that on a single host; real WAN partition
between two actual clouds is a later, larger step).

## Budget guardrails — read first

Real, current (2026) rates found for this pilot:
- **Cloud Run, `min-instances=1`**, standard memory: roughly **$5–12/month**
  if left running continuously — call it **$0.20–0.40/day**. Not
  expensive, but not free like everything before this.
- **Cloud KMS**: an active Ed25519 (elliptic-curve) key version costs
  about **$0.06/month** prorated hourly (~$0.002/day) just for existing,
  plus **$0.03 per 10,000** sign operations — a few hundred pilot sign
  calls costs a fraction of a cent.
- **Egress**: **$0.12/GB** (Premium Tier) after the first 1GB/month free —
  a pilot load test sending a few hundred small JSON messages will not
  come close to 1GB.

**Total realistic pilot cost if torn down within a day or two: well under
$1.** The risk isn't the pilot itself — it's forgetting to tear it down
and Cloud Run running `min-instances=1` for weeks unnoticed. Two concrete
guards, do both before Step 1:

1. **Set a budget alert** in the GCP Console (Billing → Budgets & alerts)
   — e.g., alert at $5. Takes 2 minutes, catches the "forgot to tear
   down" failure mode specifically.
2. **Follow the teardown step at the end every time**, not just when
   fully done — if you pause partway through, tear down first and redeploy
   later rather than leaving `min-instances=1` running idle overnight.

## Step -1 — Install the Google Cloud CLI (if `gcloud` isn't recognized)

If `gcloud auth login` fails with `The term 'gcloud' is not recognized`,
the CLI itself isn't installed yet — this is separate from your GCP
project/billing, nothing to do with the pilot logic. Two options:

**Option A — winget (fastest, same PowerShell window):**
```powershell
winget install --id Google.CloudSDK -e
```
**Expect:** a download/install progress bar (~1-2 minutes), ending with
`Successfully installed`. **Close and reopen your PowerShell/VS Code
terminal afterwards** — the installer updates your PATH, but the current
terminal session won't pick that up until it's restarted.

**Option B — interactive installer**, if winget isn't available:
download from `https://cloud.google.com/sdk/docs/install` and run the
`.exe`. During the wizard, leave "Start Google Cloud CLI shell" and "Run
`gcloud init`" checked — it'll walk you through login and project setup
automatically at the end.

**Verify it worked**, in a fresh terminal:
```powershell
gcloud --version
```
**Expect:** a version block (`Google Cloud SDK ...`, `bq ...`, etc.), not
the "not recognized" error. Once this works, continue at Step 0 below.

**Also run this now** — it's easy to miss and causes a
`DefaultCredentialsError` at Step 4 if skipped:
```powershell
gcloud auth application-default login
```
**Expect:** a browser window for the same Google sign-in, then
`Credentials saved to file: [...\AppData\Roaming\gcloud\application_default_credentials.json]`.
This is a **separate credential from `gcloud auth login`** — `gcloud auth
login` authenticates the CLI tool itself; Python libraries like
`google-cloud-kms` (used by `kms_latency_probe.py` in Step 4) don't read
that at all, they only read this second, distinct credential file. Both
are needed; running one does not create the other.

## Step 0 — Project setup

```powershell
gcloud auth login
gcloud projects create <farf-prototype>-2026 --name="FARF ADR-006 Pilot"
gcloud config set project <farf-prototype>-2026
gcloud beta billing projects link <farf-prototype>-2026 --billing-account=YOUR_BILLING_ACCOUNT_ID
```
**What to expect:** a browser window for auth, then the project creates in
a few seconds. Find `YOUR_BILLING_ACCOUNT_ID` with
`gcloud beta billing accounts list` if you don't have it handy.

Enable the APIs the pilot needs:
```powershell
gcloud services enable run.googleapis.com cloudkms.googleapis.com artifactregistry.googleapis.com
```
**Expect:** three `Operation finished successfully` lines, ~30-60s total.

**Now set the budget alert** (Console: Billing → Budgets & alerts → Create
Budget → this project → alert at $5) before continuing.

## Step 1 — Build and push the image

```powershell
gcloud auth configure-docker us-central1-docker.pkg.dev
gcloud artifacts repositories create <farf-prototype> --repository-format=docker --location=us-central1
```
**Expect:** repository created confirmation.

Replace `docker/Dockerfile` reference below with the attached
`Dockerfile.cloudrun` (copy it into your `docker/` folder, or build with
`-f`):
```powershell
docker build -f docker/Dockerfile.cloudrun -t us-central1-docker.pkg.dev/<farf-prototype>-2026/<farf-prototype>/federation-bus:v1 .
docker push us-central1-docker.pkg.dev/<farf-prototype>-2026/<farf-prototype>/federation-bus:v1
```
**Expect:** a normal Docker build (same layers you've seen before, this is
the same image plus one `CMD` line), then a push progress bar. First push
of the base Python layers takes a minute or two.

## Step 2 — Create the Cloud KMS Ed25519 key

```powershell
gcloud kms keyrings create <farf-prototype>-keyring --location=us-central1
gcloud kms keys create <farf-prototype>-org-a-key `
    --keyring=<farf-prototype>-keyring --location=us-central1 `
    --purpose=asymmetric-signing --default-algorithm=ec-sign-ed25519
```
**Expect:** keyring created, then key created with algorithm
`EC_SIGN_ED25519` shown in the output — this is the exact algorithm FARF's
own `Ed25519PrivateKey` already uses in-process, chosen specifically so
the latency comparison is like-for-like.

Grant your own account signing permission (needed for the latency probe):
```powershell
gcloud kms keys add-iam-policy-binding <farf-prototype>-org-a-key `
    --keyring=<farf-prototype>-keyring --location=us-central1 `
    --member="user:YOUR_EMAIL@example.com" `
    --role="roles/cloudkms.signerVerifier"
```

## Step 3 — Deploy to Cloud Run with min-instances=1

```powershell
gcloud run deploy <farf-prototype>-bus `
    --image=us-central1-docker.pkg.dev/<farf-prototype>-2026/<farf-prototype>/federation-bus:v1 `
    --region=us-central1 `
    --min-instances=1 --max-instances=1 `
    --allow-unauthenticated `
    --port=8080
```
**Expect:** a deploy progress indicator (~30-60s), ending with a
`Service URL: https://<farf-prototype>-bus-XXXXXXXXXX.us-central1.run.app` line —
save this URL, every following step needs it. `--max-instances=1` is
deliberate for the pilot: prevents autoscaling from spinning up (and
billing) more instances than intended. `--allow-unauthenticated` is fine
for a short-lived pilot only — never leave a real deployment open like
this.

Confirm it's actually up:
```powershell
curl https://YOUR-SERVICE-URL/health
```
**Expect:** the same `{"status": "ok", "quorum_mode": "pbft_dynamic"}`
shape you've seen from every prior Docker test — same code, different host.

## Step 4 — Real Cloud KMS signing latency

```powershell
pip install google-cloud-kms
python gcp_pilot\kms_latency_probe.py --project <farf-prototype>-2026 --location us-central1 --keyring <farf-prototype>-keyring --key <farf-prototype>-org-a-key --n-trials 100
```
**Expect:** a warm-up call latency line, then 100 timed calls, ending with
a three-point comparison table:
```
in-process (trust_protocol.py, no network):        ~0.150-0.166 ms
Docker bridge network (/send round trip):           ~11.69-11.71 ms
Real Cloud KMS AsymmetricSign (this script):         X.XXX ms
```
Expect the real KMS number to land somewhere in the tens-of-milliseconds
range (regional API call, not local) — likely higher than the Docker
bridge figure, since it's crossing the public internet to a Google
regional endpoint rather than a local bridge network.

## Step 5 — Egress load test

```powershell
python gcp_pilot\egress_load_test.py --url https://YOUR-SERVICE-URL --n-messages 500
```
**Expect:** registration confirmations, then a progress-free block of 500
requests (~10-30s depending on your connection), ending with a byte-count
summary and a predicted egress cost (almost certainly $0.00 — inside the
free tier at this volume).

**The next day**, check Billing Console → Reports → filter service to
"Cloud Run" and SKU to "Network Data Transfer" (or similar egress line).
Compare the actual charge (likely $0.00, possibly a few cents) against
this script's prediction.

## Step 6 — Teardown (do this every session, not just at the end)

```powershell
gcloud run services delete <farf-prototype>-bus --region=us-central1 --quiet
```
**Expect:** confirmation the service is deleted — this stops the
`min-instances=1` billing immediately.

If fully done with the pilot (not just pausing):
```powershell
gcloud kms keys versions destroy 1 --key=<farf-prototype>-org-a-key --keyring=<farf-prototype>-keyring --location=us-central1
```
**Expect:** a note that destruction is scheduled, not immediate — Cloud
KMS enforces a mandatory pending-destroy window (default 24 hours) before
a key version is actually destroyed, specifically so an accidental
destroy can be cancelled. The (tiny) per-version cost continues during
that window.

```powershell
gcloud projects delete <farf-prototype>-2026
```
Optional — deletes everything (Cloud Run, Artifact Registry image, the
project itself) if you're fully done and don't want the project lingering
in your account at all.

## What to send back

Paste: the three latency numbers from Step 4's comparison table, the
egress prediction from Step 5, and (the following day) the actual billed
egress figure from the Billing Console. I'll update
`ARCHITECTURE_DECISIONS_1_3.md` (ADR-003, ADR-006), `CLOUD_PROVIDER_COMPARISON.md`
(§2.2's latency floor gets a second, real data point; §2.3's "hardest to
estimate" KMS cost caveat gets resolved with real numbers), and
`PHASE1_TO_CLOUD_DECISION_BRIEF.md` §5 with the real results.
