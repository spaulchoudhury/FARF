# FARF Phase 2 — Cloud Provider Comparison (AWS vs Azure vs GCP)

Companion to `ARCHITECTURE_DECISIONS.md`. Built to help decide which **two**
of the three providers to finalise for the two-cloud federation, by laying
out service equivalence, real 2026 pricing (web-searched and sourced — see
the Sources section at the end — not recalled from training data, since
cloud pricing changes too often to trust from memory), and a judged
evaluation of hybrid-cloud maturity for post-deployment operation. Figures
are cited by source number `[n]`; where a figure comes from a third-party
aggregator rather than the provider's own pricing page, that's noted, since
aggregator numbers can lag official pricing by weeks.

---

## 1. Service-by-service mapping, all three providers

| FARF Phase 2 need | AWS | Azure | GCP |
|---|---|---|---|
| Per-org KMS (ADR-003) | AWS KMS — asymmetric signing keys, pay-as-you-go, $1/month per key created, prorated hourly, consistent across key types, plus per-operation API charges [1] | Azure Key Vault — Standard tier roughly $0.03 per 10,000 operations; Premium HSM tier adds $1.50/key/month plus operation charges [2] | Google Cloud KMS — pricing structured around protection level of key versions, number of active key versions, and per-operation usage rate, rather than a flat per-key fee [3] |
| Stateless agent workers | Lambda — leads on raw invocation count (1M/month free), most mature (launched 2014), largest ecosystem [4] | Azure Functions — matches Lambda at 1M requests/month free tier, best fit if already Microsoft-stack [4] | Cloud Functions / **Cloud Run** — most generous free tier overall (2M requests, 360K GB-seconds, 1GB free egress) [4] |
| Relay / orchestration service (containers) | Fargate | Container Apps | Cloud Run (same product covers both the "container" and "serverless function" story — a genuine simplicity advantage) |
| Ledger quorum nodes (always-on, ADR-006) | Fargate (on-demand, not spot) | Container Apps (always-on tier) | Cloud Run with `min-instances` ≥1, or GKE Autopilot for a hard availability guarantee |
| Durable audit store (ADR-009) | Aurora Serverless v2 / DynamoDB on-demand | Azure SQL Serverless / Cosmos DB serverless | Cloud SQL (auto-scaling) / **Firestore** (closest DynamoDB/Cosmos DB analogue) |
| LLM gateway (ADR-011, ADR-015 below) | API Gateway → Bedrock | API Management → Azure OpenAI Service | Apigee (or simpler API Gateway) → **Vertex AI** |
| Native structured-log sink (ADR-007) | CloudWatch Logs | Azure Monitor / Log Analytics | Cloud Logging |
| Identity / IAM | AWS IAM | Entra ID (Azure AD) | Google Cloud IAM |
| Managed Kubernetes (hybrid-relevant, §3) | EKS | AKS | **GKE** — the strongest of the three; Kubernetes originated at Google and GKE remains the reference implementation most other distros track |

---

## 2. Cost comparison — the numbers that actually move for THIS architecture

FARF's cloud build is unusually **egress-heavy** relative to a typical web
app: ADR-001's relay-to-relay channel, ADR-002's context-graph replication,
and ADR-009's cross-cloud hash-chain anchoring all mean constant, small,
frequent cross-cloud messages — a chatty architecture, not a bulk-data one.
That makes **egress rate and per-operation KMS/API cost** the dominant cost
variables here, not compute — compute is nearly identical across all three
providers for equivalent instance types.

### 2.1 Compute (context only — not where the cost difference is)

On-demand compute pricing between AWS, Azure, and GCP is nearly identical
for equivalent instance types in US regions — a 4 vCPU/16GB Linux instance
runs approximately $0.19/hr on all three [5]. A 2 vCPU/8GB general-purpose
instance costs roughly $30/month on AWS and Azure, versus approximately
$24/month on GCP, helped by an 8% compute price cut across all regions in
Q1 2026 [6]. On committed-use 1-year pricing, AWS generally offers the
lowest rates, GCP close behind, with Azure typically 8–10% more expensive
for equivalent configurations [6] — though Azure becomes competitive when
factored with Enterprise Agreements and Microsoft 365 bundling many large
organisations already have [6].

**Verdict: compute cost should not be the deciding factor between these
three for FARF.** The gap is small (~20%) and dwarfed by egress below.

### 2.2 Egress — the number that actually matters for a federation architecture

| Provider | Entry-tier internet egress | Notes |
|---|---|---|
| AWS | $0.09/GB [7] | First 10TB tier; drops to $0.05/GB above 150TB [8] |
| Azure | $0.087/GB [7] | First 10TB at $0.087/GB, next 40TB at $0.083/GB, converging to AWS's rate above 150TB [9] |
| GCP (Premium Tier) | $0.12/GB [7] | Highest of the three at entry tier |
| GCP (Standard Tier) | $0.085/GB [9] | Cheaper than AWS/Azure, but routes over the public internet rather than Google's private backbone — a real latency/reliability trade-off for a security-relevant relay channel, not a free lunch |

GCP Premium Tier egress is more expensive than AWS at all volume levels,
but GCP Standard Tier is slightly cheaper than AWS and comparable to
Azure [10] — meaning **GCP's cost position depends entirely on which
network tier you pick**, a decision AWS and Azure don't force on you.

**For inter-region traffic specifically** (relevant to ADR-002's
context-graph replication and ADR-006's quorum witnessing, which are
frequent and small): GCP has the lowest inter-region rate within the US at
$0.01/GB; AWS and Azure both charge $0.02/GB for cross-region transfer [5]
— this is the one place GCP has an unambiguous, tier-independent cost edge
directly relevant to FARF's actual traffic pattern.

**Verdict: if AWS+GCP is chosen, put the relay/ledger/context-graph channel
on GCP's Premium Tier (not Standard)** despite the higher entry-tier egress
rate — the private-backbone reliability matters more than the ~$0.03/GB
delta for a security-relevant channel, and GCP's cheaper *inter-region* rate
(relevant once either provider scales past one region per cloud) is a
genuine structural advantage worth banking for future growth.

### 2.3 KMS operation cost (ADR-003, recurring per-signature cost)

AWS KMS costs $1/month per key, prorated hourly, consistent across
symmetric and asymmetric key types [1], plus a small per-request API
charge. Azure Key Vault Standard tier runs roughly $0.03 per 10,000
operations [2] — cheaper per-operation at low-to-moderate volume than
AWS's flat per-key charge implies, though the comparison depends heavily on
signing frequency. GCP Cloud KMS pricing is structured around active
key-version count and per-operation usage rather than a flat per-key
fee [3], making it the hardest of the three to estimate without a concrete
signing-volume figure.

**Recommend a short pilot measuring ADR-003's actual signature volume under
a realistic E1–E4 scenario load before locking in a KMS choice on cost
grounds**, rather than estimating from list price alone.

### 2.4 Serverless compute (agent workers, ADR-011)

AWS Lambda continues to dominate the bursty function-as-a-service
market [11], while Google Cloud Run has become the 2026 leader for
concurrency-heavy workloads and AI inference specifically due to its
container-native scaling and resource efficiency [11] — directly relevant
if ADR-015 (real LLM-driven agents, below) is adopted, since LLM-calling
workers are exactly the "AI inference" pattern Cloud Run is cited as
winning on. Lambda wins for event-driven, low-latency, AWS-native
workloads; Cloud Run wins for HTTP services with variable traffic,
especially at medium-high scale where per-request billing beats
per-invocation overhead; Azure Functions wins when already in Azure and
needing deep integration with Service Bus or Logic Apps [12].

**Verdict: this is a genuine, workload-dependent trade-off, not a clear
winner** — favours GCP if/when ADR-015's real-LLM agents ship (Cloud Run's
concurrency model fits LLM-calling workers well); favours AWS if the agent
workload stays closer to today's short, bursty, deterministic-rule pattern.

---

## 3. Hybrid cloud maturity — post-deployment evaluation (service / flexibility / robustness)

This section is judged, not just quoted — cloud vendor marketing on
"hybrid" differs enough from operational reality that a synthesis is more
useful than a source-by-source dump. Each provider's own reporting on
itself is treated with appropriate scepticism.

| Dimension | AWS Outposts | Azure Arc | Google Anthos |
|---|---|---|---|
| **Core model** | Brings the full AWS experience — compute, storage, services — directly to customer premises using AWS-managed hardware; narrows the operating model to just AWS everywhere rather than adapting to hybrid complexity [13] | Takes a control-first approach [13], extending Azure's management plane to any infrastructure and projecting non-Azure resources (servers, Kubernetes clusters, databases) into Azure as if they were native [14] | Optimised for Kubernetes-based workloads, integrating closely with GKE, Config Management, and Cloud Operations Suite [13]; more of a Kubernetes distribution than a hardware appliance, and by design cloud-agnostic — it can run on any public cloud, including AWS Outposts and Azure [15] |
| **Service breadth on-prem/edge** | Focuses solely on on-premises use cases; by using AWS-provided hardware, effectively prevents multi-cloud scenarios and use of your own hardware [16] — deepest single-cloud service parity, narrowest multi-cloud reach | Broad management-plane reach (policy, monitoring, security posture) across heterogeneous infra, but the workloads themselves still need their own runtime — Arc manages, it doesn't relocate AWS/GCP-native services | Service Mesh Integration via Anthos Service Mesh (Istio-based) offers advanced observability, security, and traffic management for microservices across environments [17] |
| **Flexibility (multi-cloud, avoiding lock-in)** | Lowest of the three by design — a widely-shared industry read is that AWS has been comparatively slow to embrace multi-cloud versus GCP and Azure [15] | High — genuinely designed to manage resources anywhere: on-premises, other clouds, or the edge [14] | Highest — 64% of enterprises cite avoiding vendor lock-in as a top reason for adopting hybrid/multi-cloud solutions [17], and Anthos is the platform explicitly built around that motivation from day one, being literally the GKE control plane extended outward rather than a single-vendor hardware appliance |
| **Robustness / operational maturity** | Most mature *within* its narrow scope — creates a private AWS micro-region inside a customer's data centre, the most cloud-like of the three since hardware is designed, produced, and managed only by AWS [18], giving strong consistency guarantees but only for AWS-native services | Strong for enterprises with existing Windows Server/Active Directory/System Center investment — the natural extension of decades of Microsoft enterprise tooling | Strongest for Kubernetes-native, container-first organisations; weaker fit for teams without existing container maturity — its operational model assumes maturity in containers and declarative infrastructure [13] |
| **Best fit for FARF specifically** | Poor fit if AWS+GCP is chosen — Outposts actively discourages the multi-cloud posture ADR-001 requires; fine only in an AWS-only or AWS+on-prem deployment, which isn't the scenario under consideration | Good fit if AWS+Azure — Arc's control-plane-anywhere model can supervise both clouds' relays from one pane of glass without forcing either cloud's workloads to relocate | **Best fit if AWS+GCP** — FARF's relay/orchestration layer (ADR-001) is already container-based (Fargate/Cloud Run), so Anthos's GKE-centric, cloud-agnostic design lines up naturally with the architecture already chosen, buying a genuine post-deployment path to a third cloud or on-prem later without redesigning ADR-001's relay pattern |

**Judged synthesis:** for a **research prototype specifically evaluating
genuine cross-cloud federation** (which is exactly what this dissertation is
testing), **Anthos's Kubernetes-native, vendor-agnostic design philosophy is
the closest philosophical match to what FARF's own architecture is trying to
prove** — a system where no single cloud is structurally privileged. Azure
Arc is the pragmatic enterprise choice if organisational buy-in / existing
Microsoft investment matters more than architectural purity. AWS Outposts is
the weakest fit for *any* two-cloud federation scenario by design — it
exists to make hybrid deployments feel like more AWS, not less
single-cloud.

---

## 4. Decision framework (trade-offs to weigh — not a recommendation)

| If your priority is… | Lean toward |
|---|---|
| Lowest recurring egress cost at moderate-to-high cross-cloud traffic volume, and inter-region cost as the federation scales | **AWS + GCP** (GCP's Standard Tier and inter-region rates are the cheapest combination, with the Premium Tier fallback available for the security-critical relay channel) |
| Philosophical/architectural alignment with "no cloud is privileged," strongest post-deployment hybrid story, Kubernetes-native operations | **AWS + GCP** (Anthos) |
| Fastest path if there's existing institutional Azure/Microsoft investment (dissertation committee, supervising institution, or eventual industry partner already on Microsoft) | **AWS + Azure** (as currently drafted in `ARCHITECTURE_DECISIONS.md`) |
| Cheapest KMS at low signing volume, simplest per-operation billing to reason about | **Azure** (flat, low per-10k-ops rate) over either alternative — relevant only if Azure is one of the two chosen |
| Best AI-inference-workload economics if ADR-015 (real LLM agents) ships | **GCP** (Cloud Run's concurrency-based billing model is cited as the 2026 leader for exactly this workload shape) |

This document deliberately stops short of picking one combination — that's
your call to make, informed by whichever row above matters most for the
dissertation's actual constraints (budget ceiling, institutional
relationships, timeline for standing up two real cloud accounts). The
`ARCHITECTURE_DECISIONS.md` revision that follows keeps AWS+Azure as the
**Accepted** status quo per your earlier confirmation, with GCP's equivalent
choice documented in a parallel column in every ADR, so switching the
second provider later is a find-and-replace exercise against a known-good
alternative, not a redesign.

---

## Sources

1. [Comparison of Key Management Solution By AWS, Google and Microsoft](https://entro.security/blog/comparison-key-management-solutions-google-aws-microsoft/) — Entro Security
2. [AWS KMS vs Azure Key Vault vs Google Cloud KMS](http://cloudcomparetool.com/blog/aws-kms-vs-azure-key-vault-vs-google-cloud-kms) — CloudCompareTool
3. [Azure Key Vault vs Google Cloud KMS](https://www.projectpro.io/compare/azure-key-vault-vs-google-cloud-key-management-service) — ProjectPro
4. [Serverless Free Tier Comparison 2026](https://agentdeals.dev/serverless-free-tier-comparison-2026) — AgentDeals
5. [AWS vs Azure vs GCP Pricing in 2026: Compute, Storage, and Network Compared](https://zop.dev/resources/blogs/aws-vs-azure-vs-gcp-pricing-in-2026-compute-storage-and-network-compared) — Zop.dev
6. [AWS vs Azure vs GCP 2026 Compared](https://tech-insider.org/aws-vs-azure-vs-google-cloud-2026/) — Tech Insider
7. [Cloud Egress Costs: AWS $0.09/GB, How to Pay Less (2026)](https://spendark.com/blog/cloud-egress-costs-guide/) — Spendark
8. [AWS Data Transfer Cost: The Complete 2026 Map](https://spendark.com/blog/aws-data-transfer-cost/) — Spendark
9. [Cloud Egress Cost Calculator (2026)](https://egresscost.com/calculator/) — EgressCost.com
10. [Cloud Egress Pricing Comparison 2026](https://egresscost.com/compare/) — EgressCost.com
11. [Cheat Sheet: 2026 Serverless Pricing & Quotas](https://techbytes.app/posts/2026-serverless-pricing-quota-comparison-cheat-sheet/) — TechBytes
12. [Cloud Run vs Lambda vs Azure Functions: Cost Comparison](https://reducecost.cloud/blog/cloud-run-vs-lambda-vs-functions) — ReduceCost.cloud
13. [Azure Arc vs Google Anthos vs AWS Outposts: A Comprehensive Hybrid Cloud Comparison](https://www.cloudoptimo.com/blog/azure-arc-vs-google-anthos-vs-aws-outposts-a-comprehensive-hybrid-cloud-comparison/) — CloudOptimo
14. [A guide to the multicloud strategies of AWS, Azure, and Google Cloud](https://www.infoworld.com/article/4048525/a-guide-to-the-multicloud-strategies-of-aws-azure-and-google-cloud.html) — InfoWorld
15. [Multi-cloud and Hybrid cloud - Services comparison](https://www.linkedin.com/pulse/multi-cloud-hybrid-cloud-services-comparison-alok-sharma) — LinkedIn
16. [Part 1 – AWS Outpost, Azure Arc and Google Anthos fundamentals](https://medium.com/@keremceliker/a-brief-overview-of-amazon-aws-outpost-azure-arc-and-google-anthos-fundamentals-with-a-high-level-3965ac976a9e) — Medium
17. [GCP Anthos vs Azure Arc vs AWS Outposts: Which Cloud Service Leads?](https://wetranscloud.com/blog/gcp-anthos-vs-azure-arc-vs-aws-outposts/) — WeTransCloud
18. [AWS Outposts vs. Azure Stack vs. Google Anthos hybrid storage](https://www.techtarget.com/searchstorage/feature/AWS-Outposts-vs-Azure-Stack-vs-Google-Anthos-hybrid-storage) — TechTarget

All pricing figures are third-party-aggregated 2026 estimates gathered via
web search, not pulled directly from AWS/Azure/GCP's live pricing
calculators — verify current list prices against each provider's official
pricing page before finalising a budget, as these change without notice and
regional/committed-use discounts materially shift the effective rate.
