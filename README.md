# FARF — Federated Adversarial Resilience Framework

> **Cross-Organisational Multi-Agent Collaboration Under Adversarial Conditions**  
> *Research Implementation, Penetration Testing Suite, and Multi-Cloud Experimental Testbed (v7.9.11)*

[![Python 3.11](https://img.shields.io/badge/python-3.11-blue.svg)](https://www.python.org/downloads/)
[![Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)
[![Architecture: Hybrid/Multi-Cloud](https://img.shields.io/badge/clouds-AWS%20%7C%20GCP%20%7C%20Local-orange.svg)](#multi-cloud-experimental-testbed)
[![Security Hardened](https://img.shields.io/badge/STRIDE-Hardened%20(6%2F6)-green.svg)](#threat-model--penetration-testing)

---

## 1. Executive Summary

Autonomous multi-agent systems operating across distinct organizational boundaries face unique threat vectors: Byzantine peers, compromised agent executors, prompt injections, collusion across semi-trusted participants, and silent taint propagation. Traditional perimeter security and centralized orchestrators fail when collaboration requires decentralization and data sovereignty.

The **Federated Adversarial Resilience Framework (FARF)** is a zero-trust, mathematically grounded architecture designed for secure cross-organizational agent collaboration. It guarantees resilience against adaptive adversaries through formal trust protocols, fine-grained taint tracking, behavioral policy governance, and continuous risk quantification.

This repository hosts:
1. **The Core Five FARF Artefacts**: Production-ready, deterministic Python implementations of all foundational resilience mechanisms.
2. **Local Zero-Cost Testbed**: A lightweight test harness optimized to run comprehensive multi-agent scenarios and evaluations entirely on commodity CPU hardware without external API dependencies.
3. **STRIDE Penetration Suite**: Offensive security test suites reproducing attack vectors (e.g., identity spoofing, field omission, session hijacking, prompt injection) and proving hardening efficacy.
4. **Multi-Cloud Validation Pilot (AWS + GCP)**: Cloud deployment configurations, serverless runners (AWS Lambda, GCP Cloud Run), containerized agent workers (AWS ECS Fargate), and cross-cloud latency/partition instrumentation.

---

## 2. Core FARF Architectural Artefacts

FARF decomposes federated security into five complementary architectural layers coordinated by a hardened **Federation Bus**:

```
 ┌─────────────────────────────────────────────────────────────────────────────┐
 │                         FEDERATION BUS (Zero-Trust Boundary)                │
 └──────┬──────────────────────┬────────────────────────┬──────────────────────┘
        │                      │                        │
 ┌──────▼──────┐        ┌──────▼──────┐          ┌──────▼──────┐
 │  Artefact 1 │        │  Artefact 2 │          │  Artefact 3 │
 │  Adversary  │        │    Trust    │          │ Behavioural │
 │    Model    │        │  Protocol   │          │ Governance  │
 └─────────────┘        └─────────────┘          └─────────────┘
        │                      │                        │
        └──────────────────────┼────────────────────────┘
                               │
                        ┌──────▼──────┐
                        │  Artefact 4 │
                        │    Taint    │
                        │   Engine    │
                        └──────┬──────┘
                               │
                        ┌──────▼──────┐
                        │  Artefact 5 │
                        │    FARS     │
                        │   Engine    │
                        └─────────────┘
```

### Artefact 1: Federated Adversary Model (`adversary_model.py`)
- Formal topology and trust-boundary graph modeling using NetworkX.
- Models malicious, colluding, and compromised organizations across arbitrary federation topologies (cliques, stars, bipartite, sparse graphs).
- Identifies critical path vulnerability, path-redundancy thresholds, and k-resilience parameters prior to message dispatch.

### Artefact 2: Federated Trust Protocol (`trust_protocol.py`)
- Decentralized identity using cryptographic `did:key` identifiers and Ed25519 digital signatures.
- Verifiable Credentials (VCs) for agent capability and organizational delegation.
- Cryptographic hash-commitment attestations and strict nonces/TTLs to defend against replay and man-in-the-middle attacks.

### Artefact 3: Secure Orchestration & Behavioral Governance (`orchestration.py`)
- Rule-based policy governance engine enforcing action admission at the agent-bus perimeter.
- Behavioral constraints restricting unauthorized tool execution, memory poisoning, and un-gated action escalation.
- Dual Advisor/Executor role segregation with verification barriers.

### Artefact 4: Provenance-Aware Taint Propagation Engine (`taint_engine.py`, `content_taint.py`)
- End-to-end provenance DAG tracking across cross-organizational message sequences.
- Taint classification (`content_taint_classifier.py`) identifying indirect prompt injections, adversarial poisoning, and scope-bleeding.
- Dynamic quarantine and selective branch revocation without tearing down benign federation channels.

### Artefact 5: Federated Adversarial Resilience Score — FARS (`fars.py`, `closed_loop.py`)
- Closed-loop metric engine aggregating resilience scores across all participating nodes.
- Quantifies federation health under active degradation, measuring recovery velocity, collusion resistance, and topological vulnerability.
- Closed-loop feedback mechanism dynamically adjusting admission thresholds and re-seeding trust parameters.

---

## 3. Project Structure

```text
farf_prototype_v7_9_11/
├── adversary_model.py          # Artefact 1: Graph-theoretic adversary & topology model
├── trust_protocol.py           # Artefact 2: Ed25519 DID identities & verifiable credentials
├── orchestration.py            # Artefact 3: Behavioral governance & policy enforcement
├── taint_engine.py             # Artefact 4: Message provenance & taint propagation
├── fars.py                     # Artefact 5: Federated Adversarial Resilience Score
├── federation_bus.py           # Core integration layer & perimeter boundary
├── agents.py                   # Rule-based federated agent implementations (Advisor/Executor)
├── content_taint.py            # Deep payload taint inspection & sanitization
├── content_taint_classifier.py # Deterministic heuristic/classifier for adversarial payloads
├── closed_loop.py              # Closed-loop feedback controller between FARS and Bus
├── main.py                     # Unified entry point for end-to-end scenarios
│
├── aws_pilot/                  # AWS deployment & verification suite
│   ├── lambda_agent_worker.py  # Serverless agent worker for AWS Lambda
│   ├── v11_lambda_runner.py    # Remote test dispatcher for cloud execution
│   ├── task-def*.json          # ECS Fargate task definitions (redacted/sanitized)
│   └── analyze_partition_log.py# Cross-cloud network partition analyzer
│
├── gcp_pilot/                  # GCP Cloud Run deployment & latency instrumentation
│   ├── cloud_run_final_checks.py
│   └── kms_latency_probe.py
│
├── docker/                     # Container configurations for bus & agent services
│   ├── bus_service.py          # HTTP/REST wrapper around FederationBus
│   └── org_client.py           # Client container simulating independent organization
│
├── experiments/                # Empirical validation & ablation experiments
│   ├── run_ablation.py         # System ablation (testing isolation of each artefact)
│   ├── run_baseline_comparison.py # Comparison against legacy & un-governed baselines
│   ├── run_collusion_patient.py   # Delayed/patient attacker & collusion evaluations
│   ├── run_fars_loop.py        # Continuous FARS monitoring under simulated attack
│   └── run_guard_evasion.py    # Evasion benchmarks against adaptive attackers
│
├── pentest/                    # STRIDE local exploit testbed (PT-01 through PT-15)
├── pentest_cloud/              # Cloud-native attack reproduction scripts
├── validation/                 # Third-party benchmark adapters (AgentHarm, AgentLeak)
├── docs/                       # Architecture Decision Records (ADRs), Threat Model & Specifications
│   ├── ARCHITECTURE_DECISIONS_1_5.md
│   ├── CLOUD_PROVIDER_COMPARISON.md
│   ├── THREAT_MODEL.md
│   └── TAB78_METRICS_CLOSURE.md
└── tests/                      # Pytest automated test suite
```

---

## 4. Threat Model & Penetration Testing

The security of FARF was established using empirical STRIDE penetration tests against the unhardened prototype, ensuring that all defenses are verified against functioning exploits:

| Test ID | Vulnerability Vector | Threat Target | Mitigation Artefact | Status |
|---|---|---|---|---|
| **PT-01** | Identity Spoofing | Trust Boundary | Cryptographic `did:key` & signature verification | **Mitigated** |
| **PT-02** | Field Omission Bypass | Action Admission | Strict schema validation & mandatory nonce enforcement | **Mitigated** |
| **PT-08** | Session Hijack / Replay | Federation Bus | Replay window TTL cache + monotonic epoch tracking | **Mitigated** |
| **PT-15** | Prompt Injection / Taint | Agent Executor | Content Taint Classifier & taint-dag quarantine | **Mitigated** |
| **PT-21** | Collusion Escalation | Orchestration | Threshold quorum voting & multi-party attestation | **Mitigated** |
| **PT-23** | Patient/Jitter Evasion | Closed Loop | Moving-window FARS decay with entropy analysis | **Mitigated** |

Full exploit reproduction scripts and remediation proofs are available in `pentest/` and documented in `docs/THREAT_MODEL.md`.

---

## 5. Multi-Cloud Experimental Testbed

While the core framework runs 100% locally on standard CPU hardware, FARF includes an enterprise multi-cloud testbed designed to validate cross-cloud latencies, KMS signature overheads, and network partition resiliency across heterogeneous providers:

- **AWS Component**:
  - AWS Lambda serverless execution (`aws_pilot/lambda_agent_worker.py`).
  - ECS Fargate container orchestration (`aws_pilot/task-def.json`).
  - AWS KMS asymmetric signature generation and verification latency profiling.
- **GCP Component**:
  - Google Cloud Run managed containers hosting the external federation bus (`gcp_pilot/`).
  - Google Cloud KMS cryptographic interop.
- **Cross-Cloud Resilience Testing**:
  - Simulated and live network split-brain partitions (`aws_pilot/analyze_partition_log.py`).
  - Egress latency characterization and recovery validation (`adr004_partition_client_v5.py`).

*Note: All cloud configurations in this repository have been strictly sanitized. Cloud accounts, project numbers, and API tokens are replaced with `<AWS_ACCOUNT_ID>`, `<GCP_PROJECT_NUMBER>`, etc.*

---

## 6. Getting Started

### Prerequisites
- Python 3.11+
- Virtual environment (`venv` or `conda`)
- Git

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/spaulchoudhury/FARF.git
   cd FARF
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv .venv
   # Windows PowerShell:
   .venv\Scripts\Activate.ps1
   # Linux/macOS:
   source .venv/bin/activate
   ```

3. Install required dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```

---

## 7. Running the Test Suite & Experiments

### Run Unit & Integration Tests
Execute the full test suite via `pytest`:
```bash
pytest tests/ -q
```

### Run Unified Scenario Pipeline
Run the baseline multi-organization federated scenario:
```bash
python main.py
```

### Run Resilience & Attack Experiments
Execute the experimental evaluation scripts directly:
```bash
# 1. Evaluate baseline comparison under attack:
python experiments/run_baseline_comparison.py

# 2. Run system ablation analysis:
python experiments/run_ablation.py

# 3. Simulate patient / colluding attackers:
python experiments/run_collusion_patient.py

# 4. Run closed-loop FARS monitoring:
python experiments/run_fars_loop.py
```

### Run Static Analysis & Quality Gate
Code formatting and correctness are enforced via `ruff`:
```bash
ruff check .
```

---

## 8. Reproducibility & Research Notes

- **Deterministic Execution**: All stochastic attacker behaviors, network jitters, and classifier thresholds support deterministic seeding for exact academic and experimental reproducibility.
- **Resource Constraints**: Designed intentionally to run full multi-org simulations without requiring GPU clusters or commercial LLM API keys.
- **Citation**: If referencing FARF in academic work, please refer to the accompanying thesis: *Federated Adversarial Resilience Framework for Cross-Organisational Multi-Agent Collaboration*, Sections 7.4–7.9.

---

## 9. License

This research prototype is distributed under the terms of the project repository license. See [LICENSE](LICENSE) for details.
