# FARF — Containerised Multi-Organisation Deployment

This directory replaces the in-process organisational namespaces disclosed in
Chapter 4 §4.6 with a genuine multi-container Docker Compose topology: one
`federation-bus` container holding the Federation Bus mediator, and three
independent `org-a` / `org-b` / `org-c` containers that talk to it exclusively
over HTTP across a Docker bridge network. No FARF artefact from Chapter 5
(agents.py, trust_protocol.py, orchestration.py, taint_engine.py, fars.py,
federation_bus.py, federation_ledger.py, memory_store.py, adversary_model.py)
is modified — this only adds a thin HTTP shim (`bus_service.py`) around the
existing, unmodified `FederationBus`.

**Disclosed boundary** (see `bus_service.py`'s module docstring for the full
statement): message signing uses the bus-side copy of each agent's key via
the existing `sign_and_send()` convenience path, not an independently-held
per-organisation private key that never leaves that container. Closing that
remaining gap is recorded as future work.

## Prerequisites

- Docker Desktop (or Docker Engine + Compose plugin) installed and running.
- Run all commands from the **repository root** (the folder containing
  `federation_bus.py`, not this `docker/` folder).

## Build and run

```bash
docker compose -f docker/docker-compose.yml up --build
```

This builds one shared image (see `docker/Dockerfile`) and starts four
containers: `farf-federation-bus`, `farf-org-a`, `farf-org-b`, `farf-org-c`.
Expected log sequence:

1. `farf-federation-bus` starts and reports healthy on `GET /health`.
2. Each `org-*` container waits for the bus to be reachable, registers its
   organisation (`POST /register_org`) — watch the bus's own log lines for
   `quorum recomputed on membership change` firing on each registration,
   the same mechanism validated in Chapter 4 §4.7 — then admits its two
   agents (`POST /admit_agent`).
3. `org-a` sends one genuinely cross-container, cryptographically signed
   message to `org-b`; `org-b` sends one to `org-c`.
4. Each org container prints the federation-wide FARS reading and status
   as observed from its own vantage point after its actions.

## Inspecting the running federation

While the stack is up, from the host:

```bash
curl http://localhost:8000/health
curl http://localhost:8000/status
curl http://localhost:8000/fars
```

## Tearing down

```bash
docker compose -f docker/docker-compose.yml down -v
```

(`-v` also removes the `farf-audit-data` volume holding the SQLite audit
trail, so the next run starts from a clean federation.)

## What this does and does not demonstrate

This closes the specific, disclosed Chapter 4 §4.6 gap: organisational
isolation is now enforced by separate OS processes in separate containers
communicating over a real network socket, not by Python namespace strings
inside one process. It does **not** by itself validate deployment-scale
performance, real network partition behaviour, or multi-host federation
(all containers here run on one Docker host); those remain the scope
boundaries already disclosed in Chapter 4 §4.14.
