"""
docker/bus_service.py
======================
HTTP shim around the existing, unmodified `FederationBus` (federation_bus.py),
so the federation's single auditable mediator (Section 4.6 of the thesis)
can run as its own container, reached over a Docker network by separate
per-organisation containers, instead of being an in-process Python object
shared by function calls in the same process.

Disclosed design boundary (stated here, not left implicit, per the thesis's
evidentiary-source convention, Section 4.1.1): this shim signs outgoing
messages using the *bus-side* copy of each agent's registered signing key
(the same key `FederationBus.register_agent_identity()` already creates and
holds internally, exercised via the existing `sign_and_send()` convenience
method). It does not give each organisation container its own independently
held private key that never leaves that container. A fully zero-trust
container topology would generate and hold each organisation's signing key
inside that organisation's own container, and have the bus verify a
signature it never had the private half of. That is recorded as a further
extension in Chapter 4 Section 4.14, not implemented here: it require
reworking `sign_and_send()`'s convenience-signing path, which was out of
scope for closing the specific gap this session's request targets (running
the federation across genuinely separate containers on a Docker network,
in place of in-process namespaces).

No FARF artefact (agents.py, trust_protocol.py, orchestration.py,
taint_engine.py, fars.py, federation_bus.py, federation_ledger.py,
memory_store.py, adversary_model.py) is modified to build this shim --
it imports and drives them exactly as `main.py` and the pentest suite do.
"""
import os
import sys
import threading

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify

from federation_bus import FederationBus

app = Flask(__name__)
_lock = threading.Lock()

DB_PATH = os.environ.get("FARF_AUDIT_DB", "/data/farf_audit.db")
QUORUM_MODE = os.environ.get("FARF_QUORUM_MODE", "pbft_dynamic")

bus = FederationBus(db_path=DB_PATH, require_message_signatures=True, quorum_mode=QUORUM_MODE)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "quorum_mode": QUORUM_MODE}), 200


@app.route("/register_org", methods=["POST"])
def register_org():
    data = request.get_json(force=True)
    org = data["org"]
    with _lock:
        bus.register_organisation(org)
    return jsonify({"registered": org, "quorum_required": bus.ledger.quorum_required}), 200


@app.route("/admit_agent", methods=["POST"])
def admit_agent():
    data = request.get_json(force=True)
    agent_id, org, role = data["agent_id"], data["org"], data.get("role", "advisor")
    base_privilege = data.get("base_privilege", 0.2)
    with _lock:
        bus.register_agent(agent_id, org, base_privilege=base_privilege)
        vc = bus.trust.issue_credential(
            org, subject_did=f"did:key:agent:{agent_id}",
            claims={"role": role}, ttl_seconds=300.0,
        )
        result = bus.admit_agent(agent_id, org, vc)
    return jsonify(result), (200 if result.get("valid") else 403)


@app.route("/delegate", methods=["POST"])
def delegate():
    data = request.get_json(force=True)
    with _lock:
        bus.adversary_model.add_delegation(
            data["from_agent"], data["to_agent"], privilege=data.get("privilege", 0.3))
    return jsonify({"delegated": True}), 200


@app.route("/send", methods=["POST"])
def send():
    """
    Accepts a message on behalf of a genuinely separate organisation
    container. Signing uses the bus-side key for `from_agent` via the
    existing `sign_and_send()` convenience path -- see the module
    docstring's disclosed boundary above.
    """
    data = request.get_json(force=True)
    with _lock:
        result = bus.sign_and_send(
            from_agent=data["from_agent"], from_org=data["from_org"],
            to_agent=data["to_agent"], to_org=data["to_org"],
            action_type=data["action_type"], payload=data.get("payload", {}),
            taint_delta=data.get("taint_delta", 0.0),
        )
    return jsonify(result), 200


@app.route("/fars", methods=["GET"])
def fars():
    with _lock:
        result = bus.current_fars()
    return jsonify(result), 200


@app.route("/status", methods=["GET"])
def status():
    with _lock:
        result = {
            "total_messages": bus.total_messages,
            "tainted_messages": bus.tainted_messages,
            "quarantined_agents": sorted(bus.orchestration.quarantined_agents),
            "quorum_required": bus.ledger.quorum_required,
            "registered_orgs": sorted(bus.trust.identities.keys()) if hasattr(bus.trust, "identities") else [],
        }
    return jsonify(result), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 8000)))
