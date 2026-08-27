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


@app.route("/propose_reinstatement", methods=["POST"])
def propose_reinstatement():
    """
    ADR-004/ADR-006 partition testing support. Thin wrapper around the
    existing, unmodified FederationBus.propose_federation_reinstatement() --
    added for this testing session, not part of the original v7.9.10 shim.
    """
    data = request.get_json(force=True)
    org = data["org"]
    with _lock:
        result = bus.propose_federation_reinstatement(org)
    return jsonify(result), 200


@app.route("/witness", methods=["POST"])
def witness():
    """
    Thin wrapper around FederationBus.sign_and_witness_federation_reinstatement()
    -- signs with the witnessing org's bus-held DID key (same disclosed
    bus-side-signing boundary as /send, see module docstring) and submits
    the vote. Returns whether quorum has committed yet.
    """
    data = request.get_json(force=True)
    proposal_id, witnessing_org = data["proposal_id"], data["witnessing_org"]
    with _lock:
        result = bus.sign_and_witness_federation_reinstatement(proposal_id, witnessing_org)
    return jsonify(result), 200


# ============================================================================
# PENTEST-SUPPORT ROUTES -- gated, off by default, not part of the normal
# federation-bus API surface. These exist ONLY to let pentest scripts
# replicate their exact in-process attack scenarios over HTTP against a
# real cross-cloud deployment. Each does something a legitimate client
# should never need to do (register an identity without admitting it;
# send a message with no signature) -- that's the point: the pentest is
# checking that FederationBus's OWN guardrails still hold even when an
# attacker can reach these calls directly, not that these calls are safe
# to expose generally. Gated behind FARF_PENTEST_MODE=1 so a normal
# deployment (including the earlier ADR-006 pilot) never has this attack
# surface live; every route 404s unless the env var is set.
# ============================================================================
import os as _os
_PENTEST_MODE = _os.environ.get("FARF_PENTEST_MODE") == "1"


def _pentest_gate():
    if not _PENTEST_MODE:
        from flask import abort
        abort(404)


@app.route("/pentest/register_agent_structural", methods=["POST"])
def pentest_register_agent_structural():
    """
    Registers an agent in the adversary model ONLY (bus.register_agent()) --
    deliberately does NOT call admit_agent(), so the agent structurally
    exists (as if its ID leaked via logs/DNS/docs, per PT-01's hypothesis)
    but holds no credential and no session key. Never call this for a
    legitimate agent; it exists so PT-01-style tests can set up the exact
    "attacker knows the ID but never obtained a credential" precondition
    over HTTP.
    """
    _pentest_gate()
    data = request.get_json(force=True)
    with _lock:
        bus.register_agent(data["agent_id"], data["org"],
                            base_privilege=data.get("base_privilege", 0.1))
    return jsonify({"registered_structurally": True, "agent_id": data["agent_id"]}), 200


@app.route("/pentest/send_raw", methods=["POST"])
def pentest_send_raw():
    """
    Calls FederationBus.send() DIRECTLY -- no signature, no nonce, none of
    /send's sign_and_send() convenience wrapper. This is deliberate: it
    replicates PT-01's original in-process bus.send() call exactly, which
    tests whether send()'s own admission gate (_is_admitted(), checked
    BEFORE the signature check) fails closed on its own, independent of
    the signing layer. /send (production route) would raise an unhandled
    KeyError for an unadmitted from_agent, since sign_and_send() tries to
    sign with a key that was never registered -- a real shim-level gap
    this route exists specifically to test around, not to hide.
    """
    _pentest_gate()
    data = request.get_json(force=True)
    with _lock:
        result = bus.send(
            from_agent=data["from_agent"], from_org=data["from_org"],
            to_agent=data["to_agent"], to_org=data["to_org"],
            action_type=data["action_type"], payload=data.get("payload", {}),
            taint_delta=data.get("taint_delta", 0.0),
            signature=data.get("signature"), nonce=data.get("nonce"),
        )
    return jsonify(result), 200


@app.route("/pentest/sign_only", methods=["POST"])
def pentest_sign_only():
    """
    Produces a genuine bus-side signature over a caller-specified message
    (via FederationBus.canonical_message_bytes + TrustProtocol.sign_message)
    WITHOUT sending it -- exists so PT-08-style replay tests can obtain one
    real, valid (signature, nonce) pair and then submit it via
    /pentest/send_raw twice, to test whether the SECOND submission is
    correctly rejected as a replay. Requires the agent to already be
    admitted (a real key must exist to sign with) -- this does not let a
    caller sign as an arbitrary/unadmitted identity, only as one that
    already has a legitimate bus-held key.
    """
    _pentest_gate()
    data = request.get_json(force=True)
    payload_bytes = FederationBus.canonical_message_bytes(
        data["from_agent"], data["to_agent"], data["action_type"],
        data.get("payload", {}), data["nonce"],
    )
    with _lock:
        signature = bus.trust.sign_message(data["from_agent"], payload_bytes)
    return jsonify({"signature": signature, "nonce": data["nonce"]}), 200


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
