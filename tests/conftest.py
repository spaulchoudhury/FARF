"""
Shared pytest fixtures for the FARF test protocol.

Each test gets a completely fresh FederationBus + 3-org federation so
tests never leak quarantine/taint state into each other, and each uses
its own SQLite file (cleaned up automatically) so runs are reproducible.
"""
import os
import sys
import uuid

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from federation_bus import FederationBus
from main import build_federation


@pytest.fixture
def fresh_bus(tmp_path):
    """A brand-new FederationBus + 3-org federation (OrgA, OrgB, OrgC).

    require_message_signatures is explicitly turned OFF here. As of v4
    it defaults to True (see federation_bus.py, THREAT_MODEL.md Section
    7), but this suite's tests are deliberately unit-scoped -- each one
    targets a specific layer (taint propagation, orchestration decisions,
    FARS, credential replay, etc.) via plain send() calls, not the
    message-signing plumbing itself. Re-signing every call here would
    just add noise without adding coverage. The signing/replay
    enforcement path has its own dedicated, fully end-to-end test:
    pentest/pt08_session_hijack.py.
    """
    db_path = str(tmp_path / f"test_{uuid.uuid4().hex}.db")
    bus = FederationBus(db_path=db_path, require_message_signatures=False)
    agents = build_federation(bus, n_orgs=3)
    yield bus, agents
    bus.close()


def baseline_fars_ceiling(bus) -> float:
    """
    The maximum FARS achievable for a given federation topology once
    trust_health, taint_containment and policy_compliance are all 1.0
    -- i.e. the "clean federation" ceiling set purely by graph
    connectivity. Used as the reference point attack scenarios must
    degrade below.
    """
    fars = bus.current_fars()
    return fars["components"]["connectivity"] * 100 * 0.25  # connectivity weight
