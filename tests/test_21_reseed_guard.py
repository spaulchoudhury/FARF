"""G9/L15/F16 - the opt-in incident-root re-seed guard.

Default behaviour must be unchanged (guard off re-seeds after decay_s, as documented in Chapter 4); with the guard
on, a collateral-quarantined neighbour that retries after the scope has decayed must NOT re-seed a scope that
reaches the next organisation along the chain."""
from closed_loop import FarsFeedback
from experiments.check_scope_reseeding import scenario


def test_guard_is_off_by_default():
    fb = FarsFeedback()
    assert fb.reseed_guard is False and fb.reseed_memory_s is None


def test_default_still_reseeds_after_decay():
    sens3, hops = scenario(retry_after_decay=True, guard=False)
    assert sens3 > 1.0                                  # the documented limitation L15 is still reproducible


def test_guard_blocks_reseeding_after_decay():
    sens3, hops = scenario(retry_after_decay=True, guard=True)
    assert abs(sens3 - 1.0) < 1e-9


def test_guard_does_not_change_the_within_decay_case():
    a = scenario(retry_after_decay=False, guard=False)[0]
    b = scenario(retry_after_decay=False, guard=True)[0]
    assert abs(a - b) < 1e-9
