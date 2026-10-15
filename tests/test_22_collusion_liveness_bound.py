"""G12/L16/F20 - a colluding minority of up to f = floor((N-1)/3) withholding witnesses cannot block a legitimate
reinstatement under the gated policy, and f+1 can; a below-quorum colluding minority cannot reinstate a hostile
organisation under either policy."""
from experiments.run_collusion_patient import GATED, IDENTITY, collusion_trial, liveness_trial


def test_liveness_tolerates_f_withholders_at_n4():
    assert liveness_trial(4, 1, GATED)["reinstated"] is True       # f = 1
    assert liveness_trial(4, 2, GATED)["reinstated"] is False      # f + 1


def test_below_quorum_collusion_never_reinstates():
    q = collusion_trial(7, 0, GATED, t_max=1)["quorum"]
    for pol in (IDENTITY, GATED):
        assert collusion_trial(7, int(q) - 1, pol)["reinstated"] is False


def test_gated_refuses_quorum_collusion_while_attacker_transmits():
    q = collusion_trial(7, 0, GATED, t_max=1)["quorum"]
    assert collusion_trial(7, int(q), GATED)["reinstated"] is False
