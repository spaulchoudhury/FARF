# Archived: run_fars_loop_sweep_v1_SUPERSEDED.py

Superseded by experiments/run_fars_loop_sweep_v2.py per a second TS ruling (2025-09-30) requiring:
a 5-arm design (off/global/scoped-naive/scoped-cold/scoped-hop-cap) instead of 3 arms, a required
long-chain (>=3 hop) topology test, a slow-distributed-adversary test targeting the cold-gate
specifically, an extended multiplier sweep run until something breaks (not a fixed {1.5,2,3} set),
and CI+Wilcoxon significance reporting throughout rather than means alone.

v1's own numbers were internally correct for what it tested (three arms: off/global/scoped, the
"scoped" here being what v2 calls "scoped-cold") and are not being retracted as WRONG -- v1's
scoped-cold vs global distinction is a real, reproduced result. It is archived because v2 is a more
complete evaluation of the same mechanism, not because v1's numbers were invalidated.
