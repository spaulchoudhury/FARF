# External validation against public agent-safety datasets

Two adapters, both measuring FARF's **prompt-injection signal** (`agents.detect_prompt_injection`, PT-15).
Neither reproduces the datasets' own metrics, and neither shows that FARF detects PII leakage or refuses harmful
tasks: the FARF bus performs no payload-content inspection (`taint_delta` is caller-supplied).

| Script | Dataset | Positives | Negatives | Status |
|---|---|---|---|---|
| `agentleak_pt15.py` | AgentLeak, MIT, pinned commit `1301eb92...` | 19 independent attack templates | 50 benign request skeletons | run; result in `results/agentleak_pt15.json` |
| `agentharm_pt15.py` | AgentHarm (HF `ai-safety-institute/AgentHarm`, licence "other") | harmful behaviours | benign counterparts | written and unit-tested on synthetic fixtures; **not yet run on real files** |

Expectations were written into each script header before its first run. Datasets go in `validation/data/`
(git-ignored and docker-ignored). AgentHarm files carry an anti-contamination canary: never commit them.

```
git clone https://github.com/Privatris/AgentLeak validation/data/AgentLeak
git -C validation/data/AgentLeak checkout 1301eb9245a03bbee8694ee2b74accbc8f6fefe6
python validation/agentleak_pt15.py --scenarios validation/data/AgentLeak/agentleak_data/datasets/scenarios_full_1000.jsonl --dataset-commit 1301eb9245a03bbee8694ee2b74accbc8f6fefe6
```
Counting unit is the independent template, not the scenario: AgentLeak's 496 attack scenarios reduce to 19
templates once random `CANARY_*` tokens are collapsed.
