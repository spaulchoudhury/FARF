"""Draw a seeded, reproducible sample of single-sentence user requests from a locally downloaded public dataset file.

    python tools/sample_public_text.py --file tau_tasks.json --field instruction --n 30 --seed 20261004 --out data/heldout/raw_taubench.txt
    python tools/sample_public_text.py --file released_data.json --field instruction --where fulfillable=1 --n 50 --seed 20261004 --out data/heldout/raw_asb.txt

First INSPECT the file's real field names (the script prints the keys of the first record if --field is wrong).
--field is a dotted path; integers index lists (e.g. conversations.0.value). Nested lists of records: add --records-key.
Filters (printed in the output header): first sentence only, 5-35 words, no code fences / braces / URLs.
It does not label anything benign: you still read every line and delete any that is not an ordinary task request.
"""
from __future__ import annotations

import argparse, csv, hashlib, json, random, re


def records(path: str, records_key: str | None):
    if path.endswith(".jsonl"):
        with open(path, encoding="utf-8") as fh:
            return [json.loads(l) for l in fh if l.strip()]
    if path.endswith(".csv"):
        with open(path, encoding="utf-8", newline="") as fh:
            return list(csv.DictReader(fh))
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if records_key:
        for k in records_key.split("."):
            data = data[k]
    return data if isinstance(data, list) else list(data.values())


def dig(rec, dotted: str):
    cur = rec
    for k in dotted.split("."):
        cur = cur[int(k)] if isinstance(cur, list) else cur[k]
    return cur


def first_sentence(text: str) -> str:
    text = " ".join(str(text).split())
    m = re.match(r"(.+?[.?!])(\s|$)", text)
    return (m.group(1) if m else text).strip()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", required=True)
    ap.add_argument("--field", required=True)
    ap.add_argument("--records-key")
    ap.add_argument("--where", action="append", default=[],
                    help="keep only records whose dotted field equals a value, repeatable (e.g. --where fulfillable=1)")
    ap.add_argument("--n", type=int, default=30)
    ap.add_argument("--seed", type=int, required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    recs = records(a.file, a.records_key)
    for cond in a.where:
        key, _, want = cond.partition("=")
        kept = []
        for r in recs:
            try:
                if str(dig(r, key)) == want:
                    kept.append(r)
            except (KeyError, IndexError, TypeError):
                continue
        print(f"--where {cond}: kept {len(kept)} of {len(recs)} records")
        recs = kept
    if not recs:
        print("no records left after --where; check the field name and value")
        return 2
    try:
        raw = [dig(r, a.field) for r in recs]
    except (KeyError, IndexError, TypeError):
        print("field not found; first record keys:", list(recs[0]) if isinstance(recs[0], dict) else type(recs[0]))
        return 2
    cands, seen = [], set()
    for x in raw:
        s = first_sentence(x)
        w = len(s.split())
        if 5 <= w <= 35 and not re.search(r"```|[{}]|https?://", s) and s.casefold() not in seen:
            seen.add(s.casefold())
            cands.append(s)
    random.Random(a.seed).shuffle(cands)
    pick = cands[: a.n]
    with open(a.out, "w", encoding="utf-8") as fh:
        with open(a.file, "rb") as src_fh:
            digest = hashlib.sha256(src_fh.read()).hexdigest()
        fh.write(f"# source={a.file} sha256={digest} field={a.field} seed={a.seed} n={len(pick)} of {len(cands)} eligible\n")
        fh.write("# filters: first sentence, 5-35 words, no code fences/braces/URLs. REVIEW EVERY LINE BEFORE SCORING.\n")
        fh.writelines(p + "\n" for p in pick)
    print(f"wrote {len(pick)} phrases ({len(cands)} eligible of {len(raw)} records) to {a.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
