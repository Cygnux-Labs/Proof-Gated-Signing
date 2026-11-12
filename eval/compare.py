"""Check a fresh evaluation against the committed one: every field of every run except latency_s.

usage: python eval/compare.py FRESH_RUNS [COMMITTED_RUNS=results/runs.jsonl]
A slice (--variants 1, --families ...) is checked against the same runs in the committed file.
"""
import json, sys


def runs(path):
    out = {}
    for line in open(path):
        r = json.loads(line)
        for s in r["steps"]:
            s.pop("latency_s", None)
        out[(r["sid"], r["defense"])] = r
    return out


def main(fresh, committed="results/runs.jsonl"):
    a, b = runs(fresh), runs(committed)
    bad = [k for k in a if a[k] != b.get(k)]
    for k in bad[:5]:
        print("differs:", *k)
    print(f"{len(a) - len(bad)}/{len(a)} runs identical to {committed} (all fields but latency_s)")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main(*sys.argv[1:]))
