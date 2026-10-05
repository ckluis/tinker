#!/usr/bin/env python3
"""Compare two item-47 bench reports: latency deltas + sample byte-equality.

Usage: scripts/compare_bench.py BEFORE.json AFTER.json

- Latency: per transport/op, prints before/after p50/p99 and the % delta.
- Samples: normalizes uuids and ISO timestamps in the canonicalized tool
  responses, then requires byte-equality. Any difference means a hot-path
  change altered tool outputs and must be investigated before landing.

Exit 0 when samples match; exit 1 otherwise (latency regressions do NOT
fail — they are reported for a human to judge, since the bench is
timing-sensitive by design).
"""

import json
import re
import sys

UUID_RE = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
TS_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?")
# The bench fixture uses random slugs per run (uniq() in mcp_bench.rs);
# they appear in describe/query samples and must normalize too.
SLUG_RE = re.compile(r"(benchobj|mcpbenchorg)[0-9a-f]{8}")


def normalize(v):
    if isinstance(v, str):
        v = UUID_RE.sub("<uuid>", v)
        v = TS_RE.sub("<ts>", v)
        v = SLUG_RE.sub(r"<\1>", v)
        return v
    if isinstance(v, list):
        return [normalize(x) for x in v]
    if isinstance(v, dict):
        return {k: normalize(val) for k, val in sorted(v.items())}
    return v


def main():
    before_path, after_path = sys.argv[1], sys.argv[2]
    before = json.load(open(before_path))
    after = json.load(open(after_path))
    print(f"before: {before_path} (git={before.get('git')}, profile={before.get('profile')})")
    print(f"after:  {after_path} (git={after.get('git')}, profile={after.get('profile')})")
    if before.get("profile") != after.get("profile"):
        print("WARNING: profiles differ; latency deltas are not comparable.")

    print("\n== latency (us) ==")
    print(f"{'transport/op':<28}{'p50 before':>12}{'p50 after':>12}{'delta':>9}"
          f"{'p99 before':>12}{'p99 after':>12}{'delta':>9}")
    for transport in ("http", "stdio"):
        for op in ("describe", "query_hit", "query_miss", "create_record"):
            b = before["transports"][transport][op]
            a = after["transports"][transport][op]
            dp50 = (a["p50_us"] - b["p50_us"]) / b["p50_us"] * 100 if b["p50_us"] else 0
            dp99 = (a["p99_us"] - b["p99_us"]) / b["p99_us"] * 100 if b["p99_us"] else 0
            print(f"{transport}/{op:<22}{b['p50_us']:>12}{a['p50_us']:>12}{dp50:>8.1f}%"
                  f"{b['p99_us']:>12}{a['p99_us']:>12}{dp99:>8.1f}%")

    print("\n== cache hit rates ==")
    for transport in ("http", "stdio"):
        b = before["transports"][transport]
        a = after["transports"][transport]
        print(f"{transport}: hit_rate {b['query_hit_rate']:.3f} -> {a['query_hit_rate']:.3f}, "
              f"miss_rate {b['query_miss_rate']:.3f} -> {a['query_miss_rate']:.3f}")

    print("\n== RSS (KiB) ==")
    for transport in ("http", "stdio"):
        b = before["transports"][transport]["rss_kb"]
        a = after["transports"][transport]["rss_kb"]
        print(f"{transport}: startup {b['startup']}->{a['startup']}, "
              f"peak {b['peak']}->{a['peak']}, end {b['end']}->{a['end']}")

    print("\n== sample byte-equality (uuid/ts normalized) ==")
    ok = True
    for name in ("describe", "query", "get_record", "create_record_shape"):
        sb = normalize(before["samples"][name])
        sa = normalize(after["samples"][name])
        # plan_hash is SHA256(sql + params), and the params fold in the
        # per-run fixture org/actor UUIDs — it differs between runs by
        # construction, not by behavior. The rows it governs are what
        # must be identical.
        if name == "query":
            sb.pop("plan_hash", None)
            sa.pop("plan_hash", None)
        nb = json.dumps(sb, sort_keys=True)
        na = json.dumps(sa, sort_keys=True)
        match = nb == na
        ok = ok and match
        print(f"{name}: {'IDENTICAL' if match else 'DIFFERENT'} "
              f"(before {len(nb)} bytes, after {len(na)} bytes)")
        if not match:
            # Show the first divergence for triage.
            for i, (cb, ca) in enumerate(zip(nb, na)):
                if cb != ca:
                    print(f"  first diff at char {i}:")
                    print(f"    before: ...{nb[max(0,i-80):i+80]}...")
                    print(f"    after:  ...{na[max(0,i-80):i+80]}...")
                    break
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
