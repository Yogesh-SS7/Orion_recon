#!/usr/bin/env python3
"""
pattern_dedupe.py

Exact dedupe (sort -u) only removes byte-identical lines. On a crawl of
a real target, the bulk of "unique" URLs katana finds are the SAME endpoint
with a different id/page/token value:

    /product?id=1001
    /product?id=1002
    /product?id=1003
    ...x thousands

This script collapses those down to ONE representative URL per unique
(path + sorted param-name signature), which is the actual lever that
turns 80k raw URLs into a low-thousands/hundreds candidate list an
AI agent (or a human) can usefully review.

Usage:
    python3 pattern_dedupe.py input.txt output.txt [--max-per-pattern N]

--max-per-pattern (default 1): how many example URLs to keep per unique
    pattern. Keep at 1 for max reduction. Set to 2-3 if you want a couple
    of real examples per pattern (e.g. to eyeball value variety) without
    losing the collapse benefit.
"""
import sys
import argparse
from urllib.parse import urlsplit, parse_qsl
from collections import defaultdict


def normalize_pattern(url: str):
    """Return a signature key: (scheme, netloc, path, sorted_param_names)."""
    try:
        parts = urlsplit(url.strip())
    except Exception:
        return None
    if not parts.scheme or not parts.netloc:
        return None
    params = parse_qsl(parts.query, keep_blank_values=True)
    param_names = tuple(sorted(p[0] for p in params))
    # normalize path: collapse numeric path segments too (e.g. /user/123/profile -> /user/{n}/profile)
    segs = []
    for seg in parts.path.split("/"):
        if seg.isdigit():
            segs.append("{n}")
        else:
            segs.append(seg)
    norm_path = "/".join(segs)
    return (parts.scheme, parts.netloc, norm_path, param_names)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input")
    ap.add_argument("output")
    ap.add_argument("--max-per-pattern", type=int, default=1)
    ap.add_argument("--only-with-params", action="store_true", default=True,
                     help="Drop URLs with zero query parameters (default on)")
    args = ap.parse_args()

    seen = defaultdict(int)
    kept = 0
    total = 0
    out_lines = []

    with open(args.input, "r", errors="ignore") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            total += 1
            key = normalize_pattern(url)
            if key is None:
                continue
            # key[3] is the tuple of param names; empty tuple = no params
            if args.only_with_params and len(key[3]) == 0:
                continue
            if seen[key] < args.max_per_pattern:
                seen[key] += 1
                out_lines.append(url)
                kept += 1

    with open(args.output, "w") as f:
        f.write("\n".join(out_lines) + "\n")

    print(f"[pattern_dedupe] input lines:      {total}")
    print(f"[pattern_dedupe] unique patterns:  {len(seen)}")
    print(f"[pattern_dedupe] kept URLs:        {kept}")
    print(f"[pattern_dedupe] reduction:        {total} -> {kept} "
          f"({(1 - kept/total)*100:.1f}% cut)" if total else "")


if __name__ == "__main__":
    main()
