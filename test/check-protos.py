#!/usr/bin/env python3
"""Compare fanfp.py output against expected fingerprints.

Usage: check-protos.py <fanfp.py> <capture.pcap> <expected.json>

Each line of expected.json must be a JSON object.  Comparison is multiset-
based: every unique fingerprint string must appear the exact same number of
times in actual output as it does in the expected file.

Exit 0  — counts match for every fingerprint (no missing, no unexpected).
Exit 1  — mismatches found, printed in red at the end.
Exit 2  — usage or runtime error.
"""

import json
import subprocess
import sys
from collections import Counter

RED    = "\033[31m"
GREEN  = "\033[32m"
RESET  = "\033[0m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
LINE   = "─" * 60


def load_jsonl(path: str) -> list:
    records = []
    with open(path) as fh:
        for lineno, raw in enumerate(fh, 1):
            raw = raw.strip()
            if raw:
                try:
                    records.append(json.loads(raw))
                except json.JSONDecodeError as exc:
                    print(f"{RED}ERROR{RESET}: {path}:{lineno}: {exc}", file=sys.stderr)
                    sys.exit(2)
    return records


def run_fanfp(fanfp: str, pcap: str) -> list:
    proc = subprocess.run(
        [sys.executable, fanfp, pcap],
        capture_output=True,
        text=True,
    )
    if proc.returncode != 0:
        print(f"{RED}ERROR{RESET}: fanfp.py exited {proc.returncode}", file=sys.stderr)
        if proc.stderr:
            print(proc.stderr.rstrip(), file=sys.stderr)
        sys.exit(2)
    records = []
    for raw in proc.stdout.splitlines():
        raw = raw.strip()
        if raw:
            records.append(json.loads(raw))
    return records


def short_feat(feat: str, width: int = 72) -> str:
    return feat if len(feat) <= width else feat[:width] + "…"


def main() -> int:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} fanfp.py capture.pcap expected.json")
        return 2

    fanfp_script, pcap, expected_file = sys.argv[1:4]

    expected = load_jsonl(expected_file)
    print(f"\n{BOLD}Running{RESET} fanfp.py against {pcap} …")
    actual = run_fanfp(fanfp_script, pcap)

    # Build a sample record (for display) per unique fingerprint
    exp_sample: dict[str, dict] = {}
    for r in expected:
        exp_sample.setdefault(r["fingerprint"], r)

    act_sample: dict[str, dict] = {}
    for r in actual:
        act_sample.setdefault(r["fingerprint"], r)

    exp_counts = Counter(r["fingerprint"] for r in expected)
    act_counts = Counter(r["fingerprint"] for r in actual)

    all_fps = sorted(set(exp_counts) | set(act_counts))

    failures: list[tuple[str, str, dict, int, int]] = []
    passed = 0

    print()
    for fp in all_fps:
        exp_n = exp_counts.get(fp, 0)
        act_n = act_counts.get(fp, 0)
        rec   = exp_sample.get(fp) or act_sample.get(fp, {})
        proto    = rec.get("protocol", "?")
        role     = rec.get("role", "?")
        mult_str = f"{DIM} ×{exp_n}{RESET}" if exp_n > 1 else ""

        if exp_n == act_n:
            passed += 1
            print(f"  {GREEN}✓{RESET} {proto}/{role}{mult_str}")
        else:
            kind = "MISSING" if act_n == 0 else "UNEXPECTED" if exp_n == 0 else "COUNT"
            failures.append((kind, fp, rec, exp_n, act_n))
            if kind == "COUNT":
                detail = f"expected {exp_n}× got {act_n}×"
            elif kind == "MISSING":
                detail = f"missing (expected {exp_n}×)"
            else:
                detail = f"unexpected (got {act_n}×)"
            print(f"  {RED}✗{RESET} {proto}/{role}{mult_str}  {RED}{detail}{RESET}")

    total  = len(all_fps)
    n_fail = len(failures)

    # ── summary ───────────────────────────────────────────────────────────────
    print(
        f"\n{total} tests: "
        f"  {GREEN}{passed} passed{RESET}"
        + (f"  {RED}{n_fail} failed{RESET}" if n_fail else "")
    )

    if not failures:
        print(f"\n{GREEN}{BOLD}All {total} tests passed.{RESET}\n")
        return 0

    # ── failures in red ───────────────────────────────────────────────────────
    print(f"\n{RED}{BOLD}{LINE}")
    print(f"  FAILED TESTS  ({n_fail})")
    print(f"{LINE}{RESET}\n")

    for kind, fp, rec, exp_n, act_n in failures:
        proto = rec.get("protocol", "?")
        role  = rec.get("role", "?")
        feat  = short_feat(rec.get("features", ""))

        if kind == "COUNT":
            detail = f"expected {exp_n}×  got {act_n}×"
        elif kind == "MISSING":
            detail = f"expected {exp_n}×  got 0 (missing)"
        else:
            detail = f"not expected  got {act_n}× (unexpected)"

        print(f"  {RED}✗ {proto}/{role}{RESET}  {DIM}{detail}{RESET}")
        print(f"    {DIM}features{RESET}:    {feat}")
        print(f"    {DIM}fingerprint{RESET}: {fp}")
        print()

    print(f"{RED}{BOLD}{LINE}{RESET}\n")
    return 1


if __name__ == "__main__":
    sys.exit(main())
