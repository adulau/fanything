#!/usr/bin/env python3
"""Cluster fanfp.py JSON output by 128-bit SimHash Hamming distance."""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Iterator, List, Optional, TextIO, Tuple

SIMHASH_BITS = 128
DEFAULT_THRESHOLD = 12


@dataclass(frozen=True)
class FingerprintRecord:
    index: int
    item: Dict[str, Any]
    simhash: int

    @property
    def protocol(self) -> str:
        return str(self.item.get("protocol", ""))

    @property
    def role(self) -> str:
        return str(self.item.get("role", ""))

    @property
    def mode(self) -> str:
        return str(self.item.get("mode", ""))

    @property
    def flow(self) -> Any:
        return self.item.get("flow", {})

    @property
    def simhash_hex(self) -> str:
        return f"{self.simhash:032x}"

    @property
    def group_key(self) -> Tuple[str, str, str]:
        return self.protocol, self.role, self.mode


def parse_simhash(value: Any) -> int:
    if not isinstance(value, str):
        raise ValueError("simhash128 field is missing or is not a string")
    value = value.lower().removeprefix("0x")
    if len(value) != 32:
        raise ValueError("simhash128 must be exactly 32 hexadecimal characters")
    parsed = int(value, 16)
    if parsed >= 1 << SIMHASH_BITS:
        raise ValueError("simhash128 is wider than 128 bits")
    return parsed


def hamming_distance(left: int, right: int) -> int:
    return (left ^ right).bit_count()


def iter_json_values(handle: TextIO) -> Iterator[Dict[str, Any]]:
    text = handle.read().strip()
    if not text:
        return
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        for line_number, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"invalid JSON on line {line_number}: {exc}") from exc
            if not isinstance(item, dict):
                raise ValueError(f"JSON value on line {line_number} is not an object")
            yield item
        return

    if isinstance(value, list):
        for position, item in enumerate(value, start=1):
            if not isinstance(item, dict):
                raise ValueError(f"JSON array item {position} is not an object")
            yield item
    elif isinstance(value, dict):
        yield value
    else:
        raise ValueError("input must be JSON object lines, one JSON object, or a JSON array")


def load_records(path: Optional[Path]) -> List[FingerprintRecord]:
    if path is None or str(path) == "-":
        raw_items = iter_json_values(sys.stdin)
    else:
        with path.open("r", encoding="utf-8") as handle:
            raw_items = list(iter_json_values(handle))

    records = []
    for index, item in enumerate(raw_items, start=1):
        try:
            records.append(FingerprintRecord(index, item, parse_simhash(item.get("simhash128"))))
        except ValueError as exc:
            raise ValueError(f"record {index}: {exc}") from exc
    return records


class DisjointSet:
    def __init__(self, size: int) -> None:
        self.parent = list(range(size))

    def find(self, item: int) -> int:
        while self.parent[item] != item:
            self.parent[item] = self.parent[self.parent[item]]
            item = self.parent[item]
        return item

    def union(self, left: int, right: int) -> None:
        left_root = self.find(left)
        right_root = self.find(right)
        if left_root != right_root:
            self.parent[right_root] = left_root


def build_clusters(records: List[FingerprintRecord], threshold: int, cross_roles: bool) -> Tuple[List[List[int]], List[Dict[str, Any]]]:
    disjoint = DisjointSet(len(records))
    edges: List[Dict[str, Any]] = []
    for left_index, left in enumerate(records):
        for right_index in range(left_index + 1, len(records)):
            right = records[right_index]
            if not cross_roles and left.group_key != right.group_key:
                continue
            distance = hamming_distance(left.simhash, right.simhash)
            if distance <= threshold:
                disjoint.union(left_index, right_index)
                edges.append({"left": left_index, "right": right_index, "distance": distance})

    by_root: Dict[int, List[int]] = {}
    for index in range(len(records)):
        by_root.setdefault(disjoint.find(index), []).append(index)
    clusters = [members for members in by_root.values() if len(members) > 1]
    clusters.sort(key=lambda members: (len(members), -min(members)), reverse=True)
    return clusters, edges


def jsonable_record(record: FingerprintRecord) -> Dict[str, Any]:
    return {
        "record": record.index,
        "protocol": record.protocol,
        "role": record.role,
        "mode": record.mode,
        "simhash128": record.simhash_hex,
        "flow": record.flow,
        "fingerprint": record.item.get("fingerprint"),
        "features": record.item.get("features"),
        "frame": record.item.get("frame"),
    }


def render_json(records: List[FingerprintRecord], clusters: List[List[int]], edges: List[Dict[str, Any]], threshold: int) -> None:
    payload = []
    for cluster_number, members in enumerate(clusters, start=1):
        member_set = set(members)
        cluster_edges = [
            {
                "left_record": records[edge["left"]].index,
                "right_record": records[edge["right"]].index,
                "distance": edge["distance"],
            }
            for edge in edges
            if edge["left"] in member_set and edge["right"] in member_set
        ]
        payload.append({
            "cluster": cluster_number,
            "threshold": threshold,
            "members": [jsonable_record(records[index]) for index in members],
            "similar_pairs": sorted(cluster_edges, key=lambda edge: edge["distance"]),
        })
    print(json.dumps({"clusters": payload}, indent=2, sort_keys=True))


def flow_label(flow: Any) -> str:
    if isinstance(flow, dict):
        return f"{flow.get('src', '?')}:{flow.get('sport', '?')} -> {flow.get('dst', '?')}:{flow.get('dport', '?')}"
    return str(flow)


def render_text(records: List[FingerprintRecord], clusters: List[List[int]], edges: List[Dict[str, Any]], threshold: int) -> None:
    if not clusters:
        print(f"No clusters found at Hamming distance <= {threshold}.")
        return
    edge_lookup = {(edge["left"], edge["right"]): edge["distance"] for edge in edges}
    for cluster_number, members in enumerate(clusters, start=1):
        print(f"Cluster {cluster_number} ({len(members)} flows, threshold <= {threshold})")
        for index in members:
            record = records[index]
            print(f"  [{record.index}] {record.protocol}/{record.role}/{record.mode} {record.simhash_hex} {flow_label(record.flow)}")
        print("  Similar flow pairs:")
        pairs = []
        for offset, left in enumerate(members):
            for right in members[offset + 1:]:
                distance = edge_lookup.get((left, right))
                if distance is not None:
                    pairs.append((distance, left, right))
        for distance, left, right in sorted(pairs):
            print(f"    distance={distance:3d}: [{records[left].index}] {flow_label(records[left].flow)}  <->  [{records[right].index}] {flow_label(records[right].flow)}")
        print()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("json", nargs="?", type=Path, help="fanfp.py JSON output file, or '-' / omitted for stdin")
    parser.add_argument("--threshold", type=int, default=DEFAULT_THRESHOLD, help=f"maximum Hamming distance for similar simhash128 values (default: {DEFAULT_THRESHOLD})")
    parser.add_argument("--cross-roles", action="store_true", help="compare records across protocol, role, and mode instead of grouping by them")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    args = parser.parse_args()

    if args.threshold < 0 or args.threshold > SIMHASH_BITS:
        parser.error(f"--threshold must be between 0 and {SIMHASH_BITS}")

    try:
        records = load_records(args.json)
        clusters, edges = build_clusters(records, args.threshold, args.cross_roles)
    except ValueError as exc:
        parser.exit(1, f"fanfp_cluster.py: error: {exc}\n")

    if args.format == "json":
        render_json(records, clusters, edges, args.threshold)
    else:
        render_text(records, clusters, edges, args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
