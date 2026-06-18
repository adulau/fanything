#!/usr/bin/env python3
"""Cluster fanfp.py JSON output by 128-bit SimHash Hamming distance."""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, DefaultDict, Dict, Iterable, Iterator, List, Optional, Sequence, TextIO, Tuple

SIMHASH_BITS = 128
DEFAULT_THRESHOLD = 12


@dataclass(frozen=True, slots=True)
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


@dataclass(slots=True)
class LightProtocolSummary:
    compared_records: int = 0
    similar_pairs: int = 0
    ip_counts: DefaultDict[str, int] = field(default_factory=lambda: defaultdict(int))


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
    """Yield top-level JSON objects without loading JSON Lines inputs at once."""
    decoder = json.JSONDecoder()
    buffer = ""
    position = 0
    value_count = 0
    line_offset = 0

    def trim_consumed() -> None:
        nonlocal buffer, position, line_offset
        if position <= 4096:
            return
        line_offset += buffer.count("\n", 0, position)
        buffer = buffer[position:]
        position = 0

    while True:
        chunk = handle.read(65536)
        if chunk:
            buffer += chunk

        while True:
            while position < len(buffer) and buffer[position].isspace():
                position += 1
            if position >= len(buffer):
                trim_consumed()
                break

            try:
                value, position = decoder.raw_decode(buffer, position)
            except json.JSONDecodeError as exc:
                if chunk:
                    trim_consumed()
                    break
                line_number = line_offset + buffer.count("\n", 0, exc.pos) + 1
                raise ValueError(f"invalid JSON on line {line_number}: {exc}") from exc

            value_count += 1
            if isinstance(value, list):
                for item_position, item in enumerate(value, start=1):
                    if not isinstance(item, dict):
                        raise ValueError(f"JSON array item {item_position} is not an object")
                    yield item
            elif isinstance(value, dict):
                yield value
            else:
                raise ValueError("input must be JSON object lines, JSON objects, one JSON object, or a JSON array")
            trim_consumed()

        if not chunk:
            break

    if value_count == 0:
        raise ValueError("input must contain at least one JSON value")


def load_records(path: Optional[Path]) -> List[FingerprintRecord]:
    records: List[FingerprintRecord] = []

    def append_records(raw_items: Iterator[Dict[str, Any]]) -> None:
        for index, item in enumerate(raw_items, start=1):
            try:
                records.append(FingerprintRecord(index, item, parse_simhash(item.get("simhash128"))))
            except ValueError as exc:
                raise ValueError(f"record {index}: {exc}") from exc

    if path is None or str(path) == "-":
        append_records(iter_json_values(sys.stdin))
    else:
        with path.open("r", encoding="utf-8") as handle:
            append_records(iter_json_values(handle))

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


Edge = Tuple[int, int, int]


def _block_slices(threshold: int) -> List[Tuple[int, int]]:
    """Return low-bit offsets and masks for exact multi-index Hamming search."""
    block_count = min(threshold + 1, SIMHASH_BITS)
    base_width, extra = divmod(SIMHASH_BITS, block_count)
    slices = []
    offset = 0
    for block_index in range(block_count):
        width = base_width + (1 if block_index < extra else 0)
        slices.append((offset, (1 << width) - 1))
        offset += width
    return slices


def _candidate_pairs_for_group(records: Sequence[FingerprintRecord], indices: Sequence[int], threshold: int) -> Iterator[Tuple[int, int, int]]:
    if threshold >= SIMHASH_BITS:
        for offset, left_index in enumerate(indices):
            left = records[left_index]
            for right_index in indices[offset + 1:]:
                yield left_index, right_index, hamming_distance(left.simhash, records[right_index].simhash)
        return

    block_slices = _block_slices(threshold)
    block_maps: List[DefaultDict[int, List[int]]] = [defaultdict(list) for _ in block_slices]

    for right_index in indices:
        right_simhash = records[right_index].simhash
        candidates = set()
        block_values = []
        for (offset, mask), block_map in zip(block_slices, block_maps):
            block_value = (right_simhash >> offset) & mask
            block_values.append(block_value)
            candidates.update(block_map.get(block_value, ()))

        for left_index in candidates:
            distance = hamming_distance(records[left_index].simhash, right_simhash)
            if distance <= threshold:
                yield left_index, right_index, distance

        for block_value, block_map in zip(block_values, block_maps):
            block_map[block_value].append(right_index)


def build_clusters(records: List[FingerprintRecord], threshold: int, cross_roles: bool) -> Tuple[List[List[int]], List[Edge]]:
    disjoint = DisjointSet(len(records))
    edges: List[Edge] = []

    if cross_roles:
        grouped_indices = [list(range(len(records)))]
    else:
        groups: DefaultDict[Tuple[str, str, str], List[int]] = defaultdict(list)
        for index, record in enumerate(records):
            groups[record.group_key].append(index)
        grouped_indices = groups.values()

    for indices in grouped_indices:
        if len(indices) < 2:
            continue
        for left_index, right_index, distance in _candidate_pairs_for_group(records, indices, threshold):
            disjoint.union(left_index, right_index)
            edges.append((left_index, right_index, distance))

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


def render_json(records: List[FingerprintRecord], clusters: List[List[int]], edges: List[Edge], threshold: int) -> None:
    payload = []
    for cluster_number, members in enumerate(clusters, start=1):
        member_set = set(members)
        cluster_edges = [
            {
                "left_record": records[left].index,
                "right_record": records[right].index,
                "distance": distance,
            }
            for left, right, distance in edges
            if left in member_set and right in member_set
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


def flow_ips(flow: Any) -> Tuple[str, ...]:
    if not isinstance(flow, dict):
        return ()
    ips = []
    for key in ("src", "dst"):
        value = flow.get(key)
        if value is not None and value != "":
            ips.append(str(value))
    return tuple(ips)


def _iter_candidate_indices(
    simhash: int,
    threshold: int,
    block_slices: Sequence[Tuple[int, int]],
    block_maps: Sequence[DefaultDict[int, List[int]]],
) -> Tuple[Iterable[int], List[int]]:
    if threshold >= SIMHASH_BITS:
        return (), []

    candidates = set()
    block_values = []
    for (offset, mask), block_map in zip(block_slices, block_maps):
        block_value = (simhash >> offset) & mask
        block_values.append(block_value)
        candidates.update(block_map.get(block_value, ()))
    return candidates, block_values


def build_light_summaries(records: List[FingerprintRecord], threshold: int, cross_roles: bool) -> Dict[str, LightProtocolSummary]:
    """Aggregate only per-protocol IP counts for similar pairs.

    This avoids materializing cluster membership and every similar edge in the
    final output path. It still keeps the compact record list needed for exact
    Hamming comparisons, but discards the expensive cluster/edge structures.
    """
    summaries: DefaultDict[str, LightProtocolSummary] = defaultdict(LightProtocolSummary)

    if cross_roles:
        grouped_indices = [list(range(len(records)))]
    else:
        groups: DefaultDict[Tuple[str, str, str], List[int]] = defaultdict(list)
        for index, record in enumerate(records):
            groups[record.group_key].append(index)
        grouped_indices = groups.values()

    for indices in grouped_indices:
        if not indices:
            continue
        protocol_names = {records[index].protocol for index in indices}
        for protocol in protocol_names:
            summaries[protocol].compared_records += sum(1 for index in indices if records[index].protocol == protocol)

        if len(indices) < 2:
            continue

        if threshold >= SIMHASH_BITS:
            for offset, left_index in enumerate(indices):
                left = records[left_index]
                for right_index in indices[offset + 1:]:
                    right = records[right_index]
                    distance = hamming_distance(left.simhash, right.simhash)
                    if distance <= threshold:
                        _count_light_pair(summaries, left, right)
            continue

        block_slices = _block_slices(threshold)
        block_maps: List[DefaultDict[int, List[int]]] = [defaultdict(list) for _ in block_slices]

        for right_index in indices:
            right = records[right_index]
            candidates, block_values = _iter_candidate_indices(right.simhash, threshold, block_slices, block_maps)

            for left_index in candidates:
                left = records[left_index]
                if hamming_distance(left.simhash, right.simhash) <= threshold:
                    _count_light_pair(summaries, left, right)

            for block_value, block_map in zip(block_values, block_maps):
                block_map[block_value].append(right_index)

    return dict(summaries)


def _count_light_pair(summaries: DefaultDict[str, LightProtocolSummary], left: FingerprintRecord, right: FingerprintRecord) -> None:
    protocols = (left.protocol,) if left.protocol == right.protocol else (left.protocol, right.protocol)
    for protocol in protocols:
        summary = summaries[protocol]
        summary.similar_pairs += 1
        for ip in (*flow_ips(left.flow), *flow_ips(right.flow)):
            summary.ip_counts[ip] += 1


def render_light_text(summaries: Dict[str, LightProtocolSummary], threshold: int, top: int) -> None:
    if not summaries:
        print(f"No records found at Hamming distance <= {threshold}.")
        return

    found = False
    for protocol in sorted(summaries):
        summary = summaries[protocol]
        print(f"Protocol {protocol or '?'} ({summary.similar_pairs} similar pairs, threshold <= {threshold})")
        if not summary.ip_counts:
            print("  No similar IPs found.")
            print()
            continue
        found = True
        for ip, count in sorted(summary.ip_counts.items(), key=lambda item: (-item[1], item[0]))[:top]:
            print(f"  {ip}: {count}")
        print()

    if not found:
        print(f"No similar IPs found at Hamming distance <= {threshold}.")


def render_light_json(summaries: Dict[str, LightProtocolSummary], threshold: int, top: int) -> None:
    protocols = []
    for protocol in sorted(summaries):
        summary = summaries[protocol]
        protocols.append({
            "protocol": protocol,
            "threshold": threshold,
            "compared_records": summary.compared_records,
            "similar_pairs": summary.similar_pairs,
            "top_ips": [
                {"ip": ip, "count": count}
                for ip, count in sorted(summary.ip_counts.items(), key=lambda item: (-item[1], item[0]))[:top]
            ],
        })
    print(json.dumps({"protocols": protocols}, indent=2, sort_keys=True))


def render_text(records: List[FingerprintRecord], clusters: List[List[int]], edges: List[Edge], threshold: int) -> None:
    if not clusters:
        print(f"No clusters found at Hamming distance <= {threshold}.")
        return
    edge_lookup = {(left, right): distance for left, right, distance in edges}
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
    parser.add_argument("--light", action="store_true", help="use a lower-resource summary showing only top common similar IPs per protocol")
    parser.add_argument("--top", type=int, default=10, help="number of IPs to show per protocol with --light (default: 10)")
    parser.add_argument("--format", choices=("text", "json"), default="text", help="output format (default: text)")
    args = parser.parse_args()

    if args.threshold < 0 or args.threshold > SIMHASH_BITS:
        parser.error(f"--threshold must be between 0 and {SIMHASH_BITS}")
    if args.top < 1:
        parser.error("--top must be at least 1")

    try:
        records = load_records(args.json)
        if args.light:
            light_summaries = build_light_summaries(records, args.threshold, args.cross_roles)
        else:
            clusters, edges = build_clusters(records, args.threshold, args.cross_roles)
    except ValueError as exc:
        parser.exit(1, f"fanfp_cluster.py: error: {exc}\n")

    if args.light and args.format == "json":
        render_light_json(light_summaries, args.threshold, args.top)
    elif args.light:
        render_light_text(light_summaries, args.threshold, args.top)
    elif args.format == "json":
        render_json(records, clusters, edges, args.threshold)
    else:
        render_text(records, clusters, edges, args.threshold)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
