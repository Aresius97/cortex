"""
FlowScope-lite: cycle-based money-flow tracer
-------------------------------------------------
Implements the core idea of Li et al. (AAAI 2020) "FlowScope: Spotting
Money Laundering Based on Graph Flow Analysis": trace directed flow paths
through a transaction graph to catch layering/laundering movement, rather
than relying on static density or timing alone.

What we implement:
  - A directed merchant-to-merchant transaction graph (merchant-merchant
    transfers are structurally rare/absent in legitimate traffic in this
    dataset -- normal traffic is customer<->merchant only -- so this graph
    is already a strong pre-filter before any cycle logic runs).
  - Simple-cycle enumeration on that graph.
  - Two suspicion checks per cycle, matching the actual laundering
    signature the dataset injects: amount conservation across hops (money
    shrinks a little per hop from fees/skim, but shouldn't collapse or
    balloon) and time compression (a genuine layering chain completes
    quickly, not over unrelated, spread-out timeframes).

What we deliberately do NOT implement:
  - General-purpose flow/mincut optimization across a full multi-partite
    time-layered graph, which is FlowScope's actual algorithmic
    contribution for large-scale graphs. At this dataset's scale (a few
    hundred merchants, single-digit-length cycles), direct cycle
    enumeration with amount/time consistency checks captures the same
    signature without needing the heavier machinery.

Usage:
    python3 flowscope_lite.py --data ../phase1_dataset_construction/output --out ./results
"""

import argparse
import csv
import os
from collections import defaultdict
from datetime import datetime

import networkx as nx


def load_merchant_accounts(data_dir):
    merchants = set()
    with open(os.path.join(data_dir, "accounts.csv")) as f:
        for row in csv.DictReader(f):
            if row["account_type"] == "merchant":
                merchants.add(row["account_id"])
    return merchants


def load_merchant_to_merchant_edges(data_dir, merchants):
    """Merchant-to-merchant transactions are the pre-filter: legitimate
    traffic in this dataset is customer<->merchant only, so any
    merchant->merchant edge is already unusual before cycle logic runs."""
    edges = defaultdict(list)  # (src, dst) -> [(timestamp, amount), ...]
    with open(os.path.join(data_dir, "transactions.csv")) as f:
        for row in csv.DictReader(f):
            if row["src_account"] in merchants and row["dst_account"] in merchants:
                ts = datetime.fromisoformat(row["timestamp"])
                amt = float(row["amount"])
                edges[(row["src_account"], row["dst_account"])].append((ts, amt))
    return edges


def build_graph(edges):
    g = nx.DiGraph()
    for (src, dst), txns in edges.items():
        # if multiple transactions exist on the same directed pair, keep the
        # one used for cycle-consistency scoring as the most recent -- rare
        # in this dataset but handled explicitly rather than silently
        # picking the first list entry
        ts, amt = max(txns, key=lambda t: t[0])
        g.add_edge(src, dst, timestamp=ts, amount=amt)
    return g


def score_cycle(g, cycle, max_span_minutes, min_amount_ratio):
    """A cycle is a list of nodes, e.g. [A, B, C] meaning A->B->C->A.
    Returns (is_suspicious, span_minutes, amount_ratio, hop_amounts) so
    the caller can report the actual numbers, not just a boolean."""
    hops = list(zip(cycle, cycle[1:] + cycle[:1]))
    timestamps, amounts = [], []
    for src, dst in hops:
        data = g.get_edge_data(src, dst)
        timestamps.append(data["timestamp"])
        amounts.append(data["amount"])

    span_minutes = (max(timestamps) - min(timestamps)).total_seconds() / 60.0
    amount_ratio = min(amounts) / max(amounts) if max(amounts) > 0 else 0

    is_suspicious = (span_minutes <= max_span_minutes) and (amount_ratio >= min_amount_ratio)
    return is_suspicious, span_minutes, amount_ratio, amounts


def detect(data_dir, max_span_minutes, min_amount_ratio, max_cycle_length, verbose=True):
    merchants = load_merchant_accounts(data_dir)
    edges = load_merchant_to_merchant_edges(data_dir, merchants)
    g = build_graph(edges)

    if verbose:
        print(f"Merchant-to-merchant graph: {g.number_of_nodes()} nodes, {g.number_of_edges()} edges "
              f"(out of {len(merchants)} total merchants)")

    found_cycles = []
    for cycle in nx.simple_cycles(g, length_bound=max_cycle_length):
        if len(cycle) < 3:
            continue  # a 2-node back-and-forth isn't a laundering chain
        is_suspicious, span, ratio, hop_amounts = score_cycle(g, cycle, max_span_minutes, min_amount_ratio)
        found_cycles.append({
            "cycle": cycle, "flagged": is_suspicious,
            "span_minutes": span, "amount_ratio": ratio,
            "total_hop_amount": sum(hop_amounts),
        })

    return found_cycles


def evaluate(found_cycles, ground_truth_path):
    true_rings = defaultdict(set)
    ring_level = {}
    with open(ground_truth_path) as f:
        for row in csv.DictReader(f):
            if row["ring_type"] == "circular_flow_laundering":
                true_rings[row["ring_id"]].add(row["account_id"])
                ring_level[row["ring_id"]] = row["camouflage_level"]

    all_true = set()
    for s in true_rings.values():
        all_true |= s

    flagged_accounts = set()
    for c in found_cycles:
        if c["flagged"]:
            flagged_accounts |= set(c["cycle"])

    tp = len(flagged_accounts & all_true)
    fp = len(flagged_accounts - all_true)
    fn = len(all_true - flagged_accounts)
    precision = tp / len(flagged_accounts) if flagged_accounts else 0
    recall = tp / len(all_true) if all_true else 0

    by_level_true = defaultdict(set)
    for ring_id, members in true_rings.items():
        by_level_true[ring_level[ring_id]] |= members

    tier_recall = {}
    for lvl, members in by_level_true.items():
        tier_recall[lvl] = len(flagged_accounts & members) / len(members) if members else 0

    return {
        "precision": precision, "recall": recall,
        "tp": tp, "fp": fp, "fn": fn,
        "tier_recall": tier_recall, "flagged_accounts": flagged_accounts,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../phase1_dataset_construction/output")
    parser.add_argument("--out", default="./results")
    parser.add_argument("--max_span_minutes", type=float, default=180.0)
    parser.add_argument("--min_amount_ratio", type=float, default=0.3)
    parser.add_argument("--max_cycle_length", type=int, default=10)
    args = parser.parse_args()

    found_cycles = detect(args.data, args.max_span_minutes, args.min_amount_ratio, args.max_cycle_length)
    flagged_cycles = [c for c in found_cycles if c["flagged"]]
    print(f"\nFound {len(found_cycles)} candidate cycle(s) total, {len(flagged_cycles)} flagged as suspicious")
    for c in found_cycles:
        marker = "FLAGGED " if c["flagged"] else "        "
        print(f"  {marker} len={len(c['cycle']):2d}  span={c['span_minutes']:7.1f}min  "
              f"amount_ratio={c['amount_ratio']:.2f}")

    report = evaluate(found_cycles, os.path.join(args.data, "ground_truth.csv"))
    print(f"\nOverall: precision={report['precision']:.3f}  recall={report['recall']:.3f}  "
          f"(TP={report['tp']} FP={report['fp']} FN={report['fn']})")
    print("\nRecall by camouflage tier:")
    for lvl in ["easy", "medium", "hard"]:
        if lvl in report["tier_recall"]:
            print(f"  {lvl:8s}: recall={report['tier_recall'][lvl]:.2f}")

    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, "flowscope_cycles.csv")
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cycle_accounts", "flagged", "span_minutes", "amount_ratio"])
        for c in found_cycles:
            w.writerow([";".join(c["cycle"]), c["flagged"],
                        round(c["span_minutes"], 2), round(c["amount_ratio"], 3)])
    print(f"\nWritten to {out_path}")


if __name__ == "__main__":
    main()
