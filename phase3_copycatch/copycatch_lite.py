"""
CopyCatch-lite: fixed-width time-window lockstep detector
------------------------------------------------------------
Implements the core mechanism of Beutel et al. (WWW 2013) "CopyCatch:
Stopping Group Attacks by Spotting Lockstep Behavior in Social Networks":
detect groups of accounts acting within a suspiciously tight time window.

What we implement:
  - Per-merchant chargeback timestamp extraction and sorting.
  - A fixed-width sliding time window, counting distinct accounts active
    in each window.
  - Flagging windows whose distinct-account count exceeds a threshold,
    then merging overlapping flagged windows into single "events."

What we deliberately do NOT implement:
  - The original paper's local-search heuristic for finding the optimal
    bipartite dense-block boundary. Basic time-window clustering is
    sufficient to catch lockstep behavior at low-to-medium camouflage
    (wide jitter is the archetype's actual camouflage mechanism here,
    not a structural evasion CopyCatch's original optimization was built
    for), and its expected degradation as jitter widens is itself a
    reportable finding, not a flaw to hide.

Usage:
    python3 copycatch_lite.py --data ../phase1_dataset_construction/output --out ./results
"""

import argparse
import csv
import os
from collections import defaultdict
from datetime import datetime, timedelta


def load_chargebacks(data_dir):
    """Returns {merchant_id: [(timestamp, account_id, amount), ...]} sorted
    by time. Chargebacks are src_account=merchant, dst_account=customer in
    this dataset's schema."""
    by_merchant = defaultdict(list)
    with open(os.path.join(data_dir, "transactions.csv")) as f:
        for row in csv.DictReader(f):
            if row["txn_type"] != "chargeback":
                continue
            ts = datetime.fromisoformat(row["timestamp"])
            by_merchant[row["src_account"]].append((ts, row["dst_account"], float(row["amount"])))
    for m in by_merchant:
        by_merchant[m].sort(key=lambda x: x[0])
    return by_merchant


def find_lockstep_windows(events, window_minutes, min_accounts):
    """Slide a fixed-width window across sorted (timestamp, account, amount)
    events for one merchant. Returns a list of (window_start, window_end,
    {accounts}, total_amount) for every window whose distinct account
    count >= min_accounts. Uses a simple two-pointer sweep -- O(n) per
    merchant, not the full local-search optimization from the original
    paper."""
    flagged = []
    window = timedelta(minutes=window_minutes)
    n = len(events)
    left = 0
    for right in range(n):
        while events[right][0] - events[left][0] > window:
            left += 1
        in_window = events[left:right + 1]
        accounts_in_window = set(acc for _, acc, _ in in_window)
        if len(accounts_in_window) >= min_accounts:
            total_amount = sum(amt for _, _, amt in in_window)
            flagged.append((events[left][0], events[right][0], accounts_in_window, total_amount))
    return flagged


def merge_overlapping_events(flagged_windows):
    """Merge windows whose time ranges overlap into single events, unioning
    their account sets and summing their amounts. Without this, a single
    lockstep burst gets reported as dozens of near-duplicate overlapping
    windows instead of one event. NOTE: summing amounts across merged,
    overlapping windows can double-count a chargeback that appears in more
    than one source window -- acceptable here since we only use this total
    as an approximate exposure figure, not a ledger balance, but worth
    knowing if this number is reused elsewhere."""
    if not flagged_windows:
        return []
    flagged_windows = sorted(flagged_windows, key=lambda w: w[0])
    merged = [list(flagged_windows[0])]
    for start, end, accounts, amount in flagged_windows[1:]:
        last_start, last_end, last_accounts, last_amount = merged[-1]
        if start <= last_end:
            merged[-1] = [last_start, max(last_end, end), last_accounts | accounts, last_amount + amount]
        else:
            merged.append([start, end, accounts, amount])
    return merged


def detect(data_dir, window_minutes, min_accounts):
    by_merchant = load_chargebacks(data_dir)
    all_events = []
    for merchant, events in by_merchant.items():
        flagged = find_lockstep_windows(events, window_minutes, min_accounts)
        merged = merge_overlapping_events(flagged)
        for start, end, accounts, total_amount in merged:
            all_events.append({
                "merchant": merchant, "start": start, "end": end,
                "accounts": accounts, "total_amount": total_amount,
            })
    return all_events


def evaluate(events, ground_truth_path):
    true_rings = defaultdict(set)
    ring_level = {}
    with open(ground_truth_path) as f:
        for row in csv.DictReader(f):
            if row["ring_type"] == "lockstep_chargeback_ring":
                true_rings[row["ring_id"]].add(row["account_id"])
                ring_level[row["ring_id"]] = row["camouflage_level"]

    all_true = set()
    for s in true_rings.values():
        all_true |= s

    all_flagged = set()
    for e in events:
        all_flagged |= e["accounts"]

    tp = len(all_flagged & all_true)
    fp = len(all_flagged - all_true)
    fn = len(all_true - all_flagged)
    precision = tp / len(all_flagged) if all_flagged else 0
    recall = tp / len(all_true) if all_true else 0

    by_level_true = defaultdict(set)
    for ring_id, members in true_rings.items():
        by_level_true[ring_level[ring_id]] |= members

    tier_recall = {}
    for lvl, members in by_level_true.items():
        tier_recall[lvl] = len(all_flagged & members) / len(members) if members else 0

    return {
        "precision": precision, "recall": recall,
        "tp": tp, "fp": fp, "fn": fn,
        "tier_recall": tier_recall,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../phase1_dataset_construction/output")
    parser.add_argument("--out", default="./results")
    parser.add_argument("--window_minutes", type=float, default=30.0)
    parser.add_argument("--min_accounts", type=int, default=4)
    args = parser.parse_args()

    events = detect(args.data, args.window_minutes, args.min_accounts)
    print(f"Found {len(events)} lockstep events "
          f"(window={args.window_minutes}min, min_accounts={args.min_accounts})")

    report = evaluate(events, os.path.join(args.data, "ground_truth.csv"))
    print(f"\nOverall: precision={report['precision']:.3f}  recall={report['recall']:.3f}  "
          f"(TP={report['tp']} FP={report['fp']} FN={report['fn']})")
    print("\nRecall by camouflage tier:")
    for lvl in ["easy", "medium", "hard"]:
        if lvl in report["tier_recall"]:
            print(f"  {lvl:8s}: recall={report['tier_recall'][lvl]:.2f}")

    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, "copycatch_events.csv")
    with open(out_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["merchant", "start", "end", "n_accounts", "accounts"])
        for e in events:
            w.writerow([e["merchant"], e["start"].isoformat(), e["end"].isoformat(),
                        len(e["accounts"]), ";".join(sorted(e["accounts"]))])
    print(f"\nWritten to {out_path}")


if __name__ == "__main__":
    main()
