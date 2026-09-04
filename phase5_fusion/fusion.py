"""
Phase 5: Fusion Layer -- Three Operating Modes, Not One "Optimal" Threshold
------------------------------------------------------------------------------
Earlier version of this script picked a single cost-minimizing threshold per
detector and called it done. That bakes a business judgment (how much fraud
loss is worth trading for how much investigator workload) into the algorithm,
when it's actually a decision that belongs to whoever owns the tradeoff --
Compliance, the CFO, or Risk Ops, and they don't all want the same tradeoff.

This version sweeps every threshold, reports precision/recall/flagged-volume/
financial-cost/investigator-headcount at EVERY point (not just the winner),
and surfaces three named operating modes:

  CONSERVATIVE -- maximize recall. For Compliance/Legal: missing a ring is
                  the expensive mistake, not reviewing an extra account.
  BALANCED     -- minimize total expected financial cost (Bahnsen et al.,
                  2016 framework). For CFO/Ops: optimize total P&L impact.
  AGGRESSIVE   -- minimize flagged volume / investigator workload, subject
                  to a stated minimum recall floor (so it can't degenerate
                  to "flag nothing"). For Risk teams with limited review
                  capacity.

The output is a menu, not an answer: "here are your options," not "here is
the optimal threshold."

Usage:
    python3 fusion.py --data ../phase1_dataset_construction/output --out ./results
"""

import argparse
import csv
import math
import os
import sys
import statistics
from collections import defaultdict
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase2_detection"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase3_copycatch"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase4_flowscope"))

import fraudar_lite
import copycatch_lite
import flowscope_lite

# ------------------------------------------------------------------
# STATED ASSUMPTIONS -- all exposed as constants, all trivially swappable
# for real operational numbers. None of these are measured; all are
# labeled as assumptions in every place they're printed or written.
# ------------------------------------------------------------------
REVIEW_COST_PER_ACCOUNT = 150.0          # Rs, analyst time per account reviewed
INVESTIGATOR_CAPACITY_PER_DAY = 20       # accounts one investigator can review per day
REVIEW_SLA_DAYS = 1                      # alerts should be cleared within this many days
AGGRESSIVE_MIN_RECALL = 0.5              # floor so "aggressive" can't degenerate to "flag nothing"


# ------------------------------------------------------------------
# Ground truth / data-driven FN cost (unchanged from v1 -- this part
# was already real, not assumed)
# ------------------------------------------------------------------
def load_ground_truth_costs(data_dir):
    ring_members = defaultdict(set)
    ring_type = {}
    with open(os.path.join(data_dir, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            ring_members[row["ring_id"]].add(row["account_id"])
            ring_type[row["ring_id"]] = row["ring_type"]

    account_to_ring = {}
    for rid, members in ring_members.items():
        for m in members:
            account_to_ring[m] = rid

    ring_amount = defaultdict(float)
    with open(os.path.join(data_dir, "transactions.csv")) as f:
        for row in csv.DictReader(f):
            for acc in (row["src_account"], row["dst_account"]):
                if acc in account_to_ring:
                    ring_amount[account_to_ring[acc]] += float(row["amount"])
                    break

    ring_per_member_cost = {
        rid: ring_amount[rid] / len(members) for rid, members in ring_members.items()
    }
    return account_to_ring, ring_type, ring_per_member_cost


def compute_metrics(flagged, account_to_ring, ring_per_member_cost, all_true_accounts):
    """Every metric a risk-team stakeholder would actually ask about, not
    just cost. This is the point of the rewrite: cost was the only lens
    before, now precision/recall/volume/headcount are all first-class."""
    tp = flagged & all_true_accounts
    fp = flagged - all_true_accounts
    fn = all_true_accounts - flagged

    precision = len(tp) / len(flagged) if flagged else 0.0
    recall = len(tp) / len(all_true_accounts) if all_true_accounts else 0.0
    financial_cost = len(fp) * REVIEW_COST_PER_ACCOUNT + \
        sum(ring_per_member_cost[account_to_ring[a]] for a in fn)
    investigators_needed = math.ceil(len(flagged) / (INVESTIGATOR_CAPACITY_PER_DAY * REVIEW_SLA_DAYS)) if flagged else 0

    return {
        "precision": round(precision, 3), "recall": round(recall, 3),
        "n_flagged": len(flagged), "fp": len(fp), "fn": len(fn),
        "financial_cost": round(financial_cost, 2),
        "investigators_needed": investigators_needed,
    }


# ------------------------------------------------------------------
# Per-detector threshold sweeps -- now capturing ALL metrics at every
# point, not just cost
# ------------------------------------------------------------------
def sweep_fraudar(data_dir, account_to_ring, ring_per_member_cost, archetype_accounts):
    edges = fraudar_lite.load_bipartite_graph(data_dir)
    scores = fraudar_lite.score_accounts(edges)
    results = []
    for k in [0.25, 0.5, 0.75, 1.0, 1.25, 1.5, 1.75, 2.0, 2.25, 2.5]:
        flagged, cutoff, mean, stdev = fraudar_lite.flag_by_threshold(scores, k_std=k, direction="below")
        m = compute_metrics(flagged, account_to_ring, ring_per_member_cost, archetype_accounts)
        results.append({"detector": "fraudar", "param": f"k_std={k}", "flagged": flagged, **m})
    return results


def sweep_copycatch(data_dir, account_to_ring, ring_per_member_cost, archetype_accounts):
    results = []
    for window in [10, 15, 30, 60]:
        for min_acc in [3, 4, 5, 6]:
            events = copycatch_lite.detect(data_dir, window, min_acc)
            flagged = set()
            for e in events:
                flagged |= e["accounts"]
            m = compute_metrics(flagged, account_to_ring, ring_per_member_cost, archetype_accounts)
            results.append({"detector": "copycatch", "param": f"window={window},min_acc={min_acc}",
                             "flagged": flagged, **m})
    return results


def sweep_flowscope(data_dir, account_to_ring, ring_per_member_cost, archetype_accounts):
    results = []
    for span in [20, 40, 60, 120, 180, 300]:
        for ratio in [0.2, 0.3, 0.5, 0.7]:
            cycles = flowscope_lite.detect(data_dir, span, ratio, max_cycle_length=10, verbose=False)
            flagged = set()
            for c in cycles:
                if c["flagged"]:
                    flagged |= set(c["cycle"])
            m = compute_metrics(flagged, account_to_ring, ring_per_member_cost, archetype_accounts)
            results.append({"detector": "flowscope", "param": f"span={span},ratio={ratio}",
                             "flagged": flagged, **m})
    return results


# ------------------------------------------------------------------
# Mode selection -- this is the actual point of the rewrite
# ------------------------------------------------------------------
def select_modes(results):
    """Returns {mode_name: chosen_result_dict, ...}. Each selection rule is
    stated explicitly, not hidden in a scoring formula."""
    modes = {}

    # CONSERVATIVE: max recall, tie-break on lowest financial cost
    modes["conservative"] = max(results, key=lambda r: (r["recall"], -r["financial_cost"]))

    # BALANCED: min financial cost (the old v1 behavior, now one of three
    # options instead of THE answer)
    modes["balanced"] = min(results, key=lambda r: r["financial_cost"])

    # AGGRESSIVE: min flagged volume (= min investigator workload),
    # SUBJECT TO a stated minimum recall floor so it can't degenerate to
    # "flag nobody, zero workload, zero recall"
    eligible = [r for r in results if r["recall"] >= AGGRESSIVE_MIN_RECALL]
    if eligible:
        modes["aggressive"] = min(eligible, key=lambda r: r["n_flagged"])
        modes["aggressive"]["_fallback_used"] = False
    else:
        # no threshold clears the recall floor -- fall back to best
        # precision available, and say so explicitly rather than silently
        # picking something that violates the stated floor
        modes["aggressive"] = max(results, key=lambda r: r["precision"])
        modes["aggressive"]["_fallback_used"] = True

    return modes


def print_mode_table(detector_name, modes):
    print(f"\n--- {detector_name} ---")
    header = f"{'Mode':13s} {'Param':28s} {'Precision':>9s} {'Recall':>7s} {'Flagged':>8s} {'Cost(Rs)':>10s} {'Investigators':>13s}"
    print(header)
    for mode_name in ["conservative", "balanced", "aggressive"]:
        r = modes[mode_name]
        fallback = "  [recall floor not reachable -- fell back to max precision]" if r.get("_fallback_used") else ""
        print(f"{mode_name:13s} {r['param']:28s} {r['precision']:9.3f} {r['recall']:7.3f} "
              f"{r['n_flagged']:8d} {r['financial_cost']:10.0f} {r['investigators_needed']:13d}{fallback}")


# ------------------------------------------------------------------
# Evidence dossier (unchanged logic from v1, bug-fixed version --
# both-sides transaction lookup)
# ------------------------------------------------------------------
def compute_transaction_risk_scores(data_dir, flagged_accounts):
    txns_by_account = defaultdict(list)
    all_amounts = []
    with open(os.path.join(data_dir, "transactions.csv")) as f:
        for row in csv.DictReader(f):
            amt = float(row["amount"])
            all_amounts.append(amt)
            ts = datetime.fromisoformat(row["timestamp"])
            if row["src_account"] in flagged_accounts:
                txns_by_account[row["src_account"]].append((ts, amt, row["dst_account"]))
            if row["dst_account"] in flagged_accounts:
                txns_by_account[row["dst_account"]].append((ts, amt, row["src_account"]))

    pop_mean = statistics.mean(all_amounts)
    pop_stdev = statistics.pstdev(all_amounts)

    scores = {}
    for acc in flagged_accounts:
        txns = txns_by_account.get(acc, [])
        if not txns:
            scores[acc] = {"risk_score": 0.0, "velocity_txn_per_day": 0.0,
                            "max_amount_zscore": 0.0, "new_counterparty_fraction": 0.0,
                            "n_transactions": 0}
            continue
        txns.sort()
        span_days = max((txns[-1][0] - txns[0][0]).total_seconds() / 86400.0, 1.0)
        velocity = len(txns) / span_days
        amounts = [t[1] for t in txns]
        max_amt_z = (max(amounts) - pop_mean) / pop_stdev if pop_stdev > 0 else 0
        counterparties = [t[2] for t in txns]
        new_counterparty_fraction = len(set(counterparties)) / len(counterparties)
        risk_score = (0.4 * min(velocity / 5.0, 1.0) +
                      0.4 * min(max(max_amt_z, 0) / 3.0, 1.0) +
                      0.2 * new_counterparty_fraction)
        scores[acc] = {"risk_score": round(risk_score, 3), "velocity_txn_per_day": round(velocity, 2),
                        "max_amount_zscore": round(max_amt_z, 2),
                        "new_counterparty_fraction": round(new_counterparty_fraction, 2),
                        "n_transactions": len(txns)}
    return scores


def write_evidence_dossier(path, flagged, account_source, all_true_accounts, data_dir):
    risk_scores = compute_transaction_risk_scores(data_dir, flagged)
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["account_id", "flagged_by_detector", "archetype", "is_true_fraud",
                     "risk_score", "velocity_txn_per_day", "max_amount_zscore",
                     "new_counterparty_fraction", "n_transactions"])
        for acc in sorted(flagged, key=lambda a: -risk_scores.get(a, {}).get("risk_score", 0)):
            detector, archetype = account_source.get(acc, ("unknown", "unknown"))
            rs = risk_scores.get(acc, {})
            w.writerow([acc, detector, archetype, acc in all_true_accounts,
                        rs.get("risk_score", ""), rs.get("velocity_txn_per_day", ""),
                        rs.get("max_amount_zscore", ""), rs.get("new_counterparty_fraction", ""),
                        rs.get("n_transactions", "")])


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../phase1_dataset_construction/output")
    parser.add_argument("--out", default="./results")
    args = parser.parse_args()

    account_to_ring, ring_type, ring_per_member_cost = load_ground_truth_costs(args.data)
    all_true_accounts = set(account_to_ring.keys())
    archetypes = {
        "shared_infra_promo_abuse": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "shared_infra_promo_abuse"),
        "lockstep_chargeback_ring": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "lockstep_chargeback_ring"),
        "circular_flow_laundering": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "circular_flow_laundering"),
    }

    print("=" * 100)
    print("THREE OPERATING MODES -- pick based on your team's constraint, not ours")
    print(f"Assumptions (all adjustable): review cost=Rs{REVIEW_COST_PER_ACCOUNT}/account, "
          f"investigator capacity={INVESTIGATOR_CAPACITY_PER_DAY} accounts/day, "
          f"SLA={REVIEW_SLA_DAYS} day(s), aggressive-mode recall floor={AGGRESSIVE_MIN_RECALL}")
    print("=" * 100)

    all_sweeps = []
    per_detector_modes = {}

    fraudar_results = sweep_fraudar(args.data, account_to_ring, ring_per_member_cost,
                                     archetypes["shared_infra_promo_abuse"])
    all_sweeps += fraudar_results
    per_detector_modes["fraudar"] = select_modes(fraudar_results)
    print_mode_table("FRAUDAR-lite (shared_infra_promo_abuse)", per_detector_modes["fraudar"])

    cc_results = sweep_copycatch(args.data, account_to_ring, ring_per_member_cost,
                                  archetypes["lockstep_chargeback_ring"])
    all_sweeps += cc_results
    per_detector_modes["copycatch"] = select_modes(cc_results)
    print_mode_table("CopyCatch-lite (lockstep_chargeback_ring)", per_detector_modes["copycatch"])

    fs_results = sweep_flowscope(args.data, account_to_ring, ring_per_member_cost,
                                  archetypes["circular_flow_laundering"])
    all_sweeps += fs_results
    per_detector_modes["flowscope"] = select_modes(fs_results)
    print_mode_table("FlowScope-lite (circular_flow_laundering)", per_detector_modes["flowscope"])

    # ------------------------------------------------------------------
    # Fused system-level view PER MODE: apply the same mode consistently
    # across all three detectors, union the flags, report combined metrics
    # ------------------------------------------------------------------
    print("\n" + "=" * 100)
    print("FUSED SYSTEM-LEVEL VIEW -- what the risk team actually sees per mode")
    print("=" * 100)
    print(f"{'Mode':13s} {'Precision':>9s} {'Recall':>7s} {'Flagged':>8s} {'Cost(Rs)':>10s} {'Investigators':>13s}")

    os.makedirs(args.out, exist_ok=True)
    operating_modes_rows = []

    for mode_name in ["conservative", "balanced", "aggressive"]:
        union_flagged = set()
        account_source = {}
        for detector_key, modes in per_detector_modes.items():
            chosen = modes[mode_name]
            union_flagged |= chosen["flagged"]
            archetype = {"fraudar": "shared_infra_promo_abuse",
                         "copycatch": "lockstep_chargeback_ring",
                         "flowscope": "circular_flow_laundering"}[detector_key]
            for a in chosen["flagged"]:
                account_source[a] = (detector_key, archetype)

            operating_modes_rows.append({
                "mode": mode_name, "detector": detector_key, "param": chosen["param"],
                "precision": chosen["precision"], "recall": chosen["recall"],
                "n_flagged": chosen["n_flagged"], "financial_cost": chosen["financial_cost"],
                "investigators_needed": chosen["investigators_needed"],
            })

        fused_metrics = compute_metrics(union_flagged, account_to_ring, ring_per_member_cost, all_true_accounts)
        print(f"{mode_name:13s} {fused_metrics['precision']:9.3f} {fused_metrics['recall']:7.3f} "
              f"{fused_metrics['n_flagged']:8d} {fused_metrics['financial_cost']:10.0f} "
              f"{fused_metrics['investigators_needed']:13d}")

        operating_modes_rows.append({
            "mode": mode_name, "detector": "FUSED (all 3)", "param": "-",
            "precision": fused_metrics["precision"], "recall": fused_metrics["recall"],
            "n_flagged": fused_metrics["n_flagged"], "financial_cost": fused_metrics["financial_cost"],
            "investigators_needed": fused_metrics["investigators_needed"],
        })

        dossier_path = os.path.join(args.out, f"evidence_dossier_{mode_name}.csv")
        write_evidence_dossier(dossier_path, union_flagged, account_source, all_true_accounts, args.data)

    # ------------------------------------------------------------------
    # Write full threshold sweep (every point, every detector, every metric)
    # ------------------------------------------------------------------
    sweep_path = os.path.join(args.out, "threshold_sweep.csv")
    with open(sweep_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["detector", "param", "precision", "recall",
                                            "n_flagged", "fp", "fn", "financial_cost",
                                            "investigators_needed"])
        w.writeheader()
        for row in all_sweeps:
            w.writerow({k: row[k] for k in w.fieldnames})

    modes_path = os.path.join(args.out, "operating_modes.csv")
    with open(modes_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["mode", "detector", "param", "precision", "recall",
                                            "n_flagged", "financial_cost", "investigators_needed"])
        w.writeheader()
        w.writerows(operating_modes_rows)

    print(f"\nWritten: {sweep_path}  (every threshold tried, every metric -- the full tradeoff surface)")
    print(f"Written: {modes_path}  (the three modes, per-detector and fused)")
    print(f"Written: {os.path.join(args.out, 'evidence_dossier_conservative.csv')} / "
          f"_balanced.csv / _aggressive.csv (the actual review queue for whichever mode you pick)")


if __name__ == "__main__":
    main()
