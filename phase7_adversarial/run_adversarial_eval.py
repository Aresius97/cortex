"""
Phase 7: Adversarial Evaluation
------------------------------------
Runs the full detection + case-prioritization pipeline against both the
baseline dataset (Phase 1's original output) and the adversarial dataset
(baseline + 4 targeted attacks), then answers the actual question that
matters: when the attacker adapts, does the system still put the right
cases in front of a constrained investigation team -- not just "does
recall fall."

For each attack, reports:
  - Recall specifically on THAT ATTACK's own accounts (isolated from the
    baseline rings sharing the same archetype label, which would
    otherwise blend into one misleading aggregate number)
  - Precision / false-positive rate at the same operating point
  - Which detector's signal this attack targets, and whether it actually
    disappeared (recall on the attack vs. that detector's normal recall)
  - Rs exposure attributable to the attack that WAS vs. WASN'T captured
  - Whether the attack ring appears anywhere in the final priority queue
    at all (the "did it evade the whole system silently" check)
  - Whether the previously-top-ranked genuine cases got displaced

Usage:
    python3 run_adversarial_eval.py --investigators 5
"""

import argparse
import csv
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase2_detection"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase3_copycatch"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase4_flowscope"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase5_fusion"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase6_case_prioritization"))

import fraudar_lite
import copycatch_lite
import flowscope_lite
import fusion
import case_prioritizer as cp

ADVERSARIAL_DATA = "./adversarial_output"

ATTACK_TARGET_DETECTOR = {
    "attack1_fraudar_camouflage": "fraudar",
    "attack1b_fraudar_corrected": "fraudar",
    "attack2_copycatch_jitter": "copycatch",
    "attack2b_copycatch_spaced": "copycatch",
    "attack3_flowscope_delay": "flowscope",
    "attack4_cross_detector": "cross-detector (fraudar + copycatch jointly)",
}


def load_attack_accounts(data_dir):
    """Returns {attack_id: set(account_id)} and total Rs moved by each
    attack ring (from its own transactions, evidence-specific, not the
    account's entire history -- same principle as Phase 6)."""
    attack_accounts = defaultdict(set)
    with open(os.path.join(data_dir, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            if row.get("is_adversarial") == "True":
                attack_accounts[row["attack_id"]].add(row["account_id"])
    return attack_accounts


def get_conservative_flags_all(data_dir):
    """Returns the conservative-mode flagged set for each detector, run
    fresh against the given dataset."""
    account_to_ring, ring_type, ring_per_member_cost = fusion.load_ground_truth_costs(data_dir)
    archetypes = {
        "shared_infra_promo_abuse": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "shared_infra_promo_abuse"),
        "lockstep_chargeback_ring": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "lockstep_chargeback_ring"),
        "circular_flow_laundering": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "circular_flow_laundering"),
    }
    fraudar_c, cc_c, fs_c = cp.get_conservative_flags(data_dir, account_to_ring, ring_per_member_cost, archetypes)
    return {"fraudar": fraudar_c["flagged"], "copycatch": cc_c["flagged"], "flowscope": fs_c["flagged"]}


def evaluate_attack(attack_id, attack_accounts, flags_by_detector):
    target = ATTACK_TARGET_DETECTOR[attack_id]
    all_flagged = flags_by_detector["fraudar"] | flags_by_detector["copycatch"] | flags_by_detector["flowscope"]

    n = len(attack_accounts)
    caught = attack_accounts & all_flagged
    recall_system_wide = len(caught) / n if n else 0.0

    per_detector_recall = {}
    for det, flagged in flags_by_detector.items():
        per_detector_recall[det] = len(attack_accounts & flagged) / n if n else 0.0

    return {
        "attack_id": attack_id, "target_detector": target, "n_accounts": n,
        "system_wide_recall": round(recall_system_wide, 3),
        "per_detector_recall": per_detector_recall,
        "fully_evaded": len(caught) == 0,
    }


def compare_priority_queues(adversarial_data, investigators):
    """IMPORTANT: this does NOT compare against a separately-generated
    baseline dataset. Account IDs use uuid4 (OS entropy), which is not
    reproducible across separate script invocations even with the same
    --seed -- an earlier version of this comparison did exactly that and
    produced a meaningless "0/5 overlap" result purely because the two
    runs' account-ID strings could never match, regardless of whether the
    attacks had any real effect. See ENGINEERING_LOG.md Entry 12.

    Instead, this builds cases ONCE against the single adversarial
    dataset, then constructs the "what would the queue have looked like
    without the adversary" view by filtering OUT any case that touches an
    adversarial account from that SAME case pool -- both views share the
    same underlying ID space, so the comparison is actually meaningful."""
    data_dir = adversarial_data
    account_to_ring, ring_type, ring_per_member_cost = fusion.load_ground_truth_costs(data_dir)
    archetypes = {
        "shared_infra_promo_abuse": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "shared_infra_promo_abuse"),
        "lockstep_chargeback_ring": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "lockstep_chargeback_ring"),
        "circular_flow_laundering": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "circular_flow_laundering"),
    }
    adversarial_accounts = set()
    with open(os.path.join(data_dir, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            if row.get("is_adversarial") == "True":
                adversarial_accounts.add(row["account_id"])

    fraudar_c, cc_c, fs_c = cp.get_conservative_flags(data_dir, account_to_ring, ring_per_member_cost, archetypes)
    fraudar_cases = cp.build_fraudar_cases(data_dir, fraudar_c["flagged"])
    n_recovered = cp.expand_case_entities_safely(data_dir, fraudar_cases)
    print(f"  (recovered {n_recovered} dense-but-non-bridging entities for exposure attribution)")
    window = int(cc_c["param"].split("window=")[1].split(",")[0])
    min_acc = int(cc_c["param"].split("min_acc=")[1])
    copycatch_cases = cp.build_copycatch_cases(data_dir, window, min_acc)
    span = float(fs_c["param"].split("span=")[1].split(",")[0])
    ratio = float(fs_c["param"].split("ratio=")[1])
    flowscope_cases = cp.build_flowscope_cases(data_dir, span, ratio)

    all_cases = fraudar_cases + copycatch_cases + flowscope_cases
    exposure_by_fraudar_case = cp.compute_fraudar_case_exposure_bulk(data_dir, fraudar_cases)
    for i, case in enumerate(fraudar_cases):
        case["exposure"] = round(exposure_by_fraudar_case.get(i, 0.0), 2)
    for case in copycatch_cases:
        case["exposure"] = round(case["total_amount"], 2)
    for case in flowscope_cases:
        case["exposure"] = round(case["total_hop_amount"], 2)
    for case in all_cases:
        case["effort_hours"] = round(len(case["accounts"]) * cp.EFFORT_HOURS_PER_ACCOUNT, 2)
        cp.annotate_case(case)
        case["is_genuine"] = len(case["accounts"] & set(account_to_ring.keys())) > 0
        case["touches_adversarial"] = len(case["accounts"] & adversarial_accounts) > 0

    capacity_hours = investigators * cp.HOURS_PER_INVESTIGATOR_PER_DAY

    # VIEW 1: the actual post-attack world (all cases, including any
    # attack cases that survived detection)
    _, _, full_exposure = cp.greedy_select(all_cases, capacity_hours)
    full_selected, _, full_exposure = cp.knapsack_select(all_cases, capacity_hours)
    full_selected = sorted(full_selected, key=lambda c: -c["exposure"] / c["effort_hours"])

    # VIEW 2: what the queue would have looked like with the SAME
    # underlying data but no adversary -- filter out any case touching an
    # adversarial account entirely
    counterfactual_cases = [c for c in all_cases if not c["touches_adversarial"]]
    cf_selected, _, cf_exposure = cp.knapsack_select(counterfactual_cases, capacity_hours)
    cf_selected = sorted(cf_selected, key=lambda c: -c["exposure"] / c["effort_hours"])

    full_top5 = [frozenset(c["accounts"]) for c in full_selected[:5]]
    cf_top5 = [frozenset(c["accounts"]) for c in cf_selected[:5]]
    overlap = len(set(full_top5) & set(cf_top5))

    return {
        "counterfactual_n_selected": len(cf_selected), "full_n_selected": len(full_selected),
        "counterfactual_exposure": cf_exposure, "full_exposure": full_exposure,
        "top5_overlap": overlap, "full_top5_cases": full_selected[:5],
        "adversarial_accounts": adversarial_accounts,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--investigators", type=int, default=5)
    parser.add_argument("--out", default="./results")
    args = parser.parse_args()

    print("=" * 100)
    print("PHASE 7: ADVERSARIAL EVALUATION")
    print("=" * 100)

    print("\nRunning conservative-mode detection against ADVERSARIAL dataset...")
    adversarial_flags = get_conservative_flags_all(ADVERSARIAL_DATA)

    attack_accounts = load_attack_accounts(ADVERSARIAL_DATA)

    print("\n" + "=" * 100)
    print("PER-ATTACK RESULTS")
    print("=" * 100)
    attack_reports = []
    for attack_id in ["attack1_fraudar_camouflage", "attack1b_fraudar_corrected",
                       "attack2_copycatch_jitter", "attack2b_copycatch_spaced",
                       "attack3_flowscope_delay", "attack4_cross_detector"]:
        report = evaluate_attack(attack_id, attack_accounts[attack_id], adversarial_flags)
        attack_reports.append(report)
        print(f"\n{attack_id}  (targets: {report['target_detector']})")
        print(f"  Accounts in this attack ring: {report['n_accounts']}")
        print(f"  System-wide recall (caught by ANY detector): {report['system_wide_recall']:.1%}")
        for det, r in report["per_detector_recall"].items():
            flag = "  <-- targeted detector" if det in report["target_detector"] else ""
            print(f"    {det:12s} recall on this attack: {r:.1%}{flag}")
        if report["fully_evaded"]:
            print("  *** FULLY EVADED -- zero detector flagged any account in this ring ***")

    print("\n" + "=" * 100)
    print(f"PRIORITY QUEUE COMPARISON ({args.investigators} investigators)")
    print("=" * 100)
    pq = compare_priority_queues(ADVERSARIAL_DATA, args.investigators)
    print(f"Counterfactual (no adversary, same underlying data): {pq['counterfactual_n_selected']} cases selected, "
          f"Rs{pq['counterfactual_exposure']:,.0f} captured")
    print(f"Actual (post-attack):                                {pq['full_n_selected']} cases selected, "
          f"Rs{pq['full_exposure']:,.0f} captured")
    pct_change = (pq['full_exposure'] / pq['counterfactual_exposure'] - 1) * 100 \
        if pq['counterfactual_exposure'] else 0
    print(f"Change in Rs captured at fixed investigator capacity: {pct_change:+.1f}%")
    print(f"Top-5 case overlap (with vs without the adversary, same dataset): {pq['top5_overlap']}/5")

    print("\nActual post-attack top 5 selected cases:")
    all_adversarial_accounts = pq["adversarial_accounts"]
    for i, c in enumerate(pq["full_top5_cases"], 1):
        adv_marker = " [CONTAINS ADVERSARIAL ACCOUNT]" if c["accounts"] & all_adversarial_accounts else ""
        print(f"  {i}. {c['detector']:10s} {len(c['accounts'])} accounts, "
              f"Rs{c['exposure']:,.0f}, conf={c['confidence']:.2f}{adv_marker}")

    os.makedirs(args.out, exist_ok=True)
    with open(os.path.join(args.out, "attack_results.csv"), "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["attack_id", "target_detector", "n_accounts", "system_wide_recall",
                     "fraudar_recall", "copycatch_recall", "flowscope_recall", "fully_evaded"])
        for r in attack_reports:
            w.writerow([r["attack_id"], r["target_detector"], r["n_accounts"], r["system_wide_recall"],
                         r["per_detector_recall"]["fraudar"], r["per_detector_recall"]["copycatch"],
                         r["per_detector_recall"]["flowscope"], r["fully_evaded"]])

    print(f"\nWritten: {os.path.join(args.out, 'attack_results.csv')}")


if __name__ == "__main__":
    main()
