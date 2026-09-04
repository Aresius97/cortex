"""
Phase 9a runner: applies the cross-signal reasoning engine to
  (a) real single-archetype cases from the baseline dataset,
  (b) real cases from Phase 7's attack lineages (including two with a
      genuine before/after pair, giving a real adaptation indicator),
  (c) a small number of CLEARLY-LABELED SYNTHETIC cases illustrating
      genuine multi-signal agreement and disagreement, which this
      dataset cannot produce naturally (see reasoning_engine.py header).

Also writes the full 27-row rule table as a standalone auditable artifact.

Usage:
    python3 run_reasoning.py --baseline ../phase1_dataset_construction/output \
                              --adversarial ../phase7_adversarial/adversarial_output \
                              --out ./results
"""

import argparse
import csv
import json
import os
import sys
from collections import defaultdict

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase8_adaptive_threat"))
import adaptive_threat_detector as p8
from reasoning_engine import (reason_about_case, format_case_report, classify_signal_pattern,
                                compute_priority, disagreement_line, what_would_change_confidence,
                                write_rule_table_reference)


def load_ring_accounts_by_ring_id(data_dir, ring_id):
    accounts = set()
    with open(os.path.join(data_dir, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            if row["ring_id"] == ring_id:
                accounts.add(row["account_id"])
    return accounts


def pick_one_baseline_ring_per_archetype(data_dir):
    """First non-adversarial ring_id found for each of the three
    archetypes -- real cases, not cherry-picked for a flattering result."""
    seen = {}
    with open(os.path.join(data_dir, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            if row.get("is_adversarial") == "True":
                continue
            if row["ring_type"] not in seen:
                seen[row["ring_type"]] = row["ring_id"]
    return seen


def make_synthetic_case(case_id, fraudar, copycatch, flowscope, n_accounts, exposure,
                         fraudar_frac, copycatch_frac, flowscope_frac, adaptation_indicator="NONE"):
    """Bypasses live detection entirely -- these signal values are
    specified directly, not derived from any real account set, because
    this dataset structurally cannot produce genuine multi-detector
    agreement/disagreement (Phase 1's archetypes each trip one detector).
    Clearly labeled as synthetic everywhere it's printed or written,
    exactly like Phase 8's negative control."""
    interpretation, confidence, disagreement_type = classify_signal_pattern(fraudar, copycatch, flowscope)
    priority, priority_reason = compute_priority(confidence, adaptation_indicator, exposure)
    signals = {"FRAUDAR": fraudar, "CopyCatch": copycatch, "FlowScope": flowscope}
    high = [d for d, s in signals.items() if s == "HIGH"]
    low = [d for d, s in signals.items() if s == "LOW"]
    disagreement = disagreement_line(fraudar, copycatch, flowscope, disagreement_type, high, low)
    confidence_driver = what_would_change_confidence(disagreement_type, high, low)

    def line(name, sig, frac):
        if sig == "HIGH":
            return f"  ✓ {name}: HIGH -- {frac:.0%} of the ring's {n_accounts} accounts flagged (SYNTHETIC)"
        elif sig == "LOW":
            return f"  ✗ {name}: LOW -- checked, only {frac:.0%} flagged (SYNTHETIC)"
        else:
            return f"  ○ {name}: N/A (SYNTHETIC)"

    return {
        "case_id": f"{case_id} [SYNTHETIC — illustrates rule table, not a live detection]",
        "n_accounts": n_accounts, "fraudar": fraudar, "copycatch": copycatch, "flowscope": flowscope,
        "fraudar_frac": fraudar_frac, "copycatch_frac": copycatch_frac, "flowscope_frac": flowscope_frac,
        "evidence": [line("FRAUDAR", fraudar, fraudar_frac), line("CopyCatch", copycatch, copycatch_frac),
                     line("FlowScope", flowscope, flowscope_frac)],
        "interpretation": interpretation, "confidence": confidence,
        "disagreement_type": disagreement_type, "disagreement_line": disagreement,
        "confidence_driver": confidence_driver,
        "adaptation_indicator": adaptation_indicator, "adaptation_detail": None,
        "exposure": exposure, "priority": priority, "priority_reason": priority_reason,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline", default="../phase1_dataset_construction/output")
    parser.add_argument("--adversarial", default="../phase7_adversarial/adversarial_output")
    parser.add_argument("--out", default="./results")
    args = parser.parse_args()

    os.makedirs(args.out, exist_ok=True)

    params = p8.get_operational_params(args.adversarial)
    all_results = []

    print("=" * 100)
    print("PART A — REAL CASES: one baseline ring per archetype")
    print("=" * 100)
    ring_by_archetype = pick_one_baseline_ring_per_archetype(args.baseline)
    for archetype, ring_id in ring_by_archetype.items():
        accounts = load_ring_accounts_by_ring_id(args.baseline, ring_id)
        result = reason_about_case(args.baseline, accounts, case_id=ring_id, params=params)
        print("\n" + format_case_report(result))
        all_results.append(result)

    print("\n" + "=" * 100)
    print("PART B — REAL CASES: Phase 7 attack lineages (two with genuine before/after)")
    print("=" * 100)
    lineage_pairs = [
        ("attack1_fraudar_camouflage", "attack1b_fraudar_corrected"),
        ("attack2_copycatch_jitter", "attack2b_copycatch_spaced"),
    ]
    single_snapshot_attacks = ["attack3_flowscope_delay", "attack4_cross_detector"]

    for before_id, after_id in lineage_pairs:
        before_accounts = p8.load_ring_accounts_by_attack(args.adversarial, before_id)
        after_accounts = p8.load_ring_accounts_by_attack(args.adversarial, after_id)
        result = reason_about_case(args.adversarial, after_accounts, case_id=after_id,
                                    params=params, lineage_before_accounts=before_accounts)
        print("\n" + format_case_report(result))
        all_results.append(result)

    for attack_id in single_snapshot_attacks:
        accounts = p8.load_ring_accounts_by_attack(args.adversarial, attack_id)
        result = reason_about_case(args.adversarial, accounts, case_id=attack_id, params=params)
        print("\n" + format_case_report(result))
        all_results.append(result)

    print("\n" + "=" * 100)
    print("PART C — SYNTHETIC illustrative cases (this dataset cannot produce genuine")
    print("multi-signal agreement/disagreement naturally -- see reasoning_engine.py header)")
    print("=" * 100)
    synthetic_cases = [
        make_synthetic_case("SYN-AGREE-01", "HIGH", "HIGH", "HIGH", n_accounts=9, exposure=118000.0,
                             fraudar_frac=0.89, copycatch_frac=0.78, flowscope_frac=0.83),
        make_synthetic_case("SYN-AGREE-02", "HIGH", "LOW", "HIGH", n_accounts=7, exposure=94000.0,
                             fraudar_frac=0.86, copycatch_frac=0.20, flowscope_frac=0.75),
        make_synthetic_case("SYN-DISAGREE-01", "HIGH", "LOW", "N/A", n_accounts=6, exposure=31000.0,
                             fraudar_frac=0.83, copycatch_frac=0.17, flowscope_frac=0.0),
    ]
    for result in synthetic_cases:
        print("\n" + format_case_report(result))
        all_results.append(result)

    # ------------------------------------------------------------------
    rule_table_path = os.path.join(args.out, "rule_table_reference.csv")
    n_rules = write_rule_table_reference(rule_table_path)
    print(f"\n{'='*100}\nWritten: {rule_table_path} ({n_rules} rows -- every reachable signal "
          f"combination and its decision, for audit)")

    cases_path = os.path.join(args.out, "case_reports.csv")
    with open(cases_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["case_id", "n_accounts", "fraudar", "copycatch", "flowscope", "interpretation",
                     "confidence", "adaptation_indicator", "exposure", "priority"])
        for r in all_results:
            w.writerow([r["case_id"], r["n_accounts"], r["fraudar"], r["copycatch"], r["flowscope"],
                         r["interpretation"], r["confidence"], r["adaptation_indicator"],
                         r["exposure"], r["priority"]])
    print(f"Written: {cases_path} ({len(all_results)} cases)")

    # also dump full structured results as JSON, for Phase 9b (the LLM
    # layer) to consume as its grounding input
    json_path = os.path.join(args.out, "case_reports.json")
    with open(json_path, "w") as f:
        json.dump([{k: v for k, v in r.items() if k != "adaptation_detail"} for r in all_results], f, indent=2)
    print(f"Written: {json_path} (structured grounding data for Phase 9b)")


if __name__ == "__main__":
    main()
