"""
Phase 8: Adaptive Threat Detection
------------------------------------
Answers one question: "is this fraud ring becoming harder to detect while
remaining financially active?" That combination -- shrinking visibility,
persistent money movement -- is the actual signature of an adapting
attacker, as opposed to a ring that's simply winding down (which would
show BOTH visibility and exposure dropping together).

Deliberately NOT built here: another detector, an ML model, an LLM, or
predictive modeling. This is arithmetic over signals the existing three
detectors already produce, plus a transparent formula and a templated
explanation -- every number in the output is traceable to a specific
detector run, not a learned weight.

What this script does:
  1. Takes two snapshots of the same ring lineage ("before" and "after")
     and computes each detector's signal strength (HIGH / LOW / N/A) at
     each snapshot, plus the ring's actual Rs exposure at each snapshot.
  2. Computes the signal delta per detector (did it drop, hold, or rise).
  3. Computes exposure persistence (did the money keep moving even as
     detectability fell).
  4. Combines these into a single adaptation score: high only when
     detector visibility dropped AND exposure held up -- neither
     condition alone is enough, which is what distinguishes "the
     attacker adapted" from "the ring collapsed" or "nothing changed."
  5. Generates a plain-language explanation.
  6. Validates the whole mechanism against Phase 7's real attack pairs
     (attack1->attack1b, attack2->attack2b are literally the same
     conceptual ring getting smarter) plus a negative control.

Usage:
    python3 adaptive_threat_detector.py --data ../phase7_adversarial/adversarial_output --out ./results
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

SIGNAL_THRESHOLD = 0.5  # fraction of ring accounts a detector must flag to count as HIGH


def get_operational_params(data_dir):
    """Signal-strength checks must use the SAME parameters the deployed
    system actually runs at (Conservative mode, per Phase 5/6) -- not
    arbitrary hardcoded defaults. An earlier version of this script used
    window=30/min_acc=4 for CopyCatch, which disagreed with the real
    Conservative-mode parameters and misclassified a ring Phase 7 had
    already established was caught at 88.9% recall as "LOW". Fixed by
    deriving the actual operational parameters via the same sweep-and-
    select logic Phase 5/6 use, rather than guessing."""
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
    k_std = float(fraudar_c["param"].split("k_std=")[1])
    window = int(cc_c["param"].split("window=")[1].split(",")[0])
    min_acc = int(cc_c["param"].split("min_acc=")[1])
    span = float(fs_c["param"].split("span=")[1].split(",")[0])
    ratio = float(fs_c["param"].split("ratio=")[1])
    print(f"Operational params (Conservative mode, derived not guessed): "
          f"fraudar k_std={k_std}, copycatch window={window}/min_acc={min_acc}, "
          f"flowscope span={span}/ratio={ratio}")
    return {"k_std": k_std, "window": window, "min_acc": min_acc, "span": span, "ratio": ratio}


# ------------------------------------------------------------------
# Per-detector signal strength: HIGH / LOW / N/A for a given account set
# ------------------------------------------------------------------
def fraudar_signal(data_dir, ring_accounts, k_std):
    edges = fraudar_lite.load_bipartite_graph(data_dir)
    scores = fraudar_lite.score_accounts(edges)
    relevant = ring_accounts & set(scores.keys())
    if not relevant:
        return "N/A", 0.0  # no device/IP structure at all for this ring -- not this detector's domain
    flagged, cutoff, mean, stdev = fraudar_lite.flag_by_threshold(scores, k_std=k_std, direction="below")
    frac = len(relevant & flagged) / len(relevant)
    return ("HIGH" if frac >= SIGNAL_THRESHOLD else "LOW"), frac


def copycatch_signal(data_dir, ring_accounts, window, min_acc):
    has_chargebacks = False
    with open(os.path.join(data_dir, "transactions.csv")) as f:
        for row in csv.DictReader(f):
            if row["txn_type"] == "chargeback" and row["dst_account"] in ring_accounts:
                has_chargebacks = True
                break
    if not has_chargebacks:
        return "N/A", 0.0  # this ring never files chargebacks -- not this detector's domain
    events = copycatch_lite.detect(data_dir, window, min_acc)
    flagged = set()
    for e in events:
        flagged |= e["accounts"]
    frac = len(ring_accounts & flagged) / len(ring_accounts)
    return ("HIGH" if frac >= SIGNAL_THRESHOLD else "LOW"), frac


def flowscope_signal(data_dir, ring_accounts, span, ratio):
    merchants = flowscope_lite.load_merchant_accounts(data_dir)
    edges = flowscope_lite.load_merchant_to_merchant_edges(data_dir, merchants)
    touched = set()
    for (s, d) in edges:
        if s in ring_accounts or d in ring_accounts:
            touched.add(s)
            touched.add(d)
    relevant = ring_accounts & touched
    if not relevant:
        return "N/A", 0.0  # this ring never appears in merchant-to-merchant flow -- not this detector's domain
    cycles = flowscope_lite.detect(data_dir, span, ratio, max_cycle_length=10, verbose=False)
    flagged = set()
    for c in cycles:
        if c["flagged"]:
            flagged |= set(c["cycle"])
    frac = len(relevant & flagged) / len(relevant)
    return ("HIGH" if frac >= SIGNAL_THRESHOLD else "LOW"), frac


# ------------------------------------------------------------------
# Ring exposure: one archetype-agnostic rule (same principle as Phase 6
# Entry 14's counterparty-sharing fix) -- count a transaction if it's
# between two ring members directly, or its counterparty is shared by 2+
# ring members. Covers shared-device, lockstep, and flow rings with one
# consistent rule.
# ------------------------------------------------------------------
def compute_ring_exposure(data_dir, ring_accounts):
    with open(os.path.join(data_dir, "transactions.csv")) as f:
        rows = list(csv.DictReader(f))

    counterparty_members = defaultdict(set)
    for row in rows:
        if row["src_account"] in ring_accounts:
            counterparty_members[row["dst_account"]].add(row["src_account"])
        if row["dst_account"] in ring_accounts:
            counterparty_members[row["src_account"]].add(row["dst_account"])

    exposure = 0.0
    counted = set()
    for row in rows:
        both_ring = row["src_account"] in ring_accounts and row["dst_account"] in ring_accounts
        shared_counterparty = (
            (row["src_account"] in ring_accounts and len(counterparty_members[row["dst_account"]]) >= 2) or
            (row["dst_account"] in ring_accounts and len(counterparty_members[row["src_account"]]) >= 2)
        )
        if (both_ring or shared_counterparty) and row["txn_id"] not in counted:
            exposure += float(row["amount"])
            counted.add(row["txn_id"])
    return exposure


# ------------------------------------------------------------------
# Snapshot + adaptation scoring
# ------------------------------------------------------------------
def snapshot(data_dir, ring_accounts, label, params):
    fr_sig, fr_frac = fraudar_signal(data_dir, ring_accounts, params["k_std"])
    cc_sig, cc_frac = copycatch_signal(data_dir, ring_accounts, params["window"], params["min_acc"])
    fs_sig, fs_frac = flowscope_signal(data_dir, ring_accounts, params["span"], params["ratio"])
    exposure = compute_ring_exposure(data_dir, ring_accounts)
    return {
        "label": label, "n_accounts": len(ring_accounts),
        "fraudar": fr_sig, "fraudar_frac": round(fr_frac, 2),
        "copycatch": cc_sig, "copycatch_frac": round(cc_frac, 2),
        "flowscope": fs_sig, "flowscope_frac": round(fs_frac, 2),
        "exposure": round(exposure, 2),
    }


def compute_adaptation(before, after):
    """Transparent formula, no learned weights: adaptation_score =
    (fraction of previously-HIGH signals that dropped to LOW) x
    (exposure persistence, capped at 1.0). Both factors must be present
    for a high score -- a ring with dropped signals but ALSO collapsed
    exposure looks like genuine decline, not adaptation; a ring with
    persistent exposure but no dropped signals was never harder to see
    in the first place."""
    detectors = ["fraudar", "copycatch", "flowscope"]
    before_high = [d for d in detectors if before[d] == "HIGH"]
    dropped = [d for d in before_high if after[d] == "LOW"]
    held = [d for d in before_high if after[d] == "HIGH"]

    drop_fraction = len(dropped) / len(before_high) if before_high else 0.0
    exposure_persistence = min(1.0, after["exposure"] / before["exposure"]) if before["exposure"] > 0 else 0.0
    adaptation_score = round(drop_fraction * exposure_persistence, 3)

    return {
        "dropped_signals": dropped, "held_signals": held,
        "drop_fraction": round(drop_fraction, 3),
        "exposure_persistence": round(exposure_persistence, 3),
        "adaptation_score": adaptation_score,
    }


def explain(before, after, adaptation):
    if not adaptation["dropped_signals"]:
        return "No adaptation signature detected — detector visibility unchanged or was never established."

    dropped_str = " and ".join(d.upper() for d in adaptation["dropped_signals"])
    held_str = (" while " + " and ".join(d.upper() for d in adaptation["held_signals"]) + " remained HIGH")\
        if adaptation["held_signals"] else ""

    if adaptation["adaptation_score"] >= 0.4:
        verdict = "⚠️  Potential adaptation detected"
        reasoning = (f"Structural and temporal observability decreased ({dropped_str} dropped from HIGH to LOW)"
                     f"{held_str}, while financial exposure persisted at "
                     f"{adaptation['exposure_persistence']:.0%} of its prior level "
                     f"(₹{before['exposure']:,.0f} → ₹{after['exposure']:,.0f}). "
                     f"This combination — falling detectability, steady money movement — is "
                     f"consistent with adaptive evasion, not genuine ring collapse.")
    else:
        verdict = "Signal dropped, but exposure also declined — looks like decline, not adaptation"
        reasoning = (f"{dropped_str} dropped from HIGH to LOW, but exposure fell to only "
                     f"{adaptation['exposure_persistence']:.0%} of its prior level "
                     f"(₹{before['exposure']:,.0f} → ₹{after['exposure']:,.0f}) as well. "
                     f"A ring that is genuinely winding down loses both visibility and activity "
                     f"together — this does not show the persistent-exposure signature of evasion.")
    return f"{verdict}\n  {reasoning}"


def load_ring_accounts_by_attack(data_dir, attack_id):
    accounts = set()
    with open(os.path.join(data_dir, "ground_truth.csv")) as f:
        for row in csv.DictReader(f):
            if row.get("attack_id") == attack_id:
                accounts.add(row["account_id"])
    return accounts


def run_lineage(data_dir, before_id, after_id, lineage_name, out_rows, params):
    before_accounts = load_ring_accounts_by_attack(data_dir, before_id)
    after_accounts = load_ring_accounts_by_attack(data_dir, after_id)

    before_snap = snapshot(data_dir, before_accounts, f"{lineage_name} — BEFORE ({before_id})", params)
    after_snap = snapshot(data_dir, after_accounts, f"{lineage_name} — AFTER ({after_id})", params)
    adaptation = compute_adaptation(before_snap, after_snap)
    explanation = explain(before_snap, after_snap, adaptation)

    print(f"\n{'='*90}\nLINEAGE: {lineage_name}\n{'='*90}")
    print(f"{'':20s} {'FRAUDAR':>10s} {'CopyCatch':>10s} {'FlowScope':>10s} {'Exposure':>14s}")
    print(f"{'BEFORE':20s} {before_snap['fraudar']:>10s} {before_snap['copycatch']:>10s} "
          f"{before_snap['flowscope']:>10s} {'₹'+format(before_snap['exposure'], ',.0f'):>14s}")
    print(f"{'AFTER':20s} {after_snap['fraudar']:>10s} {after_snap['copycatch']:>10s} "
          f"{after_snap['flowscope']:>10s} {'₹'+format(after_snap['exposure'], ',.0f'):>14s}")
    print(f"\nAdaptation score: {adaptation['adaptation_score']}  "
          f"(drop_fraction={adaptation['drop_fraction']}, exposure_persistence={adaptation['exposure_persistence']})")
    print(f"\n{explanation}")

    out_rows.append({
        "lineage": lineage_name, "before_id": before_id, "after_id": after_id,
        "before_fraudar": before_snap["fraudar"], "after_fraudar": after_snap["fraudar"],
        "before_copycatch": before_snap["copycatch"], "after_copycatch": after_snap["copycatch"],
        "before_flowscope": before_snap["flowscope"], "after_flowscope": after_snap["flowscope"],
        "before_exposure": before_snap["exposure"], "after_exposure": after_snap["exposure"],
        "adaptation_score": adaptation["adaptation_score"],
    })


def run_negative_control(out_rows):
    """A synthetic case where BOTH signal and exposure drop together --
    the signature of a ring genuinely shutting down, not adapting. Built
    directly (not from live data) specifically to prove the score
    discriminates between these two situations rather than firing on any
    HIGH->LOW transition regardless of exposure."""
    before = {"fraudar": "HIGH", "copycatch": "N/A", "flowscope": "N/A", "exposure": 42000.0}
    after = {"fraudar": "LOW", "copycatch": "N/A", "flowscope": "N/A", "exposure": 1200.0}
    adaptation = compute_adaptation(before, after)
    explanation = explain(before, after, adaptation)

    print(f"\n{'='*90}\nNEGATIVE CONTROL: synthetic genuine ring collapse (not from live detection)\n{'='*90}")
    print(f"BEFORE: FRAUDAR=HIGH, exposure=₹{before['exposure']:,.0f}")
    print(f"AFTER:  FRAUDAR=LOW,  exposure=₹{after['exposure']:,.0f}  (97% collapse, not persistence)")
    print(f"\nAdaptation score: {adaptation['adaptation_score']}  (should be LOW despite the signal drop)")
    print(f"\n{explanation}")

    out_rows.append({
        "lineage": "negative_control_genuine_collapse", "before_id": "synthetic", "after_id": "synthetic",
        "before_fraudar": before["fraudar"], "after_fraudar": after["fraudar"],
        "before_copycatch": "N/A", "after_copycatch": "N/A",
        "before_flowscope": "N/A", "after_flowscope": "N/A",
        "before_exposure": before["exposure"], "after_exposure": after["exposure"],
        "adaptation_score": adaptation["adaptation_score"],
    })


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../phase7_adversarial/adversarial_output")
    parser.add_argument("--out", default="./results")
    args = parser.parse_args()

    params = get_operational_params(args.data)
    out_rows = []

    run_lineage(args.data, "attack1_fraudar_camouflage", "attack1b_fraudar_corrected",
                "FRAUDAR-targeting ring, naive -> corrected camouflage", out_rows, params)
    run_lineage(args.data, "attack2_copycatch_jitter", "attack2b_copycatch_spaced",
                "CopyCatch-targeting ring, uniform jitter -> spaced timing", out_rows, params)
    run_negative_control(out_rows)

    os.makedirs(args.out, exist_ok=True)
    out_path = os.path.join(args.out, "adaptation_scores.csv")
    with open(out_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(out_rows[0].keys()))
        w.writeheader()
        w.writerows(out_rows)

    print(f"\n{'='*90}\nWritten: {out_path}")


if __name__ == "__main__":
    main()
