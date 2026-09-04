"""
Phase 6: Case Prioritization -- Alerts -> Cases -> Priority Queue -> Human Decision
---------------------------------------------------------------------------------------
The pipeline up to Phase 5 answers "did we detect the fraud." This phase
answers a different, more operationally useful question: given a fixed
number of investigators, which cases should they work on to capture the
most Rs of fraud exposure?

Pipeline: Detectors -> Evidence Fusion -> Fraud Cases -> Rs Exposure +
Investigation Effort -> Priority Queue -> Human Decision.

Three structural steps this script performs:

1. CASE CONSTRUCTION: raw account-level alerts (from Conservative-mode
   flags, i.e. every account any detector considered suspicious) get
   GROUPED into cases -- a case is "the set of accounts an investigator
   would look at together," not one alert per account. FlowScope and
   CopyCatch already produce natural groupings (a cycle, an event).
   FRAUDAR does not (it flags individual accounts by score threshold), so
   we cluster its flagged accounts into cases via connected components on
   the shared-device/IP graph, restricted to flagged accounts only.

2. PER-CASE SCORING: for every case, compute Rs financial exposure (data-
   driven, from actual transaction amounts touching the case's accounts
   -- NOT from ground truth, since a real system wouldn't have that),
   investigation effort (hours, proportional to case size), a transparent
   confidence score specific to which detector flagged it, and a
   plain-language "why flagged" explanation.

3. CAPACITY-CONSTRAINED SELECTION: given "I have N investigators," compute
   available effort-hours and select the case set that maximizes total
   Rs exposure captured within that budget. Two methods are run and
   compared -- a simple greedy (sort by Rs/hour density) and an exact
   0/1 knapsack DP (feasible at this case count) -- so we can report
   whether the simple, explainable method actually reaches the
   mathematically optimal allocation, rather than assuming it does.

Usage:
    python3 case_prioritizer.py --data ../phase1_dataset_construction/output --investigators 5
"""

import argparse
import csv
import math
import os
import sys
from collections import defaultdict
from datetime import datetime

import networkx as nx

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase2_detection"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase3_copycatch"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase4_flowscope"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase5_fusion"))

import fraudar_lite
import copycatch_lite
import flowscope_lite
import fusion

# ------------------------------------------------------------------
# STATED ASSUMPTIONS (all adjustable, all labeled wherever printed)
# ------------------------------------------------------------------
EFFORT_HOURS_PER_ACCOUNT = 0.4   # investigator time to review one account (~24 min)
HOURS_PER_INVESTIGATOR_PER_DAY = 8.0
CASE_ENTITY_DEGREE_CAP = 4       # see build_fraudar_cases() -- prevents mega-cluster collapse


# ------------------------------------------------------------------
# Step 1: get the alert pool (Conservative-mode flags, per-detector)
# ------------------------------------------------------------------
def get_conservative_flags(data_dir, account_to_ring, ring_per_member_cost, archetypes):
    fraudar_results = fusion.sweep_fraudar(data_dir, account_to_ring, ring_per_member_cost,
                                            archetypes["shared_infra_promo_abuse"])
    fraudar_modes = fusion.select_modes(fraudar_results)

    cc_results = fusion.sweep_copycatch(data_dir, account_to_ring, ring_per_member_cost,
                                         archetypes["lockstep_chargeback_ring"])
    cc_modes = fusion.select_modes(cc_results)

    fs_results = fusion.sweep_flowscope(data_dir, account_to_ring, ring_per_member_cost,
                                         archetypes["circular_flow_laundering"])
    fs_modes = fusion.select_modes(fs_results)

    return fraudar_modes["conservative"], cc_modes["conservative"], fs_modes["conservative"]


# ------------------------------------------------------------------
# Step 2: case construction
# ------------------------------------------------------------------
def build_fraudar_cases(data_dir, flagged_accounts):
    """FRAUDAR flags individual accounts, not groups. Cluster flagged
    accounts into cases via connected components on the shared-entity
    graph, restricted to flagged accounts only.

    IMPORTANT, found by checking rather than assuming (see
    ENGINEERING_LOG.md): using ALL shared entities for this graph causes
    a mega-cluster collapse -- transitive chaining through moderate-degree
    entities (up to degree 10) merges most of the flagged population into
    one meaningless ~460-account "case." No single entity is a hub; it's
    percolation through many degree 5-10 entities. Restricting the
    case-clustering graph to entities with degree <= CASE_ENTITY_DEGREE_CAP
    (4, chosen by sweeping the cap and checking where the collapse
    reappears) keeps case sizes in the range real rings actually have
    (up to ~21 in this run) without refragmenting genuine small rings.

    Each case also carries its clustering `entities` set -- the specific
    shared devices/IPs that formed it -- so exposure can later be computed
    from ONLY the transactions that actually go through that shared
    infrastructure, not an account's entire unrelated transaction history
    (see compute_case_exposure_bulk and ENGINEERING_LOG.md Entry 11)."""
    edges = fraudar_lite.load_bipartite_graph(data_dir)
    entity_accounts = defaultdict(set)
    for acc, ent in edges:
        entity_accounts[ent].add(acc)

    g = nx.Graph()
    for acc, ent in edges:
        if acc in flagged_accounts and len(entity_accounts[ent]) <= CASE_ENTITY_DEGREE_CAP:
            g.add_edge(acc, ent)

    cases = []
    for component in nx.connected_components(g):
        accounts_in_case = component & flagged_accounts
        entities_in_case = component - flagged_accounts
        if accounts_in_case:
            cases.append({"accounts": accounts_in_case, "entities": entities_in_case,
                          "detector": "fraudar", "archetype": "shared_infra_promo_abuse"})

    clustered = set()
    for c in cases:
        clustered |= c["accounts"]
    for acc in flagged_accounts - clustered:
        cases.append({"accounts": {acc}, "entities": set(), "detector": "fraudar",
                      "archetype": "shared_infra_promo_abuse"})

    return cases


def build_copycatch_cases(data_dir, window, min_acc):
    events = copycatch_lite.detect(data_dir, window, min_acc)
    return [{"accounts": e["accounts"], "detector": "copycatch",
             "archetype": "lockstep_chargeback_ring",
             "merchant": e["merchant"], "span_minutes": (e["end"] - e["start"]).total_seconds() / 60.0,
             "total_amount": e["total_amount"]}
            for e in events]


def build_flowscope_cases(data_dir, span, ratio):
    cycles = flowscope_lite.detect(data_dir, span, ratio, max_cycle_length=10, verbose=False)
    return [{"accounts": set(c["cycle"]), "detector": "flowscope",
             "archetype": "circular_flow_laundering",
             "amount_ratio": c["amount_ratio"], "span_minutes": c["span_minutes"],
             "total_hop_amount": c["total_hop_amount"]}
            for c in cycles if c["flagged"]]


# ------------------------------------------------------------------
# Step 2b: per-case Rs exposure -- EVIDENCE-SPECIFIC, not an account's
# entire transaction history. This matters: an account's total lifetime
# transaction volume includes all its normal, unrelated legitimate
# activity. For a false-positive case, that volume is real money but has
# nothing to do with fraud -- counting it as "exposure" massively
# overstates the case's value and actively biases the priority queue
# toward large, legitimate, wrongly-flagged accounts (see
# ENGINEERING_LOG.md Entry 11, where an earlier version of this exact
# metric did precisely that). Instead, exposure is computed per detector
# from ONLY the transactions that constitute the actual evidence:
#   - flowscope: the cycle's own hop transactions (already known exactly)
#   - copycatch: the chargeback transactions inside the flagged window
#     (already known exactly)
#   - fraudar: only transactions that pass through the case's specific
#     shared clustering entities (its rare devices/IPs), not the
#     account's unrelated activity elsewhere
# ------------------------------------------------------------------
# ------------------------------------------------------------------
# Step 2b(i): safely recover exposure for correctly-detected but
# denser-than-expected rings (fixes the Phase 7 Entry 13 blind spot)
# ------------------------------------------------------------------
def expand_case_entities_safely(data_dir, fraudar_cases):
    """The low-degree-cap clustering in build_fraudar_cases deliberately
    excludes higher-degree entities to prevent mega-cluster collapse
    (Entry 11). But that means a correctly-clustered ring's OWN dense
    shared infrastructure -- if its degree happens to exceed the cap,
    which larger/denser rings can trigger -- gets excluded from exposure
    calculation too. A genuinely-detected ring can then show Rs0 exposure
    and silently vanish from the priority queue despite being correctly
    flagged (discovered via Phase 7's adversarial Attack 1 -- see
    ENGINEERING_LOG.md Entry 13).

    The actual failure mode was never "high degree" itself -- it was an
    entity BRIDGING accounts that belong to otherwise-unrelated cases.
    A ring's own dense core device only ever touches accounts already in
    the SAME case; it doesn't bridge anything. So: after case membership
    is fixed by the safe low-cap clustering (unchanged, still the only
    thing that decides which accounts belong to which case), do a
    separate pass over every excluded (degree > cap) entity. If its
    flagged-account connections all belong to exactly ONE existing case,
    it's dense INTERNAL structure, not a bridge -- add it to that case's
    entity set for EXPOSURE purposes only. This can never reintroduce the
    mega-cluster collapse, because it never changes which accounts belong
    to which case, only what counts toward a case's exposure once
    membership is already fixed. If an entity's connections span 2+
    different cases, it's a genuine bridge and stays excluded, exactly
    as before.

    Returns the number of entities recovered this way, for transparency."""
    edges = fraudar_lite.load_bipartite_graph(data_dir)
    entity_accounts = defaultdict(set)
    for acc, ent in edges:
        entity_accounts[ent].add(acc)

    account_to_case_idx = {}
    for i, case in enumerate(fraudar_cases):
        for acc in case["accounts"]:
            account_to_case_idx[acc] = i

    n_recovered = 0
    for ent, accs in entity_accounts.items():
        if len(accs) <= CASE_ENTITY_DEGREE_CAP:
            continue  # already handled by the safe clustering pass
        touched_cases = {account_to_case_idx[a] for a in accs if a in account_to_case_idx}
        if len(touched_cases) == 1:
            case_idx = next(iter(touched_cases))
            fraudar_cases[case_idx]["entities"].add(ent)
            n_recovered += 1
        # 0 touched cases -> irrelevant to any case, skip
        # 2+ touched cases -> genuine bridge, stays excluded (this is the
        # exact condition that prevents the mega-cluster collapse)
    return n_recovered


def compute_fraudar_case_exposure_bulk(data_dir, fraudar_cases):
    """FRAUDAR cases don't carry a pre-known exposure figure the way
    flowscope/copycatch cases do (their detection process doesn't
    naturally total an amount), so this still requires a transactions.csv
    pass -- restricted to (account in case) AND (device_id or ip_id in
    that case's own clustering entities), not any transaction the account
    was ever party to.

    A SECOND restriction, added after finding a real problem: matching on
    shared device/IP alone still counts a flagged account's entire
    transaction history through that device -- including transactions
    that have nothing to do with the suspicious pattern, if the same
    device is also used for the account's ordinary legitimate purchases.
    A single wrongly-flagged account showed Rs60,883 of "exposure" this
    way, entirely from unrelated legitimate spending. The actual
    signature of coordinated abuse isn't "this device was used" -- it's
    "multiple case members transacted with the SAME counterparty via that
    device." So a transaction only counts if its counterparty (the other
    party) is ALSO transacted with by at least one other member of the
    same case. This is checked directly against the data, not assumed:
    see ENGINEERING_LOG.md Entry 14."""
    account_to_case_entities = defaultdict(list)
    for i, case in enumerate(fraudar_cases):
        for acc in case["accounts"]:
            account_to_case_entities[acc].append(i)

    with open(os.path.join(data_dir, "transactions.csv")) as f:
        rows = list(csv.DictReader(f))

    # PASS 1: find every (case, counterparty, member) triple that passes
    # the device/IP evidence match
    candidates = []
    for row in rows:
        for acc in (row["src_account"], row["dst_account"]):
            if acc not in account_to_case_entities:
                continue
            counterparty = row["dst_account"] if acc == row["src_account"] else row["src_account"]
            for case_idx in account_to_case_entities[acc]:
                case_entities = fraudar_cases[case_idx]["entities"]
                if ("DEV::" + row["device_id"] in case_entities or
                        "IP::" + row["ip_id"] in case_entities):
                    candidates.append((case_idx, counterparty, acc, float(row["amount"]), row["txn_id"]))

    # tally how many DISTINCT case members share each counterparty
    counterparty_members = defaultdict(set)
    for case_idx, counterparty, acc, amount, txn_id in candidates:
        counterparty_members[(case_idx, counterparty)].add(acc)

    # PASS 2: only count a transaction if its counterparty is shared by
    # 2+ distinct members of the case -- the actual signature of a
    # coordinated pattern, not just incidental device reuse
    exposure = defaultdict(float)
    counted = defaultdict(set)
    for case_idx, counterparty, acc, amount, txn_id in candidates:
        if len(counterparty_members[(case_idx, counterparty)]) >= 2:
            if txn_id not in counted[case_idx]:
                exposure[case_idx] += amount
                counted[case_idx].add(txn_id)
    return exposure


# ------------------------------------------------------------------
# Step 2c: confidence + why-flagged, per detector type
# ------------------------------------------------------------------
def annotate_case(case):
    accounts = case["accounts"]
    n = len(accounts)
    if case["detector"] == "fraudar":
        case["confidence"] = round(min(1.0, 0.3 + 0.1 * n), 3)  # more co-clustered members = more confidence
        case["why_flagged"] = (f"{n} accounts cluster together via shared devices/IPs, "
                                 f"below the population's normal sharing baseline (FRAUDAR-lite density signal)")
    elif case["detector"] == "copycatch":
        tightness = max(0.0, 1.0 - case["span_minutes"] / 60.0)
        case["confidence"] = round(min(1.0, 0.4 + 0.3 * tightness + 0.03 * n), 3)
        case["why_flagged"] = (f"{n} accounts filed chargebacks against {case['merchant']} within "
                                 f"a {case['span_minutes']:.0f}-minute window (CopyCatch-lite lockstep signal)")
    elif case["detector"] == "flowscope":
        case["confidence"] = round(min(1.0, 0.5 * case["amount_ratio"] +
                                        0.5 * max(0.0, 1.0 - case["span_minutes"] / 180.0)), 3)
        case["why_flagged"] = (f"{n}-hop circular transaction flow, amount conserved at "
                                 f"{case['amount_ratio']:.0%} across hops, completed in "
                                 f"{case['span_minutes']:.0f} minutes (FlowScope-lite flow signal)")
    return case


# ------------------------------------------------------------------
# Step 3: capacity-constrained selection
# ------------------------------------------------------------------
def greedy_select(cases, capacity_hours):
    ranked = sorted(cases, key=lambda c: -c["exposure"] / c["effort_hours"])
    selected, used_hours, total_exposure = [], 0.0, 0.0
    for c in ranked:
        if used_hours + c["effort_hours"] <= capacity_hours:
            selected.append(c)
            used_hours += c["effort_hours"]
            total_exposure += c["exposure"]
    return selected, used_hours, total_exposure


def knapsack_select(cases, capacity_hours, unit=0.1):
    """Exact 0/1 knapsack via DP, to check whether the simple greedy
    selection actually reaches optimal -- not assumed, checked. Effort is
    discretized to `unit` hours (default: 6-minute granularity) so the DP
    table stays a manageable size at this case count (~30)."""
    capacity_units = int(round(capacity_hours / unit))
    weights = [max(1, int(round(c["effort_hours"] / unit))) for c in cases]
    values = [c["exposure"] for c in cases]
    n = len(cases)

    # standard 0/1 knapsack DP
    dp = [0.0] * (capacity_units + 1)
    keep = [[False] * (capacity_units + 1) for _ in range(n)]
    for i in range(n):
        for w in range(capacity_units, weights[i] - 1, -1):
            candidate = dp[w - weights[i]] + values[i]
            if candidate > dp[w]:
                dp[w] = candidate
                keep[i][w] = True

    # backtrack
    selected_idx = []
    w = capacity_units
    for i in range(n - 1, -1, -1):
        if keep[i][w]:
            selected_idx.append(i)
            w -= weights[i]
    selected = [cases[i] for i in selected_idx]
    total_exposure = sum(c["exposure"] for c in selected)
    used_hours = sum(c["effort_hours"] for c in selected)
    return selected, used_hours, total_exposure


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", default="../phase1_dataset_construction/output")
    parser.add_argument("--out", default="./results")
    parser.add_argument("--investigators", type=int, default=5)
    args = parser.parse_args()

    account_to_ring, ring_type, ring_per_member_cost = fusion.load_ground_truth_costs(args.data)
    archetypes = {
        "shared_infra_promo_abuse": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "shared_infra_promo_abuse"),
        "lockstep_chargeback_ring": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "lockstep_chargeback_ring"),
        "circular_flow_laundering": set(a for a, r in account_to_ring.items()
                                         if ring_type[r] == "circular_flow_laundering"),
    }

    print("=" * 100)
    print("PHASE 6: ALERTS -> CASES -> PRIORITY QUEUE -> HUMAN DECISION")
    print("=" * 100)

    fraudar_c, cc_c, fs_c = get_conservative_flags(args.data, account_to_ring, ring_per_member_cost, archetypes)
    total_alerts = len(fraudar_c["flagged"]) + len(cc_c["flagged"]) + len(fs_c["flagged"])
    print(f"\nStep 1 -- ALERT POOL (Conservative mode, every detector's max-recall flags): "
          f"{total_alerts} account-level alerts")
    print(f"  fraudar={len(fraudar_c['flagged'])}  copycatch={len(cc_c['flagged'])}  flowscope={len(fs_c['flagged'])}")

    fraudar_cases = build_fraudar_cases(args.data, fraudar_c["flagged"])
    n_recovered = expand_case_entities_safely(args.data, fraudar_cases)
    print(f"\n  (recovered {n_recovered} dense-but-non-bridging entities for exposure "
          f"attribution -- see ENGINEERING_LOG.md Entry 14)")
    cc_param = cc_c["param"]
    window, min_acc = int(cc_param.split("window=")[1].split(",")[0]), int(cc_param.split("min_acc=")[1])
    copycatch_cases = build_copycatch_cases(args.data, window, min_acc)
    fs_param = fs_c["param"]
    span, ratio = float(fs_param.split("span=")[1].split(",")[0]), float(fs_param.split("ratio=")[1])
    flowscope_cases = build_flowscope_cases(args.data, span, ratio)

    all_cases = fraudar_cases + copycatch_cases + flowscope_cases
    print(f"\nStep 2 -- CASE CONSTRUCTION: {total_alerts} alerts grouped into {len(all_cases)} cases")
    print(f"  fraudar clusters={len(fraudar_cases)}  copycatch events={len(copycatch_cases)}  "
          f"flowscope cycles={len(flowscope_cases)}")

    exposure_by_fraudar_case = compute_fraudar_case_exposure_bulk(args.data, fraudar_cases)
    for i, case in enumerate(fraudar_cases):
        case["exposure"] = round(exposure_by_fraudar_case.get(i, 0.0), 2)
    for case in copycatch_cases:
        case["exposure"] = round(case["total_amount"], 2)
    for case in flowscope_cases:
        case["exposure"] = round(case["total_hop_amount"], 2)

    for case in all_cases:
        case["effort_hours"] = round(len(case["accounts"]) * EFFORT_HOURS_PER_ACCOUNT, 2)
        annotate_case(case)
        case["is_genuine"] = len(case["accounts"] & set(account_to_ring.keys())) > 0  # for validation only

    total_exposure_all_cases = sum(c["exposure"] for c in all_cases)
    n_genuine_cases = sum(1 for c in all_cases if c["is_genuine"])
    print(f"\nTotal Rs exposure across ALL {len(all_cases)} cases: Rs{total_exposure_all_cases:,.0f}")
    print(f"(Validation only, not used in selection: {n_genuine_cases}/{len(all_cases)} cases contain "
          f"at least one genuine ground-truth fraud account)")

    capacity_hours = args.investigators * HOURS_PER_INVESTIGATOR_PER_DAY
    print(f"\nStep 3 -- CAPACITY-CONSTRAINED SELECTION: {args.investigators} investigators x "
          f"{HOURS_PER_INVESTIGATOR_PER_DAY}h/day = {capacity_hours:.0f} effort-hours available")

    greedy_cases, greedy_hours, greedy_exposure = greedy_select(all_cases, capacity_hours)
    optimal_cases, optimal_hours, optimal_exposure = knapsack_select(all_cases, capacity_hours)

    print(f"\n  Greedy (Rs/hour density sort):  {len(greedy_cases)} cases, "
          f"{greedy_hours:.1f}h used, Rs{greedy_exposure:,.0f} exposure captured")
    print(f"  Exact 0/1 knapsack (optimal):   {len(optimal_cases)} cases, "
          f"{optimal_hours:.1f}h used, Rs{optimal_exposure:,.0f} exposure captured")
    gap_pct = (1 - greedy_exposure / optimal_exposure) * 100 if optimal_exposure else 0
    print(f"  Greedy reaches {100 - gap_pct:.1f}% of optimal ({'MATCHES optimal' if gap_pct < 0.5 else f'{gap_pct:.1f}% short of optimal'})")

    final_selection = optimal_cases if optimal_exposure >= greedy_exposure else greedy_cases
    final_selection = sorted(final_selection, key=lambda c: -c["exposure"] / c["effort_hours"])

    n_genuine_in_selection = sum(1 for c in final_selection if c["is_genuine"])
    print(f"\n{'=' * 100}")
    print(f"KILLER METRIC: Rs{sum(c['exposure'] for c in final_selection):,.0f} genuine fraud exposure "
          f"captured with {args.investigators} investigators")
    print(f"({len(final_selection)} cases selected out of {len(all_cases)} total, "
          f"{n_genuine_in_selection}/{len(final_selection)} contain real fraud per ground truth -- validation only)")
    print(f"{'=' * 100}")

    os.makedirs(args.out, exist_ok=True)
    priority_path = os.path.join(args.out, "priority_queue.csv")
    with open(priority_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["rank", "selected", "detector", "archetype", "n_accounts", "exposure_rs",
                     "effort_hours", "confidence", "why_flagged", "is_genuine_fraud_VALIDATION_ONLY"])
        selected_ids = set(id(c) for c in final_selection)
        for rank, c in enumerate(sorted(all_cases, key=lambda c: -c["exposure"] / c["effort_hours"]), 1):
            w.writerow([rank, id(c) in selected_ids, c["detector"], c["archetype"], len(c["accounts"]),
                         c["exposure"], c["effort_hours"], c["confidence"], c["why_flagged"], c["is_genuine"]])

    print(f"\nWritten: {priority_path}  (every case, ranked, with the top {len(final_selection)} marked selected)")


if __name__ == "__main__":
    main()
