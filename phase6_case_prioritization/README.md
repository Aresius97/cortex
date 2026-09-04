# Phase 6: Case Prioritization — Alerts → Cases → Priority Queue → Human Decision

## The reframe

Every phase up to this point answers "did we detect the fraud." This phase answers the question a risk team actually has: **given a fixed number of investigators, which cases should they work on to capture the most ₹ of fraud exposure?**

Pipeline: `Detectors → Evidence Fusion → Fraud Cases → ₹ Exposure + Investigation Effort → Priority Queue → Human Decision`

The killer metric isn't recall. It's **₹ genuine fraud exposure captured at a fixed investigation capacity** — a number a CFO or Head of Risk can act on directly, unlike a precision/recall pair.

## What this phase does, in three steps

1. **Case construction.** Raw account-level alerts (Conservative-mode flags — every account any detector considered suspicious) get *grouped* into cases. A case is what an investigator actually looks at together, not one alert per account. FlowScope and CopyCatch already produce natural groupings (a cycle, a lockstep event). FRAUDAR doesn't — it flags individual accounts by score threshold — so its flagged accounts are clustered into cases via connected components on the shared-device/IP graph.
2. **Per-case scoring.** Every case gets a ₹ exposure figure, an investigation-effort estimate (hours), a detector-specific confidence score, and a plain-language "why flagged" explanation.
3. **Capacity-constrained selection.** Given "I have N investigators," the script computes available effort-hours and selects the case set that maximizes total ₹ exposure captured — using both a simple, explainable greedy method and an exact 0/1 knapsack, so the simple method's quality is *checked*, not assumed.

## Run it

```bash
python3 case_prioritizer.py --data ../phase1_dataset_construction/output --investigators 5
```

## Two real bugs found and fixed while building this — then a third, found by fixing the first two

### Bug 1: case-clustering mega-merge (the same failure mode as Phase 2, in a new place)

The first version of FRAUDAR case-clustering used **all** shared entities to build connected components. Result: one "case" swallowed 461 of the 537 flagged accounts — not through a single super-popular hub, but through transitive chaining across many degree-5-to-10 entities (a percolation effect, not a bug in any single step). Fixed by restricting the case-clustering graph to entities with degree ≤ 4 (found by sweeping the cap and checking exactly where the collapse reappears — case sizes jump from a sane ~21 at cap=4 to 291+ at cap=5).

### Bug 2: exposure measured an account's entire history, not the actual evidence — and it silently favored false positives

After fixing Bug 1, the numbers still looked wrong: selected-case precision *dropped* (from 12/31 to 3/51) even though total captured exposure *rose*. The cause: exposure was computed as the sum of **all** transactions touching a flagged account. For a genuine ring, that's a reasonable proxy. For a false positive — an innocent account wrongly flagged — it just measures how large and active that legitimate account normally is, which has nothing to do with fraud. The optimizer, working over a set with many weak, cheap, single-account flags, happily filled the investigator budget with legitimate high-volume accounts because their ordinary business activity looked like "high-value exposure" by this metric.

**Fixed by making exposure evidence-specific per detector**, not account-wide:
- FlowScope: sum of the cycle's own hop amounts (already known exactly from detection).
- CopyCatch: sum of the chargeback amounts inside the flagged lockstep window (already known exactly).
- FRAUDAR: sum of only the transactions that pass through the case's *own* clustering entities (its specific shared, rare devices/IPs) — not the account's unrelated activity elsewhere.

After this fix: total exposure across all 337 cases dropped from an inflated ₹15.2M to ₹871,619 — a number that actually lines up with what the injected rings moved, rather than accidentally counting legitimate commerce. Selected-case precision recovered to 20/20.

### Bug 3 (found via Phase 7's adversarial evaluation, then fixed properly — see `ENGINEERING_LOG.md` Entry 14): the degree cap from Bug 1 silently zeroed out large rings' exposure, and fixing that exposed a deeper bug underneath

Phase 7's Attack 1 was **caught at 100% recall** by FRAUDAR-lite, but showed **₹0 exposure** — because its ring shares a device used by 7 of 10 members, exceeding the `CASE_ENTITY_DEGREE_CAP=4` from Bug 1's fix. Fixing this properly required three layered corrections, not one:

1. **Adaptive entity recovery**: after case membership is fixed by the safe low-cap clustering, a second pass checks every excluded (degree > cap) entity — if its connections belong to exactly one existing case (not bridging multiple cases), it's added to that case's *entity set for exposure only*, never for membership. This can't reintroduce Bug 1's mega-cluster collapse, because membership never changes.
2. Running this revealed a **much bigger, pre-existing bug**: entities are stored with `"DEV::"`/`"IP::"` prefixes, but the exposure check compared them against raw, unprefixed transaction fields — a mismatch that meant **every FRAUDAR case's exposure had been silently zero since Phase 6 was first built**, entirely independent of the degree cap. Fixed the comparison.
3. Fixing #2 immediately caused a new problem: total exposure jumped to ₹6.1M but selected-case precision collapsed to 1/60 — a single wrongly-flagged account showed ₹60,883 of "exposure" purely from its own unrelated legitimate spending through a coincidentally-shared device. Fixed by requiring a transaction's counterparty to *also* be shared by another case member — the actual signature of coordinated abuse, not just incidental device reuse.

**Net result of all three Bug-3 fixes, measured (not assumed):** captured exposure rose 19% (₹770,796 → ₹918,272) as FRAUDAR's genuine catches finally contribute real value, while precision settled at a believable 11/15 (73%) — down from an artificially perfect 20/20 that was only that clean because FRAUDAR's true positives were contributing nothing at all.

## Current results (5 investigators, after all fixes)

- **625** account-level alerts → **337** cases (306 FRAUDAR clusters + 25 CopyCatch events + 6 FlowScope cycles)
- Total identified exposure across all cases: **₹1,656,215**
- With 5 investigators (40 effort-hours): **15 cases selected**, **₹918,272 captured**
- Greedy reaches 99.6% of the mathematically optimal (knapsack-verified) allocation.
- **11/15 selected cases contain real fraud** per ground truth (validation only) — a believable number for a system blending detectors of different individual precision, not an artificially perfect one.

## Output

`results/priority_queue.csv` — every case, ranked by ₹/hour value density, with the top N (given your investigator count) marked `selected=True`. Includes the `is_genuine_fraud_VALIDATION_ONLY` column, which exists purely to sanity-check this pipeline against synthetic ground truth — strip it in a real deployment where that label doesn't exist.
