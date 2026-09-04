# Phase 2: Detection — FRAUDAR-lite

## What this phase does

Detects the `shared_infra_promo_abuse` ring archetype using a weighted densest-subgraph algorithm, based on Hooi et al. (KDD 2016), "FRAUDAR: Bounding Graph Fraud in the Face of Camouflage."

**What we implement:** the core suspiciousness-weighted scoring (`1/log(degree+2)` per edge, so edges toward rare/small shared pools count heavily and edges toward already-popular entities barely count at all) plus a greedy peeling loop.

**What we deliberately do not implement:** the paper's formal approximation-bound proof — not needed to build a working detector, only the algorithm and its weighting scheme matter here.

## Run it

```bash
python3 fraudar_lite.py --data ../phase1_dataset_construction/output --out ./results --k_std 1.0
```

`--k_std` controls the flagging threshold (accounts scoring more than `k_std` standard deviations below the population mean are flagged — see the code comments for why "below," not "above," which is a real, empirically-verified finding, not a default assumption).

## Current results

At `k_std=1.0`: **recall 0.94** overall (0.88 easy / 0.97 medium / 1.00 hard tier), **precision 0.21**.

Sweep across thresholds (all obtained from actual runs, not projected):

| k_std | Precision | Recall |
|---|---|---|
| 0.5 | 0.15 | 0.99 |
| 1.0 | 0.21 | 0.94 |
| 1.5 | 0.32 | 0.70 |
| 2.0 | 0.40 | 0.41 |

This is the raw material for a proper cost-sensitive threshold choice (Bahnsen et al., 2016) — see `docs/PROJECT_DOCUMENTATION.md` §6. We haven't assigned final ₹ costs to false positives/negatives yet; that's the next step before picking a single operating point to present.

## Why precision is capped where it is — an honest limitation, not a hidden one

Pure entity-degree weighting cannot fully distinguish a genuine ring from an innocent small-group coincidence (e.g. two family members sharing one device can look statistically "rarer," and therefore more suspicious by this metric alone, than an actual 6-14 person ring whose shared devices have moderate degree). Closing this gap is the explicit job of the planned fusion layer (per-transaction velocity/amount scoring), not something this phase claims to have solved on its own.

## The debugging path that got here

This script went through five real, sequential bugs before reaching a working state — full details in `ENGINEERING_LOG.md` at the repo root. Summary: (1) initial density metric flagged almost the entire graph due to unpruned degree-1 noise entities, (2) fixing that caused the opposite failure — a trivial 3-account block due to a small-denominator artifact in average-degree scoring, (3) the per-account scoring formula initially rewarded camouflage instead of penalizing it (sum vs. mean of edge weights), and (4) the correct flagging direction (below-baseline, not above) had to be verified empirically rather than assumed.

## Output

`results/score_threshold_eval.csv` — every account's suspiciousness score, whether it was flagged, and whether it's a true fraud account per ground truth (for your own independent verification).
