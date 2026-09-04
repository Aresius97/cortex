# Phase 5: Fusion Layer — Three Operating Modes, Not One "Optimal" Threshold

## What changed, and why

The first version of this phase picked a single cost-minimizing threshold per detector and presented it as *the* answer. That bakes a business judgment — how much fraud loss is worth trading for how much investigator workload — into the algorithm, when that tradeoff actually belongs to whoever owns it, and different stakeholders own different sides of it:

- **Compliance/Legal** cannot afford to miss a ring — they want maximum recall, cost be damned.
- **CFO/Ops** cares about total P&L impact — they want the threshold that minimizes overall ₹ loss.
- **Risk teams with limited review capacity** need to know how many investigators a setting actually requires, not just an accuracy number.

This version doesn't pick for them. It sweeps every threshold, reports precision/recall/flagged-volume/financial-cost/investigator-headcount at **every point**, and surfaces three named, explicitly-defined operating modes. The output is a menu, not an answer.

## The three modes, as actually implemented

| Mode | Selection rule | Who it's for |
|---|---|---|
| **Conservative** | Maximize recall (tie-break: lowest cost among max-recall points) | Compliance/Legal |
| **Balanced** | Minimize total expected financial cost (Bahnsen et al., 2016 framework) | CFO/Ops |
| **Aggressive** | Minimize flagged volume (= investigator workload), **subject to a stated minimum recall floor of 0.5** | Risk teams with limited capacity |

The recall floor on Aggressive isn't cosmetic — without it, "minimize flagged volume" trivially degenerates to "flag nobody," which is a real failure mode we checked for, not a hypothetical one. If no threshold clears the floor, the script falls back to the best-precision point available and says so explicitly in its output rather than silently returning something that violates its own stated rule.

## Run it

```bash
python3 fusion.py --data ../phase1_dataset_construction/output --out ./results
```

## Current results — the fused, system-level view

| Mode | Precision | Recall | Flagged | Cost (₹) | Investigators needed |
|---|---|---|---|---|---|
| Conservative | 0.27 | 0.98 | 625 | 80,260 | 32 |
| Balanced | 0.37 | 0.95 | 435 | 56,268 | 22 |
| Aggressive | 0.49 | 0.57 | 199 | 679,783 | 10 |

**The number worth pausing on:** Aggressive mode cuts investigator headcount by more than half (10 vs. 22) — but financial cost jumps **12x** (₹680k vs. ₹56k), because recall collapses to 0.57. This is exactly the tradeoff a risk team needs to see explicitly, not have hidden inside a single "optimal" figure: shrinking the review queue by two-thirds of the way there is not free, and now the actual price tag is visible before anyone commits to it.

## Assumptions, stated explicitly (all in the code as named constants)

- **Review cost:** ₹150 per account manually reviewed — a placeholder for a real ops number, not measured.
- **Investigator capacity:** 20 accounts/day per investigator, with a 1-day SLA — both adjustable.
- **False-negative cost:** *not* assumed — computed directly from the dataset (each ring's total transaction amount attributed evenly across its members).

## Output files

- `results/threshold_sweep.csv` — **every** parameter setting tried, for all three detectors, with precision/recall/flagged-volume/cost/investigators at each one. This is the full tradeoff surface, not just the three selected points.
- `results/operating_modes.csv` — the three modes, broken out per-detector and fused system-wide.
- `results/evidence_dossier_conservative.csv` / `_balanced.csv` / `_aggressive.csv` — the actual review queue (sorted by risk score) for whichever mode a team picks. Three real, ready-to-use account lists, not one.
