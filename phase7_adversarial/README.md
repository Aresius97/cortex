# Phase 7: Adversarial Evaluation

## The question this phase actually answers

Not "does recall fall under harder camouflage" — every earlier phase already tests difficulty tiers. This phase asks: **when an attacker who has seen how our detectors work adapts specifically to defeat them, does the system still put the right cases in front of a constrained investigation team?**

Four attack types, each targeting a specific detector's actual decision mechanism (not a generic "make it harder" escalation):

| Attack | Targets | Mechanism |
|---|---|---|
| 1 → 1b | FRAUDAR-lite | Camouflage through legitimate devices/IPs |
| 2 → 2b | CopyCatch-lite | Widened/adapted coordination timing |
| 3 | FlowScope-lite | Legitimate-looking intermediary insertion |
| 4 | Cross-detector | Two signals weakened simultaneously |

Each attack is labeled `X` and `Xb` because **the first version of Attacks 1, 2, and 4 didn't actually test what they were supposed to** — building the *correct* adaptive version, and understanding precisely why the first version failed, turned out to be the most valuable part of this phase. Full diagnostic detail for all of this is in `ENGINEERING_LOG.md` Entries 12-13.

## Run it

```bash
python3 generate_adversarial_dataset.py --seed 42 --out ./adversarial_output
python3 run_adversarial_eval.py --investigators 5 --out ./results
```

## Results

| Attack | Target | Recall | Evaded? |
|---|---|---|---|
| 1 — naive popular-entity camouflage | FRAUDAR | 100% | **No — backfired** |
| 1b — corrected paired-decoy camouflage | FRAUDAR | 0% | **Yes, fully** |
| 2 — uniform random jitter (±150 min) | CopyCatch | 88.9% | No, mostly caught |
| 2b — deliberately spaced timing | CopyCatch | 0% | **Yes, fully** |
| 3 — delayed legitimate intermediary | FlowScope | 0% | **Yes, fully** |
| 4 — cross-detector (corrected) | Fraudar + CopyCatch jointly | 0% | **Yes, fully** |

Four of six attacks achieve full evasion. That's not a comfortable number, and it's reported as-is rather than only showcasing the two that failed.

## Why two attacks backfired — and why that's a real finding, not luck

**Attack 1** assumed our FRAUDAR-lite defense was vulnerable to popular-entity dilution in the way a *sum-based* scorer would be. We don't run a sum-based scorer — we fixed that away in Phase 2 Entry 5, specifically because summing rewarded exactly this kind of dilution. Our actual scorer uses **mean** edge weight, where popular (low-weight) entities pull an account's average *down*, making it look *more* suspicious, not less. Attack 1 targeted a defense we no longer run. The corrected version (1b) — pairing ring members with fresh decoy accounts on new degree-2 devices, mimicking the honest population's own high-scoring pattern — achieves genuine, full evasion.

**Attack 2** assumed wide timing jitter alone was sufficient. It wasn't, because CopyCatch-lite's window-merging step can chain adjacent flagged sub-windows into a much wider effective span than the configured parameter (a 60-minute window setting still caught a 147-minute-wide cluster). The corrected version (2b) spaces every participant's timestamp far enough apart that no two are ever close enough for chaining to link them — full evasion.

**The lesson, stated directly:** an attack failing does not mean a defense is robust. It might mean the attack targeted the wrong mechanism. We diagnosed *why* each attack failed with the same rigor as diagnosing a detector bug, rather than either declaring victory or moving on.

## A deeper finding: detection success doesn't guarantee the case survives downstream — and the fix

Attack 1, despite being **caught at 100% recall** by FRAUDAR-lite, showed **zero exposure** in the Phase 6 priority queue when we first checked. Diagnosis: Attack 1's ring shares a device used by 7 of its 10 members — degree 7, which exceeds `CASE_ENTITY_DEGREE_CAP=4`, the cap Phase 6 introduced specifically to stop case-clustering from collapsing into a mega-cluster (Entry 11). That cap was tuned against the baseline dataset's typical ring density and was never tested against a ring this dense.

**This was fixed, not just reported — completing the full loop: attack finds gap → fix system → re-attack → measure improvement.** The fix took three layered corrections (`ENGINEERING_LOG.md` Entry 14), not one:

1. An adaptive entity-recovery pass that adds a dense entity to a case's exposure calculation *only* if it doesn't bridge multiple different cases — preserving the original mega-cluster fix while recovering legitimate dense rings.
2. That fix revealed a **much bigger, pre-existing bug**: a string-prefix mismatch meant every FRAUDAR case's exposure had been silently zero since Phase 6 was first built, unrelated to the degree cap entirely.
3. Fixing #2 immediately caused precision on selected cases to collapse to 1/60, because matching on shared device/IP alone counts an account's *entire* transaction history through that device, including unrelated legitimate spending. Fixed by requiring a transaction's counterparty to also be shared by another case member — the actual signature of coordinated abuse.

**Measured result of re-running the full pipeline after the fix:** captured exposure at the same 5-investigator budget rose from ₹953,469 (counterfactual, no adversary) to **₹1,021,532 (post-attack) — a +7.1% increase**, achieved with *fewer* selected cases (13 vs. 15). This isn't noise: Attack 1's now-correctly-valued case earned a spot in the selected set and displaced a lower-value case entirely, while the top-5 ranking stayed stable (still the highest-value genuine flowscope rings). Catching an attack and *correctly valuing* what was caught measurably improved the system's overall efficiency, not just its recall.

## Priority queue impact, final numbers

| | Counterfactual (no adversary) | Actual (post-attack, all fixes applied) |
|---|---|---|
| Cases selected | 15 | 13 |
| Exposure captured | ₹953,469 | ₹1,021,532 (**+7.1%**) |
| Top-5 overlap | — | 5/5 (unchanged) |

- **Top-5 stays stable** — the highest-value cases are still the genuine baseline flowscope rings, whether or not the adversary attacked.
- **The fully-evaded attacks (1b, 2b, 3, 4) still never enter the case pool at all** — nothing to flag means nothing to construct a case from. This is the sobering half of the finding that remains true even after the fix: a fully-evaded attack isn't deprioritized, it's invisible, at any priority level, to any investigator.
- **The detected-but-caught attack (1) now contributes real, positive value** to the system instead of vanishing due to a downstream bug — which is exactly what "fix the correctness issue" was supposed to achieve, verified by rerunning rather than assumed.

## Output

`results/attack_results.csv` — every attack, its target detector, per-detector recall, and whether it fully evaded.
