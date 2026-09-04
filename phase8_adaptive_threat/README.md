# Phase 8: Adaptive Threat Detection

## The question this answers

Not "did we catch this ring" — every earlier phase answers that. This phase asks: **is this fraud ring becoming harder to detect while remaining financially active?** That specific combination — shrinking visibility, persistent money movement — is the actual signature of an attacker adapting, as distinct from a ring that's simply winding down (which loses visibility *and* activity together).

## What this deliberately is not

Per the brief: not another detector, not an ML model, not an LLM, not predictive modeling. This is arithmetic over signals the existing three detectors already produce, run at two points in time, plus a templated explanation. Every number in the output traces back to a specific detector run — nothing here is learned or opaque.

## How it works

1. **Per-case signal snapshot**: for a given ring's account set, ask each of the three existing detectors (unmodified) whether it currently flags this ring — HIGH (flagged, ≥50% of accounts caught), LOW (structurally visible to this detector but not flagged), or N/A (this ring has no activity of the type this detector even looks at — e.g. a device-sharing ring has no chargebacks for CopyCatch to see).
2. **Ring exposure**: one archetype-agnostic rule, reusing the same principle as Phase 6 Entry 14's fix — count a transaction if both parties are ring members, or its counterparty is shared by 2+ ring members.
3. **Adaptation score** (the only piece of arithmetic that matters): `(fraction of previously-HIGH signals that dropped to LOW) × (exposure persistence, capped at 1.0)`. Both factors are required — a ring with dropped signals but also collapsed exposure looks like decline, not evasion; a ring with steady exposure but no dropped signals was never harder to see in the first place.
4. **Explanation**: a templated sentence naming exactly which signals dropped, which held, and the exposure numbers behind the persistence figure.

## Validation against Phase 7 — the actual point of this phase

Phase 7's naive→corrected attack pairs are a genuine "same underlying ring, attacker adapts" scenario, not a synthetic stand-in: an attacker who fails once (naive camouflage, caught) and comes back with a corrected approach (evades) is exactly what this phase is meant to detect.

| Lineage | Before → After | Adaptation score | Correct? |
|---|---|---|---|
| FRAUDAR-targeting (attack1 → attack1b) | HIGH → LOW, exposure ₹7,440 → ₹8,187 (100% held) | **1.0** | ✅ Yes — full signature |
| CopyCatch-targeting (attack2 → attack2b) | HIGH → LOW, exposure ₹35,604 → ₹16,676 (47% held) | **0.468** | ✅ Yes — borderline, and honestly so (exposure genuinely fell too, not pure evasion) |
| Negative control (synthetic genuine collapse) | HIGH → LOW, exposure ₹42,000 → ₹1,200 (3% held) | **0.029** | ✅ Correctly low — this is decline, not adaptation |

The CopyCatch lineage's 0.468 score is deliberately reported as-is, not tuned to look cleaner — exposure really did drop to 47% of its prior level alongside the signal loss, which is a genuinely more ambiguous case than the FRAUDAR lineage's clean 100%-persistence result, and the score reflects that honestly rather than rounding it up to a tidier number.

## A real bug found while building this

The first run classified Attack 2 as CopyCatch "LOW" even at its "before" snapshot — directly contradicting Phase 7's own established result that Attack 2 was caught at 88.9% recall. Cause: hardcoded signal-detection parameters (`window=30, min_acc=4`) that didn't match the actual Conservative-mode parameters the system uses operationally (`window=60, min_acc=3`, derived by Phase 5/6's sweep). Fixed by deriving operational parameters the same way Phase 5/6 do, rather than guessing at a third set of values. Full detail in `ENGINEERING_LOG.md` Entry 15.

## Run it

```bash
python3 adaptive_threat_detector.py --data ../phase7_adversarial/adversarial_output --out ./results
```

## Output

`results/adaptation_scores.csv` — every lineage evaluated, with before/after signal state per detector, before/after exposure, and the final adaptation score.
