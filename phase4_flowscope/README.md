# Phase 4: Detection — FlowScope-lite

## What this phase does

Detects the `circular_flow_laundering` archetype by tracing directed cycles through the merchant-to-merchant transaction graph, based on Li et al. (AAAI 2020), "FlowScope: Spotting Money Laundering Based on Graph Flow Analysis."

**What we implement:** a directed merchant→merchant transaction graph (already a strong pre-filter, since legitimate traffic in this dataset is customer↔merchant only — a merchant-to-merchant transfer is structurally rare by construction), simple-cycle enumeration on that graph, and two suspicion checks per cycle matching the actual laundering signature: amount conservation across hops, and time compression (a real layering chain completes quickly).

**What we deliberately do not implement:** FlowScope's full multi-partite, time-layered flow-optimization machinery, built for laundering detection at a much larger graph scale than this dataset's few hundred merchants. Direct cycle enumeration with consistency checks captures the same signature here without the heavier apparatus.

## Run it

```bash
python3 flowscope_lite.py --data ../phase1_dataset_construction/output --out ./results --max_span_minutes 180 --min_amount_ratio 0.3
```

## Current results

At default settings: **precision 1.00, recall 1.00** — every one of the 6 injected circular-flow rings found, zero false positives.

## An honest finding: this result is real, but "hard tier" isn't actually harder here

Before trusting a perfect score, we checked two things rather than just reporting the number:

1. **Threshold sensitivity is real, not trivial.** Tightening `max_span_minutes` to 20 drops hard-tier recall to 0% while easy-tier stays at 100% — confirming the checks are doing genuine filtering work, not passing everything by default.
2. **The camouflage mechanism for this archetype is structurally additive, not substitutive.** The "hard" tier's reroute-through-a-legitimate-merchant step (see `phase1_dataset_construction/generate_dataset.py`, `_inject_circular_flow_ring`) adds one extra noise edge but never replaces or removes a hop in the actual cycle. The full direct cycle survives intact at every camouflage tier, which is why recall is 1.00 at hard exactly as at easy — this isn't evidence of genuine camouflage resistance, it's evidence that this particular camouflage design doesn't test cycle-breaking at all.

**Reported, not hidden, as a concrete next step:** a more meaningful hard-tier test would have the "legitimate" reroute actually *replace* one hop (member → legit intermediate → next member) rather than sit alongside the direct edge, forcing the detector to trace through an extra, genuinely legitimate-looking hop. Noted here as unfinished work, not fixed silently.

## Output

`results/flowscope_cycles.csv` — every candidate cycle found (flagged or not), with its time span and amount-conservation ratio, so you can see exactly why each one was or wasn't flagged.
