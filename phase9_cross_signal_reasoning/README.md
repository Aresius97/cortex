# Phase 9a: Cross-Signal Reasoning Engine (deterministic, auditable)

## What this does

Interprets *patterns* of agreement and disagreement across FRAUDAR-lite, CopyCatch-lite, and FlowScope-lite — not just their union (Phase 5/6) and not just their change over time alone (Phase 8, reused here for the adaptation indicator). This is a fixed rule table, not a model: five ordered rules, applied to each case's three HIGH/LOW/N-A readings, produce an interpretation, a confidence level, and (combined with Phase 8's adaptation check and the case's ₹ exposure) a priority. Nothing here is learned from data or opaque — the full 27-row rule table is written to disk as its own artifact specifically so it can be audited without running any code.

## The rules, in order

1. **Two or more detectors agree (HIGH)** → Confidence HIGH. This is the strongest pattern the system can produce, and critically: a third detector reading LOW does *not* weaken it. This is the literal example from the brief — weak/absent timing evidence doesn't override strong structural+flow agreement, because each detector targets a genuinely different mechanism.
2. **Exactly one HIGH, others N/A** → Confidence MEDIUM. Single-source evidence, but *uncontradicted* — the other detectors were never in a position to weigh in, since this ring's activity has no structural basis for them to evaluate (e.g., a device-sharing ring has no chargebacks for CopyCatch to see).
3. **Exactly one HIGH, another detector applicable but LOW** → Confidence MEDIUM. A real, partial disagreement, named explicitly rather than averaged away — but still not a contradiction, since one detector's silence doesn't disprove another's positive finding.
4. **No HIGH, at least one LOW** → Confidence LOW. Checked, not currently actionable.
5. **Everything N/A** → Confidence LOW. Outside every detector's scope entirely.

Priority is a separate, equally simple rule: an adaptation indicator of POSSIBLE always escalates to P1 regardless of confidence (an attacker actively adapting is worth escalating on its own), HIGH confidence is P1 above a ₹20,000 exposure threshold and P2 below it, MEDIUM confidence is P2, everything else is P3.

## Every derived statement is generated from the same code path as the decision, not narrated separately

An earlier version of this engine returned only `(interpretation, confidence)` from the rule classifier and a bare `priority` string from the priority function — which meant anything downstream that wanted to explain *why* a priority was assigned had to re-derive that reasoning separately, risking drift between the explanation and the actual decision. Both functions now return their reasoning as a first-class output:

- `classify_signal_pattern()` returns a `disagreement_type` tag (`agreement` / `single_source` / `partial_disagreement` / `none_flagged` / `not_applicable`) alongside the interpretation, so a case with genuine detector disagreement renders "FRAUDAR HIGH, CopyCatch LOW — this is a genuine, real disagreement," a single-source case renders "no other detector was structurally able to weigh in," and a 3-way agreement case renders "all triggered detectors agree" — three different, specific sentences instead of one generic "no detector disagreement" line repeated on every case regardless of its actual signal shape.
- `compute_priority()` returns its own reason string as part of the same return value — e.g. *"MEDIUM confidence... is always P2 regardless of exposure — corroboration, not dollar value, is what would move this to P1."* This can't drift from the real decision because it's generated inside the same branch that makes it.
- A new `what_would_change_confidence()` function, keyed to the same `disagreement_type` tag, states what evidence is actually decision-changing for this specific case (e.g., for a partial-disagreement case: *"independent confirmation of CopyCatch's mechanism... would raise confidence toward HIGH"*) — stronger than a generic gap list because it names the specific thing that would move the needle.

All three are consumed downstream by Phase 9b's Co-Pilot, which is where they actually matter for an investigator reading a briefing.

## An honest limitation about what this dataset can demonstrate

This project's three fraud archetypes are each constructed to trip essentially one detector (Phase 1's design) — so real cases in this dataset almost always show exactly one HIGH signal and two N/A signals. There is very little *genuine* multi-detector agreement or disagreement to observe live, because the data was never built to produce it. Rather than pretend otherwise, Part C of the runner output uses a small number of **clearly-labeled synthetic cases** to illustrate Rule 1 (genuine agreement) and Rule 3 (genuine disagreement) — the same honest pattern Phase 8 used for its negative control, not real detections dressed up as something they're not.

## A second honest limitation: how the Phase 7 attack cases were fed in

Part B evaluates all six Phase 7 attack rings, including the two with a real before/after lineage (giving a genuine adaptation indicator via Phase 8's machinery). **These account sets were pulled directly from ground truth, not surfaced by the live pipeline.** In a real deployment, a ring that evades every detector (as four of the six attacks do) never becomes a "case" at all — Phase 6 only ever constructs cases from accounts at least one detector flagged, and Phase 7 Entry 13 already established that a fully-evaded ring is invisible to the system, not merely deprioritized. Part B is a validation exercise answering "what would the reasoning engine conclude about these specific accounts if something else — a tip, an audit, an external signal — brought them to its attention," not a claim that the system found them unassisted. Stated plainly rather than left implicit.

## Cross-validation against earlier phases

The exposure and signal values computed here for the two real lineages (attack1→1b, attack2→2b) match Phase 8's independently-computed numbers exactly (₹8,187 and ₹16,676 respectively) — worth noting because this is genuine cross-validation between two separately-written scripts calling the same underlying detector functions, not a single number trusted in isolation.

## Run it

```bash
python3 run_reasoning.py --baseline ../phase1_dataset_construction/output \
                          --adversarial ../phase7_adversarial/adversarial_output \
                          --out ./results
```

## Output

- `results/rule_table_reference.csv` — all 27 signal combinations and their decisions, for audit without running code.
- `results/case_reports.csv` — every case evaluated, one row each.
- `results/case_reports.json` — the same data in structured form, used as grounding input for Phase 9b (the LLM investigation-brief layer).
