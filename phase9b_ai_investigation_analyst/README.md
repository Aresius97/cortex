# Phase 9b: AI Investigation Co-Pilot

## The pipeline, before and after this phase

**Before:** Detect → Fuse → Prioritize → Investigator
**After:** Detect → Fuse → Prioritize → Investigator → **AI Co-Pilot**

The key principle, which shapes every design choice below: **CORTEX makes the risk decision; the AI helps the human investigate it.** This is not an LLM generating a report — it's an assistant that makes the priority queue actionable, built specifically so it cannot quietly become the decision-maker.

## The six things the Co-Pilot does, and how each is grounded

| # | Capability | How it's grounded |
|---|---|---|
| 1 | Explain evidence | Prose synthesis of Phase 9a's fixed signals (LLM, but nothing to invent — the signals are given) |
| 2 | Highlight contradictions & uncertainty | Prose synthesis of Phase 9a's rule output (LLM, grounded) |
| 3 | **Identify evidence gaps** | A **fixed checklist** (`evidence_gaps.py`) — narrated by the LLM, never invented by it |
| 4 | Suggest next investigative checks | Prose recommendation, informed by the gaps and similar cases (LLM, grounded) |
| 5 | **Compare similar historical cases** | A **deterministic match** against the real 337-case pool (`similar_cases.py`) — narrated by the LLM, never decided by it |
| 6 | **Read investigator notes** | Extracts structured tags from free text (LLM) — logged as **pending human review**, never auto-applied to change a case |

Items 3 and 5 are the genuinely new capabilities this phase adds beyond the earlier six-section brief; both are deterministic modules with the LLM only permitted to narrate their output, not decide it — consistent with everything else in this project that involves a judgment call.

## Evidence gaps — why this had to be a fixed checklist, not an LLM guess

An LLM asked "what evidence is missing" with no grounding produces generic, plausible-sounding gaps that may or may not reflect what this system actually has access to. `evidence_gaps.py` is a fixed catalog of seven gaps, each tagged with which case types it applies to (e.g., "no merchant-side dispute resolution outcome" only applies when CopyCatch is structurally relevant) — every gap corresponds to a real, structural limitation of this project's data model, not an invented plausibility. Tested directly: a FlowScope-only case correctly surfaces only the gaps relevant to flow evidence, not FRAUDAR- or CopyCatch-specific ones.

## Similar historical cases — a fixed rule, not an embedding space

`similar_cases.py` matches against the **real 337-case pool** from Phase 6 (not just the 10-case illustration set from Phase 9a), using an explicit, auditable rule: same detector (heaviest weight — a FRAUDAR case is never "similar" to a FlowScope case just because the exposure happens to match), then exposure order-of-magnitude, account-count ratio, and confidence band. No embeddings, no learned similarity — every match is explainable by which of the four rules fired. Tested directly against a real case: querying a FlowScope case (5 accounts, ₹82,925) correctly returns other FlowScope cases of comparable size and confidence, all excluding cross-detector matches entirely.

**A known simplification, stated honestly:** for a case where multiple detectors agree (e.g., a synthetic all-HIGH illustration), the similarity search currently uses only the primary/first-applicable detector's pool, not a composite across all three. This is a reasonable simplification for this dataset (where genuine multi-detector cases barely occur naturally — see Phase 9a's own limitation notice) but is not a fully general multi-signal similarity metric.

## Investigator notes — read, never auto-applied

`--note "..."` extracts three structured fields from free text: the concrete finding, a suggested tag (`CONFIRMS_FRAUD` / `LIKELY_FALSE_POSITIVE` / `NEEDS_MORE_INFO` / `ESCALATE` / `NO_CLEAR_SIGNAL`), and a note to a second human reviewer. The system prompt explicitly forbids the model from claiming any case status has changed, and the script's own closing line reinforces it: *"this is a suggestion for human review — no case status has been changed."* Tested in mock mode; verified the closing guardrail line prints correctly.

## Fixed: the briefing was structurally boilerplate, not just occasionally generic

The first version of every briefing repeated the same three lines regardless of the case — "no detector disagreement," three identical "recommended next steps," and a summary that restated the numbers without saying what to do with them. That's not a phrasing problem, it's a grounding problem: those lines were fixed strings, not values derived from the case. Fixed by making every one of them a **computed field**, not a better-written template:

- **Disagreement line** now comes from Phase 9a's `disagreement_type` tag, giving three genuinely different sentences for a single-source case, a 3-way agreement case, and a real disagreement case — not one line reused everywhere (see Phase 9a's README for the underlying change).
- **Next steps** are now assembled from three real inputs: a per-detector "most common false-positive" tip (`DETECTOR_FALSE_POSITIVE_TIP`, grounded in this project's own established findings — e.g. FRAUDAR's ~21% raw precision ceiling, driven by coincidental small-group device sharing), the single highest-value evidence gap for this case, and a recommendation keyed to the similar-cases genuine-fraud rate (verify identity when precedent is strong, verify foundational evidence when it's weak).
- **Bottom line** is a one-sentence, decision-oriented close (*"Bottom line: low historical precedent for fraud (0% of similar cases confirmed) — verify foundational evidence before escalating"*), not a restatement of numbers already given above it.
- **Why this priority** and **what would change my mind** are two new sections, both narrating Phase 9a's own `priority_reason` and `confidence_driver` fields — the actual rule that fired, not a plausible-sounding guess at one.
- **A QUICK VIEW section** (section 0, before the numbered depth sections) gives three one-line fields — EVIDENCE / INTERPRETATION / RECOMMENDATION — so the boundary between "what a detector observed," "what the deterministic rule concluded," and "what to do next" stays visually distinct, which matters specifically because blurring that boundary is where hallucination becomes hard to catch.

Verified directly: running all 10 demonstration cases produces three genuinely different disagreement lines, three different bottom-line precedent bands (0%, 67%, 100%, each with distinct wording), and zero grounding warnings.

## An honest limitation, unchanged from the earlier version of this phase

The live Gemini API call has **not** been executed by the assistant that wrote this code — the development sandbox's network access doesn't reach `generativelanguage.googleapis.com`. The REST call matches Google's documented `v1beta` endpoint (confirmed via web search at write-time), but verify it with your own key before trusting it. What **was** tested end-to-end in this sandbox: both new deterministic modules individually, the full mock-mode briefing pipeline (all 10 cases, zero grounding warnings), and the notes-extraction path.

## Run it

```bash
# Full briefing pipeline, mock mode (no key needed)
python3 ai_analyst.py --cases ../phase9_cross_signal_reasoning/results/case_reports.json \
                       --pool ../phase6_case_prioritization/results/priority_queue.csv \
                       --out ./results --mock

# Live mode (requires your own free-tier key from aistudio.google.com)
export GEMINI_API_KEY="..."
python3 ai_analyst.py --cases ../phase9_cross_signal_reasoning/results/case_reports.json \
                       --pool ../phase6_case_prioritization/results/priority_queue.csv --out ./results

# Extract feedback from a single investigator note
python3 ai_analyst.py --note "Checked device X, it's a shared family tablet" --mock
```

## Output

`results/copilot_briefings.json` — one entry per case: the case ID, the fixed evidence-gaps list, the fixed similar-cases match with their summary statistic, the full six-section briefing text, and any grounding warnings raised.
