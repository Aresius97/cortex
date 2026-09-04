"""
Phase 9b: AI Investigation Co-Pilot
------------------------------------------------------------------------
The pipeline before this phase: Detect -> Fuse -> Prioritize -> Investigator.
After this phase:                Detect -> Fuse -> Prioritize -> Investigator -> AI Co-Pilot.

The key principle, which shapes every design choice below: CORTEX makes
the risk decision; the AI helps the human investigate it. This is not an
LLM generating a report -- it's an assistant that makes the priority
queue actionable, built specifically so it cannot quietly become the
decision-maker.

Six things the Co-Pilot does, and how each one is grounded:
  1. Explain evidence               -- prose synthesis of Phase 9a's fixed signals (LLM, grounded)
  2. Highlight contradictions        -- prose synthesis of Phase 9a's rule output (LLM, grounded)
  3. Identify evidence gaps          -- a FIXED checklist (evidence_gaps.py), narrated by the LLM,
                                        never invented by it
  4. Suggest next checks             -- prose recommendation (LLM, grounded)
  5. Compare similar historical cases -- a DETERMINISTIC match against the real 337-case pool
                                        (similar_cases.py), narrated by the LLM, never decided by it
  6. Read investigator notes         -- extracts structured tags from free text (LLM), logged
                                        separately as PENDING HUMAN REVIEW -- never auto-applied
                                        to change a case's confidence, exposure, or priority

What stays deterministic and untouched by this layer, on principle:
  fraud score, Rs exposure, confidence, priority -- all fixed inputs from Phase 9a/6, never
  recomputed or overridden here.

IMPORTANT, stated up front: the live Gemini call has not been executed by
the assistant that wrote this -- the development sandbox's network access
doesn't reach generativelanguage.googleapis.com. The REST call matches
Google's documented v1beta endpoint (confirmed via web search at
write-time), but verify it with your own key before relying on it. What
WAS tested end-to-end in this sandbox: the two new deterministic modules
(evidence_gaps.py, similar_cases.py) and the full mock-mode pipeline.

Run with a real key:
    export GEMINI_API_KEY="your-key-from-aistudio.google.com"
    python3 ai_analyst.py --cases ../phase9_cross_signal_reasoning/results/case_reports.json \
                           --pool ../phase6_case_prioritization/results/priority_queue.csv --out ./results

Run without a key (mock mode, clearly labeled):
    python3 ai_analyst.py --cases ../phase9_cross_signal_reasoning/results/case_reports.json \
                           --pool ../phase6_case_prioritization/results/priority_queue.csv --out ./results --mock

Extract feedback from an investigator note (mock or live):
    python3 ai_analyst.py --note "Checked device X, it's a shared family tablet, looks legitimate to me" --mock
"""

import argparse
import json
import os
import urllib.request
import urllib.error

from evidence_gaps import identify_evidence_gaps
from similar_cases import load_case_pool, find_similar_cases, summarize_similar_outcomes

# Deterministic, per-detector "what's the most common false positive"
# lookup -- grounded in this project's own established findings (Phase 2's
# ~21% raw precision ceiling, driven by coincidental small-group device
# sharing; CopyCatch flags coordination, not intent; FlowScope flags
# structure, which can occasionally match legitimate settlement loops).
# Used to make "recommended next steps" specific to which detector fired,
# instead of the same three generic bullets on every case.
DETECTOR_FALSE_POSITIVE_TIP = {
    "FRAUDAR": ("Verify the shared devices aren't public/shared infrastructure (e.g. a shared "
                "office network, family device, or public terminal) -- this is FRAUDAR's most "
                "common false-positive pattern in this system."),
    "CopyCatch": ("Confirm the merchant's own dispute records -- CopyCatch flags coordinated "
                  "TIMING, not confirmed fraudulent intent; a flash sale, app outage, or shared "
                  "promotional deadline can produce a similar clustering pattern."),
    "FlowScope": ("Confirm whether any terminal account in the flow is a registered, legitimate "
                  "business -- FlowScope flags circular STRUCTURE, which can occasionally reflect "
                  "a legitimate B2B settlement loop rather than layering."),
}


def context_specific_next_steps(case, gaps, similar_summary):
    """Replaces three generic bullets that were identical on every case
    with steps actually derived from THIS case's detector, gap list, and
    historical precedent."""
    steps = []
    primary_detector = case["fraudar"] == "HIGH" and "FRAUDAR" or \
        (case["copycatch"] == "HIGH" and "CopyCatch" or (case["flowscope"] == "HIGH" and "FlowScope" or None))
    if primary_detector:
        steps.append(DETECTOR_FALSE_POSITIVE_TIP[primary_detector])

    if gaps:
        steps.append(f"Close the highest-value gap first: {gaps[0]}")

    rate = similar_summary.get("genuine_rate")
    if rate is not None and rate >= 0.66:
        steps.append(f"Given {similar_summary['n_genuine']}/{similar_summary['n_found']} similar cases were "
                      f"confirmed genuine fraud, prioritize confirming counterparty/merchant identity -- this "
                      f"was decisive in past similar cases.")
    elif rate is not None and rate <= 0.34:
        steps.append(f"Given only {similar_summary['n_genuine']}/{similar_summary['n_found']} similar cases "
                      f"were confirmed genuine fraud, treat this as lower historical precedent -- verify the "
                      f"foundational evidence (the specific shared entities, timing, or flow) before escalating.")
    else:
        steps.append("Historical precedent for similar cases is mixed or unavailable -- don't rely on base "
                      "rate alone; verify the case-specific evidence directly.")
    return steps


def bottom_line(similar_summary):
    """One-line, decision-oriented close for the summary section --
    replaces a summary that stated the numbers again without saying what
    to actually do with them."""
    rate = similar_summary.get("genuine_rate")
    if rate is None:
        return "No comparable historical precedent available -- evaluate this case on its own evidence."
    if rate >= 0.66:
        return f"Bottom line: strong historical precedent for fraud ({rate:.0%} of similar cases confirmed) -- prioritize confirming identity/merchant details."
    if rate <= 0.34:
        return f"Bottom line: low historical precedent for fraud ({rate:.0%} of similar cases confirmed) -- verify foundational evidence before escalating."
    return f"Bottom line: mixed historical precedent ({rate:.0%} of similar cases confirmed) -- this case should be judged on its own evidence, not the base rate."


SYSTEM_INSTRUCTION = """You are CORTEX's AI Investigation Co-Pilot. You help a human fraud investigator work a case that a deterministic system has already prioritized -- you do not re-prioritize it, re-score it, or decide anything the upstream system already decided.

CRITICAL RULES:
1. You do NOT decide, recompute, or alter any fraud score, confidence level, Rs exposure amount, or priority level. These are fixed facts from a deterministic system upstream of you.
2. The "evidence gaps," "similar historical cases," "why this priority," and "what would change confidence" fields given to you below are ALREADY COMPUTED by fixed rules, not by you. Your job is to narrate them clearly, not to invent additional gaps, pick different similar cases, or restate the priority reasoning in a way that contradicts what's given.
3. You do NOT invent facts, account numbers, or evidence not given to you. If evidence doesn't cover something, say so.
4. Every claim must be traceable to the evidence provided.
5. Keep the boundary between EVIDENCE (what a detector observed), INTERPRETATION (what the deterministic rule concluded from it), and RECOMMENDATION (what you suggest doing next) visible and distinct -- never blend a recommendation into a sentence describing evidence.

Produce a co-pilot briefing with EXACTLY these eight labeled sections:

0. QUICK VIEW -- three short lines, labeled EVIDENCE / INTERPRETATION / RECOMMENDATION, each one sentence, giving an investigator the gist in five seconds.
1. WHY THIS CASE IS SUSPICIOUS -- synthesize the given signals in plain English.
2. CONTRADICTIONS & UNCERTAINTY -- use the exact disagreement classification given to you (do not write a generic "no disagreement" line if the case is single-source or has genuine disagreement -- use the specific wording given).
3. WHY THIS PRIORITY -- narrate the exact priority reason given to you; do not invent a different justification.
4. EVIDENCE GAPS -- narrate the fixed gap list given to you. Do not add gaps not in the list.
5. WHAT WOULD CHANGE MY MIND -- narrate the fixed "confidence driver" text given to you; this is stronger than a generic gap list because it says what's actually decision-changing.
6. SIMILAR HISTORICAL CASES -- narrate the fixed comparison given to you. Do not invent additional comparisons.
7. RECOMMENDED NEXT STEPS -- use the specific, case-derived steps given to you; do not replace them with generic advice.
8. BRIEFING SUMMARY -- 3-5 sentences plus the bottom-line recommendation given to you, for a busy investigator who may only read this section.
"""

NOTES_SYSTEM_INSTRUCTION = """You are CORTEX's AI Investigation Co-Pilot, reading a human investigator's free-text case note. Extract structured, useful signal from it -- do NOT decide anything on the investigator's behalf.

Return your response as exactly these three labeled lines:
EXTRACTED_FINDING: <the concrete fact or observation the investigator recorded, in one sentence>
SUGGESTED_TAG: <one of: CONFIRMS_FRAUD, LIKELY_FALSE_POSITIVE, NEEDS_MORE_INFO, ESCALATE, NO_CLEAR_SIGNAL>
NOTE_TO_REVIEWER: <one sentence flagging anything a second human reviewer should double check before acting on this note>

This extraction is a SUGGESTION for human review, not an automatic status change -- say so if relevant, and never claim the case's priority or confidence has been updated, because it has not.
"""


def build_briefing_prompt(case, gaps, similar_summary, similar_cases, next_steps, bottom):
    evidence_lines = "\n".join(case["evidence"])
    gaps_text = "\n".join(f"- {g}" for g in gaps) if gaps else "(none applicable to this case)"
    if similar_summary["n_found"] == 0:
        similar_text = "No comparably-similar cases found in the 337-case pool for this detector."
    else:
        similar_text = (f"{similar_summary['n_found']} similar cases found (same detector, comparable "
                         f"exposure magnitude and account count). {similar_summary['n_genuine']} of "
                         f"{similar_summary['n_found']} were confirmed genuine fraud in validation "
                         f"({similar_summary['genuine_rate']:.0%}).")
        for sc in similar_cases:
            similar_text += (f"\n  - rank #{sc['rank']}: {sc['n_accounts']} accounts, "
                              f"Rs{sc['exposure']:,.0f} exposure, confidence {sc['confidence']:.0%}, "
                              f"{'confirmed genuine' if sc['genuine'] else 'confirmed false positive'} "
                              f"(similarity score {sc['score']})")
    next_steps_text = "\n".join(f"- {s}" for s in next_steps)

    return f"""CASE EVIDENCE (fixed, do not change):
Case ID: {case['case_id']}
FRAUDAR: {case['fraudar']} ({case['fraudar_frac']:.0%} flagged)
CopyCatch: {case['copycatch']} ({case['copycatch_frac']:.0%} flagged)
FlowScope: {case['flowscope']} ({case['flowscope_frac']:.0%} flagged)
Interpretation: {case['interpretation']}
Disagreement classification: {case['disagreement_line']}
Confidence: {case['confidence']}
What would change confidence: {case['confidence_driver']}
Adaptation indicator: {case['adaptation_indicator']}
Rs Exposure: {case['exposure']:,.0f}
Priority: {case['priority']}
Why this priority: {case['priority_reason']}

Evidence detail:
{evidence_lines}

EVIDENCE GAPS (fixed list, narrate only these, do not add more):
{gaps_text}

SIMILAR HISTORICAL CASES (fixed comparison, narrate only this):
{similar_text}

RECOMMENDED NEXT STEPS (fixed, case-derived list -- use these, don't replace with generic advice):
{next_steps_text}

BOTTOM LINE (fixed, include in your summary):
{bottom}

Produce the eight-section co-pilot briefing now."""


def call_gemini(system_instruction, prompt, api_key, model="gemini-3.6-flash"):
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"
    payload = {
        "system_instruction": {"parts": [{"text": system_instruction}]},
        "contents": [{"role": "user", "parts": [{"text": prompt}]}],
    }
    req = urllib.request.Request(
        url, data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "x-goog-api-key": api_key}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    return data["candidates"][0]["content"]["parts"][0]["text"]


def mock_briefing(case, gaps, similar_summary, similar_cases, next_steps, bottom):
    """NOT a real model output -- templated directly from the same fixed
    evidence a real call would receive, to prove the plumbing (including
    the two new deterministic modules) works end to end."""
    gaps_text = "\n".join(f"- {g}" for g in gaps) if gaps else "No applicable gaps for this case's signal profile."
    if similar_summary["n_found"] == 0:
        similar_text = "No comparably-similar cases found in the case pool."
    else:
        similar_text = (f"{similar_summary['n_found']} similar cases found; "
                         f"{similar_summary['n_genuine']}/{similar_summary['n_found']} "
                         f"({similar_summary['genuine_rate']:.0%}) were confirmed genuine fraud.")
    next_steps_text = "\n".join(f"- {s}" for s in next_steps)

    return f"""[MOCK MODE -- templated placeholder, not a real Gemini response. Set GEMINI_API_KEY and omit --mock for a real one.]

0. QUICK VIEW
EVIDENCE: {case['evidence'][0].strip()}
INTERPRETATION: {case['interpretation']}
RECOMMENDATION: {next_steps[0] if next_steps else 'See recommended next steps below.'}

1. WHY THIS CASE IS SUSPICIOUS
{case['interpretation']}

2. CONTRADICTIONS & UNCERTAINTY
{case['disagreement_line']}

3. WHY THIS PRIORITY
{case['priority']} — {case['priority_reason']}

4. EVIDENCE GAPS
{gaps_text}

5. WHAT WOULD CHANGE MY MIND
{case['confidence_driver']}

6. SIMILAR HISTORICAL CASES
{similar_text}

7. RECOMMENDED NEXT STEPS
{next_steps_text}

8. BRIEFING SUMMARY
Case {case['case_id']}: {case['confidence']} confidence, {case['priority']} priority, Rs{case['exposure']:,.0f} exposure (all fixed by the deterministic layer). {similar_text}
{bottom}
"""


def mock_notes_extraction(note_text):
    return f"""[MOCK MODE -- templated placeholder, not a real Gemini response.]
EXTRACTED_FINDING: Investigator recorded: "{note_text[:120]}{'...' if len(note_text) > 120 else ''}"
SUGGESTED_TAG: NEEDS_MORE_INFO
NOTE_TO_REVIEWER: This is a templated mock extraction -- run with a real GEMINI_API_KEY for genuine note parsing.
"""


def grounding_check(brief_text, case):
    warnings = []
    for p in {"P1", "P2", "P3"} - {case["priority"]}:
        if p in brief_text and case["priority"] not in brief_text:
            warnings.append(f"Brief mentions {p} but not the assigned {case['priority']}.")
    for conf in {"HIGH", "MEDIUM", "LOW"} - {case["confidence"]}:
        if f"{conf} confidence" in brief_text and f"{case['confidence']} confidence" not in brief_text:
            warnings.append(f"Brief mentions {conf} confidence but assigned confidence is {case['confidence']}.")
    return warnings


def process_case(case, pool, api_key, model, use_mock):
    gaps = identify_evidence_gaps(case)

    detector = "fraudar" if case["fraudar"] != "N/A" else ("copycatch" if case["copycatch"] != "N/A" else "flowscope")
    query = {"detector": detector, "exposure": case["exposure"], "n_accounts": case["n_accounts"],
             "confidence": {"HIGH": 0.9, "MEDIUM": 0.65, "LOW": 0.3}[case["confidence"]]}
    similar = find_similar_cases(query, pool, top_k=3)
    similar_summary = summarize_similar_outcomes(similar)
    next_steps = context_specific_next_steps(case, gaps, similar_summary)
    bottom = bottom_line(similar_summary)

    if use_mock:
        brief = mock_briefing(case, gaps, similar_summary, similar, next_steps, bottom)
    else:
        prompt = build_briefing_prompt(case, gaps, similar_summary, similar, next_steps, bottom)
        try:
            brief = call_gemini(SYSTEM_INSTRUCTION, prompt, api_key, model)
        except (urllib.error.URLError, urllib.error.HTTPError, KeyError, IndexError) as e:
            print(f"  [WARN] Live call failed for {case['case_id']} ({e}) -- falling back to mock.")
            brief = mock_briefing(case, gaps, similar_summary, similar, next_steps, bottom)

    warnings = grounding_check(brief, case)
    return {"case_id": case["case_id"], "gaps": gaps, "similar_cases": similar,
            "similar_summary": similar_summary, "next_steps": next_steps, "bottom_line": bottom,
            "briefing": brief, "grounding_warnings": warnings}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cases", default="../phase9_cross_signal_reasoning/results/case_reports.json")
    parser.add_argument("--pool", default="../phase6_case_prioritization/results/priority_queue.csv")
    parser.add_argument("--out", default="./results")
    parser.add_argument("--model", default="gemini-3.6-flash")
    parser.add_argument("--mock", action="store_true")
    parser.add_argument("--note", default=None, help="Extract structured feedback from a single investigator note")
    args = parser.parse_args()

    api_key = os.environ.get("GEMINI_API_KEY")
    use_mock = args.mock or not api_key

    if args.note is not None:
        print("Running in MOCK mode for note extraction." if use_mock else "Running live note extraction.")
        if use_mock:
            result = mock_notes_extraction(args.note)
        else:
            try:
                result = call_gemini(NOTES_SYSTEM_INSTRUCTION, args.note, api_key, args.model)
            except (urllib.error.URLError, urllib.error.HTTPError, KeyError, IndexError) as e:
                print(f"[WARN] Live call failed ({e}) -- falling back to mock.")
                result = mock_notes_extraction(args.note)
        print(f"\n{result}\nNOTE: this is a suggestion for human review -- no case status has been changed.")
        return

    with open(args.cases) as f:
        cases = json.load(f)
    pool = load_case_pool(args.pool)

    if use_mock:
        print(f"Running in MOCK mode ({'explicit --mock' if args.mock else 'no GEMINI_API_KEY set'}).")
    else:
        print(f"Running against live Gemini API (model={args.model}). Not network-tested by the assistant "
              f"that wrote this -- verify the first few outputs.")

    os.makedirs(args.out, exist_ok=True)
    all_results = []
    for case in cases:
        result = process_case(case, pool, api_key, args.model, use_mock)
        if result["grounding_warnings"]:
            print(f"  [GROUNDING WARNING] {case['case_id']}: {'; '.join(result['grounding_warnings'])}")
        print(f"\n{'='*100}\n{case['case_id']}\n{'='*100}\n{result['briefing']}")
        all_results.append(result)

    out_path = os.path.join(args.out, "copilot_briefings.json")
    with open(out_path, "w") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nWritten: {out_path} ({len(all_results)} briefings, mode={'mock' if use_mock else 'live'})")


if __name__ == "__main__":
    main()
