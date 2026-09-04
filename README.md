# CORTEX
### Fraud-Ring Intelligence & Investigation Co-Pilot

**RazorPay AI Hackathon 2026 — Track 02: AI Risk Manager**

> **Detection is only the first problem. The real problem is deciding what investigators should act on when the attacker adapts and investigator capacity is finite.**
>
> CORTEX detects coordinated fraud that transaction-level models miss, prices every case in ₹ exposure, ranks it against finite investigator capacity, and keeps working when the attacker adapts — with an AI Co-Pilot that explains evidence but never decides it.

All numbers below come from **one clean, complete run of the entire pipeline**, executed immediately before this README was finalized, from a fully wiped output state. Nothing here is carried forward from an earlier phase or an earlier draft. The exact commands are in [§14](#14-reproducibility) and every number links to the file it came from in [§11](#11-evaluation--evidence-frozen).

| Result | Value |
|---|---:|
| Alerts → Cases | **625 → 337** |
| ₹ Exposure captured (5 investigators) | **₹918,272** |
| Adversarial evaluation | **4 of 6** corrected attacks fully evade detection — reported, not hidden |
| Engineering discipline | **16** documented bugs found and fixed, each with cause, fix, and re-measured result |

---

## 1. The problem

Transaction-level fraud detection has a structural blind spot: the suspicious pattern often doesn't live in any single transaction, it lives in the **relationship** between accounts — shared infrastructure, coordinated timing, circular money flow. A model scoring transactions one at a time can miss all three.

That's only half the problem. Even a system that detects everything still has to answer a harder question: **a risk team has a fixed number of investigators, and a large alert queue doesn't tell them which cases deserve the next hour of attention.** Detecting more fraud is not the same as making a limited investigation team more effective.

```
DETECTION PROBLEM                          INVESTIGATION PROBLEM
Individual transactions look normal        Large alert volume
        ↓                                          ↓
Group-level coordination is missed         Limited investigator capacity
                                                    ↓
                                            Important cases get buried
```

CORTEX is built around both halves, not just the first one.

---

## 2. Why this is a different design

| Traditional approach | CORTEX |
|---|---|
| Transaction-level anomaly scoring | Group-level coordination across accounts |
| Single signal | Three independent, structurally different signals |
| Maximizes detection metrics | Detection **+** financial impact **+** investigator effort |
| One flat alert queue | Investigator-capacity-aware, ₹-ranked priority queue |
| One "optimal" threshold | Three named operating modes — the team picks the tradeoff |
| Static evaluation | Adaptive adversarial evaluation, including a self-correcting fix loop |
| AI makes or changes the decision | AI explains evidence; a deterministic layer owns every risk output |

**Core thesis:** detection alone doesn't tell an investigator what to act on. That decision only becomes real when it accounts for two things most systems ignore — a finite investigator capacity, and an attacker who adapts once they realize they're being watched.

---

## 3. Solution overview

```
Data
  ↓
FRAUDAR-lite ─────┐
CopyCatch-lite ───┼──→ Cross-Signal Reasoning (deterministic, auditable)
FlowScope-lite ───┘             ↓
                            Fraud Cases
                                 ↓
                     ₹ Exposure + Confidence + Priority
                                 ↓
                     Investigator Capacity (3 named modes)
                                 ↓
                          Priority Queue
                                 ↓
                    AI Investigation Co-Pilot (Gemini)
                                 ↓
                          Human Investigator
```

Nine build phases, each in its own folder with its own README and its own reproducible run command — see [§16](#16-judge-evidence-map) for the fastest path to any specific claim.

---

## 4. Architecture

| Layer | Purpose | Technique | Output | Folder |
|---|---|---|---|---|
| Dataset | Controlled fraud environment | Rule-based synthetic simulation (not GAN — see §5) | Transactions + entities + ground truth | `phase1_dataset_construction/` |
| FRAUDAR-lite | Shared infrastructure | Weighted bipartite densest-subgraph scoring | Structural signal | `phase2_detection/` |
| CopyCatch-lite | Coordinated timing | Time-window lockstep clustering | Temporal signal | `phase3_copycatch/` |
| FlowScope-lite | Circular money movement | Directed-cycle flow tracing | Flow signal | `phase4_flowscope/` |
| Fusion | Combine detectors into modes | Cost-sensitive threshold sweep | 3 named operating modes | `phase5_fusion/` |
| Case engine | Form investigable units | Evidence-scoped clustering | 337 cases from 625 alerts | `phase6_case_prioritization/` |
| Prioritization | Allocate investigator capacity | ₹-exposure / effort-hour knapsack | Ranked priority queue | `phase6_case_prioritization/` |
| Adversarial eval | Test robustness | Detector-specific adaptive attacks | Evasion + self-correction results | `phase7_adversarial/` |
| Adaptive threat | Detect an attacker adapting over time | Signal-delta × exposure-persistence arithmetic | Adaptation score | `phase8_adaptive_threat/` |
| Cross-signal reasoning | Interpret agreement/disagreement | Fixed 5-rule table, 27-row audit artifact | Interpretation + confidence + priority | `phase9_cross_signal_reasoning/` |
| AI Co-Pilot | Assist the investigator | LLM (Gemini) over fixed structured evidence | Six-part briefing | `phase9b_ai_investigation_analyst/` |

---

## 5. Technical approach — and why each choice was made

**FRAUDAR-lite** — *Problem:* device/IP sharing signal. *Technique:* Hooi et al. (KDD 2016) weighted densest-subgraph scoring, adapted. *Why not a plain classifier:* the suspicious signal is relational — no single account's features flag it, only its relationship to others does. *Why not plain community detection (e.g. Louvain):* it optimizes exactly the metric camouflage defeats — see the mean-vs-sum scoring bug in `ENGINEERING_LOG.md` Entry 5. *Actual limitation:* raw precision is 21% (see §11) — pure entity-degree weighting cannot fully separate a coordinated ring from an innocent two-person coincidence (e.g. family device sharing), which is exactly why this signal is not used alone downstream.

**CopyCatch-lite** — *Problem:* lockstep coordination. *Technique:* Beutel et al. (WWW 2013) fixed time-window clustering, simplified (no full local-search bipartite-core optimization — unnecessary at this scale). *Actual limitation:* the window-merge mechanism gives real but incidental robustness to moderate jitter, and a flat `min_accounts` threshold isn't robust to ring-size variation (Entry 7).

**FlowScope-lite** — *Problem:* circular money flow. *Technique:* Li et al. (AAAI 2020) cycle tracing with amount-conservation and time-compression checks, simplified from the paper's full multi-partite flow-optimization machinery (unnecessary at this dataset's scale). *Actual limitation:* the "hard" camouflage tier for this archetype was found to be additive, not substitutive — it doesn't structurally break the cycle (Entry 8), a limitation reported rather than hidden.

**Fusion** — *Problem:* one threshold bakes a business judgment into the algorithm. *Technique:* sweep every threshold, surface three named modes (Conservative / Balanced / Aggressive) instead of one recommendation. *Why:* Compliance, the CFO, and Risk Ops do not own the same tradeoff — see §6.

**Case engine** — *Problem:* FRAUDAR flags individual accounts, not groups. *Technique:* connected-components clustering on the shared-entity graph, capped at entity degree ≤4 to prevent a mega-cluster collapse (Entry 3), with a second pass that safely recovers dense-but-non-bridging entities for exposure attribution without reintroducing that collapse (Entry 14).

**Prioritization** — *Problem:* raw account-level exposure massively overstates false positives (an innocent, active account's entire transaction history isn't fraud). *Technique:* evidence-scoped exposure — count only transactions tied to the actual flagged pattern (shared counterparty, cycle hop, lockstep window), verified against a knapsack-optimal allocation, not just a greedy heuristic.

**Adversarial evaluation** — *Problem:* a detector that hasn't been attacked hasn't been tested. *Technique:* four adaptive attacks, each targeting a specific detector's actual decision mechanism, not a generic difficulty escalation. *Why this matters more than recall:* see §7.

**Adaptive threat detection** — *Problem:* "did we catch it" isn't the same question as "is this ring adapting." *Technique:* transparent arithmetic — `(fraction of dropped detector signals) × (exposure persistence)` — deliberately not ML, not an LLM, not predictive modeling, per the track's own explicit instruction.

**Cross-signal reasoning** — *Problem:* averaging three detector outputs together loses information about *why* they agree or disagree. *Technique:* a fixed 5-rule table (two-detector agreement is never weakened by a third reading LOW; single-source evidence is flagged as such; genuine disagreement is named, not smoothed over). Every one of the 27 reachable signal combinations is enumerated in a standalone audit file — not asserted, checkable.

**AI Co-Pilot** — see §9.

---

## 6. Investigator-centric design — the actual funnel

```
625 raw account-level alerts     (Conservative-mode: every detector's max-recall flags)
   ↓
337 consolidated cases           (306 FRAUDAR clusters + 25 CopyCatch events + 6 FlowScope cycles)
   ↓
5 investigators × 8h/day = 40 effort-hours available
   ↓
15 highest-value cases selected
   ↓
₹918,272 genuine fraud exposure captured
```

CORTEX does not optimize for recall alone. **The headline metric is ₹ genuine fraud exposure captured at a fixed investigation capacity** — a number a CFO or Head of Risk can act on directly, unlike a precision/recall pair, because it answers "what can my team actually get done today," not "how good is the model in the abstract."

The 15-case selection is verified against the mathematical optimum, not just trusted: a simple, explainable greedy method (sort by ₹/hour density) captures ₹914,170; an exact 0/1 knapsack captures ₹918,272. **Greedy reaches 99.6% of optimal** — close enough that the simple, auditable method is the one actually used.

Three operating modes, not one recommendation — because the tradeoff belongs to whoever owns the consequence:

| Mode | Investigators needed | Precision | Recall | Total cost |
|---|---:|---:|---:|---:|
| Conservative (max recall — Compliance/Legal) | 32 | 26.6% | 97.6% | ₹80,260 |
| Balanced (min ₹ cost — CFO/Ops) | 22 | 37.2% | 95.3% | ₹56,268 |
| Aggressive (min headcount — Risk Ops) | 10 | 48.7% | 57.1% | ₹679,783 |

**The number worth pausing on:** going Balanced → Aggressive cuts headcount by more than half but costs **12x more** in missed fraud. That tradeoff was always in the data — showing three modes instead of one "optimal" threshold is what makes it visible before anyone commits to it.

---

## 7. Adversarial evaluation — not hidden

CORTEX is evaluated on whether its performance *degrades gracefully or catastrophically* when an attacker deliberately reverse-engineers each detector's own decision mechanism — not just on whether it catches a static, injected ring.

| Detector | Attack mechanism | Result |
|---|---|---|
| FRAUDAR | Camouflage through popular legitimate devices/IPs | **Evaded** (corrected version) |
| CopyCatch | Deliberately spaced coordination timing | **Evaded** (corrected version) |
| FlowScope | Delayed, legitimate-looking intermediary hop | **Evaded** |
| Cross-detector | Two signals weakened simultaneously, each below its own threshold | **Evaded** |

**4 of 6 attack variants achieve full evasion of the detector they target.** Stated as the headline of this section, not buried in a table. Two attacks (the *first*, uncorrected attempts against FRAUDAR and CopyCatch) failed — and diagnosing *why* they failed was more informative than either success or failure alone:

> Attack 1 assumed FRAUDAR was vulnerable to popular-entity dilution the way a *sum-based* scorer would be. It isn't — that was fixed away in Entry 5, specifically because summing rewarded exactly this kind of dilution. The actual (mean-based) scorer penalizes it instead. Attack 1 targeted a defense no longer in use; Attack 1b, corrected to exploit the real mean-based mechanism, achieved full evasion.

**The self-correcting loop, measured, not asserted:** one caught attack (Attack 1) showed **₹0 exposure** in the priority queue despite 100% detection — a real correctness bug, not an evasion. Root cause required three layered fixes, including a pre-existing string-prefix bug that had silently zeroed *every* FRAUDAR case's exposure since Phase 6 was first built (Entry 14). Re-running the identical evaluation after the fix: captured exposure at the same 5-investigator budget rose from ₹953,469 (no adversary) to **₹1,021,532 (post-attack, +7.1%)**, using *fewer* cases — because the caught attack's case finally contributes real value instead of silently vanishing. Top-5 case ranking stayed stable throughout (5/5 overlap) — the fix improved the *depth* of the queue, not the very top of it.

---

## 8. The unexpected finding

> **A detector can be correct while the investigation pipeline built on top of it is still wrong.**

Attack 1 was detected at 100% recall by FRAUDAR-lite. It still received ₹0 measured exposure and would have silently never reached an investigator's desk — not because detection failed, but because a downstream case-clustering safeguard (introduced to fix a *different* problem, Entry 11's mega-cluster collapse) had an unrelated blind spot for denser-than-expected rings. Fixing it surfaced a second, larger bug that had been masked the entire time.

**The lesson:** end-to-end risk systems have to be evaluated across the whole pipeline, not only at the detector boundary. A recall number alone would never have surfaced this.

---

## 9. AI Investigation Co-Pilot

**The LLM is an investigation interface over deterministic evidence — not the risk engine.**

| The Co-Pilot does | The Co-Pilot does NOT do |
|---|---|
| Explain why FRAUDAR/CopyCatch/FlowScope flagged a case | Calculate a fraud score |
| Highlight contradictions between detectors | Calculate ₹ exposure |
| Surface evidence gaps (what hasn't been established) | Determine priority |
| Compare similar historical cases | Modify a detector's output |
| Read investigator notes and extract structured feedback | Invent evidence not given to it |
| Suggest next investigative checks | Make the final fraud determination |

Two of these six capabilities are **fixed, deterministic modules**, not LLM judgment calls, precisely because they involve something checkable:

- **Evidence gaps** (`evidence_gaps.py`): a fixed catalog of seven real, structural data-model limitations (e.g., no KYC linkage, no prior-SAR check), each tagged with which case types it applies to. Not an LLM guessing plausible-sounding gaps.
- **Similar historical cases** (`similar_cases.py`): matched against the real 337-case pool using an explicit rule (same detector, exposure magnitude, account count, confidence band) — no embeddings, no learned similarity, every match explainable by which rule fired.

The LLM's only job is turning these fixed facts into prose. A guardrail checks every briefing for the one failure mode that matters most: the model asserting a *different* priority or confidence than the deterministic layer actually assigned. Tested directly against a deliberately drifted brief — confirmed to fire.

**Why this had to be built as two layers, not one:** an earlier version returned only a bare `priority` string with no reasoning attached. "Why this priority" and "what would change my mind" are now generated *inside the same function that makes the decision* (`compute_priority()` returns its own reason as part of its return value), so the explanation can never drift from the decision it explains — narrating a decision separately from making it is exactly how explanations and reality quietly diverge.

**Honest limitation:** the live Gemini API call has not been network-tested by the assistant that built this — the development sandbox doesn't reach `generativelanguage.googleapis.com`. The REST integration matches Google's documented endpoint; a full mock-mode fallback (clearly labeled, never presented as real model output) was tested end-to-end, all 10 demonstration cases, zero grounding warnings. See `phase9b_ai_investigation_analyst/README.md`.

---

## 10. Evidence provenance

```
DETERMINISTIC, AUDITABLE, COMPUTED BY THE DETERMINISTIC LAYER
✓ Fraud/confidence classification   (fixed 5-rule table, phase9_cross_signal_reasoning/)
✓ ₹ exposure                        (evidence-scoped transaction accounting, phase6/)
✓ Priority                          (fixed rule, returns its own reason, phase9a/)
✓ Detector signals (HIGH/LOW/N-A)   (phase2/3/4, unmodified detector code)
✓ Similar-case matching             (fixed similarity rule, phase9b/similar_cases.py)
✓ Evidence gaps                     (fixed catalog, phase9b/evidence_gaps.py)

AI CO-PILOT (Gemini, phase9b/)
→ Explains what the fixed evidence above means, in prose
→ Narrates contradictions already computed, doesn't detect new ones
→ Suggests next steps, informed by (never overriding) the above
→ Reads investigator notes as a suggestion for human review, never an automatic status change
```

No ML model and no LLM makes a risk decision anywhere in this system. That is a design choice, not a limitation — see the track's own bar: *"every money action explainable, bounded and gated."* A black-box score fails that bar by construction, however good its accuracy looks.

---

## 11. Evaluation & evidence (frozen)

**Every number below is from one clean run, executed immediately before this README, seed=42.** No number here was copied from an earlier draft.

| Metric | Result | Evidence file |
|---|---:|---|
| FRAUDAR-lite precision / recall (Balanced) | 21.3% / 93.7% | `phase2_detection/results/score_threshold_eval.csv` |
| CopyCatch-lite precision / recall | 100% / 95.1% | `phase3_copycatch/results/copycatch_events.csv` |
| FlowScope-lite precision / recall | 100% / 100% | `phase4_flowscope/results/flowscope_cycles.csv` |
| Fused Conservative / Balanced / Aggressive modes | see §6 table | `phase5_fusion/results/operating_modes.csv` |
| Alerts → Cases | 625 → 337 | `phase6_case_prioritization/results/priority_queue.csv` |
| ₹ Exposure captured (5 investigators, optimal) | ₹918,272 | same file — `selected=True` rows |
| Greedy vs. optimal allocation | ₹914,170 vs. ₹918,272 (99.6%) | printed in `case_prioritizer.py` run log |
| Attacks fully evading their target detector | 4 of 6 | `phase7_adversarial/results/attack_results.csv` |
| Priority-queue impact of the Entry-14 fix | +7.1% (₹953,469 → ₹1,021,532) | printed in `run_adversarial_eval.py` run log |
| Adaptation score, real lineage (FRAUDAR) | 1.0 (fully persistent exposure) | `phase8_adaptive_threat/results/adaptation_scores.csv` |
| Adaptation score, negative control | 0.029 (correctly low) | same file |
| Rule-table coverage | 27/27 signal combinations enumerated | `phase9_cross_signal_reasoning/results/rule_table_reference.csv` |
| Co-Pilot mock-mode grounding warnings | 0 / 10 briefings | `phase9b_ai_investigation_analyst/results/copilot_briefings.json` |

**On the cost of false positives, specifically** (the track's explicit bar): FRAUDAR-lite's raw 21.3% precision means roughly 4 in 5 raw flags are false positives — stated plainly, not smoothed over. This is exactly why exposure is evidence-scoped (§5) rather than account-wide, and why the fusion layer (§6) prices a false positive at ₹150 in investigator review time per account, explicit and adjustable, not folded invisibly into an accuracy number.

---

## 12. Failure recovery — engineering lessons

**16 entries** in `ENGINEERING_LOG.md`, each with what broke, how it was caught, the fix, and the re-measured result. Not written retrospectively — written as each thing was found. A representative sample:

| Failure | Diagnosis | Fix | Re-measured result |
|---|---|---|---|
| Mega-cluster collapse (Entry 3) | Degree-1 noise entities inflate density uniformly, collapsing the graph into one 2,073-account "block" | Prune entities with degree < 2 before scoring | Density signal became meaningful |
| Sum-vs-mean scoring inversion (Entry 5) | Summing edge weights rewarded camouflage instead of penalizing it | Switch to mean edge weight, verified the correct flagging direction empirically (not assumed) | Detector became genuinely camouflage-resistant — later confirmed by Attack 1's failure in §7 |
| Exposure inflation (Entry 11) | Account-wide transaction volume counted as "exposure" — a false positive's ordinary spending looked like fraud value | Evidence-scoped exposure: only transactions tied to the actual flagged pattern | Selected-case precision recovered from 3/51 to 20/20 |
| Cross-run ID comparison (Entry 13) | Compared two separately-generated datasets by exact account ID; `uuid4()` isn't reproducible across runs even with the same seed | Compare within one dataset generation via a counterfactual filter | Made the priority-queue-impact comparison actually meaningful |
| Silent exposure-zeroing bug (Entry 14) | Entity strings stored prefixed (`"DEV::x"`), compared against unprefixed transaction fields — every FRAUDAR case's exposure had been ₹0 since Phase 6 was built | Fixed the string comparison; found via checking why a *correct* fix (the degree-cap recovery) changed nothing | +7.1% captured exposure once fixed (§7) |
| Boilerplate masquerading as reasoning (Entry 16) | Generic template lines ("no detector disagreement") repeated on every case regardless of actual signal shape | Made every explanatory line a computed field, not a phrasing choice | Verified 3 genuinely distinct disagreement sentences and 3 distinct precedent-band summaries across real output |

Two of these were caught not by the assistant building the system, but by direct, specific critique during development — Entries 14 and 16 exist in their current, corrected form because a reviewer checked the actual output and found it wanting. That review loop is part of what this log documents.

---

## 13. Known limitations — stated directly

- **Synthetic dataset, not production data.** Built deliberately (rule-based, not GAN — GANs were rejected after research showed they destroy exactly the temporal-burst and shared-infrastructure signals fraud detection depends on), but synthetic nonetheless.
- **Detector implementations are lightweight, documented adaptations** of their source papers (FRAUDAR/CopyCatch/FlowScope), not full reproductions — each phase's README states exactly which parts of the original algorithm were simplified and why.
- **Historical case-similarity matching is a fixed rule, not a learned embedding space**, and currently uses a primary-detector heuristic rather than a true multi-detector composite for cases where several detectors agree.
- **This dataset's three archetypes each trip essentially one detector by design**, so genuine multi-signal agreement/disagreement is demonstrated with clearly-labeled synthetic cases (Phase 9a's Part C) alongside real ones — not fabricated as live detections.
- **2 of 6 adaptive attacks remain effective against the corresponding detector** with no further mitigation attempted in this build (Attack 1b, 2b, 3, 4 — see §7); this is reported as the honest current state, not resolved.
- **The live Gemini Co-Pilot path is implemented but not network-verified** by the assistant that built it (sandbox restriction) — mock mode is fully verified; live mode needs your own API key to confirm.
- **The interactive demo is a static-data walkthrough, not a live backend.** `demo/cortex_demo.html` renders the actual frozen numbers from §11 through five clickable screens (see §15), but it's driving pre-computed values embedded in the page, not calling the Python pipeline live — rebuilding it to call a real backend is the natural next step, not a limitation of the numbers shown.
- **Real-world deployment would need identity/KYC and network-level signals** this system does not have access to — enumerated explicitly per-case in the Co-Pilot's evidence-gaps output, not hidden.

---

## 14. Reproducibility

```bash
git clone <repo>
cd abuse-ring-sentinel
pip install numpy networkx --break-system-packages   # only external dependencies, everything else is stdlib

# Full pipeline, in order (each phase's own README has the identical command)
cd phase1_dataset_construction && python3 generate_dataset.py --seed 42 --out ./output && cd ..
cd phase2_detection && python3 fraudar_lite.py --data ../phase1_dataset_construction/output --out ./results --k_std 1.0 && cd ..
cd phase3_copycatch && python3 copycatch_lite.py --data ../phase1_dataset_construction/output --out ./results && cd ..
cd phase4_flowscope && python3 flowscope_lite.py --data ../phase1_dataset_construction/output --out ./results && cd ..
cd phase5_fusion && python3 fusion.py --data ../phase1_dataset_construction/output --out ./results && cd ..
cd phase6_case_prioritization && python3 case_prioritizer.py --data ../phase1_dataset_construction/output --out ./results --investigators 5 && cd ..
cd phase7_adversarial && python3 generate_adversarial_dataset.py --seed 42 --out ./adversarial_output && python3 run_adversarial_eval.py --investigators 5 --out ./results && cd ..
cd phase8_adaptive_threat && python3 adaptive_threat_detector.py --data ../phase7_adversarial/adversarial_output --out ./results && cd ..
cd phase9_cross_signal_reasoning && python3 run_reasoning.py --baseline ../phase1_dataset_construction/output --adversarial ../phase7_adversarial/adversarial_output --out ./results && cd ..
cd phase9b_ai_investigation_analyst && python3 ai_analyst.py --cases ../phase9_cross_signal_reasoning/results/case_reports.json --pool ../phase6_case_prioritization/results/priority_queue.csv --out ./results --mock && cd ..
```

Expected outputs, in order: dataset + ground truth → three detector result sets → three operating modes → a 337-case priority queue → an adversarial evaluation report → an adaptation-score report → a 27-row auditable rule table plus 10 case reports → 10 AI Co-Pilot briefings. This is the exact sequence run to produce every number in §11.

---

## 15. Demo — `demo/cortex_demo.html`

A single self-contained HTML file (open it directly in any browser, no server needed) walking the investigator's actual journey in five clickable screens — designed around, and populated entirely with, the frozen numbers in §11:

1. **Threat Overview** — *"what's happening?"* The 625→337 funnel, ₹16.6L identified exposure, the three detectors and what each one actually looks for.
2. **Priority Queue** — *"what should I investigate?"* The real top-15 ranked cases from `phase6_case_prioritization/results/priority_queue.csv`, with detector badges and confidence.
3. **Case Dossier** — *"why this case?"* A real case's full evidence breakdown (signals, interpretation, why-this-priority, what-would-change-my-mind) plus its actual AI Co-Pilot briefing (evidence gaps, similar historical cases, bottom line) — switchable via dropdown to two labeled-synthetic cases that illustrate genuine multi-detector agreement and disagreement, which this dataset can't produce naturally (§13).
4. **Adversarial Simulation** — *"what if the attacker adapts?"* The honest 4-of-6 evasion result stated as the headline, the two real before/after lineages with their adaptation scores, the negative control, and the measured +7.1% self-correction result from §7.
5. **Operating Modes** — *"what's the tradeoff?"* The three named modes from §6, clickable, with the "12x more" cost callout.

Built with vanilla HTML/CSS/JS (no build step, no external runtime dependency beyond a Google Fonts CDN call that degrades gracefully to system fonts if unavailable), rendered and screenshot-tested end to end across all five screens plus both interactive controls (case switching, mode selection) before inclusion here — verified to produce zero console/page errors, not just visually eyeballed once.

---

## 16. Judge evidence map

| Evaluation area | Where to look |
|---|---|
| Problem taste | §1–2 above, this file |
| Live demo | §15 above; `demo/cortex_demo.html`, open directly in a browser |
| Build quality — does it run | §14, and any phase folder's own README |
| Build quality — structure | 10 phase folders, one per pipeline stage, each self-contained |
| AI judgment (right tool, right place) | §9–10 above; `phase9b_ai_investigation_analyst/README.md` |
| Honest metrics incl. false-positive cost | §11 above; `phase5_fusion/README.md` (₹150/account review cost, explicit) |
| Defense-only compliance | Every phase README's compliance note; no operational thresholds published as exact evasion boundaries anywhere in this repo |
| Failure recovery | §12 above; full detail in `ENGINEERING_LOG.md` (16 entries) |
| Adversarial robustness | §7–8 above; `phase7_adversarial/README.md` |
| Reproducibility | §14 above |
| Limitations, stated honestly | §13 above |

---

## Compliance note

In line with the track's "strictly defense-only" requirement, this repository describes detection *methods* throughout without publishing exact operational thresholds as an evasion guide — see each phase's own compliance note. Nothing in this system has offensive capability: the adversarial-attack code in `phase7_adversarial/` exists solely to test this system's own detectors against a known, injected, synthetic dataset, and produces no capability transferable to evading a real production system.
