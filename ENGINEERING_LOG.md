# Engineering Log

This log is intentionally specific and unpolished. The point isn't to show a clean success story — it's to show that failures were caught, diagnosed correctly, and fixed with evidence, not guesswork. Every entry below is a real bug encountered while building Phase 1 and Phase 2, in the order it happened.

---

## Entry 1 — Camouflage that didn't actually camouflage anything

**What we built first:** A "hard" difficulty tier for injected fraud rings that added more filler transactions and wider timing jitter around ring members.

**What was wrong:** This is generic noise, not the camouflage mechanism the detection research (FRAUDAR) is actually built to resist. FRAUDAR's specific guarantee is about fraud accounts adding edges toward *already-popular, high-degree legitimate targets* — that's what dilutes a density-based suspiciousness score. Generic filler volume doesn't exploit that mechanism at all.

**How we caught it:** Direct challenge during design review, not automated testing — the gap was conceptual, not something a unit test would catch.

**Fix:** Rebuilt the "hard" tier to add targeted edges toward the top-20%-by-degree legitimate merchants, using a fresh personal device/IP rather than the ring's shared infrastructure.

**Verification, not assumption:** We measured it. Honest customers averaged ~25.6 distinct merchants over the 90-day window; our first "fixed" version of camouflage only got hard-tier ring members to ~4.6 — nowhere close. Recalibrated the camouflage-edge count until hard-tier accounts reached ~20.8, the same order of magnitude as the honest baseline. Only then was the camouflage claim actually true.

---

## Entry 2 — Camouflage that fooled the wrong graph

**What was wrong:** The Entry 1 fix added camouflage edges toward popular *merchants*. But FRAUDAR's primary target for the shared-infrastructure ring archetype is the account↔device/IP sharing graph — a structurally different graph from the account↔merchant transaction graph. Merchant-camouflage does nothing to the device/IP graph at all.

**How we caught it:** Directly checked whether ring members' persistent device/IP records (`account_device_map.csv`) changed across camouflage tiers. They didn't — 1.31 → 1.62 → 1.12 devices per account, essentially flat noise, while the merchant-transaction graph showed the intended effect clearly (2.1 → 7.6 → 21.1). Confirmed the two mechanisms were operating on two different graphs.

**Fix:** Added a second, separate camouflage mechanism specifically for the device/IP graph — ring members connect to already-popular devices/IPs (computed from the honest baseline), not just popular merchants.

---

## Entry 3 — Detector collapsed to flagging almost everyone

**What happened:** First working version of the FRAUDAR-lite greedy-peeling algorithm returned a "densest block" of 2,073 accounts out of 2,077 total — essentially the whole population.

**Diagnosis:** ~44% of devices/IPs in the base population are used by exactly one account (a personal device carries zero collusion signal by definition). These degree-1 edges inflate the whole graph's average weighted density uniformly, so the global density metric never dipped below its starting value — the peak was at the very start, before any real peeling happened.

**Fix:** Pruned entities with degree < 2 before running the algorithm — a standard, justified preprocessing step (sharing requires at least 2 accounts), not a workaround that changes what's being measured.

---

## Entry 4 — Detector collapsed to a near-empty block

**What happened:** After Entry 3's fix, the algorithm swung the other way — best block found was just 3 accounts.

**Diagnosis:** Plain average-degree density search (`total edge weight / node count`) mathematically favors tiny, tightly-connected cliques, because dividing by a small denominator inflates the ratio. A coincidental 2-3 person family/office device-sharing pair can outscore a real 6-14 person ring purely on this artifact.

**Fix:** Added a minimum block size constraint (5 accounts) before a candidate snapshot is eligible to be considered "best."

---

## Entry 5 — Detector inverted: camouflaged accounts scored as MORE suspicious

**What happened:** With minimum block size in place, the largest found block ballooned to 776 accounts (precision ~0.01) — the true ring was inside it, but so was almost everyone else.

**Diagnosis:** The account-level suspicion score was computed as the **sum** of an account's weighted edges. Summing rewards an account for having *more* edges — including the low-weight camouflage edges we deliberately added — which is backwards: a fraudster adding camouflage connections should look *less* suspicious, not more.

**Fix:** Switched the score to the **mean** edge weight per account, not the sum.

**Follow-up bug, caught by checking rather than assuming:** After switching to mean, flagging accounts *above* the mean threshold produced 0% recall on every tier. Directly comparing ring-member scores to the honest baseline showed ring members scored *below* the honest average (0.49–0.53 vs. 0.64), not above — because a ring's own shared-device pool (touched by 4-14 people) scores lower under `1/log(degree+2)` weighting than an honest 2-person coincidental sharing pair, which is the statistically "rarest" pattern by this metric. Flipped the threshold direction to flag below-baseline accounts. This is now a real, working, honestly-verified detector.

---

## Entry 6 — A dataset gap that would have made the next detector's numbers meaningless

**What we were about to do:** Run CopyCatch-lite (time-window lockstep detector) against the existing dataset and report its precision/recall.

**What was wrong:** Checked the transaction-type distribution first, out of habit from Entries 3-5. Found that **100% of chargebacks in the dataset were ring-generated** — the generator never produced an independent, uncorrelated chargeback. This means any chargeback-clustering algorithm would score artificially perfectly: there was no legitimate chargeback noise to distinguish signal from, so "precision 1.0" would have meant nothing.

**Fix:** Added `build_organic_chargebacks()` to the Phase 1 generator — 250 independent, uncorrelated chargebacks from random customer/merchant pairs at random times, with no coordination. Regenerated the dataset (chargeback count went from 104 to 397) before writing or trusting a single line of the detector.

**Lesson carried forward:** verify what "noise" actually exists in a dataset for the specific signal a detector is meant to separate, before running the detector — a clean-looking result can just mean the test was rigged by omission, not that the method works.

---

## Entry 7 — A recall pattern that looked backwards, checked before reporting

**What we saw:** CopyCatch-lite's recall was *lower* on the easy camouflage tier (0.88) than on medium/hard (1.00) — the opposite of what "camouflage resistance" should look like, and worth checking before including it in any pitch.

**Diagnosis:** Not a bug. In this particular random dataset draw, the easy-tier rings happened to be smaller (7-9 members) than the hard-tier rings (10-11 members). CopyCatch-lite's `min_accounts` threshold is a flat constant (4), which a smaller ring's individual events are naturally more likely to fall below, independent of camouflage level. Confirmed by directly inspecting per-merchant chargeback counts rather than assuming.

**What this reveals, reported rather than hidden:** a fixed `min_accounts` threshold isn't robust to ring-size variation. This is a real design gap worth closing via the planned cost-sensitive threshold selection (see `docs/PROJECT_DOCUMENTATION.md` §6), not a flaw in the underlying detection logic.

---

## Entry 8 — A perfect score that needed checking before it could be trusted

**What we saw:** FlowScope-lite (circular-flow cycle detector) scored precision 1.00, recall 1.00 across all three camouflage tiers on the first working run.

**Why we didn't just report it:** a perfect score with zero variation across difficulty tiers is exactly the kind of result that should be checked, not celebrated. Two checks, before trusting it:

1. **Are the thresholds actually doing anything, or trivially passing everything?** Tightened `max_span_minutes` from 180 to 20 — hard-tier recall dropped to 0% while easy-tier stayed at 100%. Confirms the filtering is real.
2. **Why is hard-tier not harder than easy-tier?** Traced this to the generator itself: the "hard" camouflage reroute (`_inject_circular_flow_ring`, hard branch) adds one extra edge to a legitimate-looking merchant but never removes or replaces a hop in the actual cycle. The full cycle survives structurally intact regardless of camouflage level — so equal recall across tiers reflects a gap in the camouflage design, not genuine resistance being demonstrated.

**Left as an honest, reported limitation, not fixed silently:** the circular-flow archetype's "hard" tier doesn't currently test cycle-breaking camouflage at all. A more meaningful version would have the reroute *replace* a hop rather than sit alongside it. Noted as unfinished work rather than quietly shipping a flattering-but-uninformative 100% number.

---

## Entry 9 — Evidence dossier crashed on its own output, from a one-sided view of "activity"

**What happened:** Building the fusion layer's per-account risk score, the first working run completed without error and wrote `evidence_dossier.csv` — but a follow-up analysis script reading that same file crashed with `could not convert string to float: ''`. 23 rows had a blank `risk_score`.

**Diagnosis:** The risk-scoring function only gathered a flagged account's transactions where it appeared as `src_account` (the sender). All 23 blank rows came from CopyCatch — lockstep chargeback-ring members are chargeback **recipients** (`dst_account`), not senders, for the transaction that actually implicates them. Some of these accounts genuinely have zero transactions as sender, so the sender-only view found nothing to score.

**Fix:** Rewrote the scoring function to gather activity from both sides of every transaction (as sender and as recipient), and to give a genuinely account with zero activity either direction an explicit `0.0` score rather than leaving the field blank.

**Lesson carried forward:** "does this account have any transactions" is not the same question as "does this account have any transactions in the one direction I happened to query" — worth checking which side of a transaction a given fraud pattern actually implicates before writing an activity-based feature.

---

## Entry 10 — A design flaw, not a code bug: the fusion layer was answering a question nobody asked it to answer

**What was wrong:** Phase 5's first version swept every threshold, then silently collapsed the result to a single "cost-optimal" operating point and presented it as the answer. That's not a bug in the sense of producing wrong numbers — every number was correct. The flaw was architectural: picking one threshold bakes a business judgment (how much fraud loss is worth trading for investigator workload) into the algorithm, when that judgment belongs to whoever actually owns the tradeoff, and Compliance, the CFO, and Risk Ops don't own the same tradeoff.

**Fix:** Rebuilt around three named, explicitly-defined operating modes (Conservative / Balanced / Aggressive) instead of one recommendation, with every threshold's full metric set (precision, recall, flagged volume, financial cost, investigator headcount) written out, not just the winner. Added a stated minimum-recall floor to Aggressive mode specifically to stop it from degenerating to the trivial "flag nobody, zero cost, zero workload" solution that pure workload-minimization would otherwise select.

**What this revealed, once visible:** Aggressive mode cuts investigator headcount by more than half (10 vs. 22) relative to Balanced — but at 12x the financial cost (₹680k vs. ₹56k). That tradeoff existed in the data the whole time; the single-threshold version of this script was simply never going to surface it, because it never printed the alternative.

---

## What this leaves as an open, reported limitation (not hidden)

**Phase 2 (FRAUDAR-lite):** at the current operating point, precision is 0.20 against recall of 0.90. Pure entity-degree weighting cannot fully distinguish a coordinated ring from innocent small-group device sharing — both look "rare" by this specific signal. Closing that gap is the explicit purpose of the planned fusion layer (per-transaction velocity/amount scoring, Phase 4+), not something this phase claims to have already solved.

**Phase 3 (CopyCatch-lite):** precision is clean (1.00) but the `min_accounts` threshold is a flat constant that isn't robust to ring-size variation (Entry 7). This is a concrete, named target for the cost-sensitive threshold-selection work still to come.

**Phase 4 (FlowScope-lite):** precision and recall are both 1.00, but the "hard" camouflage tier for this archetype doesn't currently test what it's supposed to (Entry 8) — the reroute mechanism is additive, not substitutive, so the perfect score across tiers reflects a dataset design gap, not proven resistance.

**Phase 5 (Fusion):** the fused result's combined precision (0.37) is dominated by FRAUDAR-lite's false positives — the cost-sensitive sweep makes this visible rather than hiding it inside one blended number, and the assumed ₹150 review cost is stated explicitly as a placeholder, not presented as a measured figure.

We're stating all of this directly rather than tuning any of it to hide behind a single flattering number.

---

## Entry 11 — Two bugs in Phase 6, the second one worse than the first because it was quietly plausible

**Bug 1 — mega-cluster collapse in case construction, same root cause as Phase 2 Entry 3, new location.** Clustering FRAUDAR's flagged accounts into cases via connected components on the full shared-entity graph produced one "case" containing 461 of 537 flagged accounts. Not a single hub this time — transitive chaining through many degree-5-to-10 entities (percolation, not one bad node). Fixed by capping the case-clustering graph to entities with degree ≤ 4, a value found by sweeping the cap and checking exactly where case sizes explode (sane up to ~21 at cap=4, jumping to 291+ at cap=5).

**Bug 2 — exposure measured an account's entire history, not the actual evidence.** After fixing Bug 1, a red flag appeared: precision on selected cases *dropped* (12/31 → 3/51) while total captured ₹ exposure *rose*. Diagnosis: exposure was computed as an account's total transaction volume, all-time, both directions. For a real fraud ring, that's a reasonable proxy. For a false positive — an innocent account wrongly flagged — it just measures how large and active that account normally is, which has nothing to do with fraud. The capacity-constrained optimizer, working over hundreds of cheap single-account false-positive cases, filled the investigator budget with ordinary legitimate commerce because it looked like high-value exposure by this metric. This is the more dangerous of the two bugs specifically because the numbers it produced (₹15.2M total exposure, a big confident-looking figure) were plausible enough to ship without the follow-up check.

**Fix:** made exposure evidence-specific per detector rather than account-wide — FlowScope uses its own cycle hop amounts, CopyCatch uses the chargeback amounts inside its flagged window, FRAUDAR uses only transactions passing through the case's own clustering entities. Total exposure across all cases dropped from ₹15.2M to ₹871,619 — smaller, but now defensible, and selected-case precision recovered to 20/20.

**Lesson carried forward:** a headline number going up is not evidence a fix worked — check what's driving it before trusting it, especially when the number in question is the one going in the pitch deck.

---

## Entry 12 — Two adversarial attacks that backfired, and why that's a real finding, not a failed attack

**Attack 1 (naive popular-entity camouflage spam) achieved 0% evasion — FRAUDAR-lite caught 100% of it, at a LOWER (more suspicious) score than the baseline dataset's own "hard" tier.** Checking why: the attack added more edges toward already-popular devices, assuming that would dilute the account's score. But our actual detector scores by **mean** edge weight (fixed to mean specifically in Phase 2 Entry 5, away from an earlier sum-based bug), and popular entities carry *low* weight under `1/log(degree+2)`. Adding more low-weight edges pulls an account's *mean* **down**, not up — the attack targeted a sum-based vulnerability we had already fixed away from, not the defense that's actually running. Built the corrected version (Attack 1b): pairing each ring member with fresh one-off decoy accounts on new degree-2 devices, mimicking the exact statistical pattern that gives honest accounts their high baseline score. Attack 1b achieved full, genuine evasion (0% recall).

**Attack 2 (uniform random timing jitter, ±150 minutes) achieved only 11% evasion (88.9% still caught) — checked why rather than assuming the jitter was simply too weak.** CopyCatch-lite's merge-overlapping-windows step can chain adjacent flagged sub-windows into a much wider effective span than the configured window parameter — a 60-minute window setting caught a 147-minute-wide cluster by daisy-chaining. This is an emergent robustness property of the simple two-pointer-plus-merge design, not something deliberately engineered. Built the corrected version (Attack 2b): deliberately spacing every participant's timestamp by more than any tested window width, so no two participants are ever close enough for the chaining mechanism to link them. Attack 2b achieved full evasion (0% recall).

**Also corrected Attack 4 (cross-detector) for the same reason as Attack 1** — its first version used the same backfiring popular-entity camouflage for its device-sharing component, so FRAUDAR catching it 100% told us nothing about the intended cross-detector blind spot. Rebuilt using the corrected paired-decoy technique at reduced strength. Result: full evasion (0% recall on all three detectors), confirming the hypothesized architectural gap — a ring that stays below each individual detector's threshold on two dimensions simultaneously evades a system that unions independently-thresholded detectors, because no single detector's threshold ever fires.

**Lesson carried forward:** an attack that fails to evade a defense is not evidence the defense is robust — it may just mean the attack targeted the wrong mechanism. Worth diagnosing *why* an attack failed with the same rigor as diagnosing why a detector failed, before either claiming victory or moving on.

---

## Entry 13 — Comparing two dataset generations by exact account ID is meaningless, and a downstream cap can silently erase a correctly-detected ring's value

**Bug A — cross-run ID comparison.** The first version of the priority-queue comparison ran case prioritization separately against the baseline dataset (Phase 1's output) and the adversarial dataset (Phase 7's own generation), then compared their top-5 selected cases by exact account-ID set overlap. Result: 0/5 overlap, which looked like a dramatic finding — until checking `rand_id()` revealed it uses `uuid.uuid4()`, drawing from OS entropy, **not** reproducible across separate script invocations even with the same `--seed`. The two runs' account IDs could never match regardless of whether the attacks had any real effect; the "0/5 overlap" was a methodology artifact, not a result. Fixed by comparing within a single dataset generation instead: build cases once against the adversarial dataset, then construct the "no adversary" counterfactual by filtering out any case touching an adversarial account from that same case pool, so both views share one ID space.

**Bug B — the case-construction degree cap (Phase 6 Entry 11's fix) has an unintended side effect on larger rings.** After fixing Bug A, every case touching an adversarial account showed **zero exposure** — including Attack 1, which FRAUDAR-lite genuinely caught at 100% recall and which definitely moved real money. Diagnosis: Attack 1's ring shares a device used by 7 of its 10 members (degree 7), which exceeds `CASE_ENTITY_DEGREE_CAP=4` — the cap chosen in Phase 6 specifically to stop case-clustering from collapsing into one mega-cluster. That cap was tuned against the baseline dataset's typical ring sizes; it was never tested against a ring as dense as Attack 1's. The result: a **correctly detected** ring can still receive zero measured exposure and silently never reach the priority queue, because the same safeguard that prevents one failure mode creates a blind spot for another.

**Left as a named, reported limitation, not patched under time pressure:** raising the cap risks reintroducing Phase 6 Entry 11's mega-cluster collapse on the baseline dataset; a proper fix needs an adaptive, per-case cap rather than a single global constant, which is out of scope to rush through safely. Recorded here as a concrete next step rather than silently shipped or silently ignored.

**Lesson carried forward:** detection recall and downstream case value are two different claims — a system can correctly flag a ring and still fail to ever put it in front of an investigator, and the only way to catch that gap is to check what happens after detection, not just at it.

---

## Entry 14 — The full loop: attack finds gap, fix system, re-attack, measure improvement (three layered bugs, not one)

Entry 13 ended with the degree-cap blind spot reported as a known limitation, deliberately not patched under time pressure. This entry is that fix, done properly, plus two more bugs it surfaced along the way — which turned out to be far more consequential than the original one.

**Fix 1 — the degree cap itself.** The actual failure mode was never "high degree" — it was an entity *bridging* accounts that belong to otherwise-unrelated cases. A ring's own dense core device only ever touches accounts already in the same case; it doesn't bridge anything. Added `expand_case_entities_safely()`: after case membership is fixed by the safe low-cap clustering (unchanged), a separate pass checks every excluded (degree > cap) entity — if its flagged-account connections belong to exactly one existing case, it's added to that case's entity set for exposure purposes only, never for membership. This can't reintroduce the mega-cluster collapse because it never changes which accounts belong to which case. Ran it: 3 entities recovered on the baseline dataset, 5 on the adversarial dataset — but captured exposure didn't move. Checked why instead of declaring victory.

**Fix 2 — a much bigger, pre-existing bug the first fix accidentally exposed.** Direct verification showed Attack 1's case still had ₹0 exposure even with entities now present. Cause: `fraudar_lite.load_bipartite_graph()` prefixes entities (`"DEV::dev_xyz"`, `"IP::ip_xyz"`) to keep device/IP namespaces from colliding — but `compute_fraudar_case_exposure_bulk()` compared these prefixed strings directly against `transactions.csv`'s raw, unprefixed `device_id`/`ip_id` columns. The comparison could never match. This means **every FRAUDAR case's exposure had been silently zero since Phase 6 was first built**, entirely independent of the degree-cap issue — the cap fix was structurally correct but couldn't matter until this was also fixed. Fixed the comparison to prefix the transaction fields before checking. Verified directly: Attack 1's cases jumped from ₹0 to real five- and six-figure numbers.

**Fix 3 — the prefix fix immediately created a new, worse-looking problem, checked rather than shipped.** Rerunning the full baseline pipeline: total exposure jumped from ₹871,619 to ₹6,107,425 and captured exposure to ₹2,140,154 — but precision on selected cases collapsed from 20/20 to **1/60**. A single wrongly-flagged, one-account "case" showed ₹60,883 of "exposure." Diagnosis: matching on shared device/IP alone counts an account's *entire* transaction history through that device, including transactions with nothing to do with any suspicious pattern — if the same device is also used for the account's ordinary legitimate purchases, all of that volume gets counted too. Unlike CopyCatch's lockstep window or FlowScope's flow cycle, "a device was used" doesn't naturally bound the transaction volume it can imply. Fixed by adding a second condition: a transaction only counts toward a case's exposure if its counterparty is *also* transacted with by at least one other member of the same case — the actual signature of coordinated abuse (multiple ring members hitting the same target), not just incidental device reuse.

**Result of the full loop, measured, not assumed:**

| | Before any Entry 14 fix | After all three fixes |
|---|---|---|
| Total exposure (baseline, all cases) | ₹871,619 | ₹1,656,215 |
| Captured exposure (5 investigators) | ₹770,796 | ₹918,272 (**+19%**) |
| Precision on selected cases | 20/20 (100%) | 11/15 (73%) |

The precision drop from 20/20 to 11/15 is not a regression — it's the removal of an illusion. The original 20/20 was only that clean because FRAUDAR's genuinely-detected true positives were contributing **zero** measured value and therefore never competing for a slot in the priority queue at all. With FRAUDAR properly contributing, the system now surfaces more real fraud (captured exposure up 19%) at a more realistic, still-strong precision — a truer picture of what the pipeline actually does, not a more flattering one.

**Lesson carried forward, twice over:** (1) a fix that changes nothing (Fix 1 alone) is a reason to keep looking, not a reason to stop; (2) a fix that makes a metric jump dramatically (Fix 2 alone) is equally a reason to keep looking, not a reason to celebrate. Both directions of surprise get the same treatment: check before trusting.

---

## Entry 15 — Phase 8's first run silently disagreed with Phase 7's own established results

**What happened:** Phase 8's adaptive-threat script computes each detector's signal strength (HIGH/LOW) for a ring by re-running that detector live, rather than reading a stored result. The first run classified Attack 2 (uniform jitter) as CopyCatch signal "LOW" at its "before" snapshot — directly contradicting Phase 7's own established finding that Attack 2 was caught at 88.9% recall.

**Diagnosis:** the signal-strength functions used hardcoded parameters (`window=30, min_acc=4`) instead of the actual Conservative-mode parameters the deployed system uses (`window=60, min_acc=3`, derived by Phase 5/6's own sweep-and-select logic). Guessed defaults, not measured ones — exactly the kind of thing this project has repeatedly found doesn't match reality.

**Fix:** derive operational parameters the same way Phase 5/6 do (via `fusion.sweep_*` + `select_modes`), rather than hardcoding separate values in a third place. Reran: Attack 2 correctly shows HIGH → LOW across its lineage, matching Phase 7.

**Lesson carried forward:** any script that reimplements "how the system currently operates" instead of asking the system what its own operating parameters are will drift out of sync the moment those parameters change elsewhere — checked against a known result here specifically because Phase 7 had already established ground truth to check against, which is what caught it.

---

## Entry 16 — Generic boilerplate masquerading as reasoning, caught by external review

**What was wrong:** the Co-Pilot's briefings had several lines that were identical across every case regardless of its actual signal pattern — "No detector disagreement in this case's signal pattern" appeared even for single-detector cases with nothing to disagree with, and "Recommended next steps" was the same three generic bullets everywhere. This wasn't caught internally; it took an external review of the actual output text to notice the repetition, which is itself worth noting — automated tests checked that the pipeline *ran*, not that its prose was *specific*.

**Fix, done at the source rather than patched in the template:** refactored `classify_signal_pattern()` to return a `disagreement_type` tag (`agreement` / `single_source` / `partial_disagreement` / `none_flagged` / `not_applicable`) alongside its existing interpretation and confidence, and refactored `compute_priority()` to return its actual firing reason as a string, not just the priority label. Both changes mean the "why" text is generated from the *same code path* that made the decision — it cannot drift from what actually happened, because it isn't a separate narration of it.

Built on top of these: a per-detector "most common false positive" lookup (grounded in this project's own established findings, e.g. FRAUDAR's ~21% precision ceiling being driven by coincidental small-group device sharing), and a "what would change my mind" generator tied to the same `disagreement_type` tag. Next-steps and the briefing's closing "bottom line" now both key off the real `similar_cases.py` genuine-fraud rate for that specific case, not a generic sentence.

Also added, per explicit request: a compact EVIDENCE / INTERPRETATION / RECOMMENDATION quick-view block at the top of every briefing, so the boundary between "what a detector observed," "what the deterministic rule concluded," and "what's being suggested" stays visually distinct — the same boundary this project has enforced in code throughout, now made visible in the output text itself.

**Lesson carried forward:** a system can be fully deterministic and auditable in its decisions while still producing prose that reads as generic — auditability of the *decision* doesn't automatically give you specificity in the *explanation* of it; that has to be built deliberately, using the same decision-time data, not bolted on as better copywriting afterward.

