"""
Similar Historical Cases (deterministic matching, not embedding/ML similarity)
-------------------------------------------------------------------------------
Given a case, finds the most similar cases from the full 337-case pool
(Phase 6's priority_queue.csv, not just the 10-case illustration set from
Phase 9a) using a fixed, auditable similarity rule -- not a learned
embedding space. This matters for the same reason everything else in this
project is deterministic where a judgment call is made: "which past cases
are relevant" is exactly the kind of thing that should be checkable, not
a black-box nearest-neighbor result.

Similarity rule (in order of weight):
  1. Same detector/archetype (heaviest weight -- a FRAUDAR case is not
     "similar" to a FlowScope case just because the exposure happens to
     match).
  2. Same order of magnitude of exposure (log10 bucket).
  3. Similar account count (within +/-50%).
  4. Similar confidence band (High/Medium/Low, i.e. >=0.8 / 0.5-0.8 / <0.5).
"""

import csv
import math


def load_case_pool(priority_queue_path):
    pool = []
    with open(priority_queue_path) as f:
        for row in csv.DictReader(f):
            pool.append({
                "rank": int(row["rank"]), "detector": row["detector"], "archetype": row["archetype"],
                "n_accounts": int(row["n_accounts"]), "exposure": float(row["exposure_rs"]),
                "confidence": float(row["confidence"]), "why": row["why_flagged"],
                "genuine": row["is_genuine_fraud_VALIDATION_ONLY"] == "True",
            })
    return pool


def _confidence_band(c):
    if c >= 0.8:
        return "high"
    if c >= 0.5:
        return "medium"
    return "low"


def similarity_score(query, candidate):
    """Higher is more similar. Fixed weights, no learning."""
    if query["detector"] != candidate["detector"]:
        return -1  # different detector = not comparable, excluded entirely

    score = 10.0  # base score for matching detector

    query_mag = math.log10(max(query["exposure"], 1))
    cand_mag = math.log10(max(candidate["exposure"], 1))
    score -= abs(query_mag - cand_mag) * 2.0  # penalize order-of-magnitude difference

    n_ratio = candidate["n_accounts"] / max(query["n_accounts"], 1)
    if 0.5 <= n_ratio <= 1.5:
        score += 2.0

    if _confidence_band(query["confidence"]) == _confidence_band(candidate["confidence"]):
        score += 3.0

    return score


def find_similar_cases(query, pool, top_k=3, exclude_self=True):
    """query: a dict with at least detector, exposure, n_accounts,
    confidence (0-1 scale). Returns up to top_k most similar cases from
    pool, with their similarity score, sorted descending."""
    scored = []
    for candidate in pool:
        if exclude_self and candidate.get("rank") == query.get("rank"):
            continue
        s = similarity_score(query, candidate)
        if s > 0:
            scored.append((s, candidate))
    scored.sort(key=lambda x: -x[0])
    return [{"score": round(s, 2), **c} for s, c in scored[:top_k]]


def summarize_similar_outcomes(similar_cases):
    """Deterministic summary stat: of the similar cases found, how many
    were confirmed genuine (validation-only ground truth) -- this is the
    number a co-pilot would narrate, computed here so the narration can't
    misstate it."""
    if not similar_cases:
        return {"n_found": 0, "n_genuine": 0, "genuine_rate": None}
    n_genuine = sum(1 for c in similar_cases if c["genuine"])
    return {"n_found": len(similar_cases), "n_genuine": n_genuine,
            "genuine_rate": round(n_genuine / len(similar_cases), 2)}
