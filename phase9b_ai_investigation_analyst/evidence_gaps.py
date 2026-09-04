"""
Evidence Gaps Checklist (deterministic, not LLM-guessed)
------------------------------------------------------------
Answers "what hasn't been established yet" for a case -- honestly, based
on what data sources this system actually has versus what a full
investigation would ideally check. This is a fixed checklist, not an LLM
inventing plausible-sounding gaps: every line below corresponds to a real,
structural limitation of this project's data (see each phase's own
ENGINEERING_LOG.md entries), not a guess.

Why deterministic: an LLM asked "what evidence is missing" with no
grounding will produce generic, plausible-sounding gaps that may or may
not reflect what the system actually has access to. Since this is meant
to tell an investigator where to look next, it needs to be an accurate
reflection of this system's real data boundary, not a plausible-sounding
guess.
"""

# Every gap here is a genuine, structural limitation of this project's
# data model -- not invented for the demo. Each is tagged with which
# case types it applies to, since not every gap is relevant to every case.
GAP_CATALOG = [
    {
        "id": "kyc_identity",
        "text": "No KYC/identity verification data — this system has no field for verified legal identity, "
                "so 'shared device' and 'shared account' cannot be distinguished from 'shared household' "
                "without an external identity check.",
        "applies_when": lambda case: case["fraudar"] in ("HIGH", "LOW"),
    },
    {
        "id": "device_history_window",
        "text": "Device/IP history is a point-in-time snapshot, not a rolling history — FRAUDAR's signal "
                "reflects current device-sharing structure only; whether this sharing pattern is new or "
                "months old is not established.",
        "applies_when": lambda case: case["fraudar"] != "N/A",
    },
    {
        "id": "prior_sar",
        "text": "No prior regulatory filing (SAR/STR) linkage — this system does not check whether any "
                "account in this case has been previously reported to a regulator.",
        "applies_when": lambda case: True,
    },
    {
        "id": "merchant_side_verification",
        "text": "No merchant-side dispute resolution outcome — CopyCatch flags coordinated chargeback timing, "
                "but this system does not know whether the merchant contested or accepted any of these "
                "chargebacks, which would materially change the read.",
        "applies_when": lambda case: case["copycatch"] != "N/A",
    },
    {
        "id": "beneficiary_kyc",
        "text": "No downstream beneficiary verification — FlowScope traces a circular flow's structure and "
                "timing, but does not verify whether the terminal accounts in the cycle are themselves "
                "registered, legitimate merchants or further unverified pass-throughs.",
        "applies_when": lambda case: case["flowscope"] != "N/A",
    },
    {
        "id": "cross_case_linkage",
        "text": "No account-level case history — this system evaluates each case independently; whether any "
                "of these specific accounts appeared in a prior case (this system's own or a different one) "
                "is not automatically checked. (Partially addressed by the similar-cases comparison below, "
                "which matches on pattern similarity, not shared account identity.)",
        "applies_when": lambda case: True,
    },
    {
        "id": "adaptation_baseline",
        "text": "No adaptation baseline for this specific ring — the adaptation indicator requires a real "
                "'before' snapshot of the same ring lineage; without one, NONE means 'no temporal data "
                "available,' not 'confirmed no adaptation occurred.'",
        "applies_when": lambda case: case["adaptation_indicator"] == "NONE",
    },
]


def identify_evidence_gaps(case):
    """Returns the list of applicable gap descriptions for a case, in a
    fixed order. Pure function of the case's signal state -- same case,
    same gaps, every time."""
    return [g["text"] for g in GAP_CATALOG if g["applies_when"](case)]
