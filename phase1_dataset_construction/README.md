# Phase 1: Dataset Construction

## What this phase does

Builds a synthetic payments dataset: a realistic base population of merchants and customers with naturally-occurring (non-fraudulent) device/IP sharing, ~45,000+ legitimate transactions over 90 days, and 21 injected fraud rings across 3 archetypes × 3 camouflage difficulty tiers, with ground truth kept in a separate file for honest evaluation.

**Why a custom generator, not a public dataset:** No single public fraud dataset provides all three structural signals our archetypes need at once (device/IP sharing fields, multi-hop money-flow topology, fine-grained timestamps). **Why not a GAN-based generator (CTGAN/TVAE):** research shows these fail to preserve the exact temporal-burst and shared-infrastructure signals fraud detection depends on, because they optimize for overall statistical distribution fidelity, not these structurally rare patterns. See `docs/PROJECT_DOCUMENTATION.md` §3.3 and §5 for the full reasoning.

## Run it

```bash
python3 generate_dataset.py --seed 42 --out ./output
```

Fully parametrized (ring counts, camouflage intensity, population scale — see `RING_PLAN` and `CAMOUFLAGE_PARAMS` in the script). Rerun with a different `--seed` to produce an independent held-out test set.

## Output files (in `./output/`)

| File | Contents |
|---|---|
| `accounts.csv` | account_id, account_type, created_date, bank_account_id |
| `account_device_map.csv` | account_id ↔ device_id, including realistic legitimate overlap |
| `account_ip_map.csv` | account_id ↔ ip_id |
| `transactions.csv` | txn_id, timestamp, src_account, dst_account, amount, txn_type, device_id, ip_id |
| `ground_truth.csv` | **Held out — do not feed into any detector.** ring_id, ring_type, camouflage_level, account_id |

## The three archetypes

1. `shared_infra_promo_abuse` — accounts sharing a small device/IP pool. Density signal. (Phase 2 target.)
2. `circular_flow_laundering` — money cycling through a chain of accounts, shrinking per hop. Flow signal. (Planned Phase 3.)
3. `lockstep_chargeback_ring` — accounts filing disputes within a tight time window. Temporal signal. (Planned Phase 3.)

## Known limitation, stated directly

Camouflage is rule-based, not adversarial — it dilutes a specific signal (merchant-transaction diversity, device/IP popularity) by design, so we know exactly what it's testing. It won't capture every real-world evasion strategy. See `ENGINEERING_LOG.md` in the repo root for two real bugs found and fixed in this camouflage mechanism during development.
