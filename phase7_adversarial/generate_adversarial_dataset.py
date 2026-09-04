"""
Phase 7: Adversarial Dataset Generator
------------------------------------------
Extends phase1's DatasetBuilder with four adaptive attacks, each crafted
with knowledge of how our own detectors work -- this is the actual point:
not "harder camouflage" in the abstract, but camouflage specifically
targeted at each detector's known decision mechanism.

    Attack 1 (FRAUDAR):  camouflage through popular legitimate devices/IPs,
                          pushed further than the baseline "hard" tier --
                          an attacker who has seen our mean-edge-weight
                          scoring would add MORE popular-entity edges,
                          specifically enough to try to push their score
                          above our flagging threshold.
    Attack 2 (CopyCatch): coordinated timing widened well past our tested
                          detection window range, so the lockstep
                          coordination still exists but is spread thin
                          enough that no single time window captures
                          enough participants.
    Attack 3 (FlowScope): a real structural evasion, not an additive one
                          (unlike the baseline "hard" tier's reroute,
                          which we already found doesn't actually break
                          the cycle -- see ENGINEERING_LOG.md Entry 8).
                          The final hop is replaced by two hops through a
                          genuine-looking legitimate intermediary, with a
                          multi-day delay inserted at that hop -- the
                          money-flow cycle still exists, but its total
                          time span blows past any reasonable
                          "fast layering" time-window check.
    Attack 4 (Cross-detector): a single ring carrying TWO simultaneously
                          weakened signals (borderline shared-device
                          sharing AND borderline lockstep timing), each
                          individually calibrated to sit just below what
                          a single detector would flag alone -- testing
                          whether the system's per-detector-then-union
                          architecture has a blind spot for fraud that
                          only becomes obvious when two weak signals are
                          considered together.

Ground truth gets two new columns: is_adversarial, attack_id. Existing
columns (ring_id, ring_type, camouflage_level, account_id) are unchanged,
so phases 2-6's code (which reads by column name via DictReader) runs
against this dataset completely unmodified.

Usage:
    python3 generate_adversarial_dataset.py --seed 42 --out ./adversarial_output
"""

import argparse
import os
import random
import sys
from datetime import timedelta

import numpy as np

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "phase1_dataset_construction"))
from generate_dataset import DatasetBuilder, rand_id, rand_timestamp, START_DATE, SIM_DAYS


class AdversarialDatasetBuilder(DatasetBuilder):

    # ------------------------------------------------------------
    # Attack 1: FRAUDAR -- escalated, targeted camouflage
    # ------------------------------------------------------------
    def inject_attack1_fraudar_camouflage(self):
        ring_id = "attack1_fraudar_camouflage"
        ring_size = 10
        members = self._new_ring_accounts(ring_size, "customer")
        shared_devices = [rand_id("dev") for _ in range(2)]
        shared_ips = [rand_id("ip") for _ in range(2)]
        target_merchant = random.choice(self._merchants)

        for m in members:
            self.account_devices.append((m, random.choice(shared_devices)))
            self.account_ips.append((m, random.choice(shared_ips)))

            # ESCALATED beyond baseline "hard" tier (which used up to 2
            # popular-entity edges) -- an adaptive attacker who has seen
            # our mean-edge-weight scoring adds more of them, specifically
            # trying to drag the account's average weight up past our
            # flagging threshold, not just "some" dilution
            if self._popular_devices:
                for pd in random.sample(self._popular_devices, k=min(8, len(self._popular_devices))):
                    self.account_devices.append((m, pd))
            if self._popular_ips:
                for pi in random.sample(self._popular_ips, k=min(8, len(self._popular_ips))):
                    self.account_ips.append((m, pi))

            for _ in range(3):
                ts = rand_timestamp(START_DATE)
                self.transactions.append({
                    "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                    "src_account": m, "dst_account": target_merchant,
                    "amount": round(np.random.uniform(50, 500), 2), "txn_type": "payment",
                    "device_id": random.choice(shared_devices), "ip_id": random.choice(shared_ips),
                })

            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "shared_infra_promo_abuse",
                "camouflage_level": "adversarial", "account_id": m,
                "is_adversarial": True, "attack_id": "attack1_fraudar_camouflage",
            })

    # ------------------------------------------------------------
    # Attack 1b: FRAUDAR -- the CORRECTED adaptive attack
    # ------------------------------------------------------------
    # Attack 1 above (popular-entity spam) turned out to backfire against
    # our actual mean-based, below-baseline scorer: since popular entities
    # get LOW weight under 1/log(degree+2), adding more of them drags an
    # account's MEAN weight DOWN, making it MORE suspicious, not less --
    # see ENGINEERING_LOG.md Entry 12. That attack targeted a SUM-based
    # scoring vulnerability we deliberately fixed away from in Phase 2
    # Entry 5. This is the attack that actually threatens the real
    # (mean-based) defense: pairing each ring member with a handful of
    # fresh, one-off "decoy" accounts on brand-new shared devices creates
    # degree-2 entities -- the SAME statistical pattern that gives honest
    # accounts their high baseline weight (~0.64, per Phase 2's own
    # findings) -- specifically to pull the ring member's mean UP toward
    # the honest population's average, not just add noise.
    def inject_attack1b_fraudar_camouflage_corrected(self):
        ring_id = "attack1b_fraudar_corrected"
        ring_size = 10
        members = self._new_ring_accounts(ring_size, "customer")
        shared_devices = [rand_id("dev") for _ in range(2)]
        shared_ips = [rand_id("ip") for _ in range(2)]
        target_merchant = random.choice(self._merchants)

        for m in members:
            self.account_devices.append((m, random.choice(shared_devices)))
            self.account_ips.append((m, random.choice(shared_ips)))

            # CORRECTED camouflage: pair with fresh decoy accounts on new
            # degree-2 devices/IPs -- mimics the exact pattern that gives
            # honest accounts their high mean weight, rather than diluting
            # via already-popular (low-weight) entities
            n_pairs = 4
            for _ in range(n_pairs):
                decoy = rand_id("customer")
                self.accounts.append({
                    "account_id": decoy, "account_type": "customer",
                    "created_date": START_DATE.date().isoformat(), "bank_account_id": rand_id("bank"),
                })
                pair_device = rand_id("dev")
                pair_ip = rand_id("ip")
                self.account_devices.append((m, pair_device))
                self.account_devices.append((decoy, pair_device))
                self.account_ips.append((m, pair_ip))
                self.account_ips.append((decoy, pair_ip))

            for _ in range(3):
                ts = rand_timestamp(START_DATE)
                self.transactions.append({
                    "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                    "src_account": m, "dst_account": target_merchant,
                    "amount": round(np.random.uniform(50, 500), 2), "txn_type": "payment",
                    "device_id": random.choice(shared_devices), "ip_id": random.choice(shared_ips),
                })

            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "shared_infra_promo_abuse",
                "camouflage_level": "adversarial", "account_id": m,
                "is_adversarial": True, "attack_id": "attack1b_fraudar_corrected",
            })

    # ------------------------------------------------------------
    # Attack 2: CopyCatch -- extreme timing jitter
    # ------------------------------------------------------------
    def inject_attack2_copycatch_jitter(self):
        ring_id = "attack2_copycatch_jitter"
        ring_size = 9
        members = self._new_ring_accounts(ring_size, "customer")
        target_merchant = random.choice(self._merchants)
        EXTREME_JITTER_MIN = 150  # far past baseline "hard" (45) and past any tested detection window (max 60)

        for _ in range(3):
            event_time = rand_timestamp(START_DATE, day_span_days=SIM_DAYS - 2)
            participants = random.sample(members, k=random.randint(6, ring_size))
            for m in participants:
                jitter = random.uniform(-EXTREME_JITTER_MIN, EXTREME_JITTER_MIN)
                ts = event_time + timedelta(minutes=jitter)
                self.transactions.append({
                    "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                    "src_account": target_merchant, "dst_account": m,
                    "amount": round(np.random.uniform(300, 3000), 2), "txn_type": "chargeback",
                    "device_id": rand_id("dev"), "ip_id": rand_id("ip"),
                })

        for m in members:
            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "lockstep_chargeback_ring",
                "camouflage_level": "adversarial", "account_id": m,
                "is_adversarial": True, "attack_id": "attack2_copycatch_jitter",
            })

    # ------------------------------------------------------------
    # Attack 2b: CopyCatch -- deliberately spaced timing (the CORRECTED
    # adaptive attack)
    # ------------------------------------------------------------
    # Attack 2 above (uniform random jitter across a wide window) did NOT
    # evade detection -- checking why revealed that our merge-overlapping-
    # windows step can chain adjacent flagged sub-windows together into a
    # much wider effective span than the nominal window parameter (a
    # 60-minute window setting still caught a 147-minute-wide cluster by
    # daisy-chaining overlapping sub-windows). See ENGINEERING_LOG.md
    # Entry 12. This is the attack that actually threatens that chaining
    # mechanism: instead of random jitter (which clusters some pairs close
    # together purely by chance), deliberately space every participant's
    # timestamp so NO two participants are ever within the window of each
    # other -- preventing any pairwise adjacency the merge step could ever
    # chain across.
    def inject_attack2b_copycatch_spaced(self):
        ring_id = "attack2b_copycatch_spaced"
        ring_size = 8
        members = self._new_ring_accounts(ring_size, "customer")
        target_merchant = random.choice(self._merchants)
        MIN_GAP_MINUTES = 90  # exceeds every window width we test (max 60)

        base_time = rand_timestamp(START_DATE, day_span_days=SIM_DAYS - 5)
        for i, m in enumerate(members):
            ts = base_time + timedelta(minutes=MIN_GAP_MINUTES * i)
            self.transactions.append({
                "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                "src_account": target_merchant, "dst_account": m,
                "amount": round(np.random.uniform(300, 3000), 2), "txn_type": "chargeback",
                "device_id": rand_id("dev"), "ip_id": rand_id("ip"),
            })

        for m in members:
            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "lockstep_chargeback_ring",
                "camouflage_level": "adversarial", "account_id": m,
                "is_adversarial": True, "attack_id": "attack2b_copycatch_spaced",
            })

    # ------------------------------------------------------------
    # Attack 3: FlowScope -- real structural evasion via a delayed,
    # genuinely-legitimate-looking intermediary hop
    # ------------------------------------------------------------
    def inject_attack3_flowscope_delay(self):
        ring_id = "attack3_flowscope_delay"
        chain_len = 5
        members = self._new_ring_accounts(chain_len, "merchant")
        legit_intermediate = random.choice(self._merchants)
        entry_amount = round(np.random.uniform(5000, 25000), 2)
        current_amount = entry_amount
        base_time = rand_timestamp(START_DATE, day_span_days=SIM_DAYS - 10)

        for hop_i in range(chain_len - 1):
            src, dst = members[hop_i], members[hop_i + 1]
            current_amount = round(current_amount * random.uniform(0.90, 0.97), 2)
            ts = base_time + timedelta(minutes=5 * hop_i)
            self.transactions.append({
                "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                "src_account": src, "dst_account": dst, "amount": current_amount,
                "txn_type": "payment" if hop_i % 2 == 0 else "refund",
                "device_id": rand_id("dev"), "ip_id": rand_id("ip"),
            })

        # final leg REPLACED by two hops through a legitimate-looking
        # intermediary, with a multi-day delay inserted -- the cycle still
        # exists structurally, but its time span now blows past any
        # "fast layering" window check
        ts1 = base_time + timedelta(minutes=5 * (chain_len - 1))
        amt1 = round(current_amount * random.uniform(0.90, 0.97), 2)
        self.transactions.append({
            "txn_id": rand_id("txn"), "timestamp": ts1.isoformat(),
            "src_account": members[-1], "dst_account": legit_intermediate, "amount": amt1,
            "txn_type": "payment", "device_id": rand_id("dev"), "ip_id": rand_id("ip"),
        })
        ts2 = ts1 + timedelta(days=3, minutes=10)
        amt2 = round(amt1 * random.uniform(0.90, 0.97), 2)
        self.transactions.append({
            "txn_id": rand_id("txn"), "timestamp": ts2.isoformat(),
            "src_account": legit_intermediate, "dst_account": members[0], "amount": amt2,
            "txn_type": "payment", "device_id": rand_id("dev"), "ip_id": rand_id("ip"),
        })

        for m in members:
            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "circular_flow_laundering",
                "camouflage_level": "adversarial", "account_id": m,
                "is_adversarial": True, "attack_id": "attack3_flowscope_delay",
            })

    # ------------------------------------------------------------
    # Attack 4: cross-detector -- two simultaneously weakened signals,
    # each individually sub-threshold. Uses the CORRECTED (paired-decoy)
    # camouflage mechanism from Attack 1b for its device-sharing
    # component, at reduced strength -- using the naive popular-entity
    # version here would be pointless, since we already found that
    # backfires against our mean-based scorer regardless of magnitude.
    # ------------------------------------------------------------
    def inject_attack4_cross_detector(self):
        ring_id = "attack4_cross_detector"
        ring_size = 7
        members = self._new_ring_accounts(ring_size, "customer")
        shared_devices = [rand_id("dev") for _ in range(2)]
        target_merchant = random.choice(self._merchants)

        # WEAK shared-device signal: small pool, PLUS a reduced dose (2
        # pairs, vs attack1b's 4) of the corrected paired-decoy technique
        # -- individually calibrated to be less complete than attack1b's
        # full evasion, testing the borderline
        for m in members:
            self.account_devices.append((m, random.choice(shared_devices)))
            for _ in range(2):
                decoy = rand_id("customer")
                self.accounts.append({
                    "account_id": decoy, "account_type": "customer",
                    "created_date": START_DATE.date().isoformat(), "bank_account_id": rand_id("bank"),
                })
                pair_device = rand_id("dev")
                self.account_devices.append((m, pair_device))
                self.account_devices.append((decoy, pair_device))
            for _ in range(2):
                ts = rand_timestamp(START_DATE)
                self.transactions.append({
                    "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                    "src_account": m, "dst_account": target_merchant,
                    "amount": round(np.random.uniform(50, 500), 2), "txn_type": "payment",
                    "device_id": random.choice(shared_devices), "ip_id": rand_id("ip"),
                })

        # WEAK lockstep timing signal: partially spaced (50 min gaps --
        # more than natural clustering, less than attack2b's full 90 min
        # evasion gap) so pairs of adjacent participants sometimes still
        # fall inside a 60-min window and sometimes don't
        base_time = rand_timestamp(START_DATE, day_span_days=SIM_DAYS - 2)
        for i, m in enumerate(members):
            ts = base_time + timedelta(minutes=50 * i)
            self.transactions.append({
                "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                "src_account": target_merchant, "dst_account": m,
                "amount": round(np.random.uniform(300, 3000), 2), "txn_type": "chargeback",
                "device_id": rand_id("dev"), "ip_id": rand_id("ip"),
            })

        for m in members:
            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "cross_detector_hybrid",
                "camouflage_level": "adversarial", "account_id": m,
                "is_adversarial": True, "attack_id": "attack4_cross_detector",
            })

    def inject_all_attacks(self):
        self.inject_attack1_fraudar_camouflage()
        self.inject_attack1b_fraudar_camouflage_corrected()
        self.inject_attack2_copycatch_jitter()
        self.inject_attack2b_copycatch_spaced()
        self.inject_attack3_flowscope_delay()
        self.inject_attack4_cross_detector()

    def write(self, out_dir):
        # backfill is_adversarial/attack_id on the ORIGINAL 21 rings' ground
        # truth rows (added before this subclass existed), so every row has
        # the same schema regardless of which pipeline version created it
        for row in self.ground_truth:
            row.setdefault("is_adversarial", False)
            row.setdefault("attack_id", "")
        super().write(out_dir)

    @staticmethod
    def _write_csv(path, rows, fieldnames):
        if "ground_truth" in path:
            fieldnames = ["ring_id", "ring_type", "camouflage_level", "account_id",
                          "is_adversarial", "attack_id"]
        DatasetBuilder._write_csv(path, rows, fieldnames)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=str, default="./adversarial_output")
    args = parser.parse_args()

    builder = AdversarialDatasetBuilder(seed=args.seed)
    builder.build_base_population()
    builder.build_legit_transactions()
    builder.build_organic_chargebacks()
    builder.inject_rings()          # original 21 baseline rings
    builder.inject_all_attacks()    # + 4 adversarial rings
    builder.write(args.out)

    n_rings = len(set(r["ring_id"] for r in builder.ground_truth))
    n_adversarial = sum(1 for r in builder.ground_truth if r["is_adversarial"])
    print(f"Accounts:      {len(builder.accounts)}")
    print(f"Transactions:  {len(builder.transactions)}")
    n_attack_rings = n_rings - 21
    print(f"Total rings:   {n_rings}  (21 baseline + {n_attack_rings} adversarial)")
    print(f"Adversarial accounts: {n_adversarial}")
    print(f"Output written to: {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
