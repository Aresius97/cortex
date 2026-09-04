"""
Synthetic Payments Fraud-Ring Dataset Generator
------------------------------------------------
Builds a realistic-looking base population of merchants/customers with
accounts, devices, IPs and bank accounts, generates ~90 days of legitimate
transaction traffic (including realistic, NON-fraudulent sharing of
devices/IPs -- e.g. office networks, family members, shared payment
terminals), then injects three ring archetypes on top at varying
"camouflage" levels:

    1. shared_infra_promo_abuse   -> density signal   (catch with FRAUDAR-style scoring)
    2. circular_flow_laundering   -> flow signal       (catch with FlowScope-style tracing)
    3. lockstep_chargeback_ring   -> temporal signal    (catch with CopyCatch-style clustering)

Ground truth (ring_id, ring_type, camouflage_level, member list) is written
to a SEPARATE file (ground_truth.csv) that must NOT be fed to your detector.
Use it only at evaluation time to compute precision/recall/cost curves.

Output files (all in ./output/):
    accounts.csv          - account_id, account_type, created_date, bank_account_id
    devices.csv            - device_id -> nothing else, just an id pool
    account_device_map.csv - account_id, device_id  (many-to-many; legit accounts
                              usually have 1, sometimes 2 devices; some legit
                              sharing exists e.g. family/office)
    account_ip_map.csv     - account_id, ip_id       (same idea for IPs)
    transactions.csv       - txn_id, timestamp, src_account, dst_account,
                              amount, txn_type, device_id, ip_id
    ground_truth.csv       - HELD OUT. ring_id, ring_type, camouflage_level,
                              account_id (one row per member account)

Run:
    python3 generate_dataset.py --seed 42 --out ./output
"""

import argparse
import csv
import os
import random
import uuid
from datetime import datetime, timedelta

import numpy as np


# ----------------------------------------------------------------------
# Config
# ----------------------------------------------------------------------

N_MERCHANTS = 400
N_CUSTOMERS = 1600
N_LEGIT_TXN = 45000
SIM_DAYS = 90
START_DATE = datetime(2026, 5, 1)

# Ring archetype counts, split across easy / medium / hard (camouflage level)
RING_PLAN = {
    "shared_infra_promo_abuse": [
        ("easy", 3), ("medium", 3), ("hard", 2),
    ],
    "circular_flow_laundering": [
        ("easy", 2), ("medium", 2), ("hard", 2),
    ],
    "lockstep_chargeback_ring": [
        ("easy", 3), ("medium", 2), ("hard", 2),
    ],
}

CAMOUFLAGE_PARAMS = {
    # filler_frac / timing_jitter_min: generic noise (volume + time spread)
    # camouflage_edge_rate: fraction of ring members that additionally get
    #   edges toward ALREADY-POPULAR legitimate merchants, using a personal
    #   (non-shared) device/ip -- this is the TRUE camouflage mechanism per
    #   FRAUDAR: edges to high-degree honest targets, not random noise.
    # camouflage_edges_per_member: how many such targeted edges each
    #   camouflaged member gets.
    # NOTE on magnitudes: honest customers average ~25-26 distinct
    # merchants transacted with over the 90-day window (verified
    # empirically -- see README). For camouflage to be a real test of a
    # detector rather than a token gesture, hard-tier ring members need
    # camouflage-edge counts in the SAME ORDER OF MAGNITUDE as that honest
    # baseline, not a handful of extra edges.
    "easy":   {"filler_frac": 0.05, "timing_jitter_min": 2,
               "camouflage_edge_rate": 0.0,  "camouflage_edges_per_member": 0},
    "medium": {"filler_frac": 0.15, "timing_jitter_min": 15,
               "camouflage_edge_rate": 0.6,  "camouflage_edges_per_member": 10},
    "hard":   {"filler_frac": 0.25, "timing_jitter_min": 45,
               "camouflage_edge_rate": 0.9,  "camouflage_edges_per_member": 22},
}


def rand_id(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:10]}"


def rand_timestamp(day_start, day_span_days=SIM_DAYS):
    offset_seconds = random.uniform(0, day_span_days * 86400)
    return day_start + timedelta(seconds=offset_seconds)


class DatasetBuilder:
    def __init__(self, seed=42):
        random.seed(seed)
        np.random.seed(seed)

        self.accounts = []          # list of dicts
        self.devices = set()
        self.ips = set()
        self.account_devices = []   # (account_id, device_id)
        self.account_ips = []       # (account_id, ip_id)
        self.transactions = []      # list of dicts
        self.ground_truth = []      # list of dicts

        self._device_pool = []
        self._ip_pool = []

    # ------------------------------------------------------------------
    # Base population: accounts, devices, ips, with REALISTIC legit sharing
    # ------------------------------------------------------------------
    def build_base_population(self):
        # device / ip pools sized so that a small amount of natural overlap
        # occurs (families, offices, shared merchant terminals) without it
        # being anomalous
        n_devices = int((N_MERCHANTS + N_CUSTOMERS) * 0.85)
        n_ips = int((N_MERCHANTS + N_CUSTOMERS) * 0.75)
        self._device_pool = [rand_id("dev") for _ in range(n_devices)]
        self._ip_pool = [rand_id("ip") for _ in range(n_ips)]

        for i in range(N_MERCHANTS):
            acc_id = rand_id("merchant")
            created = START_DATE - timedelta(days=random.randint(30, 900))
            bank_id = rand_id("bank")
            self.accounts.append({
                "account_id": acc_id,
                "account_type": "merchant",
                "created_date": created.date().isoformat(),
                "bank_account_id": bank_id,
            })
            self._assign_devices_ips(acc_id, is_merchant=True)

        for i in range(N_CUSTOMERS):
            acc_id = rand_id("customer")
            created = START_DATE - timedelta(days=random.randint(1, 700))
            bank_id = rand_id("bank")
            self.accounts.append({
                "account_id": acc_id,
                "account_type": "customer",
                "created_date": created.date().isoformat(),
                "bank_account_id": bank_id,
            })
            self._assign_devices_ips(acc_id, is_merchant=False)

    def _assign_devices_ips(self, acc_id, is_merchant):
        # merchants: usually 1-3 devices (POS terminals / checkout integrations)
        # customers: usually 1, occasionally 2 (phone + laptop)
        n_dev = np.random.choice([1, 2, 3], p=[0.7, 0.22, 0.08]) if is_merchant else \
                np.random.choice([1, 2], p=[0.85, 0.15])
        n_ip = np.random.choice([1, 2], p=[0.8, 0.2])

        for _ in range(n_dev):
            dev = random.choice(self._device_pool)  # sampling WITH replacement
            self.account_devices.append((acc_id, dev))                  # -> natural, legit overlap
        for _ in range(n_ip):
            ip = random.choice(self._ip_pool)
            self.account_ips.append((acc_id, ip))

    # ------------------------------------------------------------------
    # Legitimate transaction traffic
    # ------------------------------------------------------------------
    def build_legit_transactions(self):
        merchants = [a["account_id"] for a in self.accounts if a["account_type"] == "merchant"]
        customers = [a["account_id"] for a in self.accounts if a["account_type"] == "customer"]

        acc_to_dev = self._acc_to_list(self.account_devices)
        acc_to_ip = self._acc_to_list(self.account_ips)

        for _ in range(N_LEGIT_TXN):
            cust = random.choice(customers)
            merch = random.choice(merchants)
            ts = rand_timestamp(START_DATE)
            amount = round(np.random.lognormal(mean=6.0, sigma=1.0), 2)  # skewed, realistic
            txn_type = np.random.choice(
                ["payment", "refund"], p=[0.94, 0.06]
            )
            dev = random.choice(acc_to_dev.get(cust, [rand_id("dev")]))
            ip = random.choice(acc_to_ip.get(cust, [rand_id("ip")]))

            self.transactions.append({
                "txn_id": rand_id("txn"),
                "timestamp": ts.isoformat(),
                "src_account": cust if txn_type == "payment" else merch,
                "dst_account": merch if txn_type == "payment" else cust,
                "amount": amount,
                "txn_type": txn_type,
                "device_id": dev,
                "ip_id": ip,
            })

        self._merchants = merchants
        self._customers = customers
        self._acc_to_dev = acc_to_dev
        self._acc_to_ip = acc_to_ip

        # --- popularity index for TRUE camouflage targeting -------------
        # FRAUDAR's actual guarantee is about fraud accounts adding edges
        # to already-popular, high-degree HONEST targets -- that's what
        # lets a dense fraud block's average suspiciousness score blend
        # into the honest baseline. Generic random-merchant filler traffic
        # does NOT exploit this; only edges to *already popular* nodes do,
        # because that's where honest accounts' density is naturally high
        # too. Compute merchant popularity from the legit traffic only.
        degree = {}
        for t in self.transactions:
            m = t["dst_account"] if t["src_account"] in self._customers else t["src_account"]
            degree[m] = degree.get(m, 0) + 1
        ranked = sorted(merchants, key=lambda m: degree.get(m, 0), reverse=True)
        cutoff = max(1, int(len(ranked) * 0.20))
        self._popular_merchants = ranked[:cutoff]      # top 20% by degree
        self._long_tail_merchants = ranked[cutoff:]     # everything else

        # --- popularity index for the DEVICE/IP graph specifically -------
        # The merchant-camouflage above only fools a detector that looks at
        # account-merchant transaction patterns. FRAUDAR's primary target
        # here is the account<->device/ip SHARING graph, which is a
        # different graph entirely -- edges toward popular merchants do
        # nothing to it. For camouflage to actually test FRAUDAR, ring
        # members need edges toward already-popular DEVICES/IPS (e.g. a
        # widely-shared public wifi gateway), computed from the honest
        # baseline population only.
        dev_degree, ip_degree = {}, {}
        for acc, dev in self.account_devices:
            dev_degree[dev] = dev_degree.get(dev, 0) + 1
        for acc, ip in self.account_ips:
            ip_degree[ip] = ip_degree.get(ip, 0) + 1
        dev_ranked = sorted(dev_degree, key=lambda d: dev_degree[d], reverse=True)
        ip_ranked = sorted(ip_degree, key=lambda i: ip_degree[i], reverse=True)
        self._popular_devices = dev_ranked[:max(1, int(len(dev_ranked) * 0.10))]
        self._popular_ips = ip_ranked[:max(1, int(len(ip_ranked) * 0.10))]

    @staticmethod
    def _acc_to_list(pairs):
        d = {}
        for acc, val in pairs:
            d.setdefault(acc, []).append(val)
        return d

    def build_organic_chargebacks(self, n_organic=250):
        """Independent, uncorrelated chargebacks from individual dissatisfied
        customers -- no ring, no coordination, random timing. Without this,
        every chargeback in the dataset comes from an injected lockstep
        ring, which would make any chargeback-clustering detector score
        trivially perfectly (there'd be no legitimate noise to separate
        signal from). Sized comparably to the ring-injected chargeback
        volume so the detector has a real background to filter through."""
        for _ in range(n_organic):
            cust = random.choice(self._customers)
            merch = random.choice(self._merchants)
            ts = rand_timestamp(START_DATE)
            amount = round(np.random.uniform(200, 4000), 2)
            self.transactions.append({
                "txn_id": rand_id("txn"),
                "timestamp": ts.isoformat(),
                "src_account": merch,
                "dst_account": cust,
                "amount": amount,
                "txn_type": "chargeback",
                "device_id": rand_id("dev"),
                "ip_id": rand_id("ip"),
            })

    # ------------------------------------------------------------------
    # Ring injection
    # ------------------------------------------------------------------
    def inject_rings(self):
        for ring_type, plan in RING_PLAN.items():
            for camo_level, count in plan:
                for _ in range(count):
                    ring_id = rand_id("ring")
                    if ring_type == "shared_infra_promo_abuse":
                        self._inject_shared_infra_ring(ring_id, camo_level)
                    elif ring_type == "circular_flow_laundering":
                        self._inject_circular_flow_ring(ring_id, camo_level)
                    elif ring_type == "lockstep_chargeback_ring":
                        self._inject_lockstep_ring(ring_id, camo_level)

    def _new_ring_accounts(self, n, account_type="customer"):
        """Create n brand-new accounts to serve as ring members."""
        members = []
        for _ in range(n):
            acc_id = rand_id(account_type)
            created = START_DATE - timedelta(days=random.randint(0, 20))  # newly created, a real fraud tell
            bank_id = rand_id("bank")
            self.accounts.append({
                "account_id": acc_id,
                "account_type": account_type,
                "created_date": created.date().isoformat(),
                "bank_account_id": bank_id,
            })
            members.append(acc_id)
        return members

    # ---- Archetype 1: shared-infrastructure promo-abuse ring ----------
    def _inject_shared_infra_ring(self, ring_id, camo_level):
        params = CAMOUFLAGE_PARAMS[camo_level]
        ring_size = random.randint(6, 14)
        members = self._new_ring_accounts(ring_size, "customer")

        # core signal: ring shares a SMALL pool of devices/ips/bank accounts
        n_shared_devices = max(1, int(ring_size * (0.15 if camo_level == "hard" else 0.3)))
        n_shared_ips = max(1, int(ring_size * (0.2 if camo_level == "hard" else 0.35)))
        shared_devices = [rand_id("dev") for _ in range(n_shared_devices)]
        shared_ips = [rand_id("ip") for _ in range(n_shared_ips)]
        target_merchant = random.choice(self._merchants)  # the promo/cashback target

        for m in members:
            # each member uses 1-2 of the small shared device/ip pool -> dense overlap
            for dev in random.sample(shared_devices, k=min(len(shared_devices), random.randint(1, 2))):
                self.account_devices.append((m, dev))
            for ip in random.sample(shared_ips, k=min(len(shared_ips), 1)):
                self.account_ips.append((m, ip))

            # light generic dilution: some members ALSO get a random "normal"
            # device/ip (separate from the targeted camouflage-edge mechanism
            # in _add_camouflage_edges, which is the true FRAUDAR-style signal)
            if random.random() < (params["camouflage_edge_rate"] * 0.3):
                self.account_devices.append((m, random.choice(self._device_pool)))
                self.account_ips.append((m, random.choice(self._ip_pool)))

            # TRUE device/IP-graph camouflage: connect to already-popular
            # devices/ips (computed from the honest baseline). This is what
            # actually dilutes this member's weighted density in the graph
            # FRAUDAR analyzes -- the merchant-camouflage in
            # _add_camouflage_edges does NOT touch this graph at all.
            if random.random() < params["camouflage_edge_rate"] and self._popular_devices:
                for pd in random.sample(self._popular_devices, k=min(2, len(self._popular_devices))):
                    self.account_devices.append((m, pd))
                for pi in random.sample(self._popular_ips, k=min(2, len(self._popular_ips))):
                    self.account_ips.append((m, pi))

            n_txns = random.randint(2, 5)
            for _ in range(n_txns):
                ts = rand_timestamp(START_DATE)
                amount = round(np.random.uniform(50, 500), 2)  # small promo-farming amounts
                dev_used = random.choice(shared_devices)
                ip_used = random.choice(shared_ips)
                self.transactions.append({
                    "txn_id": rand_id("txn"),
                    "timestamp": ts.isoformat(),
                    "src_account": m,
                    "dst_account": target_merchant,
                    "amount": amount,
                    "txn_type": "payment",
                    "device_id": dev_used,
                    "ip_id": ip_used,
                })

            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "shared_infra_promo_abuse",
                "camouflage_level": camo_level, "account_id": m,
            })

        # generic noise filler + TRUE targeted camouflage edges toward
        # already-popular legitimate merchants (the actual FRAUDAR mechanism)
        self._add_filler_transactions(members, params["filler_frac"])
        self._add_camouflage_edges(members, params)

    # ---- Archetype 2: circular-flow refund laundering ------------------
    def _inject_circular_flow_ring(self, ring_id, camo_level):
        params = CAMOUFLAGE_PARAMS[camo_level]
        chain_len = random.randint(4, 8)  # number of hops
        members = self._new_ring_accounts(chain_len, "merchant")
        entry_amount = round(np.random.uniform(5000, 25000), 2)

        current_amount = entry_amount
        base_time = rand_timestamp(START_DATE, day_span_days=SIM_DAYS - 5)
        for hop_i in range(len(members)):
            src = members[hop_i]
            dst = members[(hop_i + 1) % len(members)]  # wraps back to first -> circular
            # money shrinks slightly each hop (fees/skim) -- realistic laundering signature
            current_amount = round(current_amount * random.uniform(0.90, 0.97), 2)
            hop_delay_minutes = params["timing_jitter_min"] * random.uniform(0.5, 2.0) + hop_i * 5
            ts = base_time + timedelta(minutes=hop_delay_minutes)

            self.transactions.append({
                "txn_id": rand_id("txn"),
                "timestamp": ts.isoformat(),
                "src_account": src,
                "dst_account": dst,
                "amount": current_amount,
                "txn_type": "refund" if hop_i % 2 == 1 else "payment",
                "device_id": rand_id("dev"),
                "ip_id": rand_id("ip"),
            })

        # camouflage: reroute some hops through a legitimate-looking intermediate
        # merchant to break the "obvious" cycle if hard
        if camo_level == "hard":
            legit_intermediate = random.choice(self._merchants)
            src = members[0]
            ts = base_time + timedelta(minutes=random.uniform(5, 30))
            self.transactions.append({
                "txn_id": rand_id("txn"), "timestamp": ts.isoformat(),
                "src_account": src, "dst_account": legit_intermediate,
                "amount": round(entry_amount * 0.3, 2), "txn_type": "payment",
                "device_id": rand_id("dev"), "ip_id": rand_id("ip"),
            })

        for m in members:
            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "circular_flow_laundering",
                "camouflage_level": camo_level, "account_id": m,
            })

        self._add_filler_transactions(members, params["filler_frac"])
        self._add_camouflage_edges(members, params)

    # ---- Archetype 3: lockstep chargeback/dispute ring -----------------
    def _inject_lockstep_ring(self, ring_id, camo_level):
        params = CAMOUFLAGE_PARAMS[camo_level]
        ring_size = random.randint(5, 12)
        members = self._new_ring_accounts(ring_size, "customer")
        target_merchant = random.choice(self._merchants)

        # pick several "lockstep events": tight clusters of chargebacks/refunds
        n_events = random.randint(2, 4)
        for _ in range(n_events):
            event_time = rand_timestamp(START_DATE, day_span_days=SIM_DAYS - 2)
            window_minutes = params["timing_jitter_min"]  # bigger window = harder to detect
            participants = random.sample(members, k=random.randint(max(2, ring_size // 2), ring_size))

            for m in participants:
                jitter = random.uniform(-window_minutes, window_minutes)
                ts = event_time + timedelta(minutes=jitter)
                amount = round(np.random.uniform(300, 3000), 2)
                self.transactions.append({
                    "txn_id": rand_id("txn"),
                    "timestamp": ts.isoformat(),
                    "src_account": target_merchant,
                    "dst_account": m,
                    "amount": amount,
                    "txn_type": "chargeback",
                    "device_id": rand_id("dev"),
                    "ip_id": rand_id("ip"),
                })

        for m in members:
            self.ground_truth.append({
                "ring_id": ring_id, "ring_type": "lockstep_chargeback_ring",
                "camouflage_level": camo_level, "account_id": m,
            })

        self._add_filler_transactions(members, params["filler_frac"])
        self._add_camouflage_edges(members, params)

    def _add_camouflage_edges(self, members, params):
        """TRUE camouflage, per FRAUDAR: each targeted member gets extra
        transactions toward ALREADY-POPULAR legitimate merchants, using a
        fresh personal device/ip (not the ring's shared infrastructure).
        This is fundamentally different from filler noise -- it's a
        deliberate edge placed where the honest baseline density is
        already high, which is exactly what bounds a detector's ability
        to separate fraud density from honest density. Members who get
        camouflage edges are chosen at camouflage_edge_rate; each gets
        camouflage_edges_per_member such edges."""
        rate = params["camouflage_edge_rate"]
        n_edges = params["camouflage_edges_per_member"]
        if rate <= 0 or n_edges <= 0 or not self._popular_merchants:
            return
        camouflaged_members = [m for m in members if random.random() < rate]
        for m in camouflaged_members:
            targets = random.sample(
                self._popular_merchants,
                k=min(n_edges, len(self._popular_merchants))
            )
            for target in targets:
                ts = rand_timestamp(START_DATE)
                # realistic small-to-mid amount, personal (non-ring) device/ip
                amount = round(np.random.lognormal(mean=5.8, sigma=0.7), 2)
                self.transactions.append({
                    "txn_id": rand_id("txn"),
                    "timestamp": ts.isoformat(),
                    "src_account": m,
                    "dst_account": target,
                    "amount": amount,
                    "txn_type": "payment",
                    "device_id": rand_id("dev"),   # fresh, personal -- NOT shared ring infra
                    "ip_id": rand_id("ip"),
                })

    def _add_filler_transactions(self, members, filler_frac):
        """Add normal-looking, unrelated transactions for ring members to
        dilute their footprint (the core 'camouflage' mechanism)."""
        n_filler = int(len(members) * filler_frac * 3)
        for _ in range(n_filler):
            m = random.choice(members)
            other = random.choice(self._merchants if m.startswith("customer") or True else self._customers)
            ts = rand_timestamp(START_DATE)
            amount = round(np.random.lognormal(mean=5.5, sigma=0.8), 2)
            self.transactions.append({
                "txn_id": rand_id("txn"),
                "timestamp": ts.isoformat(),
                "src_account": m,
                "dst_account": other,
                "amount": amount,
                "txn_type": "payment",
                "device_id": random.choice(self._device_pool),
                "ip_id": random.choice(self._ip_pool),
            })

    # ------------------------------------------------------------------
    # Write output
    # ------------------------------------------------------------------
    def write(self, out_dir):
        os.makedirs(out_dir, exist_ok=True)

        self._write_csv(os.path.join(out_dir, "accounts.csv"),
                         self.accounts,
                         ["account_id", "account_type", "created_date", "bank_account_id"])

        dev_ip_rows = [{"account_id": a, "device_id": d} for a, d in self.account_devices]
        self._write_csv(os.path.join(out_dir, "account_device_map.csv"),
                         dev_ip_rows, ["account_id", "device_id"])

        ip_rows = [{"account_id": a, "ip_id": i} for a, i in self.account_ips]
        self._write_csv(os.path.join(out_dir, "account_ip_map.csv"),
                         ip_rows, ["account_id", "ip_id"])

        # shuffle transactions so they're not grouped by ring in file order
        random.shuffle(self.transactions)
        self._write_csv(os.path.join(out_dir, "transactions.csv"),
                         self.transactions,
                         ["txn_id", "timestamp", "src_account", "dst_account",
                          "amount", "txn_type", "device_id", "ip_id"])

        self._write_csv(os.path.join(out_dir, "ground_truth.csv"),
                         self.ground_truth,
                         ["ring_id", "ring_type", "camouflage_level", "account_id"])

    @staticmethod
    def _write_csv(path, rows, fieldnames):
        with open(path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(rows)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--out", type=str, default="./output")
    args = parser.parse_args()

    builder = DatasetBuilder(seed=args.seed)
    builder.build_base_population()
    builder.build_legit_transactions()
    builder.build_organic_chargebacks()
    builder.inject_rings()
    builder.write(args.out)

    n_rings = len(set(r["ring_id"] for r in builder.ground_truth))
    n_fraud_accounts = len(set(r["account_id"] for r in builder.ground_truth))
    print(f"Accounts:      {len(builder.accounts)}")
    print(f"Transactions:  {len(builder.transactions)}")
    print(f"Injected rings:{n_rings}  ({n_fraud_accounts} fraud accounts)")
    print(f"Output written to: {os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
