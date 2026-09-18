#!/usr/bin/env python3
"""Generate a balanced synthetic JSONL dataset for IDOR / aspiration classifier training."""
from __future__ import annotations

import argparse
import hashlib
import json
import random
from pathlib import Path

LABELS = ("normal", "legitim_sync", "sequential_enum", "data_aspiration")
LABEL_IDS = {n: i for i, n in enumerate(LABELS)}
TEMPLATES = (
    "/api/accounts/{id}",
    "/api/users/{id}",
    "/api/resources/{id}",
    "/api/vehicles/{id}",
)


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


def _sample(label: str, rng: random.Random) -> dict:
    auth = True
    tmpl = rng.choice(TEMPLATES)
    if label == "normal":
        distinct = rng.randint(1, 8)
        seq = rng.uniform(0.0, 0.25)
        focus = rng.uniform(0.1, 0.45)
        ok = rng.uniform(0.7, 1.0)
        forbid = _clamp(1.0 - ok + rng.uniform(-0.1, 0.1))
        req = rng.randint(5, 40)
        bytes_sum = rng.randint(10_000, 400_000)
        aspir = rng.uniform(0.05, 0.35)
        ids_pm = distinct / 3.0
        status = ",".join(rng.choices(["200", "304"], k=min(6, distinct)))
    elif label == "legitim_sync":
        distinct = rng.randint(8, 25)
        seq = rng.uniform(0.1, 0.4)
        focus = rng.uniform(0.4, 0.7)
        ok = rng.uniform(0.85, 1.0)
        forbid = rng.uniform(0.0, 0.15)
        req = rng.randint(20, 80)
        bytes_sum = rng.randint(200_000, 1_500_000)
        aspir = rng.uniform(0.25, 0.5)
        ids_pm = distinct / 2.0
        status = ",".join(["200"] * min(8, distinct))
    elif label == "sequential_enum":
        distinct = rng.randint(30, 120)
        seq = rng.uniform(0.65, 0.98)
        focus = rng.uniform(0.75, 0.98)
        # probing: more 403/404 mixed with some 200
        ok = rng.uniform(0.2, 0.55)
        forbid = _clamp(1.0 - ok)
        req = rng.randint(40, 200)
        bytes_sum = rng.randint(50_000, 800_000)
        aspir = rng.uniform(0.55, 0.85)
        ids_pm = distinct / 1.2
        status = ",".join(rng.choices(["200", "403", "404"], weights=[2, 4, 4], k=10))
    else:  # data_aspiration — authenticated dump that works (many 200s)
        distinct = rng.randint(40, 200)
        seq = rng.uniform(0.55, 0.95)
        focus = rng.uniform(0.8, 0.99)
        ok = rng.uniform(0.75, 0.99)
        forbid = rng.uniform(0.0, 0.15)
        req = rng.randint(50, 300)
        bytes_sum = rng.randint(2_000_000, 40_000_000)
        aspir = rng.uniform(0.65, 0.98)
        ids_pm = distinct / 1.0
        status = ",".join(["200"] * 10)

    features = {
        "distinct_object_ids": distinct,
        "sequential_ratio": round(seq, 4),
        "forbid_ratio": round(forbid, 4),
        "ok_ratio": round(ok, 4),
        "req_count": req,
        "response_bytes_sum": bytes_sum,
        "template_focus": round(focus, 4),
        "aspiration_score": round(aspir, 4),
        "path_template": tmpl,
        "status_seq": status,
        "ids_per_minute": round(ids_pm, 2),
    }
    uid = hashlib.sha256(f"{label}-{rng.random()}".encode()).hexdigest()[:16]
    score = int(aspir * 100)
    level = "high" if aspir >= 0.75 else "medium" if aspir >= 0.5 else "low" if aspir >= 0.3 else "none"
    return {
        "user_id_hash": uid,
        "auth_present": auth,
        "score": score,
        "level": level,
        "features": features,
        "label": label,
        "label_id": LABEL_IDS[label],
        "source": "synthetic",
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--n", type=int, default=2000, help="total samples (split evenly across labels)")
    ap.add_argument("--seed", type=int, default=42)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    per = max(1, args.n // len(LABELS))
    rows = []
    for label in LABELS:
        for _ in range(per):
            rows.append(_sample(label, rng))
    rng.shuffle(rows)

    args.out.parent.mkdir(parents=True, exist_ok=True)
    with args.out.open("w", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
    print(f"wrote {len(rows)} rows → {args.out}")


if __name__ == "__main__":
    main()
