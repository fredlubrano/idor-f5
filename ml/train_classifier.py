#!/usr/bin/env python3
"""Train an IDOR / aspiration classifier (sklearn or Hugging Face transformers)."""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.features_to_text import feature_vector, features_to_text  # noqa: E402

LABEL_ORDER = ("normal", "legitim_sync", "sequential_enum", "data_aspiration")
LABEL_TO_ID = {n: i for i, n in enumerate(LABEL_ORDER)}


def load_jsonl(path: Path) -> list[dict]:
    rows = []
    with path.open(encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            rows.append(json.loads(line))
    return rows


def resolve_label(row: dict) -> str:
    if "label" in row and row["label"] in LABEL_TO_ID:
        return row["label"]
    if "label_id" in row:
        return LABEL_ORDER[int(row["label_id"])]
    raise ValueError(f"row missing label: {row.keys()}")


def train_sklearn(train_rows: list[dict], out: Path, eval_rows: list[dict] | None, report: bool) -> None:
    try:
        import joblib
        import numpy as np
        from sklearn.ensemble import GradientBoostingClassifier
        from sklearn.metrics import classification_report, confusion_matrix
        from sklearn.pipeline import Pipeline
        from sklearn.preprocessing import StandardScaler
    except ImportError as e:
        raise SystemExit(
            "sklearn/joblib required: pip install -r ml/requirements-ml.txt\n" + str(e)
        ) from e

    def xy(rows: list[dict]):
        X = np.array(
            [feature_vector(r.get("features") or {}, auth_present=bool(r.get("auth_present", True)))
             for r in rows],
            dtype=float,
        )
        y = np.array([LABEL_TO_ID[resolve_label(r)] for r in rows], dtype=int)
        return X, y

    X, y = xy(train_rows)
    clf = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("gb", GradientBoostingClassifier(random_state=42)),
        ]
    )
    clf.fit(X, y)
    out.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "labels": list(LABEL_ORDER)}, out)
    print(f"saved sklearn model → {out}")

    if report or eval_rows:
        ev = eval_rows or train_rows
        Xe, ye = xy(ev)
        pred = clf.predict(Xe)
        print(classification_report(ye, pred, target_names=LABEL_ORDER, digits=3))
        print("confusion_matrix:\n", confusion_matrix(ye, pred))


def train_transformers(
    train_rows: list[dict],
    out: Path,
    model_name: str,
    push_to_hub: str | None,
    epochs: int,
) -> None:
    try:
        from datasets import Dataset
        from transformers import (
            AutoModelForSequenceClassification,
            AutoTokenizer,
            Trainer,
            TrainingArguments,
        )
    except ImportError as e:
        raise SystemExit(
            "transformers/datasets required for --backend transformers\n" + str(e)
        ) from e

    texts, labels = [], []
    for r in train_rows:
        texts.append(
            features_to_text(
                r.get("features") or {},
                auth_present=bool(r.get("auth_present", True)),
                path_template=(r.get("features") or {}).get("path_template"),
            )
        )
        labels.append(LABEL_TO_ID[resolve_label(r)])

    ds = Dataset.from_dict({"text": texts, "label": labels}).train_test_split(test_size=0.15, seed=42)
    tok = AutoTokenizer.from_pretrained(model_name)

    def tokenize(batch):
        return tok(batch["text"], truncation=True, padding="max_length", max_length=128)

    ds = ds.map(tokenize, batched=True)
    model = AutoModelForSequenceClassification.from_pretrained(
        model_name, num_labels=len(LABEL_ORDER), id2label={i: n for i, n in enumerate(LABEL_ORDER)},
        label2id=LABEL_TO_ID,
    )
    out.mkdir(parents=True, exist_ok=True)
    args = TrainingArguments(
        output_dir=str(out / "runs"),
        num_train_epochs=epochs,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        evaluation_strategy="epoch",
        save_strategy="epoch",
        logging_steps=20,
        load_best_model_at_end=True,
        report_to=[],
    )
    trainer = Trainer(
        model=model,
        args=args,
        train_dataset=ds["train"],
        eval_dataset=ds["test"],
        tokenizer=tok,
    )
    trainer.train()
    trainer.save_model(str(out))
    tok.save_pretrained(str(out))
    print(f"saved transformers model → {out}")
    if push_to_hub:
        model.push_to_hub(push_to_hub)
        tok.push_to_hub(push_to_hub)
        print(f"pushed → https://huggingface.co/{push_to_hub}")


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--backend", choices=("sklearn", "transformers"), default="sklearn")
    ap.add_argument("--train", type=Path, required=True)
    ap.add_argument("--eval", type=Path, default=None)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--model", default="distilbert-base-uncased")
    ap.add_argument("--push_to_hub", default=None)
    ap.add_argument("--epochs", type=int, default=3)
    ap.add_argument("--report", action="store_true")
    args = ap.parse_args()

    train_rows = load_jsonl(args.train)
    eval_rows = load_jsonl(args.eval) if args.eval else None
    if args.backend == "sklearn":
        train_sklearn(train_rows, args.out, eval_rows, args.report)
    else:
        train_transformers(train_rows, args.out, args.model, args.push_to_hub, args.epochs)


if __name__ == "__main__":
    main()
