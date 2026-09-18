# ml/ — dataset & training for a custom Hugging Face IDOR model

Tools to build **fredlubrano/idor-aspiration-clf** (or a local sklearn artifact) from the same features the BIG-IP iRule / iRulesLX already use.

See [docs/HUGGINGFACE.md](../docs/HUGGINGFACE.md).

## Quick start

```bash
# from repo root
python -m pip install -r ml/requirements-ml.txt

# 1) synthetic labeled dataset (lab)
python ml/synthesize_dataset.py --out ml/data/train.jsonl --n 2000

# 2) train sklearn baseline
python ml/train_classifier.py --backend sklearn \
  --train ml/data/train.jsonl \
  --out ml/artifacts/sklearn_model.joblib \
  --report

# 3) optional local classify API (maps labels → LX contract)
python ml/serve_stub.py --model ml/artifacts/sklearn_model.joblib
# POST http://127.0.0.1:8090/v1/classify
```

Transformers train (needs more RAM/disk):

```bash
python ml/train_classifier.py --backend transformers \
  --model distilbert-base-uncased \
  --train ml/data/train.jsonl \
  --out ml/artifacts/idor-aspiration-clf
```

## Layout

| Path | Role |
| --- | --- |
| `label_map.json` | id ↔ label names |
| `schemas/feature_record.schema.json` | JSONL record shape |
| `synthesize_dataset.py` | Generate balanced lab samples |
| `features_to_text.py` | Serialize features for DistilBERT |
| `train_classifier.py` | sklearn or Hugging Face Trainer |
| `serve_stub.py` | Minimal `/v1/classify` for LX |
| `data/` | JSONL (gitignored except `.gitkeep`) |
| `artifacts/` | Models (gitignored) |

Do not commit real production features with PII.
