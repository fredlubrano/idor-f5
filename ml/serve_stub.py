#!/usr/bin/env python3
"""Minimal classify API matching the iRulesLX enrich contract.

POST /v1/classify
Body: { "auth_present": true, "features": { ... }, "score": 42, "level": "low" }
Response: { "action", "threat", "idor_likelihood", "pattern", "reason", "label", "confidence" }
"""
from __future__ import annotations

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ml.features_to_text import feature_vector  # noqa: E402

LABEL_MAP_PATH = Path(__file__).resolve().parent / "label_map.json"


def load_bundle(model_path: Path):
    import joblib

    bundle = joblib.load(model_path)
    return bundle["model"], list(bundle["labels"])


def load_action_map() -> dict:
    return json.loads(LABEL_MAP_PATH.read_text(encoding="utf-8"))


def predict(model, labels: list[str], body: dict, action_map: dict) -> dict:
    import numpy as np

    feats = body.get("features") or {}
    auth = bool(body.get("auth_present", True))
    X = np.array([feature_vector(feats, auth_present=auth)], dtype=float)
    proba = None
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(X)[0]
        idx = int(proba.argmax())
        conf = float(proba[idx])
    else:
        idx = int(model.predict(X)[0])
        conf = 1.0
    label = labels[idx]
    fail_below = float(action_map.get("confidence_fail_open_below", 0.55))
    mapped = dict(action_map["action_map"][label])
    if conf < fail_below:
        return {
            "action": "confirm",
            "threat": body.get("level") or "low",
            "idor_likelihood": conf,
            "pattern": "unclear",
            "reason": "confidence below fail-open threshold",
            "label": label,
            "confidence": conf,
            "fail_open": True,
        }
    return {
        "action": mapped["action"],
        "threat": mapped["threat"],
        "idor_likelihood": conf if label == "data_aspiration" else conf * 0.7,
        "pattern": mapped["pattern"],
        "reason": f"sklearn label={label}",
        "label": label,
        "confidence": conf,
        "fail_open": False,
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--model", type=Path, required=True, help="joblib from train_classifier.py")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    args = ap.parse_args()

    model, labels = load_bundle(args.model)
    action_map = load_action_map()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):  # noqa: N802
            if self.path.rstrip("/") != "/v1/classify":
                self.send_error(404)
                return
            length = int(self.headers.get("Content-Length", 0))
            raw = self.rfile.read(length)
            try:
                body = json.loads(raw.decode("utf-8") or "{}")
                out = predict(model, labels, body, action_map)
            except Exception as e:  # noqa: BLE001
                out = {
                    "action": "confirm",
                    "threat": "low",
                    "idor_likelihood": 0.0,
                    "pattern": "unclear",
                    "reason": f"error: {e}",
                    "fail_open": True,
                }
            data = json.dumps(out).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, fmt, *a):  # quieter
            sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % a))

    httpd = HTTPServer((args.host, args.port), Handler)
    print(f"classify API on http://{args.host}:{args.port}/v1/classify")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
