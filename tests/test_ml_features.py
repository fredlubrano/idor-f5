"""Smoke tests for ml feature serialization and label map."""
from __future__ import annotations

import json
from pathlib import Path

from ml.features_to_text import feature_vector, features_to_text

ROOT = Path(__file__).resolve().parents[1]


def test_features_to_text_stable():
    text = features_to_text(
        {
            "distinct_object_ids": 35,
            "sequential_ratio": 0.82,
            "forbid_ratio": 0.05,
            "ok_ratio": 0.95,
            "req_count": 40,
            "response_bytes_sum": 8500000,
            "template_focus": 0.9,
            "aspiration_score": 0.71,
            "path_template": "/api/accounts/{id}",
        },
        auth_present=True,
    )
    assert "auth=1" in text
    assert "distinct_object_ids=35" in text
    assert "template=/api/accounts/{id}" in text


def test_feature_vector_length():
    v = feature_vector({"distinct_object_ids": 1}, auth_present=False)
    assert len(v) == 10
    assert v[0] == 0.0


def test_label_map_has_four_classes():
    data = json.loads((ROOT / "ml" / "label_map.json").read_text(encoding="utf-8"))
    assert len(data["labels"]) == 4
    assert "data_aspiration" in data["action_map"]
    assert data["action_map"]["data_aspiration"]["action"] == "boost"
