"""Serialize IDOR feature dicts to a short text line for HF sequence classifiers."""
from __future__ import annotations

from typing import Any, Mapping


FEATURE_KEYS = (
    "distinct_object_ids",
    "sequential_ratio",
    "forbid_ratio",
    "ok_ratio",
    "req_count",
    "response_bytes_sum",
    "template_focus",
    "aspiration_score",
    "ids_per_minute",
)


def features_to_text(
    features: Mapping[str, Any],
    *,
    auth_present: bool = True,
    path_template: str | None = None,
) -> str:
    """Compact, stable serialization — keep aligned with train + serve."""
    f = features or {}
    parts = [f"auth={1 if auth_present else 0}"]
    for k in FEATURE_KEYS:
        if k in f and f[k] is not None:
            v = f[k]
            if isinstance(v, float):
                parts.append(f"{k}={v:.4f}")
            else:
                parts.append(f"{k}={v}")
    tmpl = path_template or f.get("path_template") or ""
    if tmpl:
        parts.append(f"template={tmpl}")
    seq = f.get("status_seq")
    if seq:
        parts.append(f"status_seq={seq}")
    return " ".join(parts)


def feature_vector(features: Mapping[str, Any], *, auth_present: bool = True) -> list[float]:
    """Numeric vector for sklearn (fixed order)."""
    f = features or {}
    return [
        1.0 if auth_present else 0.0,
        float(f.get("distinct_object_ids", 0) or 0),
        float(f.get("sequential_ratio", 0) or 0),
        float(f.get("forbid_ratio", 0) or 0),
        float(f.get("ok_ratio", 0) or 0),
        float(f.get("req_count", 0) or 0),
        float(f.get("response_bytes_sum", 0) or 0),
        float(f.get("template_focus", 0) or 0),
        float(f.get("aspiration_score", 0) or 0),
        float(f.get("ids_per_minute", 0) or 0),
    ]
