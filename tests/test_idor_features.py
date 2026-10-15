"""Tests for IDOR feature counters and aspiration scoring."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lib.scoring import (  # noqa: E402
    ScoringConfig,
    UserState,
    aspiration_score,
    extract_object_id,
    forbid_ratio,
    normalize_template,
    record_object_request,
    score_signals,
    sequential_ratio,
    template_focus,
)


@pytest.fixture
def cfg() -> ScoringConfig:
    with (ROOT / "config" / "default.yaml").open(encoding="utf-8") as f:
        return ScoringConfig.from_yaml_dict(yaml.safe_load(f))


def test_extract_and_normalize():
    assert extract_object_id("/api/accounts/42") == "42"
    assert extract_object_id("/api/accounts/a1b2c3d4-dead-beef") == "a1b2c3d4-dead-beef"
    assert normalize_template("/api/accounts/42") == "/api/accounts/{id}"
    assert normalize_template("/api/v1/items/99/detail") == "/api/v1/items/{id}/detail"


def test_sequential_ratio_high_on_monotonic_ids():
    ids = [str(i) for i in range(1, 21)]
    assert sequential_ratio(ids) == 1.0


def test_sequential_ratio_low_on_sparse():
    ids = ["1", "50", "3", "900", "12"]
    assert sequential_ratio(ids) < 0.3


def test_forbid_ratio():
    assert forbid_ratio([200, 200, 403, 404]) == 0.5
    assert forbid_ratio([]) == 0.0


def test_template_focus():
    tmpls = ["/api/a/{id}"] * 8 + ["/api/b/{id}"] * 2
    assert template_focus(tmpls) == 0.8


def test_success_enum_idor_aspiration(cfg: ScoringConfig):
    """Many 200s on distinct sequential IDs → success_enum + distinct + sequential points."""
    st = UserState()
    for i in range(1, 30):
        record_object_request(st, f"/api/accounts/{i}", 200, content_length=10_000)
    st = score_signals(st, cfg=cfg, now_ts=1_000)
    # distinct >= 25, sequential high, success_enum >= 20, template focus high
    assert len(set(st.object_ids)) >= cfg.distinct_ids_threshold
    assert st.score >= (
        cfg.points_distinct + cfg.points_sequential + cfg.points_success_enum
    )
    assert st.level in ("low", "medium", "high")


def test_forbid_heavy_probe(cfg: ScoringConfig):
    st = UserState()
    for i in range(1, 30):
        status = 404 if i % 2 == 0 else 403
        record_object_request(st, f"/api/accounts/{i}", status)
    st = score_signals(st, cfg=cfg, now_ts=2_000)
    assert forbid_ratio(st.statuses) >= cfg.forbid_ratio_threshold
    assert st.score >= cfg.points_forbid_ratio


def test_aspiration_weighted(cfg: ScoringConfig):
    score = aspiration_score(
        distinct_ids=50,
        rate_norm=1.0,
        sequential=0.9,
        focus=0.85,
        bytes_sum=cfg.response_bytes_threshold * 2,
        cfg=cfg,
    )
    assert score > 1.0
    low = aspiration_score(
        distinct_ids=2,
        rate_norm=0.05,
        sequential=0.0,
        focus=0.2,
        bytes_sum=100,
        cfg=cfg,
    )
    assert low < score


def test_idor_thresholds_awarded_once_per_window(cfg: ScoringConfig):
    st = UserState()
    for i in range(1, 30):
        record_object_request(st, f"/api/accounts/{i}", 200, content_length=10_000)
    st = score_signals(st, cfg=cfg, now_ts=1_000)
    first = st.score
    assert "distinct_ids" in st.awarded_signals
    assert "seq_ratio" in st.awarded_signals
    assert "success_enum" in st.awarded_signals
    st = score_signals(st, cfg=cfg, now_ts=1_001)
    assert st.score == first


def test_legitimate_low_volume_no_idor_points(cfg: ScoringConfig):
    st = UserState()
    for i in (10, 11, 12):
        record_object_request(st, f"/api/accounts/{i}", 200, content_length=500)
    before = st.score
    st = score_signals(st, cfg=cfg, now_ts=3_000)
    # Below thresholds → no IDOR point bumps
    assert st.score == before == 0
    assert st.level == "none"
