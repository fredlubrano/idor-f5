"""Tests for generic threat scoring + cooling-off + AI actions."""

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
    apply_ai_action,
    apply_cooling,
    is_ambiguous,
    level_from_score,
    score_signals,
)


@pytest.fixture
def cfg() -> ScoringConfig:
    with (ROOT / "config" / "default.yaml").open(encoding="utf-8") as f:
        return ScoringConfig.from_yaml_dict(yaml.safe_load(f))


def test_level_thresholds(cfg: ScoringConfig):
    assert level_from_score(0, cfg) == "none"
    assert level_from_score(cfg.thr_low, cfg) == "low"
    assert level_from_score(cfg.thr_medium, cfg) == "medium"
    assert level_from_score(cfg.thr_high, cfg) == "high"


def test_forbidden_and_login_accumulate(cfg: ScoringConfig):
    st = UserState()
    st = score_signals(st, cfg=cfg, forbidden=True, now_ts=1_000)
    assert st.score == cfg.points_forbidden
    st = score_signals(st, cfg=cfg, failed_login=True, now_ts=1_001)
    assert st.score == cfg.points_forbidden + cfg.points_failed_login


def test_cooling_off_steps_down(cfg: ScoringConfig):
    cool = cfg.cooling_off_minutes * 60
    level, _ = apply_cooling("high", last_abuse_ts=0.0, now_ts=cool + 1, cfg=cfg)
    assert level == "medium"
    level, _ = apply_cooling("high", last_abuse_ts=0.0, now_ts=2 * cool + 1, cfg=cfg)
    assert level == "low"
    level, _ = apply_cooling("high", last_abuse_ts=0.0, now_ts=3 * cool + 1, cfg=cfg)
    assert level == "none"


def test_cooling_no_op_inside_window(cfg: ScoringConfig):
    cool = cfg.cooling_off_minutes * 60
    level, last = apply_cooling("medium", last_abuse_ts=100.0, now_ts=100 + cool - 1, cfg=cfg)
    assert level == "medium"
    assert last == 100.0


def test_ai_boost_and_dismiss():
    assert apply_ai_action("low", "boost") == "medium"
    assert apply_ai_action("high", "boost") == "high"
    assert apply_ai_action("medium", "dismiss") == "low"
    assert apply_ai_action("low", "confirm") == "low"
    assert apply_ai_action("none", "dismiss") == "none"


def test_ai_action_on_state(cfg: ScoringConfig):
    st = UserState(score=cfg.thr_low, level="low", ai_action="boost")
    st = score_signals(st, cfg=cfg, now_ts=5_000)
    assert st.level == "medium"
    assert st.ai_applied is True


def test_ai_boost_applied_once(cfg: ScoringConfig):
    st = UserState(score=cfg.thr_low, level="low", ai_action="boost")
    st = score_signals(st, cfg=cfg, now_ts=5_000)
    assert st.level == "medium"
    st = score_signals(st, cfg=cfg, now_ts=5_001)
    assert st.level == "medium"
    assert st.ai_applied is True


def test_ambiguous_band(cfg: ScoringConfig):
    assert is_ambiguous(40, cfg)
    assert not is_ambiguous(10, cfg)
    assert not is_ambiguous(95, cfg)


def test_waf_and_rate_points(cfg: ScoringConfig):
    st = UserState()
    st = score_signals(st, cfg=cfg, waf_hit=True, rate_exceeded=True, now_ts=10)
    assert st.score == cfg.points_waf + cfg.points_rate
    first = st.score
    st = score_signals(st, cfg=cfg, waf_hit=True, rate_exceeded=True, now_ts=11)
    assert st.score == first
    assert "waf_hit" in st.awarded_signals
    assert "rate_limit" in st.awarded_signals
