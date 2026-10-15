"""Pure-Python mirror of BIG-IP malicious_user scoring / IDOR features.

Used by unit tests; keep formulas aligned with irules/malicious_user.tcl
and config/default.yaml.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Set, Tuple


LEVELS = ("none", "low", "medium", "high")


@dataclass
class ScoringConfig:
    points_forbidden: int = 15
    points_failed_login: int = 10
    points_waf: int = 12
    points_rate: int = 8
    points_distinct: int = 20
    points_sequential: int = 15
    points_forbid_ratio: int = 18
    points_success_enum: int = 22
    points_template_focus: int = 10
    points_bytes: int = 8
    thr_low: int = 30
    thr_medium: int = 60
    thr_high: int = 90
    cooling_off_minutes: int = 20
    distinct_ids_threshold: int = 25
    sequential_ratio_threshold: float = 0.6
    forbid_ratio_threshold: float = 0.4
    success_enum_threshold: int = 20
    template_focus_threshold: float = 0.7
    response_bytes_threshold: int = 5_242_880
    w_distinct: float = 0.30
    w_rate: float = 0.15
    w_sequential: float = 0.20
    w_focus: float = 0.15
    w_bytes: float = 0.20
    aspiration_threshold: float = 0.55
    success_min_200_ratio: float = 0.7
    ambiguous_min: int = 25
    ambiguous_max: int = 79

    @classmethod
    def from_yaml_dict(cls, data: dict) -> "ScoringConfig":
        s = data.get("scoring", {})
        pts = s.get("points", {})
        thr = s.get("thresholds", {})
        idor = data.get("idor", {})
        w = idor.get("weights", {})
        ai = data.get("ai", {})
        gate = ai.get("gate", {})
        return cls(
            points_forbidden=int(pts.get("forbidden_activity", 15)),
            points_failed_login=int(pts.get("failed_login", 10)),
            points_waf=int(pts.get("waf_hit", 12)),
            points_rate=int(pts.get("rate_limit", 8)),
            points_distinct=int(pts.get("distinct_object_ids", 20)),
            points_sequential=int(pts.get("sequential_ratio", 15)),
            points_forbid_ratio=int(pts.get("forbid_ratio", 18)),
            points_success_enum=int(pts.get("success_enum", 22)),
            points_template_focus=int(pts.get("template_focus", 10)),
            points_bytes=int(pts.get("response_bytes", 8)),
            thr_low=int(thr.get("low", 30)),
            thr_medium=int(thr.get("medium", 60)),
            thr_high=int(thr.get("high", 90)),
            cooling_off_minutes=int(s.get("cooling_off_minutes", 20)),
            distinct_ids_threshold=int(idor.get("distinct_ids_threshold", 25)),
            sequential_ratio_threshold=float(idor.get("sequential_ratio_threshold", 0.6)),
            forbid_ratio_threshold=float(idor.get("forbid_ratio_threshold", 0.4)),
            success_enum_threshold=int(idor.get("success_enum_threshold", 20)),
            template_focus_threshold=float(idor.get("template_focus_threshold", 0.7)),
            response_bytes_threshold=int(idor.get("response_bytes_threshold", 5_242_880)),
            w_distinct=float(w.get("distinct_ids", 0.30)),
            w_rate=float(w.get("rate", 0.15)),
            w_sequential=float(w.get("sequential_ratio", 0.20)),
            w_focus=float(w.get("template_focus", 0.15)),
            w_bytes=float(w.get("bytes", 0.20)),
            aspiration_threshold=float(idor.get("aspiration_threshold", 0.55)),
            success_min_200_ratio=float(idor.get("success_min_200_ratio", 0.7)),
            ambiguous_min=int(gate.get("ambiguous_min", 25)),
            ambiguous_max=int(gate.get("ambiguous_max", 79)),
        )


def level_from_score(score: int, cfg: ScoringConfig) -> str:
    if score >= cfg.thr_high:
        return "high"
    if score >= cfg.thr_medium:
        return "medium"
    if score >= cfg.thr_low:
        return "low"
    return "none"


def level_rank(level: str) -> int:
    try:
        return LEVELS.index(level)
    except ValueError:
        return 0


def rank_to_level(rank: int) -> str:
    rank = max(0, min(3, rank))
    return LEVELS[rank]


def apply_cooling(
    level: str,
    last_abuse_ts: Optional[float],
    now_ts: float,
    cfg: ScoringConfig,
) -> Tuple[str, Optional[float]]:
    """Drop one threat level per cooling_off period without abuse."""
    if last_abuse_ts is None or level == "none":
        return level, last_abuse_ts
    cool_sec = cfg.cooling_off_minutes * 60
    elapsed = now_ts - last_abuse_ts
    if elapsed < cool_sec:
        return level, last_abuse_ts
    steps = int(elapsed // cool_sec)
    new_rank = max(0, level_rank(level) - steps)
    new_level = rank_to_level(new_rank)
    new_last = last_abuse_ts + steps * cool_sec
    return new_level, new_last


def apply_ai_action(level: str, action: Optional[str], threat: Optional[str] = None) -> str:
    """Mirror iRule AI confirm/dismiss/boost effects on threat level."""
    if not action or action == "confirm":
        return level
    if action == "boost":
        return rank_to_level(min(3, level_rank(level) + 1))
    if action == "dismiss":
        return rank_to_level(max(0, level_rank(level) - 1))
    if action == "set" and threat:
        return threat if threat in LEVELS else level
    return level


def sequential_ratio(ids: Sequence[str]) -> float:
    """Fraction of consecutive pairs that differ by exactly 1 (numeric IDs)."""
    nums: List[int] = []
    for x in ids:
        try:
            nums.append(int(x))
        except (TypeError, ValueError):
            continue
    if len(nums) < 2:
        return 0.0
    hits = sum(1 for a, b in zip(nums, nums[1:]) if abs(b - a) == 1)
    return hits / (len(nums) - 1)


def forbid_ratio(statuses: Sequence[int]) -> float:
    if not statuses:
        return 0.0
    bad = sum(1 for s in statuses if s in (403, 404))
    return bad / len(statuses)


def template_focus(templates: Sequence[str]) -> float:
    if not templates:
        return 0.0
    from collections import Counter

    c = Counter(templates)
    return c.most_common(1)[0][1] / len(templates)


def normalize_template(path: str) -> str:
    import re

    t = re.sub(r"/\d+", "/{id}", path)
    t = re.sub(r"/[0-9a-fA-F-]{8,}", "/{id}", t)
    return t


def aspiration_score(
    *,
    distinct_ids: int,
    rate_norm: float,
    sequential: float,
    focus: float,
    bytes_sum: int,
    cfg: ScoringConfig,
) -> float:
    """Weighted aspiration score (same weights as YAML / iRule)."""
    d = distinct_ids / max(1, cfg.distinct_ids_threshold)
    b = bytes_sum / max(1, cfg.response_bytes_threshold)
    raw = (
        cfg.w_distinct * d
        + cfg.w_rate * rate_norm
        + cfg.w_sequential * sequential
        + cfg.w_focus * focus
        + cfg.w_bytes * b
    )
    return min(5.0, max(0.0, raw))


@dataclass
class UserState:
    score: int = 0
    level: str = "none"
    last_abuse_ts: Optional[float] = None
    object_ids: List[str] = field(default_factory=list)
    statuses: List[int] = field(default_factory=list)
    templates: List[str] = field(default_factory=list)
    bytes_sum: int = 0
    ai_action: Optional[str] = None
    awarded_signals: Set[str] = field(default_factory=set)
    ai_applied: bool = False

    def _award_once(self, signal_name: str, pts: int) -> int:
        """Mirror iRule mu_award_once: each IDOR/WAF/rate latch fires once per window."""
        if pts <= 0 or signal_name in self.awarded_signals:
            return 0
        self.awarded_signals.add(signal_name)
        return pts


def score_signals(
    state: UserState,
    *,
    cfg: ScoringConfig,
    forbidden: bool = False,
    failed_login: bool = False,
    waf_hit: bool = False,
    rate_exceeded: bool = False,
    now_ts: Optional[float] = None,
) -> UserState:
    """Apply classic + IDOR point bumps; update level with cooling + AI."""
    import time

    now = now_ts if now_ts is not None else time.time()
    cooled, last = apply_cooling(state.level, state.last_abuse_ts, now, cfg)
    state.level = cooled
    state.last_abuse_ts = last

    delta = 0
    if forbidden:
        delta += cfg.points_forbidden
    if failed_login:
        delta += cfg.points_failed_login
    if waf_hit:
        delta += state._award_once("waf_hit", cfg.points_waf)
    if rate_exceeded:
        delta += state._award_once("rate_limit", cfg.points_rate)

    # IDOR derived features from collected window (latched once per window)
    distinct = len(set(state.object_ids))
    seq = sequential_ratio(state.object_ids)
    fr = forbid_ratio(state.statuses)
    focus = template_focus(state.templates)
    success_n = sum(1 for s in state.statuses if s == 200)

    if distinct >= cfg.distinct_ids_threshold:
        delta += state._award_once("distinct_ids", cfg.points_distinct)
    # Match iRule: need enough samples before sequential/focus fire
    if len(state.object_ids) >= 5 and seq >= cfg.sequential_ratio_threshold:
        delta += state._award_once("seq_ratio", cfg.points_sequential)
    if len(state.statuses) >= 10 and fr >= cfg.forbid_ratio_threshold:
        delta += state._award_once("forbid_ratio", cfg.points_forbid_ratio)
    ok_ratio = (success_n / len(state.statuses)) if state.statuses else 0.0
    if (
        success_n >= cfg.success_enum_threshold
        and distinct >= max(1, cfg.distinct_ids_threshold // 2)
        and ok_ratio >= cfg.success_min_200_ratio
    ):
        delta += state._award_once("success_enum", cfg.points_success_enum)
    if len(state.templates) >= 10 and focus >= cfg.template_focus_threshold:
        delta += state._award_once("template_focus", cfg.points_template_focus)
    if state.bytes_sum >= cfg.response_bytes_threshold:
        delta += state._award_once("resp_bytes", cfg.points_bytes)

    asp = aspiration_score(
        distinct_ids=distinct,
        rate_norm=min(1.0, distinct / max(1, cfg.distinct_ids_threshold)),
        sequential=seq,
        focus=focus,
        bytes_sum=state.bytes_sum,
        cfg=cfg,
    )
    if (
        asp >= cfg.aspiration_threshold
        and delta == 0
        and distinct >= cfg.success_enum_threshold
    ):
        delta += state._award_once("success_enum", cfg.points_success_enum)

    if delta > 0:
        state.score = min(200, max(0, state.score + delta))
        state.last_abuse_ts = now
        state.level = level_from_score(state.score, cfg)

    if state.ai_action and not state.ai_applied:
        state.level = apply_ai_action(state.level, state.ai_action)
        state.ai_applied = True
    return state


def is_ambiguous(
    score: int,
    cfg: ScoringConfig,
    amb_min: int | None = None,
    amb_max: int | None = None,
) -> bool:
    lo = cfg.ambiguous_min if amb_min is None else amb_min
    hi = cfg.ambiguous_max if amb_max is None else amb_max
    return lo <= score <= hi


def extract_object_id(path: str) -> Optional[str]:
    import re

    m = re.search(r"/([0-9a-fA-F-]{1,64})$", path)
    return m.group(1) if m else None


def record_object_request(
    state: UserState,
    path: str,
    status: int,
    content_length: int = 0,
) -> UserState:
    oid = extract_object_id(path)
    if oid:
        state.object_ids.append(oid)
    state.statuses.append(status)
    state.templates.append(normalize_template(path))
    if status == 200 and content_length > 0:
        state.bytes_sum += content_length
    return state
