"""Smoke test: YAML placeholders → rendered iRule."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from render_irule import render  # noqa: E402


def test_render_fills_placeholders():
    cfg = yaml.safe_load((ROOT / "config" / "default.yaml").read_text(encoding="utf-8"))
    template = (ROOT / "irules" / "malicious_user.tcl").read_text(encoding="utf-8")
    assert "{{POINTS_FORBIDDEN}}" in template
    assert "{{LOGIN_PATH_MATCH_BODY}}" in template
    assert "{{OBJECT_PATH_MATCH_BODY}}" in template

    out = render(cfg, template)
    leftover = re.findall(r"\{\{[A-Z0-9_]+\}\}", out)
    assert leftover == [], f"Unresolved: {leftover}"

    thr = cfg["scoring"]["thresholds"]
    assert f"set static::mu_thresh_low {thr['low']}" in out
    assert f"set static::mu_thresh_med {thr['medium']}" in out
    assert f"set static::mu_thresh_high {thr['high']}" in out
    cool = int(cfg["scoring"]["cooling_off_minutes"]) * 60
    assert f"set static::mu_cooling {cool}" in out
    assert 'set static::mu_identity_mode "ip"' in out
    assert "set mu_is_login 1" in out
    assert "regexp" in out
    assert "when CLIENT_CLOSED" in out
    assert 'log local0.warn "MU-IDOR client=$mu_log_client' in out
    assert 'log local0.warn "MU-IDOR-ACT client=$mu_log_client' in out
    assert "mu_ai fail-open" in out
    # Logs live in events, not in procs (HTTP::uri in a proc + HTTP_RESPONSE fails attach).
    before_req = out.split("when HTTP_REQUEST", 1)[0]
    assert "MU-IDOR" not in before_req
