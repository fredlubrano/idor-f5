#!/usr/bin/env python3
"""Render config/default.yaml thresholds into irules/malicious_user.tcl placeholders."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:
    print("PyYAML required: pip install PyYAML", file=sys.stderr)
    sys.exit(1)


ROOT = Path(__file__).resolve().parents[1]
DEFAULT_TEMPLATE = ROOT / "irules" / "malicious_user.tcl"
DEFAULT_CONFIG = ROOT / "config" / "default.yaml"


def _bool01(v) -> str:
    return "1" if v else "0"


def _tcl_escape(s: str) -> str:
    return s.replace("\\", "\\\\").replace('"', '\\"')


def template_to_regex(tmpl: str) -> str:
    """Convert /api/accounts/{id} → ^/api/accounts/[^/]+$"""
    esc = re.escape(tmpl)
    esc = esc.replace(r"\{id\}", r"[^/]+")
    return f"^{esc}$"


def build_object_path_match(patterns: list) -> str:
    lines = []
    for p in patterns:
        lines.append(f"    if {{ [regexp {{{p}}} $path] }} {{ return 1 }}")
    return "\n".join(lines) if lines else "    # no object path patterns"


def build_login_path_match(paths: list) -> str:
    lines = ["    switch -exact -- $mu_path {"]
    for p in paths:
        lines.append(f'        "{_tcl_escape(p)}" {{ set mu_is_login 1 }}')
    lines.append("    }")
    return "\n".join(lines)


def collect_object_patterns(idor: dict) -> list[str]:
    patterns = list(idor.get("object_path_patterns") or [])
    if patterns:
        return patterns
    for tmpl in idor.get("object_path_templates") or []:
        patterns.append(template_to_regex(str(tmpl)))
    if not patterns:
        patterns = [
            r"^/api/.+/\d+$",
            r"^/api/.+/[0-9a-fA-F-]{8,}$",
        ]
    return patterns


def collect_login_paths(config: dict) -> list[str]:
    if config.get("login_paths"):
        return list(config["login_paths"])
    fl = (config.get("signals") or {}).get("failed_login") or {}
    return list(fl.get("paths") or ["/login", "/api/auth/login"])


def render(config: dict, template: str) -> str:
    scoring = config.get("scoring") or {}
    pts = scoring.get("points") or {}
    thr = scoring.get("thresholds") or {}
    idor = config.get("idor") or {}
    weights = idor.get("weights") or {}
    mit = config.get("mitigation") or {}
    ai = config.get("ai") or {}
    gate = ai.get("gate") or {}
    identity = config.get("identity") or {}
    jwt = identity.get("jwt") or {}
    cookie_hdr = identity.get("cookie_header") or {}
    deploy = config.get("deploy") or {}
    privacy = ai.get("privacy") or {}
    features = ai.get("features") or {}
    options = ai.get("options") or {}
    rate_sig = (config.get("signals") or {}).get("rate_limiting") or {}

    ai_shadow = ai.get("action") == "shadow" or bool(options.get("shadow", False))
    mit_shadow = bool(mit.get("shadow", False))
    status_seq = bool(features.get("response_status_seq")) or bool(
        options.get("response_status_seq", False)
    )

    block_ttl = mit.get("temp_block_ttl_seconds", mit.get("block_ttl_seconds", 600))
    rate_rps = mit.get("high_rate_limit_tps", scoring.get("rate_limit_rps", 2))
    window = idor.get("window_seconds") or scoring.get("window_seconds") or rate_sig.get(
        "window_seconds", 300
    )

    chal = (mit.get("low_challenge") or {}).get("cookie_name") or mit.get(
        "challenge_cookie", "mu_chal"
    )

    replacements = {
        "POINTS_FORBIDDEN": str(int(pts.get("forbidden_activity", 15))),
        "POINTS_FAILED_LOGIN": str(int(pts.get("failed_login", 10))),
        "POINTS_WAF": str(int(pts.get("waf_hit", 12))),
        "POINTS_RATE": str(int(pts.get("rate_limit", 8))),
        "POINTS_DISTINCT": str(int(pts.get("distinct_object_ids", 20))),
        "POINTS_SEQUENTIAL": str(int(pts.get("sequential_ratio", 15))),
        "POINTS_FORBID_RATIO": str(int(pts.get("forbid_ratio", 18))),
        "POINTS_SUCCESS_ENUM": str(int(pts.get("success_enum", 22))),
        "POINTS_TEMPLATE_FOCUS": str(int(pts.get("template_focus", 10))),
        "POINTS_BYTES": str(int(pts.get("response_bytes", 8))),
        "THR_LOW": str(int(thr.get("low", 30))),
        "THR_MEDIUM": str(int(thr.get("medium", 60))),
        "THR_HIGH": str(int(thr.get("high", 90))),
        "COOLING_OFF_SECONDS": str(int(scoring.get("cooling_off_minutes", 20)) * 60),
        "WINDOW_SECONDS": str(int(window)),
        "RATE_LIMIT_RPS": str(int(rate_rps)),
        "BLOCK_TTL_SECONDS": str(int(block_ttl)),
        "IDOR_DISTINCT_THRESHOLD": str(int(idor.get("distinct_ids_threshold", 25))),
        "IDOR_SEQUENTIAL_THRESHOLD": str(float(idor.get("sequential_ratio_threshold", 0.6))),
        "IDOR_FORBID_THRESHOLD": str(float(idor.get("forbid_ratio_threshold", 0.4))),
        "IDOR_SUCCESS_ENUM_THRESHOLD": str(int(idor.get("success_enum_threshold", 20))),
        "IDOR_TEMPLATE_FOCUS_THRESHOLD": str(float(idor.get("template_focus_threshold", 0.7))),
        "IDOR_BYTES_THRESHOLD": str(int(idor.get("response_bytes_threshold", 5242880))),
        "W_DISTINCT": str(float(weights.get("distinct_ids", 0.30))),
        "W_RATE": str(float(weights.get("rate", 0.15))),
        "W_SEQUENTIAL": str(float(weights.get("sequential_ratio", 0.20))),
        "W_FOCUS": str(float(weights.get("template_focus", 0.15))),
        "W_BYTES": str(float(weights.get("bytes", 0.20))),
        "AI_ENABLED": _bool01(ai.get("enabled", True)),
        "AI_AMBIGUOUS_MIN": str(int(gate.get("ambiguous_min", ai.get("ambiguous_min", 25)))),
        "AI_AMBIGUOUS_MAX": str(int(gate.get("ambiguous_max", ai.get("ambiguous_max", 55)))),
        "AI_SAMPLE_PERCENT": str(int(gate.get("sample_percent", ai.get("sample_percent", 5)))),
        "AI_SKIP_IF_HIGH": _bool01(
            gate.get("skip_if_high", ai.get("skip_if_high", True))
        ),
        "AI_SHADOW": _bool01(ai_shadow),
        "MITIGATION_SHADOW": _bool01(mit_shadow),
        "AI_FEATURE_STATUS_SEQ": _bool01(status_seq),
        "CHALLENGE_COOKIE": _tcl_escape(str(chal)),
        "IDENTITY_MODE": _tcl_escape(str(identity.get("mode", "ip"))),
        "JWT_CLAIM": _tcl_escape(str(jwt.get("claim", identity.get("jwt_claim", "sub")))),
        "COOKIE_NAME": _tcl_escape(
            str(cookie_hdr.get("name", identity.get("cookie_name", "")))
        ),
        "HEADER_NAME": _tcl_escape(str(identity.get("header_name", ""))),
        "LX_PLUGIN": _tcl_escape(
            str(
                deploy.get(
                    "lx_plugin_name",
                    deploy.get("lx_extension", deploy.get("lx_workspace", "ai_enrich")),
                )
            )
        ),
        "OBJECT_PATH_MATCH_BODY": build_object_path_match(collect_object_patterns(idor)),
        "LOGIN_PATH_MATCH_BODY": build_login_path_match(collect_login_paths(config)),
    }

    # unused but kept for future privacy flag injection
    _ = privacy

    out = template
    for key, val in replacements.items():
        token = "{{" + key + "}}"
        out = out.replace(token, val)

    leftover = re.findall(r"\{\{[A-Z0-9_]+\}\}", out)
    if leftover:
        raise SystemExit(f"Unresolved placeholders: {sorted(set(leftover))}")

    return out


def main(argv: list | None = None) -> int:
    p = argparse.ArgumentParser(description="Render malicious_user iRule from YAML")
    p.add_argument("-c", "--config", type=Path, default=DEFAULT_CONFIG)
    p.add_argument("-t", "--template", type=Path, default=DEFAULT_TEMPLATE)
    p.add_argument(
        "-o",
        "--out",
        "--output",
        dest="output",
        type=Path,
        default=ROOT / "irules" / "malicious_user.rendered.tcl",
    )
    args = p.parse_args(argv)

    with args.config.open(encoding="utf-8") as f:
        config = yaml.safe_load(f)

    template = args.template.read_text(encoding="utf-8")
    rendered = render(config, template)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(rendered, encoding="utf-8", newline="\n")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
