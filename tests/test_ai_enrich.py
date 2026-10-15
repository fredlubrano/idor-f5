"""Node 6-compatible Gemini plugin: parse candidates[0].content.parts[0].text."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
PLUGIN = ROOT / "iruleslx" / "ai_enrich"
INDEX_JS = PLUGIN / "index.js"


def test_gemini_node_unit_suite():
    proc = subprocess.run(
        ["node", str(PLUGIN / "test_gemini.js")],
        cwd=str(PLUGIN),
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stdout + "\n" + proc.stderr
    assert "ok gemini unit tests" in proc.stdout


def test_parse_gemini_candidate_text():
    decision = {
        "action": "boost",
        "threat": "high",
        "idor_likelihood": 0.88,
        "pattern": "data_aspiration",
        "reason": "volume 200s",
    }
    envelope = json.dumps(
        {"candidates": [{"content": {"parts": [{"text": json.dumps(decision)}]}}]}
    )
    script = (
        "var ai=require('./index.js');\n"
        f"var d=ai.parseGeminiHttpBody({json.dumps(envelope)});\n"
        "process.stdout.write(JSON.stringify(d));\n"
    )
    proc = subprocess.run(
        ["node", "-e", script],
        cwd=str(PLUGIN),
        check=False,
        capture_output=True,
        text=True,
    )
    assert proc.returncode == 0, proc.stderr
    parsed = json.loads(proc.stdout)
    assert parsed["action"] == "boost"
    assert parsed["pattern"] == "data_aspiration"
    assert parsed["fail_open"] is False
    assert parsed["idor_likelihood"] == 0.88


def test_yaml_google_gemini_shadow():
    cfg = yaml.safe_load((ROOT / "config" / "default.yaml").read_text(encoding="utf-8"))
    ai = cfg["ai"]
    assert ai["provider"] == "google"
    assert ai["model"] == "gemini-2.5-flash"
    assert ai["endpoint"].endswith("gemini-2.5-flash:generateContent")
    assert ai["action"] == "shadow"
    assert cfg["mitigation"]["shadow"] is True


def test_plugin_is_node6_syntax():
    src = INDEX_JS.read_text(encoding="utf-8")
    assert "async function" not in src
    assert "await " not in src
    assert "...payload" not in src
    assert "...opts" not in src
    assert "x-goog-api-key" in src
    assert "thinkingBudget" in src
    assert "GEMINI_API_KEY" in src
    assert "GOOGLE_API_KEY" in src
    assert "/config/gemini_api_key" in src
    assert "/var/tmp/gemini_api_key" in src
    assert "application/json" in src


def test_no_openai_in_plugin():
    src = INDEX_JS.read_text(encoding="utf-8")
    assert "openai" not in src.lower()
    assert "gpt-4o" not in src.lower()
