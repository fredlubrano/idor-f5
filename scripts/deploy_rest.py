#!/usr/bin/env python3
"""Deploy malicious_user iRule (+ optional iRulesLX package) via iControl REST."""

from __future__ import annotations

import argparse
import json
import os
import sys
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

try:
    import requests
    import urllib3
    import yaml
except ImportError:
    print("Need: pip install requests PyYAML", file=sys.stderr)
    sys.exit(1)

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))


class BigIPClient:
    def __init__(self, host: str, user: str, password: str, verify: bool = False):
        self.base = host.rstrip("/")
        self.session = requests.Session()
        self.session.auth = (user, password)
        self.session.verify = verify
        self.session.headers.update({"Content-Type": "application/json"})

    def _url(self, path: str) -> str:
        if not path.startswith("/"):
            path = "/" + path
        return f"{self.base}{path}"

    def get(self, path: str) -> Any:
        return self.session.get(self._url(path), timeout=60)

    def post(self, path: str, payload: Any) -> Any:
        return self.session.post(self._url(path), json=payload, timeout=120)

    def put(self, path: str, payload: Any) -> Any:
        return self.session.put(self._url(path), json=payload, timeout=120)

    def patch(self, path: str, payload: Any) -> Any:
        return self.session.patch(self._url(path), json=payload, timeout=120)


def load_config(path: Path) -> dict:
    with path.open(encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def upsert_irule(client: BigIPClient, name: str, partition: str, api_anonymous: str) -> None:
    full = f"~{partition}~{name}"
    encoded = quote(full, safe="~")
    path = f"/mgmt/tm/ltm/rule/{encoded}"
    r = client.get(path)
    body = {"name": name, "partition": partition, "apiAnonymous": api_anonymous}
    if r.status_code == 200:
        print(f"Updating iRule {partition}/{name}…")
        resp = client.put(path, body)
    elif r.status_code == 404:
        print(f"Creating iRule {partition}/{name}…")
        resp = client.post("/mgmt/tm/ltm/rule", body)
    else:
        raise SystemExit(f"GET iRule failed: {r.status_code} {r.text}")
    if resp.status_code not in (200, 201):
        raise SystemExit(f"Upsert iRule failed: {resp.status_code} {resp.text}")
    print("iRule OK")


def attach_irule_to_vs(client: BigIPClient, vs_path: str, irule_full: str) -> None:
    parts = [p for p in vs_path.split("/") if p]
    if len(parts) == 1:
        partition, name = "Common", parts[0]
    else:
        partition, name = parts[0], parts[-1]
    encoded = quote(f"~{partition}~{name}", safe="~")
    path = f"/mgmt/tm/ltm/virtual/{encoded}"
    r = client.get(path)
    if r.status_code != 200:
        raise SystemExit(f"Virtual server not found: {vs_path} ({r.status_code})")
    data = r.json()
    rules = list(data.get("rules") or [])
    if irule_full not in rules:
        rules.append(irule_full)
        print(f"Attaching {irule_full} to VS {vs_path}…")
        resp = client.patch(path, {"rules": rules})
        if resp.status_code not in (200, 201):
            raise SystemExit(f"Attach failed: {resp.status_code} {resp.text}")
        print("VS attach OK")
    else:
        print(f"iRule already on VS {vs_path}")


def zip_lx_workspace(src_dir: Path) -> bytes:
    buf = BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for f in src_dir.rglob("*"):
            if f.is_file() and "node_modules" not in f.parts:
                zf.write(f, f.relative_to(src_dir).as_posix())
    return buf.getvalue()


def deploy_ilx(
    client: BigIPClient,
    plugin_name: str,
    src_dir: Path,
    partition: str = "Common",
) -> None:
    """Best-effort LX package upload; TMOS LX REST varies by version."""
    if not src_dir.is_dir():
        print(f"WARN: LX source missing: {src_dir}", file=sys.stderr)
        return

    blob = zip_lx_workspace(src_dir)
    fname = f"{plugin_name}.zip"
    upload_url = f"/mgmt/shared/file-transfer/uploads/{fname}"
    headers = {
        "Content-Type": "application/octet-stream",
        "Content-Range": f"0-{len(blob) - 1}/{len(blob)}",
    }
    print(f"Uploading LX package {fname} ({len(blob)} bytes)…")
    up = client.session.post(
        client._url(upload_url),
        data=blob,
        headers=headers,
        timeout=120,
    )
    if up.status_code not in (200, 201):
        print(f"WARN: upload failed {up.status_code}: {up.text[:300]}", file=sys.stderr)
        return

    note = {
        "uploaded_to": f"/var/config/rest/downloads/{fname}",
        "plugin": plugin_name,
        "partition": partition,
        "hint": (
            "Finish ILX workspace/extension install via TMUI or TMSH if REST "
            "extension create differs on this TMOS version. Point iRule "
            "mu_lx_plugin / mu_lx_ext at the plugin name."
        ),
    }
    print(json.dumps(note, indent=2))

    # Best-effort workspace + extension metadata
    ws = plugin_name
    wr = client.get(f"/mgmt/tm/ilx/workspace/~{partition}~{ws}")
    if wr.status_code == 404:
        cr = client.post(
            "/mgmt/tm/ilx/workspace",
            {"name": ws, "partition": partition},
        )
        if cr.status_code not in (200, 201):
            print(
                f"WARN: workspace create {cr.status_code} — complete LX via GUI/TMSH",
                file=sys.stderr,
            )
            return
    er = client.post(
        "/mgmt/tm/ilx/extension",
        {"name": plugin_name, "partition": partition, "workspace": ws},
    )
    if er.status_code not in (200, 201):
        print(
            f"WARN: extension POST {er.status_code} — install LX manually if needed",
            file=sys.stderr,
        )
    else:
        print("ILX extension metadata OK")


def main(argv: Optional[list] = None) -> int:
    p = argparse.ArgumentParser(description="Deploy malicious_user via iControl REST")
    p.add_argument("--config", type=Path, default=ROOT / "config" / "default.yaml")
    p.add_argument("--irule", type=Path, default=None, help="Rendered iRule (auto-render if omitted)")
    p.add_argument("--host", default=os.environ.get("BIGIP_HOST", ""))
    p.add_argument("--user", default=os.environ.get("BIGIP_USER", "admin"))
    p.add_argument(
        "--password",
        default=os.environ.get("BIGIP_PASS") or os.environ.get("BIGIP_PASSWORD", ""),
    )
    p.add_argument("--vs", default="", help="Virtual server path, e.g. /Common/app_vs")
    p.add_argument("--skip-lx", action="store_true")
    p.add_argument("--verify-tls", action="store_true")
    args = p.parse_args(argv)

    if not args.host or not args.password:
        print(
            "Set BIGIP_HOST and BIGIP_PASS (or BIGIP_PASSWORD), or pass --host/--password",
            file=sys.stderr,
        )
        return 2

    config = load_config(args.config)
    deploy = config.get("deploy", {})
    partition = deploy.get("partition", "Common")
    irule_name = deploy.get("irule_name", "malicious_user")
    vs = args.vs or deploy.get("virtual_server") or ""
    lx_name = deploy.get("lx_plugin_name", "ai_enrich")

    irule_path = args.irule
    if irule_path is None:
        from render_irule import main as render_main

        rendered = ROOT / "irules" / "malicious_user.rendered.tcl"
        rc = render_main(["-c", str(args.config), "-o", str(rendered)])
        if rc != 0:
            return rc
        irule_path = rendered

    api_anonymous = irule_path.read_text(encoding="utf-8")
    client = BigIPClient(args.host, args.user, args.password, verify=bool(args.verify_tls))

    ver = client.get("/mgmt/tm/sys/version")
    if ver.status_code != 200:
        raise SystemExit(f"Auth/connectivity failed: {ver.status_code} {ver.text[:200]}")
    print("Connected to BIG-IP")

    upsert_irule(client, irule_name, partition, api_anonymous)

    if vs:
        attach_irule_to_vs(client, vs, f"/{partition}/{irule_name}")

    if not args.skip_lx and config.get("ai", {}).get("enabled", True):
        deploy_ilx(client, lx_name, ROOT / "iruleslx" / "ai_enrich", partition=partition)

    print("Deploy finished")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
