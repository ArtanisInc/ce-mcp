"""Smoke-test CE MCP SSE endpoint.

Requires:
- Cheat Engine running with the `ce-mcp.dll` plugin enabled
- Server started (MCP -> Start)

The MCP SSE endpoint is a streaming response. This script only validates that
the server accepts the request (status code) with proper authentication.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.request


def main() -> int:
    appdata = os.environ.get("APPDATA")
    if not appdata:
        print("APPDATA is not set", file=sys.stderr)
        return 2

    cfg_path = os.path.join(appdata, "CeMCP", "config.json")
    if not os.path.exists(cfg_path):
        print(f"Config not found: {cfg_path}", file=sys.stderr)
        return 2

    with open(cfg_path, "r", encoding="utf-8") as f:
        cfg = json.load(f)

    host = (cfg.get("Host") or "127.0.0.1").strip()
    port = int(cfg.get("Port") or 6300)
    token = (os.environ.get("MCP_AUTH_TOKEN") or cfg.get("AuthToken") or "").strip()
    if not token:
        print(
            "Auth token not found (set MCP_AUTH_TOKEN or configure in UI)",
            file=sys.stderr,
        )
        return 2

    url = f"http://{host}:{port}/sse"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})

    try:
        resp = urllib.request.urlopen(req, timeout=5)
    except Exception as e:
        print(f"Request failed: {e}", file=sys.stderr)
        return 1

    try:
        print(
            f"OK: {resp.status} {resp.reason} ({resp.headers.get('Content-Type', '')})"
        )
        return 0
    finally:
        try:
            resp.close()
        except Exception:
            pass


if __name__ == "__main__":
    raise SystemExit(main())
