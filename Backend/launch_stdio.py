"""Legitimate local MCP client entrypoint for Cursor.

Reads MCP_GATEWAY_TOKEN from .env and presents it as MCP_CALLER_TOKEN, then
starts the gateway. Processes that start email_server.py without that token
are rejected. This file does not make Google OAuth count as caller auth.
"""

import os
import runpy
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER = ROOT / "Backend" / "email_server.py"
ENV_FILE = ROOT / ".env"


def _gateway_token() -> str:
    if not ENV_FILE.is_file():
        return ""
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        text = line.strip()
        if not text or text.startswith("#") or "=" not in text:
            continue
        key, value = text.split("=", 1)
        if key.strip() == "MCP_GATEWAY_TOKEN":
            return value.strip().strip('"').strip("'")
    return ""


def main() -> int:
    token = _gateway_token()
    if not token:
        print("Refusing to start: set MCP_GATEWAY_TOKEN in .env.", file=sys.stderr)
        return 1
    os.environ["MCP_CALLER_TOKEN"] = token
    sys.argv = [str(SERVER), "--stdio"]
    runpy.run_path(str(SERVER), run_name="__main__")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
