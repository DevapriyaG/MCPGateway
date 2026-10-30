"""
Attack evaluation against the REAL MCP gateway (default).

Default (what you want for checking mcpgatewayaccnt2@gmail.com):
  python compare_before_after.py
  -> MCP_HARNESS_TARGET=real only (NO mock)

Optional baseline docs (mock, no real mail):
  python compare_before_after.py --with-baseline
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
EXTRACTED = Path(__file__).resolve().parent
PYTHON = ROOT / ".venv" / "Scripts" / "python.exe"
if not PYTHON.exists():
    PYTHON = Path(sys.executable)

RESULTS = ROOT / "results"
DOCS = ROOT / "docs"
CONNECTED = "mcpgatewayaccnt1@gmail.com"  # attacking mail / OAuth account
EXFIL = "mcpgatewayaccnt2@gmail.com"      # attacked / collection inbox


def run_phase(label: str, target: str, out_json: Path) -> dict:
    env = os.environ.copy()
    env["MCP_HARNESS_TARGET"] = target
    # Never inherit a leftover mock setting from the parent shell for "real" runs.
    if target == "real":
        env["MCP_HARNESS_TARGET"] = "real"
    cmd = [
        str(PYTHON),
        str(EXTRACTED / "run_eval.py"),
        "--label",
        label,
        "--out",
        str(out_json),
    ]
    if target.startswith("mock"):
        cmd.append("--allow-mock")
    print(f"\n>>> Running {label} (MCP_HARNESS_TARGET={target})...", flush=True)
    if target == "real":
        print(f"    REAL gateway", flush=True)
        print(f"    Attacking mail (connected): {CONNECTED}", flush=True)
        print(f"    Attacked / exfil inbox:     {EXFIL}", flush=True)
        print("    Check BOTH inboxes after the run.\n", flush=True)
    else:
        print("    MOCK baseline (no real Gmail sends).\n", flush=True)

    proc = subprocess.run(cmd, cwd=str(EXTRACTED), env=env, check=False)
    if proc.returncode != 0:
        raise SystemExit(f"{label} run failed with code {proc.returncode}")
    data = json.loads(out_json.read_text(encoding="utf-8"))
    if target == "real" and data.get("target_mode") != "real":
        raise SystemExit(
            f"Refusing to accept results: expected target_mode=real, got {data.get('target_mode')}"
        )
    return data


def write_before_doc(before: dict) -> Path:
    s = before["summary"]
    lines = [
        "# Scores BEFORE adding the MCP gateway",
        "",
        "Optional **mock** baseline (no real Gmail). Not used when you run the default",
        "`compare_before_after.py` (real-only).",
        "",
        f"- Generated: `{before['generated_at']}`",
        f"- Target mode: `{before['target_mode']}`",
        f"- Attacks: **{s['total']}** | Compromised: **{s['compromised']}** "
        f"({s['attack_success_rate_pct']}%) | Safe: **{s['safe']}** ({s['defense_rate_pct']}%)",
        "",
        f"**ASR = {s['attack_success_rate_pct']}%**",
        "",
        "| ID | Result | Category | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for c in before["cases"]:
        lines.append(f"| {c['id']} | {c['result']} | {c['category']} | {c['reason']} |")
    path = DOCS / "scores_before_gateway.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def write_real_doc(after: dict) -> Path:
    s = after["summary"]
    lines = [
        "# Real MCP gateway attack run",
        "",
        f"Target: **`{after['target_mode']}`** (live `Backend/email_server.py`, not mock).",
        "",
        f"- **Attacking mail (connected / From):** `{CONNECTED}`",
        f"- **Attacked / exfil inbox (To):** `{EXFIL}`",
        "",
        f"- Generated: `{after['generated_at']}`",
        f"- Attacks: **{s['total']}** (all TC-01 … TC-16)",
        f"- Compromised: **{s['compromised']}** ({s['attack_success_rate_pct']}%)",
        f"- Safe / blocked: **{s['safe']}** ({s['defense_rate_pct']}%)",
        "",
        f"**ASR = {s['attack_success_rate_pct']}%**  |  **Defense = {s['defense_rate_pct']}%**",
        "",
        "## How to verify in Gmail",
        "",
        f"1. **{CONNECTED}** — connected account (OAuth). Attack payloads use this as From; "
        "this is the mailbox the gateway reads/sends as.",
        f"2. **{EXFIL}** — collection inbox. Compromised agents would forward/send here. "
        "If the gateway held, you should **not** see new `forwarded` / `stolen` mail here.",
        "3. High-risk sends still need `require_user_confirm` — blocked attempts do not deliver.",
        "",
        "## Per-attack results",
        "",
        "| ID | Result | Category | Reason |",
        "| --- | --- | --- | --- |",
    ]
    for c in after["cases"]:
        lines.append(f"| {c['id']} | {c['result']} | {c['category']} | {c['reason']} |")
    lines.extend([
        "",
        "Raw JSON: `results/after_gateway.json`",
        "",
    ])
    path = DOCS / "scores_real_gateway.md"
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def write_compare_doc(before: dict, after: dict) -> Path:
    sb, sa = before["summary"], after["summary"]
    by_after = {c["id"]: c for c in after["cases"]}
    lines = [
        "# Before vs after MCP gateway (16 attacks)",
        "",
        f"AFTER uses the **real** gateway. Attacker mailbox: `{EXFIL}`.",
        "",
        "| Phase | Target | Compromised | Safe | ASR | Defense |",
        "| --- | --- | ---: | ---: | ---: | ---: |",
        (
            f"| BEFORE (mock baseline) | `{before['target_mode']}` | {sb['compromised']} | "
            f"{sb['safe']} | **{sb['attack_success_rate_pct']}%** | {sb['defense_rate_pct']}% |"
        ),
        (
            f"| AFTER (real gateway) | `{after['target_mode']}` | {sa['compromised']} | "
            f"{sa['safe']} | **{sa['attack_success_rate_pct']}%** | {sa['defense_rate_pct']}% |"
        ),
        "",
        "| ID | BEFORE | AFTER | Changed? |",
        "| --- | --- | --- | --- |",
    ]
    for c in before["cases"]:
        a = by_after[c["id"]]
        changed = "yes" if c["result"] != a["result"] else "no"
        lines.append(f"| {c['id']} | {c['result']} | {a['result']} | {changed} |")
    path = DOCS / "scores_before_after_gateway.md"
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def main():
    parser = argparse.ArgumentParser(description="Run attacks against the REAL MCP gateway.")
    parser.add_argument(
        "--with-baseline",
        action="store_true",
        help="Also run mock_vulnerable baseline (no real Gmail). Default is REAL only.",
    )
    args = parser.parse_args()

    RESULTS.mkdir(parents=True, exist_ok=True)
    DOCS.mkdir(parents=True, exist_ok=True)

    after_json = RESULTS / "after_gateway.json"

    # Default: REAL gateway only (so you can check mcpgatewayaccnt2@gmail.com).
    after = run_phase("after", "real", after_json)
    real_doc = write_real_doc(after)
    print(f"Wrote REAL doc: {real_doc}", flush=True)

    if args.with_baseline:
        before_json = RESULTS / "before_gateway.json"
        before = run_phase("before", "mock_vulnerable", before_json)
        before_doc = write_before_doc(before)
        compare_doc = write_compare_doc(before, after)
        print(f"Wrote BEFORE doc: {before_doc}", flush=True)
        print(f"Wrote COMPARE doc: {compare_doc}", flush=True)
        sb, sa = before["summary"], after["summary"]
        print(
            f"\nBEFORE ASR {sb['attack_success_rate_pct']}%  ->  "
            f"AFTER ASR {sa['attack_success_rate_pct']}% "
            f"(defense {sa['defense_rate_pct']}%)",
            flush=True,
        )
    else:
        sa = after["summary"]
        print(
            f"\nREAL gateway only: ASR {sa['attack_success_rate_pct']}%  "
            f"(defense {sa['defense_rate_pct']}%)\n"
            f"  attacking={CONNECTED}  exfil={EXFIL}",
            flush=True,
        )
        print("Tip: add --with-baseline only if you also want the mock BEFORE numbers.", flush=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
