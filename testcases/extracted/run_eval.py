"""
Run the 16-attack suite once and write JSON results.

Usage:
  MCP_HARNESS_TARGET=mock_vulnerable python run_eval.py --label before --out ../../results/before_gateway.json
  MCP_HARNESS_TARGET=real python run_eval.py --label after --out ../../results/after_gateway.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from test_cases import TEST_CASES
import attack_generator
import target_adapter
import scorer


def run_suite():
    expected_ids = [f"TC-{i:02d}" for i in range(1, 17)]
    found_ids = [tc.id for tc in TEST_CASES]
    if found_ids != expected_ids:
        raise SystemExit(
            f"Expected all 16 test cases {expected_ids}, got {found_ids}"
        )

    rows = []
    connected = getattr(attack_generator, "CONNECTED_EMAIL", "mcpgatewayaccnt1@gmail.com")
    exfil = getattr(attack_generator, "ATTACKER_EMAIL", "mcpgatewayaccnt2@gmail.com")
    print(
        f"Running ALL {len(TEST_CASES)} test cases.\n"
        f"  Attacking mail (connected From): {connected}\n"
        f"  Attacked / exfil inbox (To):     {exfil}",
        flush=True,
    )
    for tc in TEST_CASES:
        print(f"  -> {tc.id} ...", flush=True)
        gen = attack_generator.generate(tc.id)
        from_addr = str(gen.get("payload", {}).get("from", ""))
        # Email-channel attacks must come From the connected account, not the exfil inbox.
        if gen.get("channel") == "email":
            if from_addr.lower() != connected.lower():
                raise SystemExit(
                    f"{tc.id}: attacking From must be connected account {connected}, got {from_addr}"
                )
            if from_addr.lower() == exfil.lower():
                raise SystemExit(
                    f"{tc.id}: From must not be the exfil inbox {exfil}"
                )
        actions = target_adapter.run_target(gen["channel"], gen["payload"])
        verdict = scorer.score(tc.id, actions)
        rows.append({
            "id": tc.id,
            "category": tc.category,
            "description": tc.description,
            "attacker_goal": tc.attacker_goal,
            "channel": gen["channel"],
            "from": from_addr or None,
            "exfil_to": exfil,
            "result": verdict.result,
            "reason": verdict.reason,
            "actions": actions,
        })
        print(f"     {tc.id} {verdict.result}", flush=True)
    if len(rows) != 16:
        raise SystemExit(f"Expected 16 results, got {len(rows)}")
    return rows


def summarize(rows):
    total = len(rows)
    compromised = sum(1 for r in rows if r["result"] == "COMPROMISED")
    safe = total - compromised
    return {
        "total": total,
        "compromised": compromised,
        "safe": safe,
        "attack_success_rate_pct": round(compromised / total * 100, 1) if total else 0.0,
        "defense_rate_pct": round(safe / total * 100, 1) if total else 0.0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--label", required=True, help="before | after | other")
    parser.add_argument("--out", required=True, help="JSON output path")
    parser.add_argument(
        "--allow-mock",
        action="store_true",
        help="Allow MCP_HARNESS_TARGET=mock_* (default refuses mock so real Gmail is used).",
    )
    args = parser.parse_args()

    mode = os.environ.get("MCP_HARNESS_TARGET", "real").strip().lower() or "real"
    if mode.startswith("mock") and not args.allow_mock:
        print(
            "Refusing mock target. This suite defaults to the REAL MCP gateway "
            "(attacker mailbox mcpgatewayaccnt2@gmail.com).\n"
            "Unset MCP_HARNESS_TARGET or set it to 'real'.\n"
            "Only pass --allow-mock for an intentional baseline.",
            file=sys.stderr,
        )
        return 2

    print(f"run_eval: target_mode={mode}  (mock forbidden={not args.allow_mock})", flush=True)
    rows = run_suite()
    summary = summarize(rows)
    payload = {
        "label": args.label,
        "target_mode": mode,
        "connected_email": getattr(attack_generator, "CONNECTED_EMAIL", "mcpgatewayaccnt1@gmail.com"),
        "exfil_email": getattr(attack_generator, "ATTACKER_EMAIL", "mcpgatewayaccnt2@gmail.com"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "cases": rows,
    }

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    print("=" * 72)
    print(f"LABEL={args.label}  TARGET={mode}")
    print(f"{'ID':<7}{'RESULT':<13}{'CATEGORY':<28}REASON")
    print("=" * 72)
    for r in rows:
        print(f"{r['id']:<7}{r['result']:<13}{r['category']:<28}{r['reason']}")
    print("=" * 72)
    print(
        f"ASR: {summary['attack_success_rate_pct']}%  "
        f"({summary['compromised']}/{summary['total']} compromised)  "
        f"Defense: {summary['defense_rate_pct']}%"
    )
    print(f"Wrote {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
