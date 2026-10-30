"""
Run the full test suite against target_adapter.run_target and report results.

Usage:
    python3 harness.py

Swap target_adapter.run_target for your real agent (see the docstring in
target_adapter.py) and re-run — nothing else here needs to change.
"""

from test_cases import TEST_CASES
import attack_generator
import target_adapter
import scorer


def run_suite():
    results = []
    for tc in TEST_CASES:
        gen = attack_generator.generate(tc.id)
        # The target only ever sees channel + payload. No id, no category,
        # no attacker_goal — that metadata never crosses this line.
        actions = target_adapter.run_target(gen["channel"], gen["payload"])
        verdict = scorer.score(tc.id, actions)
        results.append((tc, verdict))
    return results


def report(results):
    compromised = [v for _, v in results if v.result == "COMPROMISED"]
    total = len(results)

    print("=" * 72)
    print(f"{'ID':<7}{'RESULT':<13}{'CATEGORY':<28}REASON")
    print("=" * 72)
    for tc, v in results:
        print(f"{v.test_id:<7}{v.result:<13}{tc.category:<28}{v.reason}")
    print("=" * 72)

    asr = len(compromised) / total * 100
    print(f"\nAttack Success Rate: {asr:.1f}%  ({len(compromised)}/{total} test cases compromised)")
    print(f"Defense Rate:         {100 - asr:.1f}%")

    if compromised:
        print("\nFailing categories to prioritize:")
        cats = sorted({tc.category for tc, v in results if v.result == "COMPROMISED"})
        for c in cats:
            print(f"  - {c}")
    else:
        print("\nAll test cases passed against this run. Remember: this is 8 test "
              "cases, not full coverage — rotate/expand payloads before calling "
              "the model production-ready, and check utility on benign input too.")


def run_security_guarantees():
    """Identity, replay, argument, route, cancellation, and restart checks."""
    import security_guarantees

    results = security_guarantees.run_guarantees()
    return security_guarantees.report(results)


if __name__ == "__main__":
    import os
    import sys

    if "--guarantees" in sys.argv:
        raise SystemExit(run_security_guarantees())

    mode = os.environ.get("MCP_HARNESS_TARGET", "real").strip().lower() or "real"
    if mode.startswith("mock") and "--allow-mock" not in __import__("sys").argv:
        raise SystemExit(
            "harness.py defaults to the REAL MCP gateway (not mock).\n"
            "Unset MCP_HARNESS_TARGET or set MCP_HARNESS_TARGET=real.\n"
            "For an intentional mock run: MCP_HARNESS_TARGET=mock_vulnerable python harness.py --allow-mock"
        )
    print(
        f"harness target_mode={mode}  "
        f"attacking=mcpgatewayaccnt1@gmail.com  exfil=mcpgatewayaccnt2@gmail.com",
        flush=True,
    )
    results = run_suite()
    report(results)
    print("\nSecurity guarantees (fresh process for restart):", flush=True)
    guarantee_code = run_security_guarantees()
    if guarantee_code != 0:
        raise SystemExit(guarantee_code)
