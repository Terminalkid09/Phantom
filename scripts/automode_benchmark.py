#!/usr/bin/env python3
"""automode_benchmark.py — run the AutoMode benchmark offline.

    python scripts/automode_benchmark.py              # the standard suite
    python scripts/automode_benchmark.py --json       # machine-readable report
    python scripts/automode_benchmark.py --scenario open_target
    python scripts/automode_benchmark.py --iterations 20

Every scenario declares GROUND TRUTH (what the target really runs, what it
accepts, whether the goal is reachable at all) and may inject failures, so the
numbers are compared against something instead of being reported into the void.
Nothing leaves the box: the scripted runner answers every command.

Exit code 0 when each scenario honours its own expectations, 1 otherwise — so
CI fails on a change in BEHAVIOUR (a false positive, a lost goal, an
inappropriate action, a silently swallowed failure) and not merely on an
exception.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--scenario", default="",
                        help="run one scenario by name (default: the suite)")
    parser.add_argument("--iterations", type=int, default=12)
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON (for tooling)")
    parser.add_argument("--list", action="store_true",
                        help="list the scenarios and their ground truth")
    parser.add_argument("--compare", action="store_true",
                        help="run the suite twice (AI off, then on) and report "
                             "whether the advice picks the move the ground "
                             "truth says works")
    args = parser.parse_args(argv)

    from phantom.automation import benchmark as bench

    if args.list:
        for scenario in bench.suite():
            data = scenario.to_dict()
            print(f"{data['name']}: {scenario.summary}")
            print(f"    goal={data['goal']} target={data['target']} "
                  f"services={data['services']} creds={data['creds']} "
                  f"reachable={data['reachable']}")
            print(f"    failures={data['failures'] or '{}'} "
                  f"forbidden={data['forbidden']} "
                  f"max_opsec={data['max_opsec']}")
            print(f"    expectations={data['expectations']}")
        return 0

    chosen = bench.suite()
    if args.scenario:
        chosen = tuple(s for s in chosen if s.name == args.scenario)
        if not chosen:
            names = ", ".join(s.name for s in bench.suite())
            print(f"unknown scenario {args.scenario!r} (have: {names})")
            return 1

    if args.compare:
        report = bench.run_comparison(chosen, max_iterations=args.iterations)
        if args.json:
            print(json.dumps(report, indent=2, default=str))
        else:
            off = report["baseline"]["rates"]
            on = report["candidate"]["rates"]
            agree = report["candidate"]["ai"].get("agreement", {})
            print("AUTOMODE BENCHMARK — AI comparison (same scenarios, twice)")
            print(f"  goal reached     off {off.get('goal_reached_pct')}%  "
                  f"on {on.get('goal_reached_pct')}%  "
                  f"delta {report['delta'].get('goal_reached_pct')}")
            print(f"  no intervention  off "
                  f"{off.get('no_operator_intervention_pct')}%  on "
                  f"{on.get('no_operator_intervention_pct')}%")
            print(f"  advice accuracy  deterministic "
                  f"{agree.get('deterministic_pct')}%  ai "
                  f"{agree.get('ai_pct')}%  delta "
                  f"{agree.get('delta_pct')}")
            print(f"  note: {report['note']}")
        return 0

    report = bench.run_suite(chosen, max_iterations=args.iterations)
    if args.json:
        print(json.dumps(report, indent=2, default=str))
    else:
        print(bench.format_table(report))
    return 0 if report.get("passed") else 1


if __name__ == "__main__":
    raise SystemExit(main())
