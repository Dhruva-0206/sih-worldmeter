#!/usr/bin/env python
"""White-Box Security Assessment Framework — CLI entry point.

    python run_assessment.py --target-config config/worldmonitor.yaml
    python run_assessment.py --target-config config/worldmonitor.yaml --target-config config/fixture.yaml
    python run_assessment.py --target-config config/fixture.yaml --sast-only
    python run_assessment.py --target-config config/worldmonitor.yaml --dast-only

Runs: load config(s) -> SAST -> DAST -> correlate -> CVSS score -> generate
PoCs -> write JSON/HTML/PDF report. Every target's base_url is validated as
local/docker-scoped by engine.common.config before any DAST probe can fire —
see that module's UnsafeTargetError for the guardrail this enforces.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from engine.common.config import UnsafeTargetError, load_scan_config
from engine.orchestrator import run_multi
from report.report_generator import generate_report


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="White-Box Security Assessment Framework for the World Monitor application (SIH 2026, PS 26163).",
    )
    parser.add_argument(
        "--target-config", action="append", dest="target_configs", required=True,
        help="Path to a target YAML config (config/worldmonitor.yaml, config/fixture.yaml). Repeatable.",
    )
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--sast-only", action="store_true", help="Run only the SAST modules.")
    mode.add_argument("--dast-only", action="store_true", help="Run only the DAST modules.")
    parser.add_argument("--out-dir", default="output", help="Directory to write the report into (default: output/).")
    parser.add_argument("--report-title", default="World Monitor Security Assessment",
                         help="Title shown at the top of the generated report.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)

    configs = []
    for path in args.target_configs:
        try:
            configs.append(load_scan_config(path))
        except UnsafeTargetError as exc:
            print(f"REFUSING to load {path}: {exc}", file=sys.stderr)
            return 2
        except (OSError, KeyError) as exc:
            print(f"Failed to load {path}: {exc}", file=sys.stderr)
            return 2

    for c in configs:
        print(f"Target loaded: {c.target.name}  (auth_profile={c.target.auth_profile}, "
              f"base_url={c.target.base_url or '(SAST-only, no base_url)'})", file=sys.stderr)

    findings = run_multi(configs, sast_only=args.sast_only, dast_only=args.dast_only)

    paths = generate_report(findings, Path(args.out_dir), report_title=args.report_title)

    print("\n=== Report written ===", file=sys.stderr)
    for kind, path in paths.items():
        print(f"  {kind}: {path if path else '(skipped)'}", file=sys.stderr)

    confirmed = sum(1 for f in findings if f.status == "confirmed")
    print(f"\n{len(findings)} findings total ({confirmed} confirmed) across {len(configs)} target(s).",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
