#!/usr/bin/env python3
"""Operation BlackEcho — full pipeline orchestrator.

Runs the complete scenario: evidence → runners → normalize →
correlate → score → report.

Usage: python3 run_blackecho.py [--skip-evidence]
"""

from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

STAGES = [
    ("evidence", [sys.executable, "evidence_factory.py"]),
    (
        "runners",
        [
            sys.executable,
            "-c",
            (
                "from pathlib import Path;"
                "from runners.phishscope import PhishScopeRunner;"
                "from runners.metatrace import MetaTraceRunner;"
                "from runners.huntforge import HuntForgeRunner;"
                "from runners.loglens import LogLensRunner;"
                "from runners.netscope import NetScopeRunner;"
                "from runners.sentinelkit import SentinelKitRunner;"
                "from runners.aegisforge import AegisForgeRunner;"
                "from runners.autoops import AutoOPRunner;"
                "ev=Path('evidence');"
                "[c().run(ev) for c in (PhishScopeRunner,MetaTraceRunner,HuntForgeRunner,"
                "LogLensRunner,NetScopeRunner,SentinelKitRunner,AegisForgeRunner,AutoOPRunner)];"
                "print('all runners complete')"
            ),
        ],
    ),
    ("normalize", [sys.executable, "normalize.py"]),
    ("correlate", [sys.executable, "correlate.py"]),
    ("score", [sys.executable, "score.py"]),
    ("report", [sys.executable, "report.py"]),
]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-evidence", action="store_true")
    ap.add_argument("--from-stage", default=None)
    args = ap.parse_args()

    started = args.from_stage is None
    for name, argv in STAGES:
        if args.from_stage == name:
            started = True
        if not started:
            continue
        if name == "evidence" and args.skip_evidence:
            print("--- skip evidence (reuse existing) ---")
            continue
        print(f"--- stage: {name} ---")
        proc = subprocess.run(argv, cwd=Path.cwd(), check=False)
        if proc.returncode != 0:
            print(f"stage {name} failed (exit {proc.returncode})", file=sys.stderr)
            sys.exit(1)
    print("BlackEcho pipeline complete.")


if __name__ == "__main__":
    main()
