"""BlackEcho tests — schema, determinism, isolation, pipeline."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))


def test_envelope_schema_valid():
    """Every normalized record carries the required envelope fields."""
    required = {"id", "entity", "source_tool", "source_version",
                "timestamp", "confidence", "provenance", "record_kind"}
    for p in (ROOT / "normalized").glob("*.json"):
        for rec in json.loads(p.read_text()):
            assert required <= set(rec), f"{p.name}: missing {required - set(rec)}"
            assert rec["entity"] in ("Finding", "IOC", "Artifact", "Event",
                                     "Host", "User", "Evidence")
            assert rec["record_kind"] in ("observed", "inferred")


def test_evidence_deterministic():
    """Two factory runs produce identical manifest hashes."""
    import hashlib
    m1 = json.loads((ROOT / "evidence" / "manifest.json").read_text())
    # Re-run factory into a temp dir and compare
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        subprocess.run([sys.executable, "evidence_factory.py", "--out", td],
                       cwd=ROOT, check=True, capture_output=True)
        m2 = json.loads((Path(td) / "manifest.json").read_text())
    for rel, info in m1["files"].items():
        assert rel in m2["files"], f"missing {rel} in second run"
        assert m2["files"][rel]["sha256"] == info["sha256"], f"{rel} not deterministic"


def test_ground_truth_isolation():
    """No runner opens/reads ground-truth/ (docstring mentions are fine)."""
    import re
    for p in (ROOT / "runners").glob("*.py"):
        for i, line in enumerate(p.read_text().splitlines(), 1):
            stripped = line.strip()
            # Skip comments and docstrings
            if stripped.startswith(("#", '"""', "'''")):
                continue
            if re.search(r'(open|Path|read_text|read_bytes)\s*\([^)]*ground', line):
                raise AssertionError(f"{p.name}:{i} reads ground truth")


def test_pipeline_outputs_exist():
    for p in ["correlation/timeline.json", "correlation/relationships.json",
              "scoring/results.json", "reports/blackecho-report.md"]:
        assert (ROOT / p).exists(), f"missing {p}"


def test_scoring_thresholds():
    r = json.loads((ROOT / "scoring" / "results.json").read_text())
    assert r["coverage_pct"] >= 75, f"coverage {r['coverage_pct']}% below 75%"
    assert r["false_positives"] <= 2, f"too many FPs: {r['false_positives']}"
    assert len(r["tools_reporting"]) == 8, "not all tools reported"
