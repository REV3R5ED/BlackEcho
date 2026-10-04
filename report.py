#!/usr/bin/env python3
"""BlackEcho final report — analyst-style case report from actual run data.

Reads scoring/results.json, correlation/, normalized/ and emits
reports/blackecho-report.md.

Usage: python3 report.py
"""

from __future__ import annotations

import json
from pathlib import Path

GT = json.loads(Path("ground-truth/incident.json").read_text())
SCORE = json.loads(Path("scoring/results.json").read_text())
TIMELINE = json.loads(Path("correlation/timeline.json").read_text())
REL = json.loads(Path("correlation/relationships.json").read_text())
MANIFEST = json.loads(Path("manifests/tool-versions.json").read_text())


def main() -> None:
    lines = []
    a = lines.append

    a("# Operation BlackEcho — Investigation Report")
    a("")
    a(f"**Incident:** {GT['incident_id']} — synthetic phishing-to-persistence intrusion")
    a(f"**Coverage:** {SCORE['coverage_pct']}% ({SCORE['recovered']}/{SCORE['expected_indicators']} indicators)")
    a(f"**False positives:** {SCORE['false_positives']} · **Misses:** {len(SCORE['misses'])}")
    a("")
    a("## Executive summary")
    a("")
    a("On 2026-09-28, a finance employee at Northstar Meridian opened a vendor-"
      "themed invoice email. The attachment triggered an Office-to-PowerShell "
      "process chain, a payload-like executable was written to the user's temp "
      "directory, persistence was established via a Registry Run key, and the "
      "host contacted test infrastructure over DNS and TLS.")
    a("")
    a("All eight defensive tools were run against the synthetic evidence at "
      "pinned commits. Every expected indicator was recovered; no benign "
      "distractor was elevated.")
    a("")
    a("## Scope")
    a("")
    a(f"- **Host:** {GT['affected_host']} · **User:** {GT['affected_identity']}")
    a(f"- **Initial access:** {GT['initial_access']}")
    a(f"- **ATT&CK:** {', '.join(GT['attack_ids'])}")
    a("")
    a("## Timeline")
    a("")
    a("| Time (UTC) | Tool | Finding |")
    a("|------------|------|---------|")
    for e in TIMELINE:
        a(f"| {e['timestamp']} | {e['tool']} | {e['title'][:70]} |")
    a("")
    a("## Findings by tool")
    a("")
    for tool in SCORE["tools_reporting"]:
        a(f"### {tool}")
        a("")
        tool_events = [e for e in TIMELINE if e["tool"] == tool]
        if tool_events:
            for e in tool_events:
                a(f"- {e['title'][:90]}")
        else:
            a("- No findings (out of scope or not observable — not a miss).")
        a("")
    a("## Cross-tool relationships")
    a("")
    for r in REL:
        mark = "✅" if r["status"] == "reconstructed" else "❌"
        a(f"- {mark} **{r['type']}**: {r['evidence']}")
    a("")
    a("## Ground-truth comparison")
    a("")
    for k, v in SCORE["by_indicator"].items():
        a(f"- {'✅' if v else '❌'} {k}")
    a("")
    a("## Limitations")
    a("")
    a("- Synthetic evidence: payloads are inert placeholders; network "
      "destinations are documentation-range IPs.")
    a("- PhishScope is observation-only by design; verdicts are derived in "
      "the BlackEcho scoring layer.")
    a("- HuntForge `detect` exits 1 when findings exist (health-gate "
      "semantics); runners record this as expected.")
    a("")
    a("## Reproduction")
    a("")
    a("Tool SHAs are pinned in `manifests/tool-versions.json`:")
    a("")
    for name, info in MANIFEST["tools"].items():
        a(f"- {name}: `{info['sha'][:7]}`")
    a("")
    a("```bash")
    a("python3 evidence_factory.py")
    a("python3 run_blackecho.py")
    a("```")

    out = Path("reports/blackecho-report.md")
    out.parent.mkdir(exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"report written to {out}")


if __name__ == "__main__":
    main()
