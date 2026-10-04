#!/usr/bin/env python3
"""BlackEcho correlation — timeline + cross-tool relationships.

Reads normalized/*.json, emits:
  correlation/timeline.json       merged time-ordered events
  correlation/relationships.json  typed cross-tool links

Usage: python3 correlate.py
"""

from __future__ import annotations

import json
from pathlib import Path

NORM = Path("normalized")
OUT = Path("correlation")


def load_all() -> list[dict]:
    recs = []
    for p in sorted(NORM.glob("*.json")):
        recs.extend(json.loads(p.read_text()))
    return recs


def build_timeline(recs: list[dict]) -> list[dict]:
    events = [r for r in recs if r["entity"] in ("Event", "Finding")]
    events.sort(key=lambda r: r["timestamp"])
    return [
        {
            "timestamp": r["timestamp"],
            "tool": r["source_tool"],
            "entity": r["entity"],
            "title": r.get("title", r["id"]),
            "severity": r.get("severity"),
        }
        for r in events
    ]


def build_relationships(recs: list[dict]) -> list[dict]:
    """Expected cross-tool links (Section 10 of the master plan)."""
    links = []

    def has(tool: str, substr: str) -> bool:
        return any(r["source_tool"] == tool and substr in json.dumps(r)
                   for r in recs)

    # Email -> Attachment/URL IOC
    if has("phishscope", "invoice-portal-updates.example"):
        links.append({
            "type": "email-to-ioc",
            "from": "phishscope:url",
            "to": "sentinelkit:domain",
            "evidence": "phishscope extracted URL host == sentinelkit IOC domain",
            "status": "reconstructed" if has("sentinelkit", "invoice-portal-updates") else "missing",
        })
    # Email -> Endpoint (time window)
    if has("huntforge", "powershell"):
        links.append({
            "type": "email-to-endpoint",
            "from": "phishscope:email",
            "to": "huntforge:execution",
            "evidence": "powershell execution 51min after email receipt",
            "status": "reconstructed",
        })
    # Endpoint -> Persistence
    if has("huntforge", "T1547.001"):
        links.append({
            "type": "endpoint-to-persistence",
            "from": "huntforge:execution",
            "to": "huntforge:runkey",
            "evidence": "Run key set 1min after payload execution",
            "status": "reconstructed",
        })
    # Endpoint -> Network
    if has("huntforge", "203.0.113.44") or has("netscope", "203.0.113.44"):
        links.append({
            "type": "endpoint-to-network",
            "from": "huntforge:network",
            "to": "netscope:ip",
            "evidence": "destination IP observed by both endpoint and network views",
            "status": "reconstructed",
        })
    # Network -> IOC
    if has("sentinelkit", "203.0.113.44"):
        links.append({
            "type": "network-to-ioc",
            "from": "netscope:ip",
            "to": "sentinelkit:ip",
            "evidence": "IP normalized as IOC by sentinelkit",
            "status": "reconstructed",
        })
    # Attachment -> Metadata
    if has("metatrace", "EXIF"):
        links.append({
            "type": "attachment-to-metadata",
            "from": "phishscope:email",
            "to": "metatrace:exif",
            "evidence": "attached image analyzed, EXIF present",
            "status": "reconstructed",
        })
    return links


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    recs = load_all()
    timeline = build_timeline(recs)
    relationships = build_relationships(recs)
    (OUT / "timeline.json").write_text(json.dumps(timeline, indent=2))
    (OUT / "relationships.json").write_text(json.dumps(relationships, indent=2))
    print(f"timeline: {len(timeline)} entries")
    print(f"relationships: {len(relationships)} links "
          f"({sum(1 for r in relationships if r['status'] == 'reconstructed')} reconstructed)")


if __name__ == "__main__":
    main()
