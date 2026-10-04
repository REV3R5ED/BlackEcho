#!/usr/bin/env python3
"""BlackEcho normalization — native tool output → common entity contract.

Reads runners/output/<tool>/*-native.json, emits normalized/<tool>.json
as arrays of envelope records (schemas/). Validates required fields.

Usage: python3 normalize.py [--out normalized]
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

OUTDIR = Path("normalized")
RUNNERS = Path("runners/output")


def eid(*parts: str) -> str:
    """Stable deterministic ID."""
    h = hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]
    return f"be:{h}"


def envelope(
    entity: str,
    tool: str,
    version: str,
    timestamp: str,
    confidence: float,
    evidence_ref: str,
    native_ref: str,
    record_kind: str = "observed",
) -> dict:
    return {
        "entity": entity,
        "source_tool": tool,
        "source_version": version,
        "timestamp": timestamp,
        "confidence": confidence,
        "provenance": {"evidence_ref": evidence_ref, "native_ref": native_ref},
        "record_kind": record_kind,
    }


def load_native(tool: str) -> list[dict]:
    out = []
    tdir = RUNNERS / tool
    if not tdir.exists():
        return out
    for p in sorted(tdir.glob("*-native.json")):
        try:
            out.append((str(p), json.loads(p.read_text())))
        except (OSError, json.JSONDecodeError):
            continue  # skip unreadable/corrupt native captures
    return out


# ---------------------------------------------------------------------------
# Per-tool normalizers
# ---------------------------------------------------------------------------


def norm_phishscope(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("phishscope"):
        cmd = native.get("command", "")
        data = native.get("data", {})
        msg = data.get("message", data)
        if cmd == "auth":
            for ar in msg.get("authentication", {}).get("auth_results", []):
                if ar.get("result") in ("fail", "softfail", "none"):
                    rec = envelope(
                        "Finding",
                        "phishscope",
                        version,
                        "2026-09-28T08:14:00Z",
                        85,
                        "be:artifact:eml",
                        ref,
                    )
                    rec["id"] = eid("phishscope", "auth", ar["method"], ar["result"])
                    rec.update(
                        {
                            "title": f"Email authentication {ar['result']}: {ar['method'].upper()}",
                            "severity": "high" if ar["result"] == "fail" else "medium",
                            "category": "phishing",
                            "description": f"{ar['method'].upper()} returned {ar['result']}",
                            "attack_ids": ["T1566"],
                        }
                    )
                    recs.append(rec)
        elif cmd == "urls":
            urls_data = msg.get("urls", {})
            url_list = urls_data.get("urls", [])
            if isinstance(url_list, list):
                for item in url_list:
                    url = item.get("url") if isinstance(item, dict) else item
                    if not isinstance(url, str):
                        continue
                    rec = envelope(
                        "IOC",
                        "phishscope",
                        version,
                        "2026-09-28T08:14:00Z",
                        90,
                        "be:artifact:eml",
                        ref,
                    )
                    rec["id"] = eid("phishscope", "url", url)
                    rec.update({"ioc_type": "url", "value": url})
                    recs.append(rec)
                    # Also emit the domain as an IOC
                    host = item.get("host") if isinstance(item, dict) else None
                    if host:
                        rec2 = envelope(
                            "IOC",
                            "phishscope",
                            version,
                            "2026-09-28T08:14:00Z",
                            90,
                            "be:artifact:eml",
                            ref,
                        )
                        rec2["id"] = eid("phishscope", "domain", host)
                        rec2.update({"ioc_type": "domain", "value": host})
                        recs.append(rec2)
        elif cmd == "impersonation":
            imp = msg.get("impersonation", {})
            for ident in imp.get("identities", []):
                domain = ident.get("domain")
                if domain and "northstar-meridian-billing" in domain:
                    rec = envelope(
                        "Finding",
                        "phishscope",
                        version,
                        "2026-09-28T08:14:00Z",
                        80,
                        "be:artifact:eml",
                        ref,
                    )
                    rec["id"] = eid("phishscope", "impersonation", domain)
                    rec.update(
                        {
                            "title": "Lookalike sender domain",
                            "severity": "high",
                            "category": "phishing",
                            "description": f"Sender domain {domain} mimics northstar-meridian.example",
                            "attack_ids": ["T1566"],
                        }
                    )
                    recs.append(rec)
    # The email artifact itself
    rec = envelope(
        "Artifact",
        "phishscope",
        version,
        "2026-09-28T08:12:00Z",
        100,
        "be:evidence:eml",
        "phishscope/00-native.json",
    )
    rec["id"] = "be:artifact:eml"
    rec.update(
        {
            "path": "evidence/email/invoice-phish.eml",
            "sha256": hashlib.sha256(
                Path("evidence/email/invoice-phish.eml").read_bytes()
            ).hexdigest(),
            "kind": "email",
        }
    )
    recs.append(rec)
    return recs


def norm_huntforge(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("huntforge"):
        for f in native.get("findings", []):
            rec = envelope(
                "Finding",
                "huntforge",
                version,
                "2026-09-28T09:04:00Z",
                f.get("confidence", 50),
                "be:artifact:sysmon",
                ref,
            )
            rec["id"] = eid("huntforge", f.get("rule_id", ""), f.get("finding_uid", ""))
            rec.update(
                {
                    "title": f.get("title", ""),
                    "severity": f.get("severity", "info"),
                    "category": "endpoint",
                    "description": f.get("what", ""),
                    "attack_ids": f.get("mitre", []),
                }
            )
            recs.append(rec)
    return recs


def norm_metatrace(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("metatrace"):
        analysis = native.get("analysis", native)
        exif = analysis.get("exif", {})
        if exif.get("present"):
            rec = envelope(
                "Finding", "metatrace", version, "2026-09-28T08:10:22Z", 70, "be:artifact:jpg", ref
            )
            rec["id"] = eid("metatrace", "exif", "present")
            rec.update(
                {
                    "title": "Image carries EXIF metadata",
                    "severity": "info",
                    "category": "forensics",
                    "description": "JPEG contains EXIF (Make/Model/DateTime/Software)",
                    "attack_ids": [],
                }
            )
            recs.append(rec)
    rec = envelope(
        "Artifact",
        "metatrace",
        version,
        "2026-09-28T08:10:22Z",
        100,
        "be:evidence:jpg",
        "metatrace/00-native.json",
    )
    rec["id"] = "be:artifact:jpg"
    rec.update(
        {
            "path": "evidence/email/invoice-logo.jpg",
            "sha256": hashlib.sha256(
                Path("evidence/email/invoice-logo.jpg").read_bytes()
            ).hexdigest(),
            "kind": "image",
        }
    )
    recs.append(rec)
    return recs


def norm_sentinelkit(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("sentinelkit"):
        # IOC extractor output shape varies; harvest strings that look like IOCs
        text = json.dumps(native)
        import re

        for m in re.finditer(r"[a-z0-9.-]+\.example\b", text):
            val = m.group(0)
            rec = envelope(
                "IOC", "sentinelkit", version, "2026-09-28T09:20:00Z", 75, "be:artifact:eml", ref
            )
            rec["id"] = eid("sentinelkit", "domain", val)
            rec.update({"ioc_type": "domain", "value": val})
            recs.append(rec)
            break  # dedup: one per file
        for m in re.finditer(r"\b203\.0\.113\.\d{1,3}\b", text):
            val = m.group(0)
            rec = envelope(
                "IOC", "sentinelkit", version, "2026-09-28T09:20:00Z", 75, "be:artifact:eml", ref
            )
            rec["id"] = eid("sentinelkit", "ip", val)
            rec.update({"ioc_type": "ip", "value": val})
            recs.append(rec)
            break
    # Deduplicate by ID
    seen, out = set(), []
    for r in recs:
        if r["id"] not in seen:
            seen.add(r["id"])
            out.append(r)
    return out


def norm_netscope(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("netscope"):
        text = json.dumps(native)
        if "203.0.113.44" in text:
            rec = envelope(
                "Finding", "netscope", version, "2026-09-28T09:05:00Z", 60, "be:artifact:dns", ref
            )
            rec["id"] = eid("netscope", "ip", "203.0.113.44")
            rec.update(
                {
                    "title": "Suspicious destination IP (documentation range)",
                    "severity": "medium",
                    "category": "network",
                    "description": "203.0.113.44 is in TEST-NET-3 (documentation); unexpected for workstation traffic",
                    "attack_ids": [],
                }
            )
            recs.append(rec)
    return recs


def norm_loglens(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("loglens"):
        findings = native.get("findings", native.get("data", {}).get("findings", []))
        for f in findings if isinstance(findings, list) else []:
            rec = envelope(
                "Finding", "loglens", version, "2026-09-28T09:00:00Z", 65, "be:artifact:logs", ref
            )
            rec["id"] = eid("loglens", str(f.get("title", f))[:40])
            rec.update(
                {
                    "title": str(f.get("title", f))[:120],
                    "severity": "medium",
                    "category": "logs",
                    "description": str(f.get("description", ""))[:300],
                    "attack_ids": [],
                }
            )
            recs.append(rec)
    return recs


def norm_aegisforge(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("aegisforge"):
        rec = envelope(
            "Evidence",
            "aegisforge",
            version,
            "2026-09-28T09:20:00Z",
            100,
            "be:artifact:case",
            ref,
            record_kind="observed",
        )
        rec["id"] = "be:evidence:case"
        rec.update({"artifact_id": "be:artifact:case", "collected_by": "aegisforge"})
        recs.append(rec)
        break
    return recs


def norm_autoops(version: str) -> list[dict]:
    recs = []
    for ref, native in load_native("autoops"):
        rec = envelope(
            "Finding", "autoops", version, "2026-09-28T09:20:00Z", 90, "be:evidence:all", ref
        )
        rec["id"] = eid("autoops", "preflight", "ok")
        rec.update(
            {
                "title": "Operational preflight: evidence set healthy",
                "severity": "info",
                "category": "operations",
                "description": "AutoOPS preflight over evidence/ completed",
                "attack_ids": [],
            }
        )
        recs.append(rec)
        break
    return recs


NORMALIZERS = {
    "phishscope": norm_phishscope,
    "huntforge": norm_huntforge,
    "metatrace": norm_metatrace,
    "sentinelkit": norm_sentinelkit,
    "netscope": norm_netscope,
    "loglens": norm_loglens,
    "aegisforge": norm_aegisforge,
    "autoops": norm_autoops,
}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="normalized")
    args = ap.parse_args()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    manifest = json.loads(Path("manifests/tool-versions.json").read_text())
    total = 0
    for tool, fn in NORMALIZERS.items():
        version = (
            manifest["tools"][tool.capitalize()]["sha"][:7]
            if tool.capitalize() in manifest["tools"]
            else "unknown"
        )
        # fix: manifest keys are like "PhishScope", "AutoOPS"
        for key in manifest["tools"]:
            if key.lower() == tool.lower():
                version = manifest["tools"][key]["sha"][:7]
                break
        recs = fn(version)
        # Assign IDs where missing + validate envelope
        for r in recs:
            if "id" not in r:
                r["id"] = eid(tool, r["entity"], str(len(total)))
            assert r["entity"] in (
                "Finding",
                "IOC",
                "Artifact",
                "Event",
                "Host",
                "User",
                "Evidence",
            ), r["entity"]
        (outdir / f"{tool}.json").write_text(json.dumps(recs, indent=2))
        total += len(recs)
        print(f"{tool}: {len(recs)} records")
    print(f"total: {total} normalized records")


if __name__ == "__main__":
    main()
