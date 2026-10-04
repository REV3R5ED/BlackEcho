# SCENARIO.md — Operation BlackEcho incident narrative

> All entities are fictional. All evidence is synthetic. Any resemblance to
> real persons, companies, or infrastructure is coincidental.

## The incident

**Northstar Meridian**, a fictional financial services company, opens a
routine Tuesday with an incident ticket: the SOC's email gateway flagged a
vendor invoice message, and the recipient — a finance employee — admits they
opened the attachment before the warning arrived.

## Timeline (ground truth)

| Time (UTC) | Event |
|------------|-------|
| 2026-09-28 08:12 | Attacker sends vendor-themed invoice email to `finance.user@northstar-meridian.example` |
| 2026-09-28 08:14 | Email received; gateway flags it 6 minutes later (too late) |
| 2026-09-28 09:03 | `finance.user` opens `Invoice_Q3_NM-4471.doc` on **WS-FINANCE-04** |
| 2026-09-28 09:03 | `WINWORD.EXE` spawns `powershell.exe` (unusual parent/child) |
| 2026-09-28 09:04 | PowerShell writes `svc-host-update.exe` to `%TEMP%` (synthetic benign placeholder) |
| 2026-09-28 09:04 | Registry Run key created: `HKCU\...\Run\SysHostUpdate` → persistence (T1547.001) |
| 2026-09-28 09:05 | Outbound DNS for `invoice-portal-updates.example` (controlled test domain) |
| 2026-09-28 09:05 | TLS connection to `203.0.113.44` (documentation-range IP) |
| 2026-09-28 09:06 | Normal user activity continues: browser traffic, Office autosave, software update check |
| 2026-09-28 09:20 | SOC begins investigation |

## What's in the evidence (and what's noise)

The dataset **deliberately** mixes signal and noise, because a lab where
everything is malicious tests nothing:

- **Signal:** the phishing email, the attachment, the Office→PowerShell
  process chain, the Run key, the DNS/TLS to test infrastructure, the
  payload-like executable (harmless placeholder with deterministic hash).
- **Noise:** normal Office activity, browser traffic to benign sites,
  a software update check, unrelated logon events, duplicate events,
  incomplete records, and false-positive candidates (e.g. a legitimate
  vendor email thread, an admin PowerShell session).

## Ground truth (for scoring only)

```json
{
  "initial_access": "phishing email",
  "affected_host": "WS-FINANCE-04",
  "affected_identity": "finance.user",
  "process_chain": ["WINWORD.EXE", "powershell.exe", "svc-host-update.exe"],
  "persistence": "Registry Run key HKCU\\...\\Run\\SysHostUpdate",
  "indicators": {
    "domain": "invoice-portal-updates.example",
    "ip": "203.0.113.44",
    "note": "documentation-range / controlled test values only"
  },
  "attack_ids": ["T1566", "T1059.001", "T1547.001"]
}
```

The authoritative copy lives in `ground-truth/incident.json`. **Tools must
never read it during analysis.** Scoring compares tool findings against it
after the run.

## Investigation chain

| Stage | Evidence | Tool | Question it answers |
|-------|----------|------|---------------------|
| 1 | `evidence/email/invoice-phish.eml` | PhishScope | Is this email malicious? What's the infrastructure? |
| 2 | `evidence/email/invoice-logo.png` | MetaTrace | Does the attached image carry hidden metadata? |
| 3 | `evidence/endpoint/*.xml` | HuntForge | What executed, what persisted, what's the timeline? |
| 4 | `evidence/logs/*.jsonl` | LogLens | What do host/app logs show around the window? |
| 5 | `evidence/network/dns.jsonl` | NetScope | Where did the host talk to? |
| 6 | All of the above | SentinelKit | What are the normalized IOCs? |
| 7 | `evidence/pcap/incident.pcap` | AegisForge | Case assembly, PCAP context, final correlation |
| 8 | Everything | AutoOPS | Is the environment and evidence set healthy? |

## Expected cross-tool relationships

- PhishScope attachment SHA-256 == AegisForge registered forensic artifact
- MetaTrace analysis references the same image evidence hash
- HuntForge timeline contains the PowerShell execution in the email's time window
- LogLens events align on host/user/time with HuntForge
- NetScope observations align with the HuntForge process network events
- SentinelKit IOCs (domain, IP, hashes) appear in the AegisForge case
- AutoOPS confirms artifact integrity for every stage

These are tested automatically in `tests/integration/`.
