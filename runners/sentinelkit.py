"""SentinelKit runner — IOC extraction and triage."""

from pathlib import Path

from runners.base import BaseRunner


class SentinelKitRunner(BaseRunner):
    tool = "sentinelkit"

    def __init__(self):
        from runners.base import load_manifest

        self.version = load_manifest()["tools"]["SentinelKit"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        eml = str(evidence / "email" / "invoice-phish.eml")
        dns = str(evidence / "network" / "dns.jsonl")
        return [
            ["sentinelkit", "ioc", eml],
            ["sentinelkit", "ioc", dns],
            ["sentinelkit", "ip", "203.0.113.44"],
            ["sentinelkit", "hash", str(evidence / "filesystem" / "svc-host-update.exe")],
        ]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json

        try:
            return json.loads(stdout)
        except Exception:  # noqa: BLE001 -- native output shape varies by tool
            return {"text": stdout}
