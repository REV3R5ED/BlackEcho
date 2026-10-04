"""NetScope runner — network observations."""

from pathlib import Path
from runners.base import BaseRunner


class NetScopeRunner(BaseRunner):
    tool = "netscope"

    def __init__(self):
        from runners.base import load_manifest
        self.version = load_manifest()["tools"]["NetScope"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        # Offline classification of the incident IOCs (no active probing
        # against test infrastructure — classification is the in-scope use).
        return [
            ["netscope", "address", "203.0.113.44", "--json"],
            ["netscope", "address", "10.20.30.5", "--json"],
            ["netscope", "network", "203.0.113.0/24", "--json"],
        ]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json
        return json.loads(stdout)
