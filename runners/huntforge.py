"""HuntForge runner — endpoint forensics."""

from pathlib import Path
from runners.base import BaseRunner


class HuntForgeRunner(BaseRunner):
    tool = "huntforge"

    def __init__(self):
        from runners.base import load_manifest
        self.version = load_manifest()["tools"]["HuntForge"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        ep = evidence / "endpoint"
        case = "BLACKECHO-001"
        return [
            ["huntforge", "case", "create", case, "--json"],
            ["huntforge", "ingest", str(ep / "sysmon.xml"),
             "--case", case, "--source", "sysmon", "--json"],
            ["huntforge", "ingest", str(ep / "powershell.xml"),
             "--case", case, "--source", "powershell", "--json"],
            ["huntforge", "timeline", "--case", case, "--json"],
            ["huntforge", "detect", "--case", case, "--json"],
        ]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json
        d = json.loads(stdout)
        return d.get("data", d)
