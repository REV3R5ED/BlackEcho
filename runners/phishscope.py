"""PhishScope runner — email forensics."""

from pathlib import Path
from runners.base import BaseRunner


class PhishScopeRunner(BaseRunner):
    tool = "phishscope"

    def __init__(self):
        from runners.base import load_manifest
        self.version = load_manifest()["tools"]["PhishScope"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        eml = str(evidence / "email" / "invoice-phish.eml")
        return [
            ["phishscope", "analyze", eml, "--json"],
            ["phishscope", "auth", eml, "--json"],
            ["phishscope", "urls", eml, "--json"],
            ["phishscope", "impersonation", eml, "--json"],
            ["phishscope", "attachments", eml, "--json"],
        ]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json
        d = json.loads(stdout)
        # Return the command-specific payload
        return {"command": d.get("command"), "data": d.get("message", d)}
