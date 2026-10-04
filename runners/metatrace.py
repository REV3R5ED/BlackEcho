"""MetaTrace runner — image forensics."""

from pathlib import Path
from runners.base import BaseRunner


class MetaTraceRunner(BaseRunner):
    tool = "metatrace"

    def __init__(self):
        from runners.base import load_manifest
        self.version = load_manifest()["tools"]["MetaTrace"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        img = str(evidence / "email" / "invoice-logo.jpg")
        return [["metatrace", "analyze", img, "--json"]]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json
        d = json.loads(stdout)
        return d.get("data", d)
