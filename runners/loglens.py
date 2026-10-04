"""LogLens runner — log analysis."""

from pathlib import Path
from runners.base import BaseRunner


class LogLensRunner(BaseRunner):
    tool = "loglens"

    def __init__(self):
        from runners.base import load_manifest
        self.version = load_manifest()["tools"]["LogLens"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        logs = evidence / "logs"
        return [
            ["loglens", "analyze", str(logs / "host.jsonl"), "--format", "json", "--json"],
            ["loglens", "analyze", str(logs / "app.jsonl"), "--format", "json", "--json"],
        ]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json
        return json.loads(stdout)
