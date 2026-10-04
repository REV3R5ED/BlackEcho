"""AutoOPS runner — operational validation."""

from pathlib import Path

from runners.base import BaseRunner


class AutoOPRunner(BaseRunner):
    tool = "autoops"

    def __init__(self):
        from runners.base import load_manifest

        self.version = load_manifest()["tools"]["AutoOPS"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        # Read-only health checks over the evidence directory.
        return [
            ["autoops", "preflight", str(evidence), "--json"],
            ["autoops", "environment", "--json"],
        ]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json

        try:
            return json.loads(stdout)
        except Exception:  # noqa: BLE001 -- native output shape varies by tool
            return {"text": stdout}
