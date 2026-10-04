"""AegisForge runner — case assembly and correlation."""

from pathlib import Path

from runners.base import BaseRunner


class AegisForgeRunner(BaseRunner):
    tool = "aegisforge"

    def __init__(self):
        from runners.base import load_manifest

        self.version = load_manifest()["tools"]["AegisForge"]["sha"][:7]

    def build_argv(self, evidence: Path) -> list[list[str]]:
        # AegisForge case workflow: create case, attach evidence.
        return [
            [
                "aegisforge",
                "case",
                "create",
                "--title",
                "BLACKECHO-001",
                "--note",
                "Operation BlackEcho synthetic incident",
                "--json",
            ],
        ]

    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        import json

        try:
            return json.loads(stdout)
        except Exception:  # noqa: BLE001 -- native output shape varies by tool
            return {"text": stdout}
