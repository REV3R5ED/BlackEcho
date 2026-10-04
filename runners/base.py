"""BlackEcho runner framework — base adapter contract.

Each tool adapter:
  1. Takes evidence paths (never reads ground-truth/).
  2. Invokes the tool CLI at its pinned commit via subprocess.
  3. Captures stdout, stderr, exit code, runtime.
  4. Saves native.json + run metadata to runners/output/<tool>/.

A tool reporting "not observable" for out-of-scope evidence exits 0
with a structured note — that is scored separately from a miss.
"""

from __future__ import annotations

import json
import subprocess
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

OUTPUT_ROOT = Path("runners/output")


@dataclass
class RunResult:
    tool: str
    argv: list[str]
    exit_code: int
    runtime_ms: int
    stdout: str
    stderr: str
    native: dict = field(default_factory=dict)
    note: str = ""


class BaseRunner(ABC):
    """One adapter per tool. Subclasses implement build_argv + parse_native."""

    tool: str = ""
    version: str = ""  # pinned short SHA

    @abstractmethod
    def build_argv(self, evidence: Path) -> list[list[str]]:
        """Return list of CLI invocations (each a argv list)."""

    @abstractmethod
    def parse_native(self, stdout: str, argv: list[str]) -> dict:
        """Extract the tool's machine-readable output into native.json."""

    def run(self, evidence: Path, outdir: Path | None = None) -> list[RunResult]:
        import os
        outdir = outdir or (OUTPUT_ROOT / self.tool)
        outdir.mkdir(parents=True, exist_ok=True)
        # Ensure tool CLIs are findable (venv bin + PATH override).
        env = dict(os.environ)
        venv_bin = str(Path.home() / "workspace" / "venvs" / "afcheck" / "bin")
        env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
        results = []
        for i, argv in enumerate(self.build_argv(evidence)):
            start = time.monotonic()
            proc = subprocess.run(argv, capture_output=True, text=True,
                                  timeout=300, env=env)
            runtime_ms = int((time.monotonic() - start) * 1000)
            try:
                native = self.parse_native(proc.stdout, argv)
            except Exception as exc:  # noqa: BLE001 — record parse failures
                native = {"_parse_error": str(exc)}
            result = RunResult(
                tool=self.tool, argv=argv, exit_code=proc.returncode,
                runtime_ms=runtime_ms, stdout=proc.stdout,
                stderr=proc.stderr, native=native,
            )
            # Persist
            tag = f"{i:02d}"
            (outdir / f"{tag}-argv.json").write_text(json.dumps(argv, indent=2))
            (outdir / f"{tag}-stdout.txt").write_text(proc.stdout)
            (outdir / f"{tag}-stderr.txt").write_text(proc.stderr)
            (outdir / f"{tag}-meta.json").write_text(json.dumps({
                "tool": self.tool, "version": self.version,
                "exit_code": proc.returncode, "runtime_ms": runtime_ms,
            }, indent=2))
            (outdir / f"{tag}-native.json").write_text(
                json.dumps(native, indent=2, default=str))
            results.append(result)
        return results


def load_manifest() -> dict:
    return json.loads(Path("manifests/tool-versions.json").read_text())
