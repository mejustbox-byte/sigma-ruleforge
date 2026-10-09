"""Install the built wheel in an isolated uv environment and exercise its CLI."""

import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[1]
    version = tomllib.loads((root / "pyproject.toml").read_text())["project"]["version"]
    wheel = root / "dist" / f"sigma_ruleforge-{version}-py3-none-any.whl"
    if not wheel.is_file():
        raise SystemExit("Build the wheel first: uv build")
    prefix = [
        "uv",
        "run",
        "--no-project",
        "--python",
        sys.executable,
        "--with",
        str(wheel),
        "--",
        "ruleforge",
    ]
    with tempfile.TemporaryDirectory() as directory:
        result = subprocess.run(
            prefix + ["--version"], cwd=directory, check=True, text=True, capture_output=True
        )
        if result.stdout.strip() != version:
            raise SystemExit("Installed wheel version mismatch")
        subprocess.run(
            prefix + ["validate", str(root / "examples/process_creation.yml"), "--strict"],
            cwd=directory,
            check=True,
        )
        subprocess.run(
            prefix + ["test", "--manifest", str(root / "examples/manifest.json")],
            cwd=directory,
            check=True,
        )
    print("PASS: isolated wheel installation, version, validation and fixture runner")


if __name__ == "__main__":
    main()
