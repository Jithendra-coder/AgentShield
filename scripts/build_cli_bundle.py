"""Create a CLI-only installable folder and ZIP from the canonical source files."""

from __future__ import annotations

import argparse
import shutil
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE_FILES = (
    "__init__.py",
    "__main__.py",
    "cli.py",
    "engine.py",
    "openai_agent.py",
    "scenarios.py",
)
PROJECT_CONFIG = '''[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[project]
name = "agentshield-cli"
version = "0.1.0"
description = "CLI for isolated AI agent security evaluations"
requires-python = ">=3.10"
dependencies = []

[project.optional-dependencies]
openai = ["celery>=5.4,<6", "openai>=2,<3"]

[project.scripts]
agentshield = "agentshield.cli:main"

[tool.setuptools]
packages = ["agentshield"]
'''


def build(output_dir: Path) -> tuple[Path, Path]:
    output_dir = output_dir.resolve()
    folder = output_dir / "AgentShield-CLI"
    archive = output_dir / "AgentShield-CLI.zip"
    if folder.exists() or archive.exists():
        raise FileExistsError(f"Refusing to overwrite existing bundle output in {output_dir}")

    package_dir = folder / "agentshield"
    package_dir.mkdir(parents=True)
    for name in PACKAGE_FILES:
        shutil.copy2(ROOT / "agentshield" / name, package_dir / name)
    (folder / "pyproject.toml").write_text(PROJECT_CONFIG, encoding="utf-8")

    with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
        for path in sorted(folder.rglob("*")):
            if path.is_file():
                bundle.write(path, Path(folder.name) / path.relative_to(folder))
    return folder, archive


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-dir", type=Path, default=ROOT / "dist", help="New directory for the folder and ZIP.")
    args = parser.parse_args()
    try:
        folder, archive = build(args.output_dir)
    except (FileExistsError, OSError) as exc:
        parser.error(str(exc))
    print(f"Folder: {folder}")
    print(f"ZIP: {archive}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
