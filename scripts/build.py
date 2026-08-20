#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
import tempfile
import zipapp
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def version() -> str:
    text = (ROOT / "xhttp_setup/__init__.py").read_text("utf-8")
    match = re.search(
        r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$', text, re.MULTILINE
    )
    if not match:
        raise SystemExit("Cannot find __version__")
    return match.group(1)


def remove_bytecode(path: Path) -> None:
    for item in sorted(path.rglob("__pycache__"), reverse=True):
        shutil.rmtree(item)
    for pattern in ("*.pyc", "*.pyo"):
        for item in path.rglob(pattern):
            item.unlink()


def build() -> Path:
    release = version()
    output_dir = ROOT / "dist"
    output_dir.mkdir(exist_ok=True)
    output = output_dir / f"xhttp-setup-{release}.pyz"
    with tempfile.TemporaryDirectory(prefix="xhttp-setup-build-") as temp:
        stage = Path(temp)
        shutil.copytree(ROOT / "xhttp_setup", stage / "xhttp_setup")
        remove_bytecode(stage)
        (stage / "__main__.py").write_text(
            "from xhttp_setup.cli import main\nraise SystemExit(main())\n",
            encoding="utf-8",
            newline="\n",
        )
        epoch = 315532800  # ZIP's first representable date, 1980-01-01 UTC.
        for item in stage.rglob("*"):
            os.utime(item, (epoch, epoch))
        zipapp.create_archive(
            stage,
            target=output,
            interpreter="/usr/bin/env python3",
            main=None,
            compressed=True,
        )
    output.chmod(output.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    (output_dir / f"{output.name}.sha256").write_text(
        digest + "\n", encoding="ascii", newline="\n"
    )
    print(output)
    print(digest)
    return output


if __name__ == "__main__":
    build()
