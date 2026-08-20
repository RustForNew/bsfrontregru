#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / "dist"
SHA256_RE = re.compile(r"[0-9a-f]{64}")
VERSION_RE = re.compile(
    r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE
)
REQUIRED_PYZ_MEMBERS = frozenset(
    {
        "__main__.py",
        "xhttp_setup/__init__.py",
        "xhttp_setup/cli.py",
        "xhttp_setup/front_discovery.py",
        "xhttp_setup/front_probe.py",
        "xhttp_setup/pc_autosetup.py",
        "xhttp_setup/remote_prepare.py",
    }
)


def _verified_payload(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"Missing regular artifact: {path}")
    sidecar = path.with_name(path.name + ".sha256")
    if sidecar.is_symlink() or not sidecar.is_file():
        raise SystemExit(f"Missing regular checksum: {sidecar}")
    expected = sidecar.read_text("ascii").strip()
    if not SHA256_RE.fullmatch(expected):
        raise SystemExit(f"Invalid SHA-256 sidecar: {sidecar}")
    payload = path.read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise SystemExit(f"SHA-256 mismatch: {path}")
    return payload


def verify() -> None:
    source = (ROOT / "xhttp_setup/__init__.py").read_text("utf-8")
    match = VERSION_RE.search(source)
    if not match:
        raise SystemExit("Cannot find __version__")
    version = match.group(1)
    pyz_name = f"xhttp-setup-{version}.pyz"
    windows_name = f"xhttp-setup-{version}-windows-wsl.zip"
    pyz_path = DIST / pyz_name
    windows_path = DIST / windows_name
    pyz_payload = _verified_payload(pyz_path)
    _verified_payload(windows_path)

    with zipfile.ZipFile(pyz_path) as archive:
        members = set(archive.namelist())
    missing = sorted(REQUIRED_PYZ_MEMBERS - members)
    if missing:
        raise SystemExit(f"Installer PYZ is missing runtime modules: {missing}")
    forbidden = sorted(
        name
        for name in members
        if "__pycache__" in name or name.endswith((".pyc", ".pyo"))
    )
    if forbidden:
        raise SystemExit(f"Installer PYZ contains bytecode artifacts: {forbidden}")

    expected_windows_members = [
        "INSTRUCTION.txt",
        "START-WINDOWS.cmd",
        "_internal/run-wsl.sh",
        f"_internal/{pyz_name}",
        "_internal/xhttp-setup.ps1",
    ]
    with zipfile.ZipFile(windows_path) as archive:
        if archive.namelist() != expected_windows_members:
            raise SystemExit("Windows ZIP has an unexpected file layout")
        if archive.read(f"_internal/{pyz_name}") != pyz_payload:
            raise SystemExit("Windows ZIP embeds a different installer PYZ")
        bundled_instruction = archive.read("INSTRUCTION.txt")
        runner = archive.read("_internal/run-wsl.sh")
        powershell = archive.read("_internal/xhttp-setup.ps1")

    instruction_path = DIST / "INSTRUCTION.txt"
    if instruction_path.is_symlink() or not instruction_path.is_file():
        raise SystemExit(f"Missing standalone instruction: {instruction_path}")
    standalone_instruction = instruction_path.read_bytes()
    if not standalone_instruction or standalone_instruction != bundled_instruction:
        raise SystemExit("Bundled and standalone instructions differ")
    for label, payload in (
        ("instruction", standalone_instruction),
        ("runner", runner),
        ("PowerShell launcher", powershell),
    ):
        if b"@@" in payload:
            raise SystemExit(f"Unresolved template token in {label}")

    pyz_sha256 = hashlib.sha256(pyz_payload).hexdigest().encode("ascii")
    runner_sha256 = hashlib.sha256(runner).hexdigest().encode("ascii")
    if pyz_sha256 not in runner or pyz_sha256 not in powershell:
        raise SystemExit("Embedded installer SHA-256 is missing")
    if runner_sha256 not in powershell:
        raise SystemExit("Embedded WSL runner SHA-256 is missing")

    print(f"Verified {pyz_name} and {windows_name}")


if __name__ == "__main__":
    verify()
