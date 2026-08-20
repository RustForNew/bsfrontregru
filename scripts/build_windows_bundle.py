#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import re
import stat
import tempfile
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
_VERSION_RE = re.compile(
    r'^__version__\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"$', re.MULTILINE
)
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)
_GUIDES = (
    ("home-pc-linux-windows.txt", "INSTRUCTION-HOME-PC-LINUX-WINDOWS.txt"),
    ("reg-ru-ispmanager-setup.txt", "INSTRUCTION-REG-RU-ISPMANAGER.txt"),
)


def version(root: Path = ROOT) -> str:
    text = (root / "xhttp_setup/__init__.py").read_text("utf-8")
    match = _VERSION_RE.search(text)
    if not match:
        raise SystemExit("Cannot find __version__")
    return match.group(1)


def _regular_file(path: Path, description: str) -> Path:
    if path.is_symlink() or not path.is_file():
        raise SystemExit(f"{description} must be a regular file: {path}")
    return path


def _read_verified_pyz(root: Path, release: str) -> tuple[Path, bytes, str]:
    pyz = _regular_file(root / "dist" / f"xhttp-setup-{release}.pyz", "Built installer")
    checksum = _regular_file(
        root / "dist" / f"xhttp-setup-{release}.pyz.sha256",
        "Installer checksum",
    )
    expected = checksum.read_text("ascii").strip().lower()
    if not _SHA256_RE.fullmatch(expected):
        raise SystemExit(f"Invalid installer checksum: {checksum}")
    payload = pyz.read_bytes()
    actual = hashlib.sha256(payload).hexdigest()
    if actual != expected:
        raise SystemExit(f"Installer checksum mismatch: {pyz}")
    return pyz, payload, actual


def _render_template(path: Path, replacements: dict[str, str]) -> bytes:
    text = _regular_file(path, "Windows bundle template").read_text("utf-8")
    for token, value in replacements.items():
        text = text.replace(token, value)
    if "@@" in text:
        raise SystemExit(f"Unresolved template token in {path}")
    newline = "\r\n" if path.suffix.lower() in {".cmd", ".ps1", ".txt"} else "\n"
    return (
        text.replace("\r\n", "\n")
        .replace("\r", "\n")
        .replace("\n", newline)
        .encode("utf-8")
    )


def _zip_info(name: str, mode: int) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(name, date_time=_ZIP_TIMESTAMP)
    info.create_system = 3
    info.compress_type = zipfile.ZIP_STORED
    info.external_attr = (stat.S_IFREG | mode) << 16
    return info


def build(*, root: Path = ROOT, output_dir: Path | None = None) -> Path:
    release = version(root)
    pyz, pyz_payload, pyz_sha256 = _read_verified_pyz(root, release)
    pyz_name = pyz.name
    pyz_sha_name = f"{pyz_name}.sha256"
    replacements = {
        "@@VERSION@@": release,
        "@@PYZ_NAME@@": pyz_name,
        "@@PYZ_SHA_NAME@@": pyz_sha_name,
        "@@PYZ_SHA256@@": pyz_sha256,
    }

    source_dir = root / "windows"
    runner_payload = _render_template(source_dir / "run-wsl.sh", replacements)
    runner_sha256 = hashlib.sha256(runner_payload).hexdigest()
    launcher_replacements = {
        **replacements,
        "@@RUNNER_SHA256@@": runner_sha256,
    }
    entries: dict[str, tuple[bytes, int]] = {
        "README-WINDOWS.txt": (
            _render_template(source_dir / "README-WINDOWS.txt", replacements),
            0o644,
        ),
        "START-WINDOWS.cmd": (
            _render_template(source_dir / "START-WINDOWS.cmd", replacements),
            0o644,
        ),
        "run-wsl.sh": (runner_payload, 0o755),
        pyz_name: (pyz_payload, 0o755),
        pyz_sha_name: ((pyz_sha256 + "\n").encode("ascii"), 0o644),
        "xhttp-setup.ps1": (
            _render_template(source_dir / "xhttp-setup.ps1", launcher_replacements),
            0o644,
        ),
    }
    for source_name, archive_name in _GUIDES:
        entries[archive_name] = (
            _render_template(root / "docs" / source_name, replacements),
            0o644,
        )

    destination = output_dir if output_dir is not None else root / "dist"
    destination.mkdir(parents=True, exist_ok=True)
    output = destination / f"xhttp-setup-{release}-windows-wsl.zip"
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            prefix=f".{output.name}.", suffix=".tmp", dir=destination, delete=False
        ) as file_handle:
            temporary = Path(file_handle.name)
        with zipfile.ZipFile(temporary, mode="w") as archive:
            for name in sorted(entries):
                payload, mode = entries[name]
                archive.writestr(_zip_info(name, mode), payload)
        temporary.replace(output)
        temporary = None
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)

    bundle_sha256 = hashlib.sha256(output.read_bytes()).hexdigest()
    (destination / f"{output.name}.sha256").write_text(
        bundle_sha256 + "\n", encoding="ascii", newline="\n"
    )
    print(output)
    print(bundle_sha256)
    return output


if __name__ == "__main__":
    build()
