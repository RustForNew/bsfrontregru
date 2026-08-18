from __future__ import annotations

import contextlib
import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Iterator, Sequence

from .errors import InstallerError

try:  # Linux applies changes; importing pure renderers still works on Windows.
    import fcntl
except ImportError:  # pragma: no cover - exercised by Windows packaging checks
    fcntl = None  # type: ignore[assignment]


def run(
    argv: Sequence[str],
    *,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
    check: bool = True,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            list(argv),
            input=input_text,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise InstallerError(f"Не удалось выполнить {argv[0]}: {exc}") from exc
    if check and result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        tail = detail[-1] if detail else f"код {result.returncode}"
        raise InstallerError(f"Команда {argv[0]} завершилась с ошибкой: {tail}")
    return result


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_dir(path: Path, mode: int = 0o700) -> None:
    if path.is_symlink():
        raise InstallerError(f"Managed-каталог не может быть symlink: {path}")
    if path.exists():
        if not path.is_dir():
            raise InstallerError(f"Ожидался каталог: {path}")
        actual_mode = stat.S_IMODE(path.stat().st_mode)
        if os.name == "posix" and actual_mode != mode:
            raise InstallerError(
                f"Права существующего каталога {path}: {actual_mode:04o}, ожидалось {mode:04o}; "
                "автоматический chmod запрещён"
            )
        return
    path.mkdir(parents=True, mode=mode)
    os.chmod(path, mode)


def atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    # Directory ownership/mode belongs to the caller. Never chmod an existing
    # system directory such as /etc/systemd/system as a side effect of a write.
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, mode)
        os.replace(temp_path, path)
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temp_path.unlink(missing_ok=True)


def atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    atomic_write(path, text.encode("utf-8"), mode)


def load_json(path: Path) -> dict:
    try:
        with path.open("r", encoding="utf-8") as stream:
            value = json.load(stream)
    except (OSError, json.JSONDecodeError) as exc:
        raise InstallerError(f"Не удалось прочитать {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InstallerError(f"Ожидался JSON object в {path}")
    return value


@contextlib.contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    if fcntl is None:
        raise InstallerError("Применение поддерживается только на Unix/Linux")
    ensure_dir(path.parent)

    flags = os.O_RDWR | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC

    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as exc:
        raise InstallerError(
            f"Не удалось безопасно открыть lock-файл {path}: {exc}"
        ) from exc

    try:
        os.set_inheritable(descriptor, False)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallerError(f"Lock-файл должен быть обычным файлом: {path}")

        actual_mode = stat.S_IMODE(metadata.st_mode)
        if actual_mode != 0o600:
            raise InstallerError(
                f"Права lock-файла {path}: {actual_mode:04o}, ожидалось 0600; "
                "автоматический chmod запрещён"
            )

        expected_uid = os.geteuid()
        if metadata.st_uid != expected_uid:
            raise InstallerError(
                f"Lock-файл {path} принадлежит UID {metadata.st_uid}, "
                f"ожидался UID {expected_uid}"
            )

        # On platforms without O_NOFOLLOW, reject a path swapped for a symlink
        # (or another inode) between opening it and validating its metadata.
        if not hasattr(os, "O_NOFOLLOW"):
            path_metadata = path.lstat()
            if stat.S_ISLNK(path_metadata.st_mode) or (
                path_metadata.st_dev,
                path_metadata.st_ino,
            ) != (metadata.st_dev, metadata.st_ino):
                raise InstallerError(f"Lock-файл не может быть symlink: {path}")

        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise InstallerError("Другой экземпляр установщика уже работает") from exc
        yield
    finally:
        os.close(descriptor)


def command_exists(name: str) -> bool:
    from shutil import which

    return which(name) is not None
