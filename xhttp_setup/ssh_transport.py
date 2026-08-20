from __future__ import annotations

import base64
import binascii
import contextlib
import hashlib
import os
import re
import shlex
import signal
import socket
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .errors import InstallerError, VerificationError
from .osutil import atomic_write_text, ensure_dir, run
from .validate import (
    validate_fingerprint,
    validate_host,
    validate_port,
    validate_ssh_user,
)


_MAX_SSH_INPUT_BYTES = 4096
_MAX_KNOWN_HOSTS_BYTES = 16 * 1024
_HOST_KEY_PREFERENCE = (
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "ssh-rsa",
)
_SSH_PERMISSION_DENIED = re.compile(
    r"(?:^|:\s)Permission denied(?:\s+\([^()\r\n]+\))?\.?$"
)


class SSHAuthenticationError(InstallerError):
    """The remote endpoint was reached but rejected the supplied credential."""


@dataclass(frozen=True)
class TCPRoute:
    """A loopback transport endpoint for one logical remote TCP service."""

    connect_host: str
    connect_port: int

    def validate(self) -> "TCPRoute":
        host = validate_host(self.connect_host)
        if host not in {"127.0.0.1", "::1"}:
            raise InstallerError("Bridge transport обязан быть loopback-only")
        return TCPRoute(
            connect_host=host,
            connect_port=validate_port(self.connect_port),
        )


@dataclass(frozen=True)
class SSHRoute:
    """Host-key scan endpoint plus a password-free OpenSSH ProxyCommand."""

    scan: TCPRoute
    proxy_command: str = field(repr=False)

    def validate(self) -> "SSHRoute":
        command = self.proxy_command
        if (
            not isinstance(command, str)
            or not command
            or len(command.encode("utf-8")) > 4096
            or any(char in command for char in "\r\n\x00")
        ):
            raise InstallerError("Некорректный SSH ProxyCommand")
        return SSHRoute(scan=self.scan.validate(), proxy_command=command)


@contextlib.contextmanager
def _password_askpass(password: str) -> Iterator[dict[str, str]]:
    """Expose one password prompt through a private, kernel-backed FIFO."""
    if not hasattr(os, "mkfifo"):
        raise InstallerError("Password-auth SSH/SFTP поддерживается только на POSIX")
    with tempfile.TemporaryDirectory(prefix="xhttp-askpass-") as temp:
        temp_dir = Path(temp)
        os.chmod(temp_dir, 0o700)
        fifo = temp_dir / "password.fifo"
        helper = temp_dir / "askpass"
        os.mkfifo(fifo, 0o600)
        os.chmod(fifo, 0o600)
        fifo_fd = os.open(
            fifo,
            os.O_RDWR | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0),
        )
        try:
            payload = (password + "\n").encode("utf-8")
            if os.write(fifo_fd, payload) != len(payload):
                raise InstallerError("Не удалось подготовить одноразовый askpass FIFO")
            helper.write_text(
                '#!/bin/sh\nIFS= read -r answer < "$XHTTP_ASKPASS_FIFO" || exit 1\n'
                'printf "%s\\n" "$answer"\n',
                encoding="utf-8",
            )
            os.chmod(helper, 0o700)
            env = os.environ.copy()
            env.update(
                {
                    "DISPLAY": "xhttp-setup",
                    "SSH_ASKPASS": str(helper),
                    "SSH_ASKPASS_REQUIRE": "force",
                    "XHTTP_ASKPASS_FIFO": str(fifo),
                    "LC_ALL": "C",
                    "LANG": "C",
                }
            )
            yield env
        finally:
            os.close(fifo_fd)


def _without_askpass_env() -> dict[str, str]:
    env = os.environ.copy()
    for name in (
        "DISPLAY",
        "SSH_ASKPASS",
        "SSH_ASKPASS_REQUIRE",
        "XHTTP_ASKPASS_FD",
        "XHTTP_ASKPASS_FIFO",
    ):
        env.pop(name, None)
    return env


def _redact_input_text(value: str, input_text: str | None) -> str:
    if input_text is None:
        return value
    secret = input_text[:-1] if input_text.endswith("\n") else input_text
    return value.replace(secret, "[REDACTED]") if secret else value


def _redact_process_result(
    result: subprocess.CompletedProcess[str], *secrets: str | None
) -> subprocess.CompletedProcess[str]:
    stdout = result.stdout
    stderr = result.stderr
    for secret in secrets:
        if stdout is not None:
            stdout = _redact_input_text(stdout, secret)
        if stderr is not None:
            stderr = _redact_input_text(stderr, secret)
    return subprocess.CompletedProcess(
        result.args,
        result.returncode,
        stdout,
        stderr,
    )


def _last_process_line(
    result: subprocess.CompletedProcess[str], *, input_text: str | None = None
) -> str:
    lines = (result.stderr or result.stdout).strip().splitlines()
    detail = lines[-1] if lines else f"код {result.returncode}"
    return _redact_input_text(detail, input_text)


def _validate_input_text(input_text: str | None) -> str | None:
    if input_text is None:
        return None
    if not isinstance(input_text, str):
        raise InstallerError("SSH stdin должен быть UTF-8 текстом")
    if "\x00" in input_text or "\r" in input_text:
        raise InstallerError("SSH stdin не может содержать NUL или CR")
    line = input_text[:-1] if input_text.endswith("\n") else input_text
    if "\n" in line:
        raise InstallerError(
            "SSH stdin должен содержать одну строку с необязательным завершающим LF"
        )
    try:
        input_size = len(input_text.encode("utf-8"))
    except UnicodeEncodeError:
        raise InstallerError("SSH stdin должен быть корректным UTF-8 текстом") from None
    if input_size > _MAX_SSH_INPUT_BYTES:
        raise InstallerError(
            f"SSH stdin превышает лимит {_MAX_SSH_INPUT_BYTES} UTF-8 bytes"
        )
    return input_text


@dataclass(frozen=True)
class SSHAuth:
    method: str
    private_key: str | None = None
    password: str | None = field(default=None, repr=False, compare=False)

    def validate(self) -> "SSHAuth":
        if self.method == "key":
            if not self.private_key:
                raise InstallerError("Не указан путь к приватному SSH-ключу")
            key = Path(self.private_key).expanduser()
            if not key.is_file():
                raise InstallerError(f"SSH-ключ не найден: {key}")
            return SSHAuth("key", str(key.resolve()), None)
        if self.method == "password":
            if not self.password:
                raise InstallerError("Пустой SSH/SFTP-пароль")
            if len(self.password.encode("utf-8")) > 4096 or any(
                char in self.password for char in "\r\n\x00"
            ):
                raise InstallerError(
                    "SSH/SFTP-пароль не помещается в безопасный askpass line"
                )
            return self
        raise InstallerError("Поддерживаются методы SSH key и password")


@dataclass(frozen=True)
class _ObservedHostKey:
    key_type: str
    key_blob: str


def tofu_known_hosts_path(*, trust_dir: Path, host: str, port: int) -> Path:
    """Return the global trust file dedicated to one normalized SSH endpoint."""
    normalized_host = validate_host(host)
    normalized_port = validate_port(port)
    endpoint = f"{normalized_host}\0{normalized_port}".encode("utf-8")
    digest = hashlib.sha256(endpoint).hexdigest()
    return Path(trust_dir) / f"{digest}.known_hosts"


def _known_hosts_token(host: str, port: int) -> str:
    return host if port == 22 else f"[{host}]:{port}"


def _canonical_host_key_line(
    *, host: str, port: int, observed: _ObservedHostKey
) -> str:
    return f"{_known_hosts_token(host, port)} {observed.key_type} {observed.key_blob}"


def _parse_host_key_fields(
    line: str, *, host: str, port: int, source: str
) -> _ObservedHostKey:
    parts = line.split()
    if len(parts) != 3:
        raise VerificationError(f"Некорректная строка SSH host key в {source}")
    host_token, key_type, key_blob = parts
    accepted_tokens = {host, f"[{host}]:{port}"}
    if host_token not in accepted_tokens:
        raise VerificationError(
            f"SSH host key в {source} относится к другому endpoint"
        )
    if key_type not in _HOST_KEY_PREFERENCE:
        raise VerificationError(
            f"Неподдерживаемый тип SSH host key в {source}: {key_type}"
        )
    try:
        decoded = base64.b64decode(key_blob, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise VerificationError(
            f"Некорректный SSH public key в {source}"
        ) from exc
    if not decoded:
        raise VerificationError(f"Пустой SSH public key в {source}")
    return _ObservedHostKey(key_type=key_type, key_blob=key_blob)


def _fingerprint_host_key(line: str, *, source: str) -> str:
    try:
        result = run(
            ["ssh-keygen", "-E", "sha256", "-lf", "-"],
            input_text=line + "\n",
        )
    except InstallerError as exc:
        raise VerificationError(
            f"Не удалось проверить SSH host key из {source}: {exc}"
        ) from exc
    parts = result.stdout.strip().split()
    if len(parts) < 2:
        raise VerificationError(
            f"ssh-keygen не вернул fingerprint для SSH host key из {source}"
        )
    try:
        return validate_fingerprint(parts[1])
    except InstallerError as exc:
        raise VerificationError(
            f"ssh-keygen вернул некорректный fingerprint для {source}"
        ) from exc


def _parse_existing_trust(
    content: bytes, *, host: str, port: int, path: Path
) -> tuple[str, str]:
    if len(content) > _MAX_KNOWN_HOSTS_BYTES:
        raise VerificationError(f"SSH trust-файл слишком велик: {path}")
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise VerificationError(f"SSH trust-файл не является UTF-8: {path}") from exc
    lines = text.splitlines()
    if len(lines) != 1 or text != lines[0] + "\n":
        raise VerificationError(
            f"SSH trust-файл должен содержать ровно один host key: {path}"
        )
    observed = _parse_host_key_fields(
        lines[0], host=host, port=port, source=str(path)
    )
    canonical = _canonical_host_key_line(host=host, port=port, observed=observed)
    if lines[0] != canonical:
        raise VerificationError(f"SSH trust-файл имеет неканоничный формат: {path}")
    fingerprint = _fingerprint_host_key(canonical, source=str(path))
    return canonical, fingerprint


def _read_existing_trust(
    path: Path, *, host: str, port: int
) -> tuple[str, str] | None:
    try:
        path_metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError(f"Не удалось проверить SSH trust-файл {path}: {exc}") from exc
    if stat.S_ISLNK(path_metadata.st_mode):
        raise InstallerError(f"SSH trust-файл не может быть symlink: {path}")
    if not stat.S_ISREG(path_metadata.st_mode):
        raise InstallerError(f"SSH trust-файл должен быть обычным файлом: {path}")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallerError(
            f"Не удалось безопасно открыть SSH trust-файл {path}: {exc}"
        ) from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallerError(f"SSH trust-файл должен быть обычным файлом: {path}")
        if os.name == "posix":
            mode = stat.S_IMODE(metadata.st_mode)
            if mode != 0o600:
                raise InstallerError(
                    f"Права SSH trust-файла {path}: {mode:04o}, ожидалось 0600"
                )
            if metadata.st_uid != os.geteuid():
                raise InstallerError(
                    f"SSH trust-файл {path} принадлежит другому пользователю"
                )
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            content = stream.read(_MAX_KNOWN_HOSTS_BYTES + 1)
    finally:
        os.close(descriptor)

    try:
        current_metadata = path.lstat()
    except OSError as exc:
        raise InstallerError(
            f"SSH trust-файл изменился во время безопасного чтения: {path}: {exc}"
        ) from exc
    if stat.S_ISLNK(current_metadata.st_mode) or (
        current_metadata.st_dev,
        current_metadata.st_ino,
    ) != (metadata.st_dev, metadata.st_ino):
        raise InstallerError(
            f"SSH trust-файл изменился во время безопасного чтения: {path}"
        )
    return _parse_existing_trust(content, host=host, port=port, path=path)


def _scan_host_keys(
    *, host: str, port: int, route: SSHRoute | None = None
) -> dict[str, str]:
    normalized_route = route.validate() if route is not None else None
    scan_host = normalized_route.scan.connect_host if normalized_route else host
    scan_port = normalized_route.scan.connect_port if normalized_route else port
    scan = run(
        [
            "ssh-keyscan",
            "-T",
            "10",
            "-p",
            str(scan_port),
            "-t",
            "ed25519,ecdsa,rsa",
            scan_host,
        ],
        check=False,
        timeout=20,
    )
    by_type: dict[str, set[str]] = {}
    for raw_line in scan.stdout.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        observed = _parse_host_key_fields(
            line, host=scan_host, port=scan_port, source="ssh-keyscan"
        )
        by_type.setdefault(observed.key_type, set()).add(observed.key_blob)
    if not by_type:
        raise VerificationError(
            f"ssh-keyscan не получил SSH host key от {host}:{port}"
        )
    ambiguous = sorted(key_type for key_type, keys in by_type.items() if len(keys) != 1)
    if ambiguous:
        raise VerificationError(
            "ssh-keyscan получил несколько разных ключей одного типа: "
            + ", ".join(ambiguous)
        )

    canonical: dict[str, str] = {}
    for key_type in _HOST_KEY_PREFERENCE:
        keys = by_type.get(key_type)
        if not keys:
            continue
        observed = _ObservedHostKey(key_type=key_type, key_blob=next(iter(keys)))
        canonical[key_type] = _canonical_host_key_line(
            host=host, port=port, observed=observed
        )
    if not canonical:
        raise VerificationError(
            f"ssh-keyscan не получил поддерживаемый SSH host key от {host}:{port}"
        )
    return canonical


def _atomic_create_trust(path: Path, content: str) -> None:
    descriptor, temp_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(content.encode("utf-8"))
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temp_path, 0o600)
        try:
            # A same-directory hard-link publishes the complete file atomically and,
            # unlike os.replace(), can never overwrite an existing trust decision.
            os.link(temp_path, path)
        except FileExistsError as exc:
            raise VerificationError(
                f"SSH trust-файл появился параллельно и не был перезаписан: {path}"
            ) from exc
        except OSError as exc:
            raise InstallerError(
                f"Не удалось атомарно сохранить SSH trust-файл {path}: {exc}"
            ) from exc
        if os.name == "posix":
            directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            directory_fd = os.open(path.parent, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
    finally:
        temp_path.unlink(missing_ok=True)


def trust_host_key_tofu(
    *, host: str, port: int, trust_dir: Path, route: SSHRoute | None = None
) -> tuple[Path, str]:
    """Trust the first network-observed key, then reject every key change.

    This is endpoint-scoped TOFU, not independent host authentication: the first
    key is obtained from the network before SSH authentication.  Later calls scan
    again and require an exact match with the private, persistent trust file.
    """
    normalized_host = validate_host(host)
    normalized_port = validate_port(port)
    trust_root = Path(trust_dir)
    ensure_dir(trust_root, 0o700)
    known_hosts = tofu_known_hosts_path(
        trust_dir=trust_root, host=normalized_host, port=normalized_port
    )
    existing = _read_existing_trust(
        known_hosts, host=normalized_host, port=normalized_port
    )
    observed = _scan_host_keys(
        host=normalized_host, port=normalized_port, route=route
    )
    if existing is not None:
        existing_line, existing_fingerprint = existing
        if existing_line not in observed.values():
            raise VerificationError(
                f"SSH host key {normalized_host}:{normalized_port} изменился; "
                f"trust-файл {known_hosts} оставлен без изменений"
            )
        return known_hosts, existing_fingerprint

    observed_line = next(
        observed[key_type]
        for key_type in _HOST_KEY_PREFERENCE
        if key_type in observed
    )
    observed_fingerprint = _fingerprint_host_key(
        observed_line, source="ssh-keyscan"
    )
    _atomic_create_trust(known_hosts, observed_line + "\n")
    return known_hosts, observed_fingerprint


def pin_host_key(
    *,
    host: str,
    port: int,
    expected_sha256: str,
    known_hosts: Path,
    route: SSHRoute | None = None,
) -> None:
    """Fetch keys, retain only the line matching an independently supplied fingerprint."""
    ensure_dir(known_hosts.parent, 0o700)
    candidates = list(
        _scan_host_keys(host=host, port=port, route=route).values()
    )
    matches: list[str] = []
    observed: list[str] = []
    for line in candidates:
        fingerprint = run(
            ["ssh-keygen", "-E", "sha256", "-lf", "-"], input_text=line + "\n"
        ).stdout.strip()
        parts = fingerprint.split()
        if len(parts) >= 2:
            observed.append(parts[1].rstrip("="))
            if parts[1].rstrip("=") == expected_sha256.rstrip("="):
                matches.append(line)
    if not matches:
        detail = ", ".join(observed) if observed else "ключи не получены"
        raise VerificationError(
            f"SSH fingerprint не совпал. Ожидался {expected_sha256}; получено: {detail}"
        )
    content = "\n".join(matches) + "\n"
    if known_hosts.exists():
        existing = known_hosts.read_text("utf-8")
        if content == existing:
            return
        raise VerificationError(
            f"Закреплённый ключ {host}:{port} изменился; файл {known_hosts} оставлен без изменений"
        )
    atomic_write_text(known_hosts, content, 0o600)


class SFTPClient:
    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        known_hosts: Path,
        auth: SSHAuth,
        route: SSHRoute | None = None,
    ) -> None:
        self.host = validate_host(host)
        self.port = validate_port(port)
        self.user = validate_ssh_user(user)
        self.known_hosts = known_hosts
        self.auth = auth.validate()
        self.route = route.validate() if route is not None else None

    def _route_argv(self) -> list[str]:
        if self.route is None:
            return []
        return ["-o", f"ProxyCommand={self.route.proxy_command}"]

    def _destination(self) -> str:
        destination_host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.user}@{destination_host}"

    def _argv(self, *, control_path: Path | None = None) -> list[str]:
        argv = [
            "sftp",
            "-F",
            "/dev/null",
            "-b",
            "-",
            "-P",
            str(self.port),
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "NumberOfPasswordPrompts=1",
        ]
        if self.auth.method == "key":
            argv.extend(
                [
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-i",
                    str(self.auth.private_key),
                ]
            )
            argv.extend(self._route_argv())
        elif control_path is not None:
            argv.extend(
                [
                    "-o",
                    "ControlMaster=no",
                    "-o",
                    f"ControlPath={control_path}",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "ProxyCommand=/bin/false",
                    "-o",
                    "PasswordAuthentication=no",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "KbdInteractiveAuthentication=no",
                    "-o",
                    "HostbasedAuthentication=no",
                    "-o",
                    "GSSAPIAuthentication=no",
                ]
            )
        else:
            raise InstallerError(
                "Password-auth SFTP требует предварительно аутентифицированный SSH transport"
            )
        argv.append(self._destination())
        return argv

    def _master_argv(self, control_path: Path) -> list[str]:
        return [
            "ssh",
            "-F",
            "/dev/null",
            "-N",
            "-M",
            "-S",
            str(control_path),
            "-p",
            str(self.port),
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "BatchMode=no",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ControlPersist=no",
            *self._route_argv(),
            self._destination(),
        ]

    def _control_argv(self, control_path: Path, operation: str) -> list[str]:
        return [
            "ssh",
            "-F",
            "/dev/null",
            "-S",
            str(control_path),
            "-O",
            operation,
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            self._destination(),
        ]

    def _wait_for_master(
        self, master: subprocess.Popen[str], control_path: Path
    ) -> None:
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            returncode = master.poll()
            if returncode is not None:
                stderr = master.stderr.read() if master.stderr is not None else ""
                lines = stderr.strip().splitlines()
                detail = lines[-1] if lines else f"код {returncode}"
                detail = _redact_input_text(detail, self.auth.password)
                if _SSH_PERMISSION_DENIED.search(detail):
                    raise SSHAuthenticationError(
                        f"SFTP SSH-аутентификация не удалась: {detail}"
                    )
                raise InstallerError(f"SFTP SSH-аутентификация не удалась: {detail}")
            try:
                check = subprocess.run(
                    self._control_argv(control_path, "check"),
                    stdin=subprocess.DEVNULL,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=_without_askpass_env(),
                    timeout=2,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise InstallerError(
                    f"Не удалось проверить временный SSH transport: {exc}"
                ) from exc
            if check.returncode == 0:
                try:
                    metadata = control_path.lstat()
                except OSError as exc:
                    raise InstallerError(
                        f"SSH сообщил готовность, но control socket недоступен: {exc}"
                    ) from exc
                if not stat.S_ISSOCK(metadata.st_mode):
                    raise InstallerError("SSH ControlPath не является Unix socket")
                if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                    raise InstallerError(
                        "Небезопасные владелец или права SSH ControlPath"
                    )
                return
            time.sleep(0.05)
        raise InstallerError("SSH transport не стал готов за 20 секунд")

    def _stop_master(self, master: subprocess.Popen[str], control_path: Path) -> None:
        if master.poll() is None:
            try:
                subprocess.run(
                    self._control_argv(control_path, "exit"),
                    stdin=subprocess.DEVNULL,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=_without_askpass_env(),
                    timeout=5,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            master.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(master.pid, signal.SIGTERM)
        except (AttributeError, ProcessLookupError, PermissionError):
            try:
                master.terminate()
            except ProcessLookupError:
                pass
        try:
            master.wait(timeout=5)
            return
        except subprocess.TimeoutExpired:
            pass
        try:
            os.killpg(master.pid, signal.SIGKILL)
        except (AttributeError, ProcessLookupError, PermissionError):
            try:
                master.kill()
            except ProcessLookupError:
                pass
        try:
            master.wait(timeout=5)
        except subprocess.TimeoutExpired as exc:
            raise InstallerError(
                f"Не удалось завершить временный SSH master pid={master.pid}"
            ) from exc

    def batch(
        self, commands: list[str], *, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        batch_text = "\n".join(commands) + "\n"
        if self.auth.method == "key":
            return run(self._argv(), input_text=batch_text, check=check, timeout=90)
        return self._batch_password(batch_text, check=check)

    def _batch_password(
        self, batch_text: str, *, check: bool
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix=".xhttp-mux-", dir="/tmp") as temp:
            temp_dir = Path(temp)
            os.chmod(temp_dir, 0o700)
            control_path = temp_dir / "c"
            master: subprocess.Popen[str] | None = None
            try:
                with _password_askpass(self.auth.password) as env:
                    master = subprocess.Popen(
                        self._master_argv(control_path),
                        stdin=subprocess.DEVNULL,
                        text=True,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.PIPE,
                        env=env,
                        start_new_session=True,
                    )
                    self._wait_for_master(master, control_path)
                result = subprocess.run(
                    self._argv(control_path=control_path),
                    input=batch_text,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=_without_askpass_env(),
                    timeout=90,
                    check=False,
                )
                result = _redact_process_result(result, self.auth.password)
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise InstallerError(f"SFTP не запустился: {exc}") from exc
            finally:
                if master is not None:
                    self._stop_master(master, control_path)
        if check and result.returncode != 0:
            raise InstallerError(
                f"SFTP завершился с ошибкой: {_last_process_line(result)}"
            )
        return result


class SSHClient:
    """Small OpenSSH wrapper with the same pinned-host-key policy as SFTPClient."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        known_hosts: Path,
        auth: SSHAuth,
    ) -> None:
        self.host = validate_host(host)
        self.port = validate_port(port)
        self.user = validate_ssh_user(user)
        self.known_hosts = known_hosts
        self.auth = auth.validate()

    def _argv(self) -> list[str]:
        argv = [
            "ssh",
            "-F",
            "/dev/null",
            "-T",
            "-p",
            str(self.port),
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "NumberOfPasswordPrompts=1",
        ]
        if self.auth.method == "key":
            argv.extend(
                [
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "IdentitiesOnly=yes",
                    "-i",
                    str(self.auth.private_key),
                ]
            )
        else:
            argv.extend(
                [
                    "-o",
                    "BatchMode=no",
                    "-o",
                    "PreferredAuthentications=password",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    "KbdInteractiveAuthentication=no",
                ]
            )
        destination_host = f"[{self.host}]" if ":" in self.host else self.host
        argv.append(f"{self.user}@{destination_host}")
        return argv

    def command(
        self,
        remote_argv: list[str],
        *,
        check: bool = True,
        timeout: int = 300,
        input_text: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
        if not remote_argv:
            raise InstallerError("Пустая удалённая SSH-команда")
        if any(
            "\n" in value or "\r" in value or "\x00" in value for value in remote_argv
        ):
            raise InstallerError("Недопустимый перевод строки в SSH-команде")
        input_text = _validate_input_text(input_text)
        command_text = shlex.join(remote_argv)
        argv = self._argv() + [command_text]
        if self.auth.method == "key":
            if input_text is None:
                return run(argv, check=check, timeout=timeout)
            try:
                result = run(
                    argv,
                    input_text=input_text,
                    check=False,
                    timeout=timeout,
                )
                result = _redact_process_result(result, input_text)
            except InstallerError as exc:
                detail = _redact_input_text(str(exc), input_text)
                raise InstallerError(detail) from None
            if check and result.returncode != 0:
                raise InstallerError(
                    "SSH завершился с ошибкой: "
                    f"{_last_process_line(result, input_text=input_text)}"
                )
            return result
        return self._command_password(
            argv,
            check=check,
            timeout=timeout,
            input_text=input_text,
        )

    def _command_password(
        self,
        argv: list[str],
        *,
        check: bool,
        timeout: int,
        input_text: str | None,
    ) -> subprocess.CompletedProcess[str]:
        with _password_askpass(self.auth.password) as env:
            try:
                if input_text is None:
                    result = subprocess.run(
                        argv,
                        stdin=subprocess.DEVNULL,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=env,
                        start_new_session=True,
                        timeout=timeout,
                        check=False,
                    )
                else:
                    result = subprocess.run(
                        argv,
                        input=input_text,
                        text=True,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=env,
                        start_new_session=True,
                        timeout=timeout,
                        check=False,
                    )
                result = _redact_process_result(
                    result, self.auth.password, input_text
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                detail = _redact_input_text(str(exc), input_text)
                detail = _redact_input_text(detail, self.auth.password)
                error = InstallerError(f"SSH не запустился: {detail}")
                if input_text is None:
                    raise error from exc
                raise error from None
        if result.returncode != 0:
            detail = _last_process_line(result, input_text=input_text)
            if _SSH_PERMISSION_DENIED.search(detail):
                raise SSHAuthenticationError(
                    f"SSH-аутентификация не удалась: {detail}"
                )
        if check and result.returncode != 0:
            raise InstallerError(
                "SSH завершился с ошибкой: "
                f"{_last_process_line(result, input_text=input_text)}"
            )
        return result


def _free_loopback_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


class SSHBridgeSession:
    """One authenticated root control master with loopback-only TCP forwards.

    The bridge password is consumed only by the FIFO-backed askpass helper while
    the master starts.  Target SSH/SFTP connections use the already-authenticated
    control socket as a password-free ProxyCommand.
    """

    def __init__(
        self,
        *,
        host: str,
        port: int,
        user: str,
        known_hosts: Path,
        auth: SSHAuth,
        forwards: dict[str, tuple[str, int]],
    ) -> None:
        self.host = validate_host(host)
        self.port = validate_port(port)
        self.user = validate_ssh_user(user)
        self.known_hosts = Path(known_hosts)
        self._auth = auth.validate()
        if self._auth.method != "password":
            raise InstallerError("PC bridge поддерживает скрытый password-вход")
        normalized: dict[str, tuple[str, int]] = {}
        for name, endpoint in forwards.items():
            if not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", name):
                raise InstallerError("Некорректное имя bridge-forward")
            if name in normalized or len(endpoint) != 2:
                raise InstallerError("Некорректный bridge-forward")
            normalized[name] = (
                validate_host(endpoint[0]),
                validate_port(endpoint[1]),
            )
        if not normalized:
            raise InstallerError("Для bridge не заданы TCP-forward endpoints")
        self._forwards = normalized
        self._temporary: tempfile.TemporaryDirectory[str] | None = None
        self._master: subprocess.Popen[str] | None = None
        self._control_path: Path | None = None
        self._routes: dict[str, TCPRoute] = {}

    def __repr__(self) -> str:
        return (
            f"SSHBridgeSession(host={self.host!r}, port={self.port!r}, "
            f"user={self.user!r}, open={self._master is not None})"
        )

    def _destination(self) -> str:
        destination_host = f"[{self.host}]" if ":" in self.host else self.host
        return f"{self.user}@{destination_host}"

    def _control_argv(self, operation: str) -> list[str]:
        if self._control_path is None:
            raise InstallerError("SSH bridge control socket ещё не создан")
        return [
            "ssh",
            "-F",
            "/dev/null",
            "-S",
            str(self._control_path),
            "-O",
            operation,
            "-p",
            str(self.port),
            "-o",
            "BatchMode=yes",
            self._destination(),
        ]

    def _require_live_master(self) -> None:
        if (
            self._control_path is None
            or self._master is None
            or self._master.poll() is not None
        ):
            raise InstallerError("SSH-мост больше не работает")

    def _fail_closed_mux_options(self) -> list[str]:
        """Prevent a mux client from falling back to a new SSH connection."""

        return [
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "BatchMode=yes",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "HostbasedAuthentication=no",
            "-o",
            "GSSAPIAuthentication=no",
            "-o",
            "IdentityAgent=none",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "ProxyCommand=/bin/false",
        ]

    def _wait_for_master(self) -> None:
        if self._master is None or self._control_path is None:
            raise InstallerError("SSH bridge master не запущен")
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            returncode = self._master.poll()
            if returncode is not None:
                stderr = (
                    self._master.stderr.read()
                    if self._master.stderr is not None
                    else ""
                )
                lines = stderr.strip().splitlines()
                detail = lines[-1] if lines else f"код {returncode}"
                detail = _redact_input_text(detail, self._auth.password)
                if _SSH_PERMISSION_DENIED.search(detail):
                    raise SSHAuthenticationError(
                        f"SSH-аутентификация моста не удалась: {detail}"
                    )
                raise InstallerError(f"SSH-мост не запустился: {detail}")
            check = subprocess.run(
                self._control_argv("check"),
                stdin=subprocess.DEVNULL,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_without_askpass_env(),
                timeout=2,
                check=False,
            )
            if check.returncode == 0:
                metadata = self._control_path.lstat()
                if not stat.S_ISSOCK(metadata.st_mode):
                    raise InstallerError("SSH bridge ControlPath не является socket")
                if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o077:
                    raise InstallerError(
                        "Небезопасные владелец или права bridge ControlPath"
                    )
                return
            time.sleep(0.05)
        raise InstallerError("SSH-мост не стал готов за 20 секунд")

    def _command_via_master(
        self, remote_argv: list[str], *, timeout: int = 30
    ) -> subprocess.CompletedProcess[str]:
        self._require_live_master()
        if not remote_argv or any(
            any(char in value for char in "\r\n\x00") for value in remote_argv
        ):
            raise InstallerError("Некорректная команда проверки SSH-моста")
        try:
            result = subprocess.run(
                [
                    "ssh",
                    "-F",
                    "/dev/null",
                    "-T",
                    "-S",
                    str(self._control_path),
                    "-p",
                    str(self.port),
                    *self._fail_closed_mux_options(),
                    self._destination(),
                    shlex.join(remote_argv),
                ],
                stdin=subprocess.DEVNULL,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=_without_askpass_env(),
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            detail = _redact_input_text(str(exc), self._auth.password)
            raise InstallerError(f"Команда проверки SSH-моста не запустилась: {detail}") from None
        return _redact_process_result(result, self._auth.password)

    def open(self) -> "SSHBridgeSession":
        if self._master is not None or self._temporary is not None:
            raise InstallerError("SSH-мост уже открыт")
        temporary = tempfile.TemporaryDirectory(prefix=".xhttp-bridge-", dir="/tmp")
        self._temporary = temporary
        temp_dir = Path(temporary.name)
        os.chmod(temp_dir, 0o700)
        self._control_path = temp_dir / "c"
        local_routes: dict[str, TCPRoute] = {}
        used_ports: set[int] = set()
        for name in sorted(self._forwards):
            local_port = _free_loopback_port()
            while local_port in used_ports:
                local_port = _free_loopback_port()
            used_ports.add(local_port)
            local_routes[name] = TCPRoute("127.0.0.1", local_port).validate()

        argv = [
            "ssh",
            "-F",
            "/dev/null",
            "-N",
            "-M",
            "-S",
            str(self._control_path),
            "-p",
            str(self.port),
            "-o",
            f"UserKnownHostsFile={self.known_hosts}",
            "-o",
            "GlobalKnownHostsFile=/dev/null",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UpdateHostKeys=no",
            "-o",
            "ConnectTimeout=15",
            "-o",
            "NumberOfPasswordPrompts=1",
            "-o",
            "BatchMode=no",
            "-o",
            "PreferredAuthentications=password",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "ControlPersist=no",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "GatewayPorts=no",
            "-o",
            "LogLevel=ERROR",
        ]
        for name in sorted(self._forwards):
            remote_host, remote_port = self._forwards[name]
            remote_token = f"[{remote_host}]" if ":" in remote_host else remote_host
            argv.extend(
                [
                    "-L",
                    f"127.0.0.1:{local_routes[name].connect_port}:"
                    f"{remote_token}:{remote_port}",
                ]
            )
        argv.append(self._destination())
        try:
            with _password_askpass(self._auth.password) as env:
                self._master = subprocess.Popen(
                    argv,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    env=env,
                    start_new_session=True,
                )
                self._wait_for_master()
            identity = self._command_via_master(["id", "-u"])
            if identity.returncode != 0 or identity.stdout.strip() != "0":
                raise InstallerError("Для SSH-моста нужен успешный вход с UID 0")
            self._routes = local_routes
            return self
        except BaseException:
            self.close()
            raise

    def tcp_route(self, name: str) -> TCPRoute:
        self._require_live_master()
        try:
            return self._routes[name]
        except KeyError as exc:
            raise InstallerError("SSH-мост не содержит запрошенный forward") from exc

    def ssh_route(self, name: str) -> SSHRoute:
        self._require_live_master()
        proxy_command = shlex.join(
            [
                "ssh",
                "-F",
                "/dev/null",
                "-S",
                str(self._control_path),
                "-W",
                "%h:%p",
                "-p",
                str(self.port),
                *self._fail_closed_mux_options(),
                "-o",
                "LogLevel=ERROR",
                self._destination(),
            ]
        )
        return SSHRoute(
            scan=self.tcp_route(name), proxy_command=proxy_command
        ).validate()

    def close(self) -> None:
        master = self._master
        control_path = self._control_path
        self._master = None
        self._routes = {}
        try:
            if master is not None and control_path is not None:
                if master.poll() is None:
                    try:
                        subprocess.run(
                            self._control_argv("exit"),
                            stdin=subprocess.DEVNULL,
                            text=True,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=_without_askpass_env(),
                            timeout=5,
                            check=False,
                        )
                    except (OSError, subprocess.TimeoutExpired):
                        pass
                try:
                    master.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(master.pid, signal.SIGTERM)
                    except (AttributeError, ProcessLookupError, PermissionError):
                        try:
                            master.terminate()
                        except ProcessLookupError:
                            pass
                    try:
                        master.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        try:
                            os.killpg(master.pid, signal.SIGKILL)
                        except (AttributeError, ProcessLookupError, PermissionError):
                            try:
                                master.kill()
                            except ProcessLookupError:
                                pass
                        master.wait(timeout=5)
                if master.stderr is not None:
                    master.stderr.close()
        finally:
            self._control_path = None
            temporary = self._temporary
            self._temporary = None
            if temporary is not None:
                temporary.cleanup()

    def __enter__(self) -> "SSHBridgeSession":
        return self.open()

    def __exit__(self, exc_type, exc, traceback) -> bool:
        self.close()
        return False


def sftp_quote(value: str) -> str:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise InstallerError("Недопустимый перевод строки в SFTP-пути")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
