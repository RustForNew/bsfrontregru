from __future__ import annotations

import os
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from .errors import InstallerError, VerificationError
from .osutil import atomic_write_text, ensure_dir, run
from .validate import validate_host, validate_port, validate_ssh_user


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


def pin_host_key(
    *, host: str, port: int, expected_sha256: str, known_hosts: Path
) -> None:
    """Fetch keys, retain only the line matching an independently supplied fingerprint."""
    ensure_dir(known_hosts.parent, 0o700)
    scan = run(
        [
            "ssh-keyscan",
            "-T",
            "10",
            "-p",
            str(port),
            "-t",
            "ed25519,ecdsa,rsa",
            host,
        ],
        check=False,
        timeout=20,
    )
    candidates = [
        line for line in scan.stdout.splitlines() if line and not line.startswith("#")
    ]
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
    ) -> None:
        self.host = validate_host(host)
        self.port = validate_port(port)
        self.user = validate_ssh_user(user)
        self.known_hosts = known_hosts
        self.auth = auth.validate()

    def _argv(self) -> list[str]:
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
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, True)
        try:
            os.write(write_fd, (self.auth.password + "\n").encode("utf-8"))
        finally:
            os.close(write_fd)
        with tempfile.TemporaryDirectory(prefix="xhttp-askpass-") as temp:
            helper = Path(temp) / "askpass"
            helper.write_text(
                '#!/bin/sh\nIFS= read -r answer <&"$XHTTP_ASKPASS_FD"\nprintf "%s\\n" "$answer"\n',
                encoding="utf-8",
            )
            os.chmod(helper, 0o700)
            env = os.environ.copy()
            env.update(
                {
                    "DISPLAY": "xhttp-setup",
                    "SSH_ASKPASS": str(helper),
                    "SSH_ASKPASS_REQUIRE": "force",
                    "XHTTP_ASKPASS_FD": str(read_fd),
                }
            )
            try:
                result = subprocess.run(
                    self._argv(),
                    input=batch_text,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    pass_fds=(read_fd,),
                    start_new_session=True,
                    timeout=90,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise InstallerError(f"SFTP не запустился: {exc}") from exc
            finally:
                os.close(read_fd)
        if check and result.returncode != 0:
            lines = (result.stderr or result.stdout).strip().splitlines()
            detail = lines[-1] if lines else f"код {result.returncode}"
            raise InstallerError(f"SFTP завершился с ошибкой: {detail}")
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
    ) -> subprocess.CompletedProcess[str]:
        if not remote_argv:
            raise InstallerError("Пустая удалённая SSH-команда")
        if any(
            "\n" in value or "\r" in value or "\x00" in value for value in remote_argv
        ):
            raise InstallerError("Недопустимый перевод строки в SSH-команде")
        command_text = shlex.join(remote_argv)
        argv = self._argv() + [command_text]
        if self.auth.method == "key":
            return run(argv, check=check, timeout=timeout)
        return self._command_password(argv, check=check, timeout=timeout)

    def _command_password(
        self, argv: list[str], *, check: bool, timeout: int
    ) -> subprocess.CompletedProcess[str]:
        read_fd, write_fd = os.pipe()
        os.set_inheritable(read_fd, True)
        try:
            os.write(write_fd, (self.auth.password + "\n").encode("utf-8"))
        finally:
            os.close(write_fd)
        with tempfile.TemporaryDirectory(prefix="xhttp-askpass-") as temp:
            helper = Path(temp) / "askpass"
            helper.write_text(
                '#!/bin/sh\nIFS= read -r answer <&"$XHTTP_ASKPASS_FD"\nprintf "%s\\n" "$answer"\n',
                encoding="utf-8",
            )
            os.chmod(helper, 0o700)
            env = os.environ.copy()
            env.update(
                {
                    "DISPLAY": "xhttp-setup",
                    "SSH_ASKPASS": str(helper),
                    "SSH_ASKPASS_REQUIRE": "force",
                    "XHTTP_ASKPASS_FD": str(read_fd),
                }
            )
            try:
                result = subprocess.run(
                    argv,
                    stdin=subprocess.DEVNULL,
                    text=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env=env,
                    pass_fds=(read_fd,),
                    start_new_session=True,
                    timeout=timeout,
                    check=False,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                raise InstallerError(f"SSH не запустился: {exc}") from exc
            finally:
                os.close(read_fd)
        if check and result.returncode != 0:
            lines = (result.stderr or result.stdout).strip().splitlines()
            detail = lines[-1] if lines else f"код {result.returncode}"
            raise InstallerError(f"SSH завершился с ошибкой: {detail}")
        return result


def sftp_quote(value: str) -> str:
    if "\n" in value or "\r" in value or "\x00" in value:
        raise InstallerError("Недопустимый перевод строки в SFTP-пути")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'
