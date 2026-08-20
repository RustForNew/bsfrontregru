"""Pinned-SSH orchestration for applying ``front`` on a trusted Linux bridge.

The bridge is only a control-plane host.  This module uploads the current
installer and handoff, invokes the existing ``front`` CLI, retrieves the
verified client profile, and removes only its exact staging files.  It never
logs remote output or returns secret material.
"""

from __future__ import annotations

import os
import platform
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from .errors import InstallerError, VerificationError
from .models import FrontDesired, Handoff
from .osutil import atomic_write, ensure_dir, load_json, sha256_file
from .render import render_vless_uri
from .ssh_transport import (
    SSHAuth,
    SSHClient,
    SFTPClient,
    pin_host_key,
    sftp_quote,
)
from .validate import (
    validate_fingerprint,
    validate_host,
    validate_port,
    validate_ssh_user,
)


RemoteApplyStatus = Literal["not_started", "failed", "unknown", "succeeded"]
ArtifactStatus = Literal["not_saved", "partial", "saved"]
CleanupStatus = Literal["not_needed", "unknown", "failed", "succeeded"]

_REMOTE_TEMP = re.compile(r"^/tmp/xhttp-front\.[A-Za-z0-9]{6,32}$")
_HASH = re.compile(r"^[0-9a-f]{64}$")
_MAX_INSTALLER_BYTES = 256 * 1024 * 1024
_MAX_HANDOFF_BYTES = 64 * 1024
_MAX_CLIENT_BYTES = 128 * 1024
_MAX_PASSWORD_BYTES = 4095  # SSH stdin also carries one trailing LF (4096 total).
_REMOTE_FRONT_ROOT = PurePosixPath("/var/lib/xhttp-setup/fronts")

_STAGE_MESSAGES = {
    "remote_identity": "не удалось подтвердить root UID доверенного bridge",
    "remote_temp": "не удалось безопасно создать временный каталог на bridge",
    "upload": "не удалось загрузить installer и handoff на bridge",
    "upload_verify": "SHA-256, тип или права загруженных файлов не подтверждены",
    "remote_apply": "удалённый frontend apply не завершился успешно",
    "artifact_download": "не удалось безопасно скачать client.vless",
    "artifact_validation": "скачанный client.vless не прошёл проверку",
    "local_persist": "не удалось транзакционно сохранить client.vless",
    "cleanup": "не удалось полностью очистить точный временный каталог на bridge",
}


@dataclass(frozen=True)
class RemoteFrontTarget:
    host: str
    user: str
    host_key_sha256: str
    port: int = 22

    def validate(self) -> "RemoteFrontTarget":
        return RemoteFrontTarget(
            host=validate_host(self.host),
            user=validate_ssh_user(self.user),
            host_key_sha256=validate_fingerprint(self.host_key_sha256),
            port=validate_port(self.port),
        )


@dataclass(frozen=True)
class RemoteFrontResult:
    target: RemoteFrontTarget
    client_path: Path
    known_hosts_path: Path
    installer_sha256: str
    remote_status: RemoteApplyStatus = "succeeded"
    artifact_status: ArtifactStatus = "saved"
    cleanup_status: CleanupStatus = "succeeded"


class RemoteFrontError(InstallerError):
    """Failure with explicit remote, artifact, and cleanup state."""

    def __init__(
        self,
        *,
        stage: str,
        remote_status: RemoteApplyStatus,
        artifact_status: ArtifactStatus,
        cleanup_status: CleanupStatus,
        remote_temp: str | None = None,
    ) -> None:
        detail = _STAGE_MESSAGES.get(stage, "удалённая настройка frontend не завершена")
        message = (
            f"{detail}; remote_apply={remote_status}; "
            f"local_artifact={artifact_status}; remote_temp_cleanup={cleanup_status}"
        )
        if cleanup_status in {"failed", "unknown"} and remote_temp is not None:
            message += f"; проверить вручную: {remote_temp}"
        super().__init__(message)
        self.stage = stage
        self.remote_status = remote_status
        self.artifact_status = artifact_status
        self.cleanup_status = cleanup_status
        self.remote_temp = remote_temp

    @property
    def remote_applied(self) -> bool | None:
        if self.remote_status == "succeeded":
            return True
        if self.remote_status == "not_started":
            return False
        return None


@dataclass(frozen=True)
class _RemoteMetadata:
    mode: int
    permissions: int
    uid: int
    gid: int
    size: int


@dataclass(frozen=True)
class _LocalSnapshot:
    data: bytes
    mode: int


@dataclass(frozen=True)
class _RemoteArtifactSnapshot:
    metadata: _RemoteMetadata
    sha256: str


class _UploadVerificationError(InstallerError):
    pass


class _LocalPersistError(InstallerError):
    def __init__(self, *, partial: bool) -> None:
        super().__init__("local client artifact transaction failed")
        self.partial = partial


def _validated_local_file(
    path: Path,
    *,
    description: str,
    maximum_bytes: int,
    secret: bool = False,
) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise InstallerError(f"{description} не может быть symlink")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise InstallerError(f"Не удалось открыть {description}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallerError(f"{description} должен быть обычным файлом")
    if metadata.st_size <= 0 or metadata.st_size > maximum_bytes:
        raise InstallerError(f"Недопустимый размер {description}")
    if secret and os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise InstallerError(f"{description} должен иметь права 0600")
    return resolved


def _validated_output_dir(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise InstallerError("Каталог локальных артефактов не может быть symlink")
    resolved = candidate.resolve(strict=False)
    ensure_dir(resolved, 0o700)
    if os.name == "posix" and resolved.stat().st_uid != os.geteuid():
        raise InstallerError("Каталог локальных артефактов принадлежит другому UID")
    return resolved


def _validate_password_line(password: str) -> str:
    if not isinstance(password, str) or not password:
        raise InstallerError("Пустой SFTP-пароль")
    if len(password.encode("utf-8")) > _MAX_PASSWORD_BYTES or any(
        char in password for char in "\r\n\x00"
    ):
        raise InstallerError("SFTP-пароль нельзя безопасно передать одной строкой")
    return password


def _load_handoff(path: Path) -> tuple[Path, Handoff]:
    validated = _validated_local_file(
        path,
        description="handoff.json",
        maximum_bytes=_MAX_HANDOFF_BYTES,
        secret=True,
    )
    return validated, Handoff.from_dict(load_json(validated))


def _validate_handoff_matches(desired: FrontDesired, handoff: Handoff) -> Handoff:
    if (
        desired.exit_address != handoff.exit_address
        or desired.exit_port != handoff.exit_port
        or desired.xhttp_path != handoff.xhttp_path
    ):
        raise VerificationError("FrontDesired не соответствует защищённому handoff")
    return handoff.with_pinned_peer_cert(desired.pinned_peer_cert_sha256)


def _assert_local_client(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise VerificationError("Локальный client.vless отсутствует") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise VerificationError("Локальный client.vless должен быть обычным файлом")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_CLIENT_BYTES:
        raise VerificationError("Недопустимый размер локального client.vless")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise VerificationError("Локальный client.vless должен иметь права 0600")


def _parse_remote_id(value: str) -> int:
    stripped = value.strip()
    if not re.fullmatch(r"[0-9]{1,10}", stripped):
        raise VerificationError("Удалённый id вернул неожиданный ответ")
    identifier = int(stripped)
    if identifier > 2**31 - 1:
        raise VerificationError("Удалённый UID вне допустимого диапазона")
    return identifier


def _checked_remote(ssh: SSHClient, argv: list[str], *, timeout: int = 60) -> None:
    result = ssh.command(argv, check=False, timeout=timeout)
    if result.returncode != 0:
        raise InstallerError("Удалённая команда вернула ошибку")


def _create_remote_temp(ssh: SSHClient) -> str:
    result = ssh.command(
        ["mktemp", "-d", "-p", "/tmp", "xhttp-front.XXXXXXXXXX"],
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise InstallerError("mktemp завершился с ошибкой")
    lines = result.stdout.splitlines()
    if len(lines) != 1 or not _REMOTE_TEMP.fullmatch(lines[0].strip()):
        raise VerificationError("mktemp вернул путь вне разрешённого шаблона")
    return lines[0].strip()


def _remote_metadata(ssh: SSHClient, path: str) -> _RemoteMetadata:
    result = ssh.command(
        ["stat", "-c", "%f %a %u %g %s", "--", path],
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise InstallerError("Не удалось проверить удалённый managed-путь")
    fields = result.stdout.strip().split()
    if len(fields) != 5:
        raise VerificationError("stat вернул неожиданный ответ")
    mode_hex, permissions, uid, gid, size = fields
    if not re.fullmatch(r"[0-9a-fA-F]{1,8}", mode_hex):
        raise VerificationError("stat вернул некорректный mode")
    if not re.fullmatch(r"[0-7]{3,4}", permissions):
        raise VerificationError("stat вернул некорректные права")
    for value in (uid, gid, size):
        if not re.fullmatch(r"[0-9]{1,20}", value):
            raise VerificationError("stat вернул некорректные метаданные")
    return _RemoteMetadata(
        mode=int(mode_hex, 16),
        permissions=int(permissions, 8),
        uid=int(uid),
        gid=int(gid),
        size=int(size),
    )


def _require_remote_path(
    ssh: SSHClient,
    path: str,
    *,
    kind: Literal["file", "directory"],
    permissions: int,
    maximum_bytes: int | None = None,
) -> _RemoteMetadata:
    metadata = _remote_metadata(ssh, path)
    correct_type = (
        stat.S_ISREG(metadata.mode) if kind == "file" else stat.S_ISDIR(metadata.mode)
    )
    if not correct_type:
        raise VerificationError("Удалённый managed-путь имеет неверный тип")
    if metadata.permissions != permissions or metadata.uid != 0 or metadata.gid != 0:
        raise VerificationError("Удалённый managed-путь имеет неверные owner или права")
    if kind == "file" and (
        metadata.size <= 0
        or (maximum_bytes is not None and metadata.size > maximum_bytes)
    ):
        raise VerificationError("Удалённый managed-файл имеет недопустимый размер")
    return metadata


def _remote_hash(ssh: SSHClient, path: str) -> str:
    result = ssh.command(["sha256sum", "--", path], check=False, timeout=30)
    if result.returncode != 0:
        raise InstallerError("Не удалось вычислить SHA-256 удалённого файла")
    lines = result.stdout.strip().splitlines()
    if len(lines) != 1:
        raise VerificationError("sha256sum вернул неожиданный ответ")
    digest = lines[0].split()[0] if lines[0].split() else ""
    if not _HASH.fullmatch(digest):
        raise VerificationError("sha256sum вернул некорректный SHA-256")
    return digest


def _upload_and_verify(
    sftp: SFTPClient,
    ssh: SSHClient,
    *,
    installer: Path,
    handoff: Path,
    remote_installer: str,
    remote_handoff: str,
    local_roundtrip_dir: Path,
) -> None:
    sftp.batch(
        [
            f"put {sftp_quote(str(installer))} {sftp_quote(remote_installer)}",
            f"chmod 700 {sftp_quote(remote_installer)}",
            f"put {sftp_quote(str(handoff))} {sftp_quote(remote_handoff)}",
            f"chmod 600 {sftp_quote(remote_handoff)}",
        ]
    )
    try:
        installer_copy = local_roundtrip_dir / "installer.roundtrip.pyz"
        handoff_copy = local_roundtrip_dir / "handoff.roundtrip.json"
        sftp.batch(
            [
                f"get {sftp_quote(remote_installer)} {sftp_quote(str(installer_copy))}",
                f"get {sftp_quote(remote_handoff)} {sftp_quote(str(handoff_copy))}",
            ]
        )
        os.chmod(installer_copy, 0o600)
        os.chmod(handoff_copy, 0o600)
        if sha256_file(installer_copy) != sha256_file(installer):
            raise VerificationError("Roundtrip SHA-256 installer не совпал")
        if sha256_file(handoff_copy) != sha256_file(handoff):
            raise VerificationError("Roundtrip SHA-256 handoff не совпал")
        _require_remote_path(
            ssh,
            remote_installer,
            kind="file",
            permissions=0o700,
            maximum_bytes=_MAX_INSTALLER_BYTES,
        )
        _require_remote_path(
            ssh,
            remote_handoff,
            kind="file",
            permissions=0o600,
            maximum_bytes=_MAX_HANDOFF_BYTES,
        )
    except Exception as exc:
        raise _UploadVerificationError() from exc


def _remote_state_dir(desired: FrontDesired) -> str:
    return str(_REMOTE_FRONT_ROOT / desired.domain)


def _remote_apply_argv(
    desired: FrontDesired,
    *,
    remote_installer: str,
    remote_handoff: str,
) -> list[str]:
    command = [
        "python3",
        remote_installer,
        "front",
        "--handoff",
        remote_handoff,
        "--domain",
        desired.domain,
        "--client-connect-ip",
        desired.client_connect_ip,
        "--dns-ipv4",
        desired.dns_ipv4,
        "--sftp-host",
        desired.sftp_host,
        "--sftp-port",
        str(desired.sftp_port),
        "--sftp-user",
        desired.sftp_user,
        "--document-root",
        desired.document_root,
        "--fingerprint",
        desired.ssh_host_key_sha256,
        "--tls-mode",
        desired.tls_mode,
        "--placeholder",
        desired.placeholder_mode,
        "--auth-method",
        "password-stdin",
        "--state-dir",
        _remote_state_dir(desired),
        "--ack-provider-rules",
        "--ack-firewall",
        "--apply",
        "--confirm",
        f"APPLY {desired.domain}",
    ]
    if desired.pinned_peer_cert_sha256 is not None:
        command.extend(["--tls-cert-sha256", desired.pinned_peer_cert_sha256])
    return command


def _snapshot_remote_client(
    ssh: SSHClient, remote_client: str
) -> _RemoteArtifactSnapshot:
    metadata = _require_remote_path(
        ssh,
        remote_client,
        kind="file",
        permissions=0o600,
        maximum_bytes=_MAX_CLIENT_BYTES,
    )
    return _RemoteArtifactSnapshot(metadata, _remote_hash(ssh, remote_client))


def _download_client(
    sftp: SFTPClient,
    *,
    remote_client: str,
    local_dir: Path,
) -> Path:
    downloaded = local_dir / "client.download.vless"
    sftp.batch([f"get {sftp_quote(remote_client)} {sftp_quote(str(downloaded))}"])
    os.chmod(downloaded, 0o600)
    return downloaded


def _validate_downloaded_client(
    ssh: SSHClient,
    *,
    remote_client: str,
    before: _RemoteArtifactSnapshot,
    downloaded: Path,
    expected: bytes,
) -> None:
    after = _snapshot_remote_client(ssh, remote_client)
    _assert_local_client(downloaded)
    if (
        before != after
        or sha256_file(downloaded) != before.sha256
        or downloaded.read_bytes() != expected
    ):
        raise VerificationError("client.vless не соответствует проверенному результату")


def _snapshot_local(path: Path) -> _LocalSnapshot | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError("Не удалось проверить локальный client.vless") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallerError(
            "Локальный managed client.vless должен быть обычным файлом"
        )
    try:
        return _LocalSnapshot(path.read_bytes(), stat.S_IMODE(metadata.st_mode))
    except OSError as exc:
        raise InstallerError("Не удалось прочитать локальный client.vless") from exc


def _persist_local_client(source: Path, output_dir: Path) -> Path:
    target = output_dir / "client.vless"
    snapshot = _snapshot_local(target)
    try:
        atomic_write(target, source.read_bytes(), 0o600)
        _assert_local_client(target)
    except Exception as original:
        try:
            if snapshot is None:
                target.unlink(missing_ok=True)
            else:
                atomic_write(target, snapshot.data, snapshot.mode)
        except Exception:
            raise _LocalPersistError(partial=True) from original
        raise _LocalPersistError(partial=False) from original
    return target


def _cleanup_remote_temp(ssh: SSHClient, remote_temp: str) -> bool:
    if not _REMOTE_TEMP.fullmatch(remote_temp):
        return False
    exact_files = [
        f"{remote_temp}/installer.pyz",
        f"{remote_temp}/handoff.json",
    ]
    try:
        removed = ssh.command(["rm", "-f", "--", *exact_files], check=False, timeout=30)
        if removed.returncode != 0:
            return False
        directory = ssh.command(["rmdir", "--", remote_temp], check=False, timeout=30)
        return directory.returncode == 0
    except Exception:
        return False


def apply_remote_front(
    *,
    installer_pyz: Path,
    handoff_path: Path,
    desired: FrontDesired,
    target: RemoteFrontTarget,
    bridge_auth: SSHAuth,
    sftp_password: str,
    output_dir: Path,
    firewall_verified: bool,
) -> RemoteFrontResult:
    """Run the existing ``front`` CLI on a pinned, trusted root bridge.

    ``firewall_verified`` must be the literal boolean ``True``.  The SFTP
    password is sent once through SSH stdin; it is never placed in argv, a
    remote file, a result object, or an error message.

    This function relies on ``SSHClient.command(..., input_text=...)`` and on
    the ``front`` CLI accepting ``--auth-method password-stdin``.
    """

    if firewall_verified is not True:
        raise InstallerError("Remote front требует явного подтверждения firewall")
    desired = desired.validate()
    target = target.validate()
    bridge_auth = bridge_auth.validate()
    password = _validate_password_line(sftp_password)
    if platform.system() != "Linux":
        raise InstallerError("Удалённый frontend поддерживается только с Linux/WSL")
    installer = _validated_local_file(
        installer_pyz,
        description="installer .pyz",
        maximum_bytes=_MAX_INSTALLER_BYTES,
    )
    handoff_file, handoff = _load_handoff(handoff_path)
    client_handoff = _validate_handoff_matches(desired, handoff)
    expected_client = (
        render_vless_uri(
            client_handoff,
            desired.domain,
            front_address=desired.client_connect_ip,
        )
        + "\n"
    ).encode("utf-8")
    output = _validated_output_dir(output_dir)
    known_hosts = output / "bridge-known_hosts"
    if known_hosts.is_symlink():
        raise InstallerError("Pinned known_hosts не может быть symlink")
    pin_host_key(
        host=target.host,
        port=target.port,
        expected_sha256=target.host_key_sha256,
        known_hosts=known_hosts,
    )
    if os.name == "posix":
        metadata = known_hosts.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise VerificationError(
                "Pinned known_hosts должен быть обычным файлом 0600"
            )

    ssh = SSHClient(
        host=target.host,
        port=target.port,
        user=target.user,
        known_hosts=known_hosts,
        auth=bridge_auth,
    )
    sftp = SFTPClient(
        host=target.host,
        port=target.port,
        user=target.user,
        known_hosts=known_hosts,
        auth=bridge_auth,
    )

    remote_status: RemoteApplyStatus = "not_started"
    artifact_status: ArtifactStatus = "not_saved"
    cleanup_status: CleanupStatus = "not_needed"
    stage = "remote_identity"
    remote_temp: str | None = None
    failure: Exception | None = None
    client_target: Path | None = None

    with tempfile.TemporaryDirectory(prefix=".remote-front-", dir=output) as temp:
        local_temp = Path(temp)
        try:
            uid_result = ssh.command(["id", "-u"], check=False, timeout=30)
            if uid_result.returncode != 0 or _parse_remote_id(uid_result.stdout) != 0:
                raise InstallerError("Remote front v1 требует UID 0")

            stage = "remote_temp"
            cleanup_status = "unknown"
            remote_temp = _create_remote_temp(ssh)
            _checked_remote(ssh, ["chmod", "700", "--", remote_temp], timeout=30)
            _require_remote_path(
                ssh,
                remote_temp,
                kind="directory",
                permissions=0o700,
            )
            remote_installer = f"{remote_temp}/installer.pyz"
            remote_handoff = f"{remote_temp}/handoff.json"

            stage = "upload"
            try:
                _upload_and_verify(
                    sftp,
                    ssh,
                    installer=installer,
                    handoff=handoff_file,
                    remote_installer=remote_installer,
                    remote_handoff=remote_handoff,
                    local_roundtrip_dir=local_temp,
                )
            except _UploadVerificationError:
                stage = "upload_verify"
                raise

            stage = "remote_apply"
            remote_status = "unknown"
            apply_result = ssh.command(
                _remote_apply_argv(
                    desired,
                    remote_installer=remote_installer,
                    remote_handoff=remote_handoff,
                ),
                check=False,
                timeout=900,
                input_text=password + "\n",
            )
            if apply_result.returncode != 0:
                remote_status = (
                    "unknown" if apply_result.returncode == 255 else "failed"
                )
                raise InstallerError("remote front apply вернул ошибку")
            remote_status = "succeeded"

            remote_client = f"{_remote_state_dir(desired)}/client.vless"
            stage = "artifact_validation"
            remote_client_before = _snapshot_remote_client(ssh, remote_client)
            stage = "artifact_download"
            downloaded = _download_client(
                sftp,
                remote_client=remote_client,
                local_dir=local_temp,
            )
            stage = "artifact_validation"
            _validate_downloaded_client(
                ssh,
                remote_client=remote_client,
                before=remote_client_before,
                downloaded=downloaded,
                expected=expected_client,
            )

            stage = "local_persist"
            try:
                client_target = _persist_local_client(downloaded, output)
            except _LocalPersistError as exc:
                artifact_status = "partial" if exc.partial else "not_saved"
                raise
            artifact_status = "saved"
        except Exception as exc:
            failure = exc
        finally:
            if remote_temp is not None:
                cleanup_status = (
                    "succeeded" if _cleanup_remote_temp(ssh, remote_temp) else "failed"
                )

    if failure is not None:
        raise RemoteFrontError(
            stage=stage,
            remote_status=remote_status,
            artifact_status=artifact_status,
            cleanup_status=cleanup_status,
            remote_temp=remote_temp,
        ) from failure
    if cleanup_status != "succeeded":
        raise RemoteFrontError(
            stage="cleanup",
            remote_status=remote_status,
            artifact_status=artifact_status,
            cleanup_status=cleanup_status,
            remote_temp=remote_temp,
        )
    if client_target is None:
        raise RemoteFrontError(
            stage="local_persist",
            remote_status=remote_status,
            artifact_status=artifact_status,
            cleanup_status=cleanup_status,
        )
    return RemoteFrontResult(
        target=target,
        client_path=client_target,
        known_hosts_path=known_hosts,
        installer_sha256=sha256_file(installer),
    )
