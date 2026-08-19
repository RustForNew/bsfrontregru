"""Bounded pinned-SSH orchestration for a standalone XHTTP exit.

This path is unit-tested; live validation on disposable exit hosts is still pending.
It stages and returns a firewall plan but never executes that plan.
"""

from __future__ import annotations

import os
import platform
import re
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from .errors import InstallerError, VerificationError
from .exit_installer import Layout, _firewall_plan
from .models import ExitDesired, Handoff
from .osutil import atomic_write, atomic_write_text, ensure_dir, load_json, sha256_file
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

_REMOTE_TEMP = re.compile(r"^/tmp/xhttp-exit\.[A-Za-z0-9]{6,32}$")
_MAX_INSTALLER_BYTES = 256 * 1024 * 1024
_MAX_HANDOFF_BYTES = 64 * 1024
_MAX_FIREWALL_PLAN_BYTES = 64 * 1024

_STAGE_MESSAGES = {
    "remote_identity": "не удалось проверить UID/GID удалённого пользователя",
    "remote_temp": "не удалось безопасно создать временный каталог на exit",
    "upload": "не удалось загрузить installer и UUID на exit",
    "upload_verify": "SHA-256 или права загруженных файлов не подтверждены",
    "remote_apply": "удалённый installer не завершил apply успешно",
    "artifact_stage": "не удалось подготовить root-only артефакты к скачиванию",
    "artifact_download": "не удалось скачать handoff и firewall-план",
    "artifact_validation": "скачанные handoff или firewall-план не прошли проверку",
    "local_persist": "не удалось транзакционно сохранить локальные артефакты",
    "cleanup": "не удалось полностью очистить точный временный каталог на exit",
}


@dataclass(frozen=True)
class RemoteExitTarget:
    host: str
    user: str
    host_key_sha256: str
    port: int = 22

    def validate(self) -> "RemoteExitTarget":
        return RemoteExitTarget(
            host=validate_host(self.host),
            user=validate_ssh_user(self.user),
            host_key_sha256=validate_fingerprint(self.host_key_sha256),
            port=validate_port(self.port),
        )


@dataclass(frozen=True)
class RemoteExitResult:
    target: RemoteExitTarget
    handoff_path: Path
    firewall_plan_path: Path
    known_hosts_path: Path
    installer_sha256: str
    remote_status: RemoteApplyStatus = "succeeded"
    artifact_status: ArtifactStatus = "saved"
    cleanup_status: CleanupStatus = "succeeded"


class RemoteExitError(InstallerError):
    """Failure with explicit local/remote partial-success state and no credentials."""

    def __init__(
        self,
        *,
        stage: str,
        remote_status: RemoteApplyStatus,
        artifact_status: ArtifactStatus,
        cleanup_status: CleanupStatus,
        remote_temp: str | None = None,
    ) -> None:
        detail = _STAGE_MESSAGES.get(stage, "удалённая установка не завершена")
        message = (
            f"{detail}; remote_apply={remote_status}; "
            f"local_artifacts={artifact_status}; remote_temp_cleanup={cleanup_status}"
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
class _LocalSnapshot:
    data: bytes
    mode: int


class _LocalPersistError(InstallerError):
    def __init__(self, *, partial: bool) -> None:
        super().__init__("local artifact transaction failed")
        self.partial = partial


class _UploadVerificationError(InstallerError):
    pass


def _validated_local_file(path: Path, *, description: str) -> Path:
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
    if metadata.st_size <= 0 or metadata.st_size > _MAX_INSTALLER_BYTES:
        raise InstallerError(f"Недопустимый размер {description}")
    return resolved


def _validated_output_dir(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise InstallerError("Каталог локальных артефактов не может быть symlink")
    resolved = candidate.resolve(strict=False)
    ensure_dir(resolved, 0o700)
    return resolved


def _assert_regular_0600(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise VerificationError(f"Локальный managed-файл отсутствует: {path}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise VerificationError(f"Локальный managed-путь не является файлом: {path}")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise VerificationError(
            f"Локальный managed-файл должен иметь права 0600: {path}"
        )


def _parse_remote_id(value: str) -> int:
    stripped = value.strip()
    if not re.fullmatch(r"[0-9]{1,10}", stripped):
        raise VerificationError("Удалённый id вернул неожиданный ответ")
    identifier = int(stripped)
    if identifier > 2**31 - 1:
        raise VerificationError("Удалённый UID/GID вне допустимого диапазона")
    return identifier


def _checked_remote(ssh: SSHClient, argv: list[str], *, timeout: int = 120) -> None:
    result = ssh.command(argv, check=False, timeout=timeout)
    if result.returncode != 0:
        raise InstallerError("Удалённая команда вернула ошибку")


def _create_remote_temp(ssh: SSHClient) -> str:
    result = ssh.command(
        ["mktemp", "-d", "-p", "/tmp", "xhttp-exit.XXXXXXXXXX"],
        check=False,
        timeout=30,
    )
    if result.returncode != 0:
        raise InstallerError("mktemp завершился с ошибкой")
    lines = result.stdout.splitlines()
    if len(lines) != 1 or not _REMOTE_TEMP.fullmatch(lines[0].strip()):
        raise VerificationError("mktemp вернул путь вне разрешённого шаблона")
    return lines[0].strip()


def _remote_mode(ssh: SSHClient, path: str) -> str:
    result = ssh.command(["stat", "-c", "%a", "--", path], check=False, timeout=30)
    if result.returncode != 0:
        raise InstallerError("Не удалось проверить права удалённого файла")
    return result.stdout.strip()


def _upload_and_verify(
    sftp: SFTPClient,
    ssh: SSHClient,
    *,
    installer: Path,
    client_id_file: Path,
    remote_installer: str,
    remote_client_id: str,
    local_roundtrip_dir: Path,
) -> None:
    sftp.batch(
        [
            f"put {sftp_quote(str(installer))} {sftp_quote(remote_installer)}",
            f"chmod 700 {sftp_quote(remote_installer)}",
            f"put {sftp_quote(str(client_id_file))} {sftp_quote(remote_client_id)}",
            f"chmod 600 {sftp_quote(remote_client_id)}",
        ]
    )
    try:
        installer_copy = local_roundtrip_dir / "installer.roundtrip.pyz"
        client_id_copy = local_roundtrip_dir / "client-id.roundtrip"
        sftp.batch(
            [
                f"get {sftp_quote(remote_installer)} {sftp_quote(str(installer_copy))}",
                f"get {sftp_quote(remote_client_id)} {sftp_quote(str(client_id_copy))}",
            ]
        )
        os.chmod(installer_copy, 0o600)
        os.chmod(client_id_copy, 0o600)
        if sha256_file(installer_copy) != sha256_file(installer):
            raise VerificationError("Roundtrip SHA-256 installer не совпал")
        if sha256_file(client_id_copy) != sha256_file(client_id_file):
            raise VerificationError("Roundtrip SHA-256 UUID не совпал")
        if _remote_mode(ssh, remote_installer) != "700":
            raise VerificationError("Удалённый installer должен иметь права 0700")
        if _remote_mode(ssh, remote_client_id) != "600":
            raise VerificationError("Удалённый UUID должен иметь права 0600")
    except Exception as exc:
        raise _UploadVerificationError() from exc


def _remote_apply_argv(
    desired: ExitDesired,
    *,
    remote_installer: str,
    remote_client_id: str,
    remote_uid: int,
) -> list[str]:
    command = [
        "python3",
        remote_installer,
        "exit",
        "--public-address",
        desired.public_address,
        "--front-egress-ip",
        desired.front_egress_ip,
        "--expected-egress-ip",
        str(desired.expected_egress_ip),
        "--port",
        str(desired.listen_port),
        "--path",
        desired.xhttp_path,
        "--client-id-file",
        remote_client_id,
        "--label",
        desired.label,
        "--tls-fingerprint",
        desired.tls_fingerprint,
        "--apply",
        "--confirm",
        "APPLY EXIT",
    ]
    if remote_uid != 0:
        return ["sudo", "-n", "--", *command]
    return command


def _stage_remote_artifact(
    ssh: SSHClient,
    *,
    source: Path,
    destination: str,
    remote_uid: int,
    remote_gid: int,
) -> None:
    command = [
        "install",
        "-m",
        "0600",
        "-o",
        str(remote_uid),
        "-g",
        str(remote_gid),
        "--",
        str(source),
        destination,
    ]
    if remote_uid != 0:
        command = ["sudo", "-n", "--", *command]
    _checked_remote(ssh, command, timeout=60)


def _download_artifacts(
    sftp: SFTPClient,
    *,
    remote_handoff: str,
    remote_firewall_plan: str,
    local_dir: Path,
) -> tuple[Path, Path]:
    handoff = local_dir / "handoff.download"
    firewall_plan = local_dir / "firewall-plan.download"
    sftp.batch(
        [
            f"get {sftp_quote(remote_handoff)} {sftp_quote(str(handoff))}",
            f"get {sftp_quote(remote_firewall_plan)} {sftp_quote(str(firewall_plan))}",
        ]
    )
    os.chmod(handoff, 0o600)
    os.chmod(firewall_plan, 0o600)
    return handoff, firewall_plan


def _validate_downloaded_artifacts(
    desired: ExitDesired,
    *,
    handoff_path: Path,
    firewall_plan_path: Path,
) -> None:
    if handoff_path.stat().st_size > _MAX_HANDOFF_BYTES:
        raise VerificationError("Handoff превышает допустимый размер")
    if firewall_plan_path.stat().st_size > _MAX_FIREWALL_PLAN_BYTES:
        raise VerificationError("Firewall-план превышает допустимый размер")
    handoff = Handoff.from_dict(load_json(handoff_path))
    expected = Handoff(
        exit_address=desired.public_address,
        exit_port=desired.listen_port,
        client_id=desired.client_id,
        xhttp_path=desired.xhttp_path,
        encryption=handoff.encryption,
        label=desired.label,
        expected_egress_ip=desired.expected_egress_ip,
        tls_fingerprint=desired.tls_fingerprint,
    ).validate()
    if handoff != expected:
        raise VerificationError("Handoff не соответствует запрошенной конфигурации")
    try:
        firewall_plan = firewall_plan_path.read_text("utf-8")
    except (OSError, UnicodeError) as exc:
        raise VerificationError("Firewall-план не является UTF-8 текстом") from exc
    if firewall_plan != _firewall_plan(desired):
        raise VerificationError(
            "Firewall-план не соответствует запрошенной конфигурации"
        )


def _snapshot_local(path: Path) -> _LocalSnapshot | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError(
            f"Не удалось проверить локальный managed-файл {path}"
        ) from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallerError(
            f"Локальный managed-путь должен быть обычным файлом: {path}"
        )
    try:
        return _LocalSnapshot(path.read_bytes(), stat.S_IMODE(metadata.st_mode))
    except OSError as exc:
        raise InstallerError(
            f"Не удалось прочитать локальный managed-файл {path}"
        ) from exc


def _restore_local(path: Path, snapshot: _LocalSnapshot | None) -> None:
    if snapshot is None:
        path.unlink(missing_ok=True)
        return
    atomic_write(path, snapshot.data, snapshot.mode)


def _persist_local_artifacts(
    *,
    handoff_source: Path,
    firewall_source: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    handoff_target = output_dir / "handoff.json"
    firewall_target = output_dir / "firewall-plan.txt"
    snapshots = {
        handoff_target: _snapshot_local(handoff_target),
        firewall_target: _snapshot_local(firewall_target),
    }
    try:
        atomic_write(handoff_target, handoff_source.read_bytes(), 0o600)
        atomic_write(firewall_target, firewall_source.read_bytes(), 0o600)
        _assert_regular_0600(handoff_target)
        _assert_regular_0600(firewall_target)
    except Exception as original:
        rollback_errors: list[Exception] = []
        for path, snapshot in snapshots.items():
            try:
                _restore_local(path, snapshot)
            except Exception as exc:
                rollback_errors.append(exc)
        if rollback_errors:
            raise _LocalPersistError(partial=True) from original
        raise _LocalPersistError(partial=False) from original
    return handoff_target, firewall_target


def _cleanup_remote_temp(ssh: SSHClient, remote_temp: str) -> bool:
    if not _REMOTE_TEMP.fullmatch(remote_temp):
        return False
    exact_files = [
        f"{remote_temp}/installer.pyz",
        f"{remote_temp}/client-id",
        f"{remote_temp}/handoff.json",
        f"{remote_temp}/firewall-plan.txt",
    ]
    try:
        removed = ssh.command(["rm", "-f", "--", *exact_files], check=False, timeout=60)
        if removed.returncode != 0:
            return False
        directory = ssh.command(["rmdir", "--", remote_temp], check=False, timeout=30)
        return directory.returncode == 0
    except Exception:
        return False


def apply_remote_exit(
    *,
    installer_pyz: Path,
    desired: ExitDesired,
    target: RemoteExitTarget,
    auth: SSHAuth,
    output_dir: Path,
) -> RemoteExitResult:
    """Install the exit through pinned OpenSSH without applying its firewall plan.

    The remote apply is transactional inside ``apply_exit``. If the SSH session
    becomes uncertain or local artifact collection fails after a successful
    apply, ``RemoteExitError`` exposes that partial state without echoing remote
    output or credentials.
    """

    desired = desired.validate()
    target = target.validate()
    auth = auth.validate()
    if platform.system() != "Linux":
        raise InstallerError("Удалённая установка поддерживается только с Linux/WSL")
    installer = _validated_local_file(installer_pyz, description="installer .pyz")
    output = _validated_output_dir(output_dir)
    known_hosts = output / "exit-known_hosts"
    if known_hosts.is_symlink():
        raise InstallerError("Pinned known_hosts не может быть symlink")
    pin_host_key(
        host=target.host,
        port=target.port,
        expected_sha256=target.host_key_sha256,
        known_hosts=known_hosts,
    )
    _assert_regular_0600(known_hosts)
    ssh = SSHClient(
        host=target.host,
        port=target.port,
        user=target.user,
        known_hosts=known_hosts,
        auth=auth,
    )
    sftp = SFTPClient(
        host=target.host,
        port=target.port,
        user=target.user,
        known_hosts=known_hosts,
        auth=auth,
    )

    remote_status: RemoteApplyStatus = "not_started"
    artifact_status: ArtifactStatus = "not_saved"
    cleanup_status: CleanupStatus = "not_needed"
    stage = "remote_identity"
    remote_temp: str | None = None
    failure: Exception | None = None
    handoff_target: Path | None = None
    firewall_target: Path | None = None

    with tempfile.TemporaryDirectory(prefix=".remote-exit-", dir=output) as temp:
        local_temp = Path(temp)
        client_id_file = local_temp / "client-id"
        atomic_write_text(client_id_file, desired.client_id + "\n", 0o600)
        try:
            uid_result = ssh.command(["id", "-u"], check=False, timeout=30)
            gid_result = ssh.command(["id", "-g"], check=False, timeout=30)
            if uid_result.returncode != 0 or gid_result.returncode != 0:
                raise InstallerError("id завершился с ошибкой")
            remote_uid = _parse_remote_id(uid_result.stdout)
            remote_gid = _parse_remote_id(gid_result.stdout)

            stage = "remote_temp"
            cleanup_status = "unknown"
            remote_temp = _create_remote_temp(ssh)
            _checked_remote(ssh, ["chmod", "700", "--", remote_temp], timeout=30)
            remote_installer = f"{remote_temp}/installer.pyz"
            remote_client_id = f"{remote_temp}/client-id"
            remote_handoff = f"{remote_temp}/handoff.json"
            remote_firewall = f"{remote_temp}/firewall-plan.txt"

            stage = "upload"
            try:
                _upload_and_verify(
                    sftp,
                    ssh,
                    installer=installer,
                    client_id_file=client_id_file,
                    remote_installer=remote_installer,
                    remote_client_id=remote_client_id,
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
                    remote_client_id=remote_client_id,
                    remote_uid=remote_uid,
                ),
                check=False,
                timeout=900,
            )
            if apply_result.returncode != 0:
                remote_status = (
                    "unknown" if apply_result.returncode == 255 else "failed"
                )
                raise InstallerError("remote apply вернул ошибку")
            remote_status = "succeeded"

            stage = "artifact_stage"
            layout = Layout()
            _stage_remote_artifact(
                ssh,
                source=layout.handoff,
                destination=remote_handoff,
                remote_uid=remote_uid,
                remote_gid=remote_gid,
            )
            _stage_remote_artifact(
                ssh,
                source=layout.firewall_plan,
                destination=remote_firewall,
                remote_uid=remote_uid,
                remote_gid=remote_gid,
            )

            stage = "artifact_download"
            handoff_download, firewall_download = _download_artifacts(
                sftp,
                remote_handoff=remote_handoff,
                remote_firewall_plan=remote_firewall,
                local_dir=local_temp,
            )
            stage = "artifact_validation"
            _validate_downloaded_artifacts(
                desired,
                handoff_path=handoff_download,
                firewall_plan_path=firewall_download,
            )

            stage = "local_persist"
            try:
                handoff_target, firewall_target = _persist_local_artifacts(
                    handoff_source=handoff_download,
                    firewall_source=firewall_download,
                    output_dir=output,
                )
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
        raise RemoteExitError(
            stage=stage,
            remote_status=remote_status,
            artifact_status=artifact_status,
            cleanup_status=cleanup_status,
            remote_temp=remote_temp,
        ) from failure
    if cleanup_status != "succeeded":
        raise RemoteExitError(
            stage="cleanup",
            remote_status=remote_status,
            artifact_status=artifact_status,
            cleanup_status=cleanup_status,
            remote_temp=remote_temp,
        )
    if handoff_target is None or firewall_target is None:
        raise RemoteExitError(
            stage="local_persist",
            remote_status=remote_status,
            artifact_status=artifact_status,
            cleanup_status=cleanup_status,
        )
    return RemoteExitResult(
        target=target,
        handoff_path=handoff_target,
        firewall_plan_path=firewall_target,
        known_hosts_path=known_hosts,
        installer_sha256=sha256_file(installer),
    )
