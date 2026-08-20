"""Safe personal-computer orchestration around the verified server installers.

The module deliberately does not reimplement either server transaction.  It
pins a remote root SSH endpoint, applies the narrow remote UFW guard, and then
delegates to :func:`apply_remote_exit`.  Frontend application remains delegated
to the existing local transaction or to :func:`apply_remote_front` by the CLI.
"""

from __future__ import annotations

import os
import platform
import re
import stat
from dataclasses import dataclass, replace
from pathlib import Path

from .errors import InstallerError, VerificationError
from .exit_network import ExitNetworkProfile
from .models import ExitDesired, FrontDesired, Handoff
from .osutil import ensure_dir
from .remote_exit import (
    RemoteExitError,
    RemoteExitResult,
    RemoteExitTarget,
    apply_remote_exit,
    cleanup_remote_exit_temp,
)
from .remote_front import RemoteFrontTarget
from .remote_network import (
    RemoteExitNetworkApplyResult,
    RemoteExitNetworkError,
    RemoteExitNetworkRecovery,
    apply_remote_exit_network,
    reconcile_remote_exit_network,
    recovery_for_remote_exit_network,
    rollback_remote_exit_network,
)
from .ssh_transport import (
    SSHAuth,
    SSHClient,
    SSHCommand,
    SSHTransportError,
    pin_host_key,
)


_MAX_INSTALLER_BYTES = 256 * 1024 * 1024
_REMOTE_ID = re.compile(r"^[0-9]{1,10}$")


@dataclass(frozen=True)
class PcExitResult:
    remote: RemoteExitResult
    network: RemoteExitNetworkApplyResult


class PcExitRecoveryError(InstallerError):
    """A bounded recovery connection could not reconcile all owned state."""

    def __init__(self, *, original_error: BaseException) -> None:
        stage = getattr(original_error, "stage", "network_apply")
        remote_status = getattr(original_error, "remote_status", "not_started")
        super().__init__(
            "Exit recovery incomplete; "
            f"original_stage={stage}; remote_apply={remote_status}; "
            "exact_recovery=failed"
        )
        self.original_error = original_error
        self.stage = stage
        self.remote_status = remote_status


@dataclass(frozen=True)
class _PcExitRecovery:
    original_error: BaseException
    network: RemoteExitNetworkRecovery | None
    remote_temp: str | None


class _PcExitRecoveryRequired(Exception):
    def __init__(self, recovery: _PcExitRecovery) -> None:
        super().__init__("bounded exit recovery required")
        self.recovery = recovery


def _require_linux_controller() -> None:
    if platform.system() != "Linux":
        raise InstallerError("Режим с персонального компьютера требует Linux/WSL")


def _validated_installer(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise InstallerError("Installer .pyz не может быть symlink")
    try:
        resolved = candidate.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as exc:
        raise InstallerError("Не удалось открыть installer .pyz") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallerError("Installer .pyz должен быть обычным файлом")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_INSTALLER_BYTES:
        raise InstallerError("Недопустимый размер installer .pyz")
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


def _root_id(result_stdout: str) -> bool:
    value = result_stdout.strip()
    if not _REMOTE_ID.fullmatch(value):
        raise VerificationError("Удалённый id вернул неожиданный ответ")
    return int(value) == 0


def _pinned_client(
    *,
    host: str,
    port: int,
    user: str,
    host_key_sha256: str,
    auth: SSHAuth,
    known_hosts: Path,
    trusted_known_hosts: Path | None = None,
) -> SSHClient:
    if known_hosts.is_symlink():
        raise InstallerError("Pinned known_hosts не может быть symlink")
    pin_host_key(
        host=host,
        port=port,
        expected_sha256=host_key_sha256,
        known_hosts=known_hosts,
        trusted_known_hosts=trusted_known_hosts,
    )
    return SSHClient(
        host=host,
        port=port,
        user=user,
        known_hosts=known_hosts,
        auth=auth,
    )


def _require_root(ssh: SSHCommand) -> None:
    identity = ssh.command(["id", "-u"], check=False, timeout=30)
    if identity.returncode != 0 or not _root_id(identity.stdout):
        raise InstallerError("Режим с ПК требует прямой SSH-вход с UID 0")


def preflight_remote_front_bridge(
    *,
    target: RemoteFrontTarget,
    auth: SSHAuth,
    output_dir: Path,
) -> Path:
    """Pin and authenticate a trusted root bridge before exit mutation."""

    _require_linux_controller()
    target = target.validate()
    auth = auth.validate()
    output = _validated_output_dir(output_dir)
    known_hosts = output / "bridge-known_hosts"
    client = _pinned_client(
        host=target.host,
        port=target.port,
        user=target.user,
        host_key_sha256=target.host_key_sha256,
        auth=auth,
        known_hosts=known_hosts,
    )
    with client.session() as ssh:
        _require_root(ssh)
    return known_hosts


def _network_recovery(
    result: RemoteExitNetworkApplyResult,
) -> RemoteExitNetworkRecovery | None:
    recovery = recovery_for_remote_exit_network(result)
    return recovery if recovery.attempted_comments else None


def _recovery_for_remote_error(
    error: RemoteExitError,
    network: RemoteExitNetworkApplyResult,
) -> _PcExitRecovery | None:
    if not error.recovery_allowed:
        return None
    remote_temp = (
        error.remote_temp if error.cleanup_status != "succeeded" else None
    )
    network_recovery = _network_recovery(network)
    if remote_temp is None and network_recovery is None:
        return None
    return _PcExitRecovery(
        original_error=error,
        network=network_recovery,
        remote_temp=remote_temp,
    )


def _raise_after_recovery(
    client: SSHClient,
    recovery: _PcExitRecovery,
) -> None:
    recovery_error: Exception | None = None
    try:
        with client.session() as ssh:
            _require_root(ssh)
            incomplete: list[str] = []
            if recovery.remote_temp is not None:
                try:
                    if not cleanup_remote_exit_temp(ssh, recovery.remote_temp):
                        incomplete.append("remote temp")
                except Exception:
                    incomplete.append("remote temp")
            if recovery.network is not None:
                try:
                    reconcile_remote_exit_network(ssh, recovery.network)
                except Exception:
                    incomplete.append("managed UFW")
            if incomplete:
                raise InstallerError(
                    "Exact recovery не подтверждён: " + ", ".join(incomplete)
                )
    except Exception as exc:
        recovery_error = exc

    if recovery_error is not None:
        raise PcExitRecoveryError(
            original_error=recovery.original_error
        ) from recovery_error

    original = recovery.original_error
    if isinstance(original, RemoteExitError):
        cleanup_status = (
            "succeeded"
            if recovery.remote_temp is not None
            else original.cleanup_status
        )
        raise RemoteExitError(
            stage=original.stage,
            remote_status=original.remote_status,
            artifact_status=original.artifact_status,
            cleanup_status=cleanup_status,
            remote_temp=original.remote_temp,
            transport_failure=True,
            session_cleanup_failed=original.session_cleanup_failed,
            recovery_completed=True,
        ) from original
    if isinstance(original, RemoteExitNetworkError):
        raise RemoteExitNetworkError(
            recovery=original.recovery,
            recovery_completed=True,
        ) from original
    raise original


def apply_pc_exit(
    *,
    installer_pyz: Path,
    desired: ExitDesired,
    target: RemoteExitTarget,
    auth: SSHAuth,
    output_dir: Path,
    trusted_known_hosts: Path | None = None,
) -> PcExitResult:
    """Apply the remote UFW guard and delegate to the existing exit installer.

    If the exit transaction definitely did not start or definitely rolled back,
    only UFW rules added by this call are removed.  An unknown or successful
    remote apply keeps the restrictive rules in place.
    """

    _require_linux_controller()
    installer = _validated_installer(installer_pyz)
    desired = desired.validate()
    target = target.validate()
    if desired.listen_port == target.port:
        raise InstallerError("Backend-порт совпадает с SSH-портом выхода")
    auth = auth.validate()
    output = _validated_output_dir(output_dir)
    known_hosts = output / "exit-known_hosts"
    client = _pinned_client(
        host=target.host,
        port=target.port,
        user=target.user,
        host_key_sha256=target.host_key_sha256,
        auth=auth,
        known_hosts=known_hosts,
        trusted_known_hosts=trusted_known_hosts,
    )
    profile = ExitNetworkProfile(
        frontend_ipv4=desired.front_egress_ip,
        backend_port=desired.listen_port,
    ).validate()
    try:
        with client.session() as ssh:
            _require_root(ssh)
            try:
                network = apply_remote_exit_network(
                    ssh,
                    profile,
                    ssh_port=target.port,
                )
            except RemoteExitNetworkError as exc:
                raise _PcExitRecoveryRequired(
                    _PcExitRecovery(
                        original_error=exc,
                        network=exc.recovery,
                        remote_temp=None,
                    )
                ) from exc
            try:
                remote = apply_remote_exit(
                    installer_pyz=installer,
                    desired=desired,
                    target=target,
                    auth=auth,
                    output_dir=output,
                    ssh_runner=ssh,
                )
            except RemoteExitError as exc:
                if exc.remote_status == "unknown":
                    # The remote transaction may have committed.  Keep the
                    # restrictive rules and never open a recovery connection.
                    raise
                recovery = _recovery_for_remote_error(exc, network)
                if recovery is not None:
                    raise _PcExitRecoveryRequired(recovery) from exc
                if exc.remote_status in {"not_started", "failed"}:
                    network_recovery = _network_recovery(network)
                    if network_recovery is None:
                        raise
                    try:
                        rollback_remote_exit_network(ssh, network)
                    except SSHTransportError as rollback_error:
                        if exc.remote_status in {"not_started", "failed"}:
                            recovery = _PcExitRecovery(
                                original_error=exc,
                                network=network_recovery,
                                remote_temp=(
                                    exc.remote_temp
                                    if exc.cleanup_status != "succeeded"
                                    else None
                                ),
                            )
                            if (
                                recovery.network is not None
                                or recovery.remote_temp is not None
                            ):
                                raise _PcExitRecoveryRequired(
                                    recovery
                                ) from rollback_error
                        raise PcExitRecoveryError(
                            original_error=exc
                        ) from rollback_error
                    except Exception as rollback_error:
                        raise PcExitRecoveryError(
                            original_error=exc
                        ) from rollback_error
                raise
            except Exception as exc:
                # Every in-transaction failure is wrapped by apply_remote_exit;
                # a plain exception is therefore definitely pre-apply.
                network_recovery = _network_recovery(network)
                if network_recovery is None:
                    raise
                try:
                    rollback_remote_exit_network(ssh, network)
                except SSHTransportError as rollback_error:
                    raise _PcExitRecoveryRequired(
                        _PcExitRecovery(
                            original_error=exc,
                            network=network_recovery,
                            remote_temp=None,
                        )
                    ) from rollback_error
                except Exception as rollback_error:
                    raise PcExitRecoveryError(
                        original_error=exc
                    ) from rollback_error
                raise
    except _PcExitRecoveryRequired as required:
        _raise_after_recovery(client, required.recovery)
        raise AssertionError("unreachable")
    return PcExitResult(remote=remote, network=network)


def front_for_handoff(desired: FrontDesired, handoff: Handoff) -> FrontDesired:
    """Bind collected frontend data to the actual protected exit handoff."""

    desired = desired.validate()
    handoff = handoff.validate()
    return replace(
        desired,
        exit_address=handoff.exit_address,
        exit_port=handoff.exit_port,
        xhttp_path=handoff.xhttp_path,
    ).validate()
