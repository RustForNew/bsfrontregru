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
)
from .remote_front import RemoteFrontTarget
from .remote_network import (
    RemoteExitNetworkApplyResult,
    apply_remote_exit_network,
    rollback_remote_exit_network,
)
from .ssh_transport import SSHAuth, SSHClient, pin_host_key


_MAX_INSTALLER_BYTES = 256 * 1024 * 1024
_REMOTE_ID = re.compile(r"^[0-9]{1,10}$")


@dataclass(frozen=True)
class PcExitResult:
    remote: RemoteExitResult
    network: RemoteExitNetworkApplyResult


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


def _pinned_root_client(
    *,
    host: str,
    port: int,
    user: str,
    host_key_sha256: str,
    auth: SSHAuth,
    known_hosts: Path,
) -> SSHClient:
    if known_hosts.is_symlink():
        raise InstallerError("Pinned known_hosts не может быть symlink")
    pin_host_key(
        host=host,
        port=port,
        expected_sha256=host_key_sha256,
        known_hosts=known_hosts,
    )
    client = SSHClient(
        host=host,
        port=port,
        user=user,
        known_hosts=known_hosts,
        auth=auth,
    )
    identity = client.command(["id", "-u"], check=False, timeout=30)
    if identity.returncode != 0 or not _root_id(identity.stdout):
        raise InstallerError("Режим с ПК требует прямой SSH-вход с UID 0")
    return client


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
    _pinned_root_client(
        host=target.host,
        port=target.port,
        user=target.user,
        host_key_sha256=target.host_key_sha256,
        auth=auth,
        known_hosts=known_hosts,
    )
    return known_hosts


def apply_pc_exit(
    *,
    installer_pyz: Path,
    desired: ExitDesired,
    target: RemoteExitTarget,
    auth: SSHAuth,
    output_dir: Path,
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
    ssh = _pinned_root_client(
        host=target.host,
        port=target.port,
        user=target.user,
        host_key_sha256=target.host_key_sha256,
        auth=auth,
        known_hosts=known_hosts,
    )
    profile = ExitNetworkProfile(
        frontend_ipv4=desired.front_egress_ip,
        backend_port=desired.listen_port,
    ).validate()
    network = apply_remote_exit_network(ssh, profile)
    try:
        remote = apply_remote_exit(
            installer_pyz=installer,
            desired=desired,
            target=target,
            auth=auth,
            output_dir=output,
        )
    except RemoteExitError as exc:
        if exc.remote_status in {"not_started", "failed"}:
            try:
                rollback_remote_exit_network(ssh, network)
            except Exception as rollback_error:
                raise InstallerError(
                    "Exit apply не завершён, а rollback managed UFW rules неполон"
                ) from rollback_error
        raise
    except Exception:
        # apply_remote_exit wraps every failure after its remote transaction
        # starts.  A plain exception here is therefore a local/pre-start error.
        try:
            rollback_remote_exit_network(ssh, network)
        except Exception as rollback_error:
            raise InstallerError(
                "Exit apply не стартовал, а rollback managed UFW rules неполон"
            ) from rollback_error
        raise
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
