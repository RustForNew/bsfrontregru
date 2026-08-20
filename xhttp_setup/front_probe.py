from __future__ import annotations

import datetime
import os
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from .errors import InstallerError
from .front import (
    _RemoteMutation,
    _download_optional,
    _rollback_journal,
    _upload_verified,
    check_front_dns,
    check_public_tls,
)
from .models import FrontDesired
from .osutil import atomic_write_text, ensure_dir, exclusive_lock
from .render import merge_managed_block, render_htaccess_block
from .ssh_transport import SFTPClient, SSHAuth, pin_host_key


T = TypeVar("T")
_STATE_MARKER = "xhttp-setup temporary frontend probe state v1\n"


def _prepare_state_dir(path: Path) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise InstallerError("Каталог состояния frontend probe не может быть symlink")
    resolved = candidate.resolve(strict=False)
    if resolved in {
        Path("/"),
        Path("/etc"),
        Path("/usr"),
        Path("/var"),
        Path("/opt"),
        Path("/root"),
        Path("/home"),
        Path("/tmp"),
    }:
        raise InstallerError("Слишком широкий каталог состояния frontend probe")
    existed = resolved.exists()
    ensure_dir(resolved, 0o700)
    if os.name == "posix" and resolved.stat().st_uid != os.geteuid():
        raise InstallerError("Каталог состояния frontend probe принадлежит другому UID")
    marker = resolved / ".xhttp-setup-probe-state"
    if existed:
        if not marker.is_file() or marker.is_symlink():
            raise InstallerError("Существующий каталог frontend probe не является managed")
        if marker.read_text("utf-8") != _STATE_MARKER:
            raise InstallerError("Маркер каталога frontend probe не совпал")
    else:
        atomic_write_text(marker, _STATE_MARKER, 0o600)
    return resolved


def run_with_temporary_front_route(
    desired: FrontDesired,
    *,
    auth: SSHAuth,
    state_dir: Path,
    operation: Callable[[], T],
) -> T:
    """Install one temporary managed route, run ``operation``, then restore bytes.

    The same verified SFTP compare-and-swap and rollback journal used by the final
    frontend transaction protect an existing ``.htaccess``.  A concurrent owner
    edit is never overwritten silently.
    """

    desired = desired.validate()
    auth = auth.validate()
    state = _prepare_state_dir(state_dir)
    check_front_dns(desired.domain, desired.dns_ipv4)
    check_public_tls(
        desired.domain,
        connect_ip=desired.client_connect_ip,
        pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
    )
    known_hosts = state / "known_hosts"
    pin_host_key(
        host=desired.sftp_host,
        port=desired.sftp_port,
        expected_sha256=desired.ssh_host_key_sha256,
        known_hosts=known_hosts,
    )
    client = SFTPClient(
        host=desired.sftp_host,
        port=desired.sftp_port,
        user=desired.sftp_user,
        known_hosts=known_hosts,
        auth=auth,
    )

    with exclusive_lock(state / "apply.lock"):
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%dT%H%M%S%fZ"
        )
        token = uuid.uuid4().hex
        work_dir = state / "backups" / f"{timestamp}-{token}"
        ensure_dir(work_dir, 0o700)
        before = work_dir / "htaccess.before"
        existed = _download_optional(
            client, desired.document_root, ".htaccess", before
        )
        try:
            existing_text = before.read_text("utf-8") if existed else ""
            temporary_text = merge_managed_block(
                existing_text,
                render_htaccess_block(
                    exit_address=desired.exit_address,
                    exit_port=desired.exit_port,
                    path=desired.xhttp_path,
                ),
            )
        except (UnicodeDecodeError, ValueError) as exc:
            raise InstallerError(
                f"Нельзя безопасно подготовить временный .htaccess: {exc}"
            ) from exc
        after = work_dir / "htaccess.temporary"
        atomic_write_text(after, temporary_text, 0o600)
        journal: list[_RemoteMutation] = []
        original: BaseException | None = None
        result: T | None = None
        try:
            _upload_verified(
                client,
                remote_dir=desired.document_root,
                local=after,
                target=".htaccess",
                backup_name=f".xhttp-backup-htaccess-probe-{timestamp}-{token}",
                work_dir=work_dir,
                journal=journal,
            )
            result = operation()
        except BaseException as exc:
            original = exc
        try:
            _rollback_journal(
                client,
                remote_dir=desired.document_root,
                journal=journal,
                original=original or InstallerError("temporary frontend route"),
            )
        except BaseException:
            if original is not None:
                raise
            raise
        if original is not None:
            raise original
        return result  # type: ignore[return-value]
