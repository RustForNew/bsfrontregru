from __future__ import annotations

import datetime
import os
import re
import secrets
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Literal, TypeVar

from .errors import (
    HTTPSResponseError,
    InstallerError,
    TLSVerificationError,
    VerificationError,
)
from .front import (
    _RemoteMutation,
    _download_optional,
    _rollback_journal_with_recovery,
    _upload_verified,
    check_front_dns,
    check_public_tls,
    https_status,
)
from .models import FrontDesired
from .osutil import atomic_write_text, ensure_dir, exclusive_lock
from .render import BEGIN_MARKER, END_MARKER, merge_managed_block, render_htaccess_block
from .ssh_transport import SFTPClient, SSHAuth, SSHRoute, TCPRoute, pin_host_key


T = TypeVar("T")
_STATE_MARKER = "xhttp-setup temporary frontend probe state v1\n"
_CONTROL_REQUEST_TIMEOUT_SECONDS = 8
_TemporaryRouteMode = Literal["proxy", "rewrite-control"]


def _render_rewrite_control_block(*, path: str, nonce: str) -> str:
    """Render one exact canary suffix without enabling proxy capability."""

    if not re.fullmatch(r"[0-9a-f]{32}", nonce):
        raise InstallerError("Некорректный nonce контрольного frontend route")
    relative = path.lstrip("/")
    control = f"{relative}/xhttp-setup-control-{nonce}"
    return "\n".join(
        [
            BEGIN_MARKER,
            "RewriteEngine On",
            "RewriteCond %{REQUEST_METHOD} ^GET$",
            f"RewriteRule ^{control}$ / [R=302,L]",
            END_MARKER,
        ]
    )


def _render_temporary_block(
    desired: FrontDesired,
    *,
    route_mode: _TemporaryRouteMode,
    rewrite_control_nonce: str | None,
) -> str:
    if route_mode == "proxy":
        if rewrite_control_nonce is not None:
            raise InstallerError("Proxy frontend route не принимает control nonce")
        return render_htaccess_block(
            exit_address=desired.exit_address,
            exit_port=desired.exit_port,
            path=desired.xhttp_path,
        )
    if route_mode == "rewrite-control":
        if rewrite_control_nonce is None:
            raise InstallerError("Для контрольного frontend route нужен nonce")
        return _render_rewrite_control_block(
            path=desired.xhttp_path,
            nonce=rewrite_control_nonce,
        )
    raise InstallerError("Неизвестный режим временного frontend route")


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
    route_mode: _TemporaryRouteMode = "proxy",
    rewrite_control_nonce: str | None = None,
    sftp_route: SSHRoute | None = None,
    https_route: TCPRoute | None = None,
    trusted_known_hosts: Path | None = None,
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
        route=https_route,
    )
    known_hosts = state / "known_hosts"
    pin_host_key(
        host=desired.sftp_host,
        port=desired.sftp_port,
        expected_sha256=desired.ssh_host_key_sha256,
        known_hosts=known_hosts,
        route=sftp_route,
        trusted_known_hosts=trusted_known_hosts,
    )
    client = SFTPClient(
        host=desired.sftp_host,
        port=desired.sftp_port,
        user=desired.sftp_user,
        known_hosts=known_hosts,
        auth=auth,
        route=sftp_route,
    )

    with client.session() as session:
        with exclusive_lock(state / "apply.lock"):
            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
                "%Y%m%dT%H%M%S%fZ"
            )
            token = uuid.uuid4().hex
            work_dir = state / "backups" / f"{timestamp}-{token}"
            ensure_dir(work_dir, 0o700)
            before = work_dir / "htaccess.before"
            existed = _download_optional(
                session, desired.document_root, ".htaccess", before
            )
            try:
                existing_text = before.read_text("utf-8") if existed else ""
                temporary_text = merge_managed_block(
                    existing_text,
                    _render_temporary_block(
                        desired,
                        route_mode=route_mode,
                        rewrite_control_nonce=rewrite_control_nonce,
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
                    session,
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
                _rollback_journal_with_recovery(
                    client,
                    session,
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


def verify_front_rewrite_control(
    desired: FrontDesired,
    *,
    auth: SSHAuth,
    state_dir: Path,
    sftp_route: SSHRoute | None = None,
    https_route: TCPRoute | None = None,
    trusted_known_hosts: Path | None = None,
) -> None:
    """Obtain a bounded ``[R=302,L]`` control signal before trying ``[P]``.

    The generated suffix exercises the same XHTTP namespace and suffix-rule
    shape without changing or revalidating a maximum-length desired path.  Only
    fixed diagnostics survive, so a transport exception cannot disclose the
    per-installation path.
    """

    desired = desired.validate()
    nonce = secrets.token_hex(16)
    control_suffix = f"xhttp-setup-control-{nonce}"
    url = f"https://{desired.domain}{desired.xhttp_path}/{control_suffix}"

    def request_control() -> None:
        outcome = "http"
        status: int | None = None
        try:
            status = https_status(
                url,
                connect_ip=desired.client_connect_ip,
                pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
                timeout=_CONTROL_REQUEST_TIMEOUT_SECONDS,
                route=https_route,
            )
        except TLSVerificationError:
            outcome = "tls"
        except HTTPSResponseError:
            outcome = "post-send"
        except VerificationError:
            outcome = "pre-send"

        if outcome == "tls":
            raise TLSVerificationError(
                "Контроль Apache/mod_rewrite: TLS/SNI/leaf-сертификат "
                "не прошёл проверку"
            )
        if outcome == "post-send":
            raise VerificationError(
                "Контроль Apache/mod_rewrite: HTTPS-запрос отправлен, но "
                "корректный HTTP-ответ не получен"
            )
        if outcome == "pre-send":
            raise VerificationError(
                "Контроль Apache/mod_rewrite: HTTPS-запрос не удалось "
                "безопасно отправить"
            )
        if type(status) is not int or not 200 <= status <= 599:
            raise VerificationError(
                "Контроль Apache/mod_rewrite вернул некорректный HTTP-статус"
            )
        if status != 302:
            raise VerificationError(
                "Контроль Apache/mod_rewrite не прошёл: ожидался HTTP 302, "
                f"получен HTTP {status}"
            )

    route_kwargs: dict[str, object] = {}
    if sftp_route is not None:
        route_kwargs["sftp_route"] = sftp_route
    if https_route is not None:
        route_kwargs["https_route"] = https_route
    if trusted_known_hosts is not None:
        route_kwargs["trusted_known_hosts"] = trusted_known_hosts
    run_with_temporary_front_route(
        desired,
        auth=auth,
        state_dir=state_dir,
        operation=request_control,
        route_mode="rewrite-control",
        rewrite_control_nonce=nonce,
        **route_kwargs,
    )
