from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path

from .errors import InstallerError, VerificationError
from .models import FrontDesired
from .osutil import atomic_write_text, ensure_dir, exclusive_lock, sha256_file
from .placeholder import neutral_placeholder
from .render import merge_managed_block, render_htaccess_block
from .ssh_transport import SFTPClient, SSHAuth, pin_host_key, sftp_quote


@dataclass(frozen=True)
class FrontResult:
    root_status: int
    path_status: int
    backup_dir: Path
    remote_htaccess_backup: str | None
    remote_index_backup: str | None


@dataclass
class _RemoteMutation:
    target: str
    backup_name: str
    remote_temp: str
    original_local: Path
    original_existed: bool
    work_dir: Path
    switch_attempted: bool = False


def check_front_dns(domain: str, expected_ipv4: str) -> None:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, 443):
            if family == socket.AF_INET:
                ipv4.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ipv6.add(sockaddr[0])
    except socket.gaierror as exc:
        raise VerificationError(f"DNS {domain} не разрешается: {exc}") from exc
    if ipv4 != {expected_ipv4}:
        actual = ", ".join(sorted(ipv4)) or "A-записей нет"
        raise VerificationError(
            f"DNS A для {domain}: ожидался только {expected_ipv4}, получено: {actual}"
        )
    if ipv6:
        raise VerificationError(
            f"Для frontend обнаружена AAAA-запись: {', '.join(sorted(ipv6))}. "
            "Уберите её, иначе часть клиентов пойдёт по неподготовленному IPv6"
        )


def check_public_tls(domain: str, *, timeout: int = 12) -> dict[str, str]:
    context = ssl.create_default_context()
    try:
        with socket.create_connection((domain, 443), timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                certificate = tls.getpeercert()
                cipher = tls.cipher()
                return {
                    "subject": str(certificate.get("subject", "")),
                    "notAfter": str(certificate.get("notAfter", "")),
                    "cipher": cipher[0] if cipher else "unknown",
                }
    except (OSError, ssl.SSLError) as exc:
        raise VerificationError(
            f"TLS для {domain}:443 не прошёл проверку системным CA: {exc}"
        ) from exc


def https_status(url: str, *, timeout: int = 15) -> int:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise VerificationError("Диагностический URL должен использовать HTTPS")
    request = urllib.request.Request(
        url, headers={"User-Agent": "xhttp-setup-doctor/0.1"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return int(response.status)
    except urllib.error.HTTPError as exc:
        return int(exc.code)
    except (OSError, urllib.error.URLError) as exc:
        raise VerificationError(f"HTTPS-запрос {url} не выполнен: {exc}") from exc


def build_front_plan(desired: FrontDesired) -> list[str]:
    desired = desired.validate()
    placeholder = (
        "явно заменить index.html на нейтральную оригинальную страницу"
        if desired.placeholder_mode == "neutral"
        else "сохранить существующий сайт без изменений"
    )
    return [
        f"Проверить DNS A={desired.front_public_ip}, отсутствие AAAA и публичный TLS https://{desired.domain}:443",
        f"Закрепить SFTP host key {desired.ssh_host_key_sha256}",
        f"Скачать и сохранить резервную копию {desired.document_root}/.htaccess",
        "Изменить только блок между XHTTP-SETUP managed-маркерами",
        f"Проксировать GET/POST {desired.xhttp_path} и suffix на {desired.exit_address}:{desired.exit_port}",
        placeholder,
        "Проверить главную страницу и отсутствие 5xx на XHTTP path",
    ]


def _download_optional(
    client: SFTPClient, remote_dir: str, name: str, local: Path
) -> bool:
    local.unlink(missing_ok=True)
    probe = client.batch(
        [
            f"cd {sftp_quote(remote_dir)}",
            f"ls -l {sftp_quote(name)}",
        ],
        check=False,
    )
    if probe.returncode != 0:
        detail = (probe.stderr + "\n" + probe.stdout).lower()
        if "no such file" in detail or "not found" in detail:
            return False
        raise InstallerError(
            f"SFTP не смог проверить существующий {name}; перезапись запрещена"
        )
    client.batch(
        [
            f"cd {sftp_quote(remote_dir)}",
            f"get {sftp_quote(name)} {sftp_quote(str(local))}",
        ]
    )
    if not local.is_file():
        raise InstallerError(
            f"SFTP сообщил успех, но локальная копия {name} не создана"
        )
    return True


def _upload_verified(
    client: SFTPClient,
    *,
    remote_dir: str,
    local: Path,
    target: str,
    backup_name: str,
    work_dir: Path,
    journal: list[_RemoteMutation],
) -> str | None:
    token = uuid.uuid4().hex
    remote_temp = f".{target}.xhttp-new-{token}"
    verify = work_dir / f"verify-{target.lstrip('.')}-{token}"
    existing_probe = work_dir / f"existing-{target.lstrip('.')}-{token}"
    existed = _download_optional(client, remote_dir, target, existing_probe)
    mutation = _RemoteMutation(
        target=target,
        backup_name=backup_name,
        remote_temp=remote_temp,
        original_local=existing_probe,
        original_existed=existed,
        work_dir=work_dir,
    )
    # Register before the first remote write. A transport failure can happen after
    # the server accepted a command but before the client received its result.
    journal.append(mutation)
    client.batch(
        [
            f"cd {sftp_quote(remote_dir)}",
            f"put {sftp_quote(str(local))} {sftp_quote(remote_temp)}",
            f"get {sftp_quote(remote_temp)} {sftp_quote(str(verify))}",
        ]
    )
    if sha256_file(local) != sha256_file(verify):
        raise VerificationError(f"SHA-256 загруженного {target} не совпал")
    commands = [f"cd {sftp_quote(remote_dir)}"]
    if existed:
        commands.append(f"rename {sftp_quote(target)} {sftp_quote(backup_name)}")
    commands.extend(
        [
            f"rename {sftp_quote(remote_temp)} {sftp_quote(target)}",
            f"chmod 644 {sftp_quote(target)}",
        ]
    )
    precondition = work_dir / f"precondition-{target.lstrip('.')}-{token}"
    current_existed = _download_optional(client, remote_dir, target, precondition)
    snapshot_matches = current_existed == existed
    if current_existed and existed:
        snapshot_matches = sha256_file(precondition) == sha256_file(existing_probe)
    if not snapshot_matches:
        raise InstallerError(
            f"Remote {target} изменён параллельно после создания снимка; "
            "переключение отменено"
        )
    mutation.switch_attempted = True
    client.batch(commands)
    return backup_name if existed else None


def _remote_digest(
    client: SFTPClient,
    *,
    remote_dir: str,
    name: str,
    mutation: _RemoteMutation,
) -> str | None:
    safe_name = name.replace("/", "_").lstrip(".") or "root"
    probe = mutation.work_dir / f"rollback-{safe_name}-{uuid.uuid4().hex}"
    if not _download_optional(client, remote_dir, name, probe):
        return None
    return sha256_file(probe)


def _is_restored(
    client: SFTPClient, *, remote_dir: str, mutation: _RemoteMutation
) -> bool:
    actual = _remote_digest(
        client,
        remote_dir=remote_dir,
        name=mutation.target,
        mutation=mutation,
    )
    if mutation.original_existed:
        if actual != sha256_file(mutation.original_local):
            return False
    elif actual is not None:
        return False
    for artifact in (mutation.backup_name, mutation.remote_temp):
        if (
            _remote_digest(
                client,
                remote_dir=remote_dir,
                name=artifact,
                mutation=mutation,
            )
            is not None
        ):
            return False
    return True


def _try_batch(client: SFTPClient, commands: list[str], errors: list[str]) -> None:
    try:
        result = client.batch(commands, check=False)
        if result.returncode != 0:
            errors.append(f"SFTP возвратил код {result.returncode}")
    except Exception as exc:  # The next probe reconciles an uncertain outcome.
        errors.append(str(exc))


def _rollback_mutation(
    client: SFTPClient, *, remote_dir: str, mutation: _RemoteMutation
) -> None:
    errors: list[str] = []
    if not mutation.switch_attempted:
        for _ in range(2):
            _try_batch(
                client,
                [
                    f"cd {sftp_quote(remote_dir)}",
                    f"-rm {sftp_quote(mutation.remote_temp)}",
                ],
                errors,
            )
            try:
                if (
                    _remote_digest(
                        client,
                        remote_dir=remote_dir,
                        name=mutation.remote_temp,
                        mutation=mutation,
                    )
                    is None
                ):
                    return
            except Exception as exc:
                errors.append(str(exc))
        detail = "; ".join(errors[-4:]) or "temporary upload остался"
        raise InstallerError(
            f"Не удалось очистить remote temp для {mutation.target}: {detail}"
        )

    cleanup = [
        f"cd {sftp_quote(remote_dir)}",
        f"-rm {sftp_quote(mutation.backup_name)}",
        f"-rm {sftp_quote(mutation.remote_temp)}",
    ]

    # First reconcile the common states left by an interrupted rename batch.
    for _ in range(2):
        try:
            target_digest = _remote_digest(
                client,
                remote_dir=remote_dir,
                name=mutation.target,
                mutation=mutation,
            )
            expected = (
                sha256_file(mutation.original_local)
                if mutation.original_existed
                else None
            )
            if target_digest == expected:
                _try_batch(client, cleanup, errors)
            elif mutation.original_existed:
                _try_batch(
                    client,
                    [
                        f"cd {sftp_quote(remote_dir)}",
                        f"-rm {sftp_quote(mutation.target)}",
                        f"-rename {sftp_quote(mutation.backup_name)} {sftp_quote(mutation.target)}",
                        f"-rm {sftp_quote(mutation.remote_temp)}",
                    ],
                    errors,
                )
            else:
                _try_batch(
                    client,
                    [
                        f"cd {sftp_quote(remote_dir)}",
                        f"-rm {sftp_quote(mutation.target)}",
                        *cleanup[1:],
                    ],
                    errors,
                )
            if _is_restored(client, remote_dir=remote_dir, mutation=mutation):
                return
        except Exception as exc:
            errors.append(str(exc))

    # If the backup rename cannot be reconciled, restore the downloaded original
    # through another verified temporary file. This also handles a lost backup.
    if mutation.original_existed:
        restore_temps: list[str] = []
        for _ in range(2):
            restore_temp = f".{mutation.target}.xhttp-restore-{uuid.uuid4().hex}"
            restore_temps.append(restore_temp)
            verify = mutation.work_dir / f"rollback-restore-{uuid.uuid4().hex}"
            try:
                client.batch(
                    [
                        f"cd {sftp_quote(remote_dir)}",
                        f"put {sftp_quote(str(mutation.original_local))} {sftp_quote(restore_temp)}",
                        f"get {sftp_quote(restore_temp)} {sftp_quote(str(verify))}",
                    ]
                )
                if sha256_file(verify) != sha256_file(mutation.original_local):
                    raise VerificationError(
                        f"SHA-256 rollback-копии {mutation.target} не совпал"
                    )
                _try_batch(
                    client,
                    [
                        f"cd {sftp_quote(remote_dir)}",
                        f"-rm {sftp_quote(mutation.target)}",
                        f"-rename {sftp_quote(restore_temp)} {sftp_quote(mutation.target)}",
                        f"-chmod 644 {sftp_quote(mutation.target)}",
                        *cleanup[1:],
                        *(f"-rm {sftp_quote(name)}" for name in restore_temps),
                    ],
                    errors,
                )
                restore_temp_left = any(
                    _remote_digest(
                        client,
                        remote_dir=remote_dir,
                        name=name,
                        mutation=mutation,
                    )
                    is not None
                    for name in restore_temps
                )
                if not restore_temp_left and _is_restored(
                    client, remote_dir=remote_dir, mutation=mutation
                ):
                    return
            except Exception as exc:
                errors.append(str(exc))

    detail = "; ".join(errors[-4:]) or "удалённое состояние не совпало"
    raise InstallerError(
        f"Не удалось проверить восстановление remote {mutation.target}: {detail}"
    )


def _rollback_journal(
    client: SFTPClient,
    *,
    remote_dir: str,
    journal: list[_RemoteMutation],
    original: Exception,
) -> None:
    failures: list[str] = []
    for mutation in reversed(journal):
        try:
            _rollback_mutation(client, remote_dir=remote_dir, mutation=mutation)
        except Exception as exc:
            failures.append(f"{mutation.target}: {exc}")
    if not failures:
        return
    detail = " | ".join(failures)
    raise InstallerError(
        f"Применение не удалось, rollback неполон: {detail}"
    ) from original


def apply_front(
    desired: FrontDesired,
    *,
    auth: SSHAuth,
    state_dir: Path,
) -> FrontResult:
    desired = desired.validate()
    expanded_state = state_dir.expanduser()
    if expanded_state.is_symlink():
        raise InstallerError(f"--state-dir не может быть symlink: {expanded_state}")
    resolved_state = expanded_state.resolve()
    if resolved_state in {
        Path("/"),
        Path("/etc"),
        Path("/usr"),
        Path("/var"),
        Path("/opt"),
        Path("/root"),
        Path("/home"),
        Path("/tmp"),
    }:
        raise InstallerError(f"Слишком широкий --state-dir запрещён: {resolved_state}")
    state_dir = resolved_state
    existed = state_dir.exists()
    ensure_dir(state_dir, 0o700)
    marker = state_dir / ".xhttp-setup-state"
    marker_text = "xhttp-setup front state v1\n"
    if existed:
        if not marker.is_file() or marker.read_text("utf-8") != marker_text:
            raise InstallerError(
                f"Существующий --state-dir не помечен как managed: {state_dir}. "
                "Выберите новый дочерний каталог"
            )
    else:
        atomic_write_text(marker, marker_text, 0o600)
    with exclusive_lock(state_dir / "apply.lock"):
        return _apply_front_locked(desired, auth=auth, state_dir=state_dir)


def _apply_front_locked(
    desired: FrontDesired,
    *,
    auth: SSHAuth,
    state_dir: Path,
) -> FrontResult:
    check_front_dns(desired.domain, desired.front_public_ip)
    check_public_tls(desired.domain)
    root_before = https_status(f"https://{desired.domain}/")
    if root_before >= 500:
        raise VerificationError(
            "До изменений главная страница frontend уже возвращает 5xx"
        )

    known_hosts = state_dir / "known_hosts"
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
    timestamp = (
        __import__("datetime")
        .datetime.now(__import__("datetime").timezone.utc)
        .strftime("%Y%m%dT%H%M%S%fZ")
    )
    backup_token = f"{timestamp}-{uuid.uuid4().hex}"
    backup_dir = state_dir / "backups" / timestamp
    ensure_dir(backup_dir, 0o700)

    existing_htaccess = backup_dir / "htaccess.before"
    has_htaccess = _download_optional(
        client, desired.document_root, ".htaccess", existing_htaccess
    )
    managed = render_htaccess_block(
        exit_address=desired.exit_address,
        exit_port=desired.exit_port,
        path=desired.xhttp_path,
    )
    try:
        existing_text = existing_htaccess.read_text("utf-8") if has_htaccess else ""
        merged = merge_managed_block(existing_text, managed)
    except (UnicodeDecodeError, ValueError) as exc:
        raise InstallerError(f"Нельзя безопасно изменить .htaccess: {exc}") from exc
    local_htaccess = backup_dir / "htaccess.after"
    atomic_write_text(local_htaccess, merged, 0o600)
    htaccess_changed = not has_htaccess or existing_text != merged

    remote_index_backup: str | None = None
    index_changed = False
    local_index: Path | None = None
    if desired.placeholder_mode == "neutral":
        existing_index = backup_dir / "index.before.html"
        has_index = _download_optional(
            client, desired.document_root, "index.html", existing_index
        )
        local_index = backup_dir / "index.after.html"
        atomic_write_text(local_index, neutral_placeholder(desired.domain), 0o600)
        index_changed = (
            not has_index or existing_index.read_bytes() != local_index.read_bytes()
        )

    remote_htaccess_backup: str | None = None
    journal: list[_RemoteMutation] = []
    try:
        if index_changed and local_index is not None:
            remote_index_backup = _upload_verified(
                client,
                remote_dir=desired.document_root,
                local=local_index,
                target="index.html",
                backup_name=f".xhttp-backup-index-{backup_token}",
                work_dir=backup_dir,
                journal=journal,
            )
        if htaccess_changed:
            remote_htaccess_backup = _upload_verified(
                client,
                remote_dir=desired.document_root,
                local=local_htaccess,
                target=".htaccess",
                backup_name=f".xhttp-backup-htaccess-{backup_token}",
                work_dir=backup_dir,
                journal=journal,
            )
        root_status = https_status(f"https://{desired.domain}/")
        path_status = https_status(
            f"https://{desired.domain}{desired.xhttp_path}/doctor"
        )
        if root_status >= 500 or path_status in {500, 502, 503, 504}:
            raise VerificationError(
                f"Frontend после применения вернул root={root_status}, path={path_status}"
            )
    except Exception as exc:
        _rollback_journal(
            client,
            remote_dir=desired.document_root,
            journal=journal,
            original=exc,
        )
        raise

    return FrontResult(
        root_status=root_status,
        path_status=path_status,
        backup_dir=backup_dir,
        remote_htaccess_backup=remote_htaccess_backup,
        remote_index_backup=remote_index_backup,
    )
