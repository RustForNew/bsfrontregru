from __future__ import annotations

import http.client
import hashlib
import hmac
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from .errors import InstallerError, VerificationError
from .models import FrontDesired, TLS_MODE_PINNED, validate_cert_sha256
from .osutil import atomic_write_text, ensure_dir, exclusive_lock, sha256_file
from .placeholder import neutral_placeholder
from .render import merge_managed_block, render_htaccess_block
from .ssh_transport import (
    SFTPClient,
    SSHAuth,
    SSHRoute,
    TCPRoute,
    pin_host_key,
    sftp_quote,
)


@dataclass(frozen=True)
class FrontResult:
    root_status: int
    path_status: int
    backup_dir: Path
    remote_htaccess_backup: str | None
    remote_index_backup: str | None


class FrontRollbackError(InstallerError):
    """Frontend mutation could not be restored to its verified baseline."""


@dataclass
class _RemoteMutation:
    target: str
    backup_name: str
    remote_temp: str
    original_local: Path
    original_existed: bool
    original_sha256: str | None
    work_dir: Path
    installed_sha256: str
    switch_attempted: bool = False


class _RemoteStateConflict(InstallerError):
    """The target no longer matches either transaction-owned exact state."""


def check_front_dns(domain: str, dns_ipv4: str) -> None:
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
    if ipv4 != {dns_ipv4}:
        actual = ", ".join(sorted(ipv4)) or "A-записей нет"
        raise VerificationError(
            f"DNS A для {domain}: ожидался только {dns_ipv4}, получено: {actual}"
        )
    if ipv6:
        raise VerificationError(
            f"Для frontend обнаружена AAAA-запись: {', '.join(sorted(ipv6))}. "
            "Уберите её, иначе часть клиентов пойдёт по неподготовленному IPv6"
        )


def _client_tls_context(pinned_peer_cert_sha256: str | None) -> ssl.SSLContext:
    if not pinned_peer_cert_sha256:
        return ssl.create_default_context()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def _verify_leaf_pin(tls: ssl.SSLSocket, expected_sha256: str) -> str:
    expected = validate_cert_sha256(expected_sha256)
    certificate_der = tls.getpeercert(binary_form=True)
    if not certificate_der:
        raise VerificationError("TLS endpoint не предоставил leaf-сертификат")
    actual = hashlib.sha256(certificate_der).hexdigest()
    if not hmac.compare_digest(actual, expected):
        raise VerificationError(
            f"SHA-256 leaf-сертификата не совпал: ожидался {expected}, получен {actual}"
        )
    return actual


def check_public_tls(
    domain: str,
    *,
    connect_ip: str | None = None,
    pinned_peer_cert_sha256: str | None = None,
    timeout: int = 12,
    route: TCPRoute | None = None,
) -> dict[str, str]:
    target = connect_ip or domain
    transport = route.validate() if route is not None else None
    pin = (
        validate_cert_sha256(pinned_peer_cert_sha256)
        if pinned_peer_cert_sha256
        else None
    )
    context = _client_tls_context(pin)
    try:
        endpoint = (
            (transport.connect_host, transport.connect_port)
            if transport is not None
            else (target, 443)
        )
        with socket.create_connection(endpoint, timeout=timeout) as raw:
            with context.wrap_socket(raw, server_hostname=domain) as tls:
                leaf_sha256 = _verify_leaf_pin(tls, pin) if pin else ""
                certificate = tls.getpeercert()
                cipher = tls.cipher()
                return {
                    "subject": str(certificate.get("subject", "")),
                    "notAfter": str(certificate.get("notAfter", "unknown")),
                    "cipher": cipher[0] if cipher else "unknown",
                    "leafSha256": leaf_sha256,
                }
    except (OSError, ssl.SSLError) as exc:
        policy = (
            "закреплённому SHA-256 leaf-сертификата"
            if pin
            else "системному CA и hostname"
        )
        raise VerificationError(
            f"TLS для {domain} через {target}:443 не прошёл проверку по {policy}: {exc}"
        ) from exc


def https_status(
    url: str,
    *,
    connect_ip: str | None = None,
    pinned_peer_cert_sha256: str | None = None,
    timeout: int = 15,
    route: TCPRoute | None = None,
) -> int:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise VerificationError("Диагностический URL должен использовать HTTPS")
    pin = (
        validate_cert_sha256(pinned_peer_cert_sha256)
        if pinned_peer_cert_sha256
        else None
    )
    transport = route.validate() if route is not None else None
    if connect_ip is not None or pin is not None or transport is not None:
        logical_target = (connect_ip or parsed.hostname, parsed.port or 443)
        target = (
            (transport.connect_host, transport.connect_port)
            if transport is not None
            else logical_target
        )
        request_target = urllib.parse.urlunsplit(
            ("", "", parsed.path or "/", parsed.query, "")
        )
        if any(char in request_target for char in "\r\n"):
            raise VerificationError("Некорректный диагностический URL")
        host = parsed.hostname
        if parsed.port and parsed.port != 443:
            host = f"{host}:{parsed.port}"
        context = _client_tls_context(pin)
        try:
            with socket.create_connection(target, timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=parsed.hostname) as tls:
                    if pin:
                        _verify_leaf_pin(tls, pin)
                    request = (
                        f"GET {request_target} HTTP/1.1\r\n"
                        f"Host: {host}\r\n"
                        "User-Agent: xhttp-setup-doctor/0.1\r\n"
                        "Connection: close\r\n\r\n"
                    )
                    tls.sendall(request.encode("ascii"))
                    response = http.client.HTTPResponse(tls)
                    response.begin()
                    status = int(response.status)
                    response.close()
                    return status
        except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
            raise VerificationError(
                f"HTTPS-запрос {url} через {logical_target[0]} не выполнен: {exc}"
            ) from exc
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
    tls_check = (
        "Проверить TLS на клиентском адресе "
        f"{desired.client_connect_ip}:443 с SNI {desired.domain} и закреплённым "
        f"SHA-256 leaf-сертификата {desired.pinned_peer_cert_sha256}"
        if desired.tls_mode == TLS_MODE_PINNED
        else "Проверить публичный TLS на клиентском адресе "
        f"{desired.client_connect_ip}:443 с SNI {desired.domain}"
    )
    return [
        f"Проверить DNS A={desired.dns_ipv4} и отсутствие AAAA для домена {desired.domain}",
        tls_check,
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
        original_sha256=sha256_file(existing_probe) if existed else None,
        work_dir=work_dir,
        installed_sha256=sha256_file(local),
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
    if mutation.installed_sha256 != sha256_file(verify):
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
        if actual != mutation.original_sha256:
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


def _remote_artifact_path(remote_dir: str, name: str) -> str:
    return f"{remote_dir.rstrip('/')}/{name}"


def _cleanup_unswitched_temp(
    client: SFTPClient,
    *,
    remote_dir: str,
    mutation: _RemoteMutation,
) -> None:
    """Remove only the exact verified temp from an aborted pre-switch upload."""
    quarantine = f"{mutation.remote_temp}.rollback-{uuid.uuid4().hex}"
    errors: list[str] = []

    for _ in range(4):
        temp_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.remote_temp,
            mutation=mutation,
        )
        quarantine_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=quarantine,
            mutation=mutation,
        )
        if temp_digest is None and quarantine_digest is None:
            return
        if temp_digest == mutation.installed_sha256 and quarantine_digest is None:
            _try_batch(
                client,
                [
                    f"cd {sftp_quote(remote_dir)}",
                    f"rename {sftp_quote(mutation.remote_temp)} {sftp_quote(quarantine)}",
                ],
                errors,
            )
            continue
        if temp_digest is None and quarantine_digest == mutation.installed_sha256:
            _try_batch(
                client,
                [
                    f"cd {sftp_quote(remote_dir)}",
                    f"rm {sftp_quote(quarantine)}",
                ],
                errors,
            )
            continue
        preserved_name = (
            quarantine if quarantine_digest is not None else mutation.remote_temp
        )
        raise _RemoteStateConflict(
            f"Изменённый remote temp сохранён: "
            f"{_remote_artifact_path(remote_dir, preserved_name)}"
        )

    detail = "; ".join(errors[-4:]) or "temporary upload остался"
    raise InstallerError(
        f"Не удалось безопасно очистить remote temp для {mutation.target}: {detail}"
    )


def _remove_installed_target(
    client: SFTPClient,
    *,
    remote_dir: str,
    mutation: _RemoteMutation,
) -> None:
    """Remove a newly-created target without digest-then-unlink on its live name."""
    quarantine = f".{mutation.target}.xhttp-current-{uuid.uuid4().hex}"
    errors: list[str] = []

    for _ in range(4):
        target_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.target,
            mutation=mutation,
        )
        quarantine_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=quarantine,
            mutation=mutation,
        )
        backup_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.backup_name,
            mutation=mutation,
        )
        temp_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.remote_temp,
            mutation=mutation,
        )

        if backup_digest is not None:
            raise _RemoteStateConflict(
                f"Неожиданный remote artifact сохранён: "
                f"{_remote_artifact_path(remote_dir, mutation.backup_name)}"
            )
        if temp_digest not in {None, mutation.installed_sha256}:
            raise _RemoteStateConflict(
                f"Изменённый remote artifact сохранён: "
                f"{_remote_artifact_path(remote_dir, mutation.remote_temp)}"
            )

        if target_digest is None and quarantine_digest is None:
            _try_batch(
                client,
                [
                    f"cd {sftp_quote(remote_dir)}",
                    f"-rm {sftp_quote(mutation.remote_temp)}",
                ],
                errors,
            )
            if _is_restored(client, remote_dir=remote_dir, mutation=mutation):
                return
            continue

        if target_digest == mutation.installed_sha256 and quarantine_digest is None:
            # The rename is the destructive boundary. If target changed after the
            # digest probe, the changed bytes move to quarantine and are retained.
            _try_batch(
                client,
                [
                    f"cd {sftp_quote(remote_dir)}",
                    f"rename {sftp_quote(mutation.target)} {sftp_quote(quarantine)}",
                ],
                errors,
            )
            continue

        if target_digest is None and quarantine_digest == mutation.installed_sha256:
            # A new canonical target may appear after this probe, but removing our
            # unique quarantine cannot delete it. The final verification detects it.
            _try_batch(
                client,
                [
                    f"cd {sftp_quote(remote_dir)}",
                    f"rm {sftp_quote(quarantine)}",
                    f"-rm {sftp_quote(mutation.remote_temp)}",
                ],
                errors,
            )
            if _is_restored(client, remote_dir=remote_dir, mutation=mutation):
                return
            continue

        if quarantine_digest is not None:
            raise _RemoteStateConflict(
                f"Remote {mutation.target} изменён во время rollback; "
                f"чужое состояние сохранено в "
                f"{_remote_artifact_path(remote_dir, quarantine)}"
            )
        raise _RemoteStateConflict(
            f"Remote {mutation.target} изменён после применения; "
            "автоматический rollback оставил его без изменений"
        )

    detail = "; ".join(errors[-4:]) or "не удалось изолировать installed target"
    raise InstallerError(
        f"Не удалось безопасно удалить remote {mutation.target}: {detail}"
    )


def _restore_expected_backup(
    client: SFTPClient,
    *,
    remote_dir: str,
    mutation: _RemoteMutation,
    expected_sha256: str,
) -> None:
    """Restore a verified backup without ever unlinking an unchecked target."""
    quarantine = f".{mutation.target}.xhttp-current-{uuid.uuid4().hex}"
    late_quarantine = f".{mutation.target}.xhttp-late-{uuid.uuid4().hex}"
    errors: list[str] = []

    def cleanup_and_verify() -> bool:
        quarantine_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=quarantine,
            mutation=mutation,
        )
        backup_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.backup_name,
            mutation=mutation,
        )
        temp_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.remote_temp,
            mutation=mutation,
        )
        late_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=late_quarantine,
            mutation=mutation,
        )
        if late_digest is not None:
            raise _RemoteStateConflict(
                f"Remote {mutation.target} появился во время rollback; "
                f"чужое состояние сохранено в "
                f"{_remote_artifact_path(remote_dir, late_quarantine)}"
            )
        artifact_states = (
            (quarantine, quarantine_digest, {None, mutation.installed_sha256}),
            (mutation.backup_name, backup_digest, {None, expected_sha256}),
            (mutation.remote_temp, temp_digest, {None, mutation.installed_sha256}),
        )
        for name, digest, allowed in artifact_states:
            if digest not in allowed:
                raise _RemoteStateConflict(
                    f"Изменённый remote artifact сохранён: "
                    f"{_remote_artifact_path(remote_dir, name)}"
                )
        _try_batch(
            client,
            [
                f"cd {sftp_quote(remote_dir)}",
                f"-rm {sftp_quote(quarantine)}",
                f"-rm {sftp_quote(mutation.backup_name)}",
                f"-rm {sftp_quote(mutation.remote_temp)}",
            ],
            errors,
        )
        quarantine_digest_after = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=quarantine,
            mutation=mutation,
        )
        return quarantine_digest_after is None and _is_restored(
            client, remote_dir=remote_dir, mutation=mutation
        )

    # Rename, rather than unlink, the current target. If an owner edit lands
    # after our first digest check, it moves into quarantine and is detected.
    for _ in range(3):
        target_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.target,
            mutation=mutation,
        )
        quarantine_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=quarantine,
            mutation=mutation,
        )
        if target_digest == expected_sha256:
            if quarantine_digest not in {None, mutation.installed_sha256}:
                raise _RemoteStateConflict(
                    f"Remote {mutation.target} изменён во время rollback; "
                    f"чужое состояние сохранено в "
                    f"{_remote_artifact_path(remote_dir, quarantine)}"
                )
            if cleanup_and_verify():
                return
            continue
        if target_digest == mutation.installed_sha256 and quarantine_digest is None:
            _try_batch(
                client,
                [
                    f"cd {sftp_quote(remote_dir)}",
                    f"rename {sftp_quote(mutation.target)} {sftp_quote(quarantine)}",
                ],
                errors,
            )
            continue
        if target_digest is None and quarantine_digest == mutation.installed_sha256:
            break
        if target_digest is None and quarantine_digest is None:
            backup_digest = _remote_digest(
                client,
                remote_dir=remote_dir,
                name=mutation.backup_name,
                mutation=mutation,
            )
            temp_digest = _remote_digest(
                client,
                remote_dir=remote_dir,
                name=mutation.remote_temp,
                mutation=mutation,
            )
            if (
                backup_digest == expected_sha256
                and temp_digest == mutation.installed_sha256
            ):
                # The first switch rename completed but the verified temp was not
                # promoted. There is no installed target to quarantine.
                break
        if target_digest is None and quarantine_digest is not None:
            raise _RemoteStateConflict(
                f"Remote {mutation.target} изменён во время rollback; "
                f"чужое состояние сохранено в "
                f"{_remote_artifact_path(remote_dir, quarantine)}"
            )
        raise _RemoteStateConflict(
            f"Remote {mutation.target} изменён во время rollback; "
            "чужое состояние сохранено"
        )
    else:
        detail = "; ".join(errors[-4:]) or "не удалось изолировать installed target"
        raise InstallerError(
            f"Не удалось безопасно подготовить rollback remote {mutation.target}: {detail}"
        )

    # Target is absent and the exact installed file is quarantined. Re-check the
    # backup after both renames so a changed backup is never promoted silently.
    for _ in range(3):
        target_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.target,
            mutation=mutation,
        )
        quarantine_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=quarantine,
            mutation=mutation,
        )
        backup_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.backup_name,
            mutation=mutation,
        )
        temp_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=mutation.remote_temp,
            mutation=mutation,
        )
        late_digest = _remote_digest(
            client,
            remote_dir=remote_dir,
            name=late_quarantine,
            mutation=mutation,
        )
        if late_digest is not None:
            raise _RemoteStateConflict(
                f"Remote {mutation.target} появился во время rollback; "
                f"чужое состояние сохранено в "
                f"{_remote_artifact_path(remote_dir, late_quarantine)}"
            )
        if target_digest == expected_sha256:
            if quarantine_digest not in {None, mutation.installed_sha256}:
                raise _RemoteStateConflict(
                    f"Remote {mutation.target} изменён во время rollback; "
                    f"изменённый quarantine сохранён: "
                    f"{_remote_artifact_path(remote_dir, quarantine)}"
                )
            if cleanup_and_verify():
                return
            continue
        if target_digest is not None:
            raise _RemoteStateConflict(
                f"Remote {mutation.target} изменён во время rollback; "
                "чужое состояние сохранено"
            )
        if (
            quarantine_digest not in {None, mutation.installed_sha256}
            or backup_digest != expected_sha256
            or temp_digest not in {None, mutation.installed_sha256}
            or (quarantine_digest is None and temp_digest != mutation.installed_sha256)
        ):
            if quarantine_digest not in {None, mutation.installed_sha256}:
                preserved_name = quarantine
            elif backup_digest != expected_sha256:
                preserved_name = (
                    mutation.backup_name if backup_digest is not None else None
                )
            elif temp_digest not in {None, mutation.installed_sha256}:
                preserved_name = mutation.remote_temp
            else:
                preserved_name = None
            artifact_detail = (
                f"artifact сохранён: "
                f"{_remote_artifact_path(remote_dir, preserved_name)}"
                if preserved_name is not None
                else "recoverable artifact отсутствует"
            )
            raise _RemoteStateConflict(
                f"Remote {mutation.target} или его backup изменён во время rollback; "
                f"автоматическое восстановление остановлено; {artifact_detail}"
            )
        _try_batch(
            client,
            [
                f"cd {sftp_quote(remote_dir)}",
                # Catch a target created at this command boundary. SFTP has no
                # compare-and-swap, so the exact residual limitation is documented.
                f"-rename {sftp_quote(mutation.target)} {sftp_quote(late_quarantine)}",
                f"rename {sftp_quote(mutation.backup_name)} {sftp_quote(mutation.target)}",
                f"-rm {sftp_quote(mutation.remote_temp)}",
            ],
            errors,
        )

    detail = "; ".join(errors[-4:]) or "не удалось восстановить verified backup"
    raise InstallerError(
        f"Не удалось безопасно восстановить remote {mutation.target}: {detail}"
    )


def _rollback_mutation(
    client: SFTPClient, *, remote_dir: str, mutation: _RemoteMutation
) -> None:
    errors: list[str] = []
    if not mutation.switch_attempted:
        _cleanup_unswitched_temp(
            client,
            remote_dir=remote_dir,
            mutation=mutation,
        )
        return

    if not mutation.original_existed:
        _remove_installed_target(
            client,
            remote_dir=remote_dir,
            mutation=mutation,
        )
        return

    expected = mutation.original_sha256
    if expected is None:  # Internal invariant; keep rollback fail-closed.
        raise InstallerError(
            f"Нет pre-apply SHA-256 для существовавшего remote {mutation.target}"
        )

    # First reconcile the common states left by an interrupted rename batch.
    for _ in range(2):
        try:
            target_digest = _remote_digest(
                client,
                remote_dir=remote_dir,
                name=mutation.target,
                mutation=mutation,
            )
            if target_digest == expected:
                _restore_expected_backup(
                    client,
                    remote_dir=remote_dir,
                    mutation=mutation,
                    expected_sha256=expected,
                )
                return
            elif target_digest == mutation.installed_sha256:
                backup_digest = _remote_digest(
                    client,
                    remote_dir=remote_dir,
                    name=mutation.backup_name,
                    mutation=mutation,
                )
                if backup_digest != expected:
                    raise _RemoteStateConflict(
                        f"Remote backup для {mutation.target} не совпал с "
                        "pre-apply снимком; возможная правка владельца сохранена в "
                        f"{_remote_artifact_path(remote_dir, mutation.backup_name)}"
                    )
                _restore_expected_backup(
                    client,
                    remote_dir=remote_dir,
                    mutation=mutation,
                    expected_sha256=expected,
                )
                return
            elif target_digest is None:
                backup_digest = _remote_digest(
                    client,
                    remote_dir=remote_dir,
                    name=mutation.backup_name,
                    mutation=mutation,
                )
                temp_digest = _remote_digest(
                    client,
                    remote_dir=remote_dir,
                    name=mutation.remote_temp,
                    mutation=mutation,
                )
                if (
                    backup_digest != expected
                    or temp_digest != mutation.installed_sha256
                ):
                    raise _RemoteStateConflict(
                        f"Remote {mutation.target} изменён после применения; "
                        "автоматический rollback отказался перезаписывать чужое состояние"
                    )
                _restore_expected_backup(
                    client,
                    remote_dir=remote_dir,
                    mutation=mutation,
                    expected_sha256=expected,
                )
                return
            else:
                raise _RemoteStateConflict(
                    f"Remote {mutation.target} изменён после применения; "
                    "автоматический rollback отказался перезаписывать чужое состояние"
                )
        except _RemoteStateConflict:
            raise
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
    original: BaseException,
) -> None:
    failures: list[str] = []
    for mutation in reversed(journal):
        try:
            _rollback_mutation(client, remote_dir=remote_dir, mutation=mutation)
        except BaseException as exc:
            detail = str(exc).strip() or type(exc).__name__
            failures.append(f"{mutation.target}: {detail}")
    if not failures:
        return
    detail = " | ".join(failures)
    raise FrontRollbackError(
        f"Применение не удалось, rollback неполон: {detail}"
    ) from original


def apply_front(
    desired: FrontDesired,
    *,
    auth: SSHAuth,
    state_dir: Path,
    pre_apply: Callable[[], None] | None = None,
    post_apply: Callable[[FrontResult], None] | None = None,
    on_failure: Callable[[BaseException], None] | None = None,
    sftp_route: SSHRoute | None = None,
    https_route: TCPRoute | None = None,
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
        try:
            if pre_apply is not None:
                pre_apply()
            return _apply_front_locked(
                desired,
                auth=auth,
                state_dir=state_dir,
                post_apply=post_apply,
                sftp_route=sftp_route,
                https_route=https_route,
            )
        except BaseException as exc:
            if on_failure is not None:
                try:
                    on_failure(exc)
                except BaseException as cleanup_error:
                    raise cleanup_error from exc
            raise


def _apply_front_locked(
    desired: FrontDesired,
    *,
    auth: SSHAuth,
    state_dir: Path,
    post_apply: Callable[[FrontResult], None] | None = None,
    sftp_route: SSHRoute | None = None,
    https_route: TCPRoute | None = None,
) -> FrontResult:
    check_front_dns(desired.domain, desired.dns_ipv4)
    check_public_tls(
        desired.domain,
        connect_ip=desired.client_connect_ip,
        pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
        route=https_route,
    )
    root_before = https_status(
        f"https://{desired.domain}/",
        connect_ip=desired.client_connect_ip,
        pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
        route=https_route,
    )
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
        route=sftp_route,
    )
    client = SFTPClient(
        host=desired.sftp_host,
        port=desired.sftp_port,
        user=desired.sftp_user,
        known_hosts=known_hosts,
        auth=auth,
        route=sftp_route,
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
        root_status = https_status(
            f"https://{desired.domain}/",
            connect_ip=desired.client_connect_ip,
            pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
            route=https_route,
        )
        path_status = https_status(
            f"https://{desired.domain}{desired.xhttp_path}/doctor",
            connect_ip=desired.client_connect_ip,
            pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
            route=https_route,
        )
        if root_status >= 500 or path_status in {500, 502, 503, 504}:
            raise VerificationError(
                f"Frontend после применения вернул root={root_status}, path={path_status}"
            )
        result = FrontResult(
            root_status=root_status,
            path_status=path_status,
            backup_dir=backup_dir,
            remote_htaccess_backup=remote_htaccess_backup,
            remote_index_backup=remote_index_backup,
        )
        if post_apply is not None:
            post_apply(result)
    except BaseException as exc:
        _rollback_journal(
            client,
            remote_dir=desired.document_root,
            journal=journal,
            original=exc,
        )
        raise

    return result
