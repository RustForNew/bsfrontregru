from __future__ import annotations

import argparse
import datetime
import getpass
import os
import platform
import re
import secrets
import sys
import urllib.parse
import uuid
from pathlib import Path
from typing import Callable, TypeVar

from . import __version__
from .doctor import Check, doctor_exit, doctor_front, e2e_probe
from .errors import InstallerError, ValidationError
from .exit_installer import Layout, apply_exit, build_exit_plan
from .front import (
    FrontResult,
    apply_front,
    build_front_plan,
    check_front_dns,
    check_public_tls,
)
from .ispmanager import inspect_site
from .models import (
    DEFAULT_TLS_FINGERPRINT,
    TLS_FINGERPRINTS,
    TLS_MODE_PINNED,
    TLS_MODE_PUBLIC,
    TLS_MODES,
    ExitDesired,
    FrontDesired,
    Handoff,
    validate_cert_sha256,
    validate_front_tls,
    validate_tls_fingerprint,
)
from .osutil import atomic_write_text, load_json
from .render import render_vless_uri
from .ssh_transport import SSHAuth
from .validate import (
    normalize_domain,
    validate_fingerprint,
    validate_host,
    validate_ipv4,
    validate_port,
    validate_remote_dir,
    validate_ssh_user,
    validate_xhttp_path,
)


T = TypeVar("T")
PROVIDER_WARNING = """ВАЖНО: правила REG.RU прямо относят proxy-сервисы на виртуальном
хостинге к запрещённым. Техническая аккуратность не делает использование
разрешённым и не гарантирует отсутствие блокировки. Получите письменное
разрешение провайдера либо выберите хостинг, где такой трафик разрешён.
"""


def _prompt(label: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    value = input(f"{label}{suffix}: ").strip()
    return value if value else (default or "")


def _validated_prompt(
    label: str, validator: Callable[[str], T], default: str | None = None
) -> T:
    while True:
        try:
            return validator(_prompt(label, default))
        except ValidationError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)


def _yes_no(label: str, *, default: bool = False) -> bool:
    marker = "Y/n" if default else "y/N"
    value = input(f"{label} [{marker}]: ").strip().lower()
    if not value:
        return default
    return value in {"y", "yes", "д", "да"}


def _default_state(domain: str) -> Path:
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        return Path("/var/lib/xhttp-setup/fronts") / domain
    return Path.home() / ".local/state/xhttp-setup/fronts" / domain


def _require_linux_apply() -> None:
    if platform.system() != "Linux":
        raise InstallerError(
            "Применение поддерживается только на Linux/WSL; plan и doctor доступны без записи"
        )


def _show_plan(title: str, lines: list[str]) -> None:
    print(f"\n{title}")
    for number, line in enumerate(lines, 1):
        print(f"  {number}. {line}")


def _confirm_apply(target: str, supplied: str | None = None) -> None:
    expected = f"APPLY {target}"
    answer = (
        supplied
        if supplied is not None
        else input(f"\nДля применения введите: {expected}\n> ")
    )
    if answer != expected:
        raise InstallerError("Подтверждение не совпало; изменений нет")


def _ack_provider(supplied: bool = False) -> None:
    print("\n" + PROVIDER_WARNING)
    if not supplied:
        print(
            "Это информационное предупреждение; оно не блокирует техническую "
            "установку и не требует кодовой фразы."
        )


def _ack_firewall(*, plan_path: Path | None = None, supplied: bool = False) -> None:
    if plan_path:
        print(f"\nПримените и проверьте firewall-план в отдельной сессии: {plan_path}")
    print(
        "Backend Xray должен принимать TCP только от фактического egress-IP frontend. "
        "Открытый всему интернету порт не считается завершённой установкой."
    )
    if supplied:
        return
    expected = "FIREWALL ПРОВЕРЕН"
    answer = input(f"После внешней проверки введите: {expected}\n> ")
    if answer != expected:
        raise InstallerError("Firewall не подтверждён; ссылка не будет создана")


def _collect_exit() -> ExitDesired:
    print("\nВыходной VPS (настройка выполняется на текущей Linux-машине)")
    public_address = _validated_prompt("Публичный IPv4 выхода", validate_ipv4)
    expected_egress = _validated_prompt(
        "Ожидаемый исходящий IPv4 выхода", validate_ipv4, public_address
    )
    front_egress = _validated_prompt(
        "Фактический исходящий IPv4 shared-hosting (не угадывать по A-записи)",
        validate_ipv4,
    )
    port = _validated_prompt("Порт Xray", validate_port, "8083")
    generated_path = "/api/" + secrets.token_urlsafe(24)
    path = _validated_prompt(
        "Случайный XHTTP path", validate_xhttp_path, generated_path
    )
    tls_fingerprint = _validated_prompt(
        "TLS fingerprint клиента",
        validate_tls_fingerprint,
        DEFAULT_TLS_FINGERPRINT,
    )
    return ExitDesired(
        public_address=public_address,
        listen_port=port,
        front_egress_ip=front_egress,
        xhttp_path=path,
        client_id=str(uuid.uuid4()),
        label=_prompt("Название подключения", "XHTTP TLS"),
        expected_egress_ip=expected_egress,
        tls_fingerprint=tls_fingerprint,
    ).validate()


def _collect_front_tls_policy() -> tuple[str, str | None]:
    if not _yes_no(
        "Закрепить SHA-256 текущего leaf-сертификата вместо проверки публичным CA?"
    ):
        return TLS_MODE_PUBLIC, None
    print(
        "ВНИМАНИЕ: pinned-режим доверяет только точному текущему leaf-сертификату. "
        "CA, SAN/hostname, срок и revocation при exact match не проверяются. После "
        "перевыпуска сертификата pin и клиентскую ссылку нужно обновить вручную. "
        "Клиент обязан поддерживать pcs. "
        "Снимайте pin только после включения SSL/443 у сайта и проверки, что SNI "
        "попадает в его vhost, а не в default-vhost провайдера."
    )
    pin = _validated_prompt(
        "SHA-256 текущего leaf-сертификата (64 hex)", validate_cert_sha256
    )
    return TLS_MODE_PINNED, pin


def _collect_front(handoff: Handoff) -> FrontDesired:
    print("\nFrontend shared-hosting")
    domain = _validated_prompt(
        "FQDN/SNI существующего сайта frontend", normalize_domain
    )
    client_connect_ip = _validated_prompt(
        "IPv4 подключения клиента (адрес в VLESS URI)", validate_ipv4
    )
    dns_ipv4 = _validated_prompt(
        "IPv4 в DNS A домена (для сайта и ACME)",
        validate_ipv4,
        client_connect_ip,
    )
    tls_mode, pinned_peer_cert_sha256 = _collect_front_tls_policy()
    sftp_host = _validated_prompt("SFTP hostname/IP", validate_host)
    sftp_port = _validated_prompt("SFTP port", validate_port, "22")
    sftp_user = _validated_prompt("SFTP user", validate_ssh_user)
    if _yes_no("Получить document root read-only запросом к ISPmanager API?"):
        endpoint = _prompt("ISPmanager endpoint", f"https://{sftp_host}:1500/ispmgr")
        panel_user = _prompt("ISPmanager user", sftp_user)
        panel_password = getpass.getpass("ISPmanager password (не сохраняется): ")
        site = inspect_site(
            endpoint=endpoint,
            username=panel_user,
            password=panel_password,
            domain=domain,
        )
        document_root = site.docroot
        print(
            f"Найден сайт {site.name}: docroot={site.docroot}, ip={site.ipaddr or 'не указан'}"
        )
        if site.ipaddr and site.ipaddr != dns_ipv4:
            print(
                "Примечание: назначенный ISPmanager IP сайта "
                f"{site.ipaddr} отличается от DNS A {dns_ipv4}. Это не блокирует "
                "установку: доступность vhost и TLS будет проверена отдельно на "
                f"клиентском адресе {client_connect_ip}."
            )
    else:
        document_root = _validated_prompt(
            "Document root из списка сайтов ISPmanager", validate_remote_dir
        )
    fingerprint = _validated_prompt(
        "Проверенный SSH host-key fingerprint SHA256", validate_fingerprint
    )
    placeholder = (
        "neutral"
        if _yes_no(
            "Заменить index.html на оригинальную нейтральную заглушку со ссылкой на RuFox?"
        )
        else "keep"
    )
    return FrontDesired(
        domain=domain,
        client_connect_ip=client_connect_ip,
        dns_ipv4=dns_ipv4,
        sftp_host=sftp_host,
        sftp_port=sftp_port,
        sftp_user=sftp_user,
        document_root=document_root,
        ssh_host_key_sha256=fingerprint,
        exit_address=handoff.exit_address,
        exit_port=handoff.exit_port,
        xhttp_path=handoff.xhttp_path,
        placeholder_mode=placeholder,
        tls_mode=tls_mode,
        pinned_peer_cert_sha256=pinned_peer_cert_sha256,
    ).validate()


def _collect_auth() -> SSHAuth:
    use_key = _yes_no("Использовать отдельный SSH-ключ вместо пароля?", default=True)
    if use_key:
        identity = _prompt("Путь к приватному ключу", "~/.ssh/id_ed25519")
        return SSHAuth(method="key", private_key=identity).validate()
    password = getpass.getpass("SFTP password (не сохраняется): ")
    return SSHAuth(method="password", password=password).validate()


def _save_verified_link(
    *, state_dir: Path, handoff: Handoff, domain: str, client_connect_ip: str
) -> Path:
    uri = render_vless_uri(handoff, domain, front_address=client_connect_ip)
    link_path = state_dir / "client.vless"
    atomic_write_text(link_path, uri + "\n", 0o600)
    print("\nE2E-проверка пройдена. Клиентская ссылка:")
    print(uri)
    print(f"\nКопия с правами 0600: {link_path}")
    return link_path


def _redact_failure_detail(error: BaseException, handoff: Handoff) -> str:
    detail = " ".join(str(error).splitlines()).strip() or type(error).__name__
    secrets_to_remove = (
        handoff.encryption,
        handoff.client_id,
        handoff.xhttp_path,
    )
    for secret in secrets_to_remove:
        encoded = urllib.parse.quote(secret, safe="")
        encoded_plus = urllib.parse.quote_plus(secret, safe="")
        json_escaped = secret.replace("\\", "\\\\").replace("/", "\\/")
        for representation in {secret, json_escaped}:
            if representation:
                detail = detail.replace(representation, "[REDACTED]")
        for representation in {encoded, encoded_plus}:
            if representation:
                detail = re.sub(
                    re.escape(representation),
                    "[REDACTED]",
                    detail,
                    flags=re.IGNORECASE,
                )
    detail = re.sub(
        r"vless://\S+",
        "[REDACTED VLESS URI]",
        detail,
        flags=re.IGNORECASE,
    )
    return detail[:2000]


def _managed_front_state(state_dir: Path) -> bool:
    marker = state_dir / ".xhttp-setup-state"
    try:
        return (
            state_dir.is_dir()
            and not state_dir.is_symlink()
            and marker.is_file()
            and not marker.is_symlink()
            and marker.read_text("utf-8") == "xhttp-setup front state v1\n"
        )
    except (OSError, UnicodeError):
        return False


def _remove_client_link(state_dir: Path) -> None:
    link_path = state_dir / "client.vless"
    try:
        link_path.unlink(missing_ok=True)
    except OSError as exc:
        raise InstallerError(
            f"Не удалось убрать непроверенный client.vless из managed state: {exc}"
        ) from exc


def _record_front_failure(
    *,
    state_dir: Path,
    stage: str,
    error: BaseException,
    handoff: Handoff,
    rollback_status: str,
    link_status: str,
) -> Path | None:
    if not _managed_front_state(state_dir):
        return None
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    detail = _redact_failure_detail(error, handoff)
    log_path = state_dir / "last-failure.log"
    try:
        atomic_write_text(
            log_path,
            "\n".join(
                (
                    f"time_utc={timestamp}",
                    f"stage={stage}",
                    f"error_type={type(error).__name__}",
                    f"error={detail}",
                    f"frontend_rollback={rollback_status}",
                    f"client_link={link_status}",
                    "",
                )
            ),
            0o600,
        )
    except OSError:
        return None
    return log_path


def _apply_front_and_issue(
    *,
    desired: FrontDesired,
    auth: SSHAuth,
    state_dir: Path,
    handoff: Handoff,
    layout: Layout,
    firewall_plan_path: Path | None = None,
    firewall_supplied: bool | None = None,
) -> FrontResult:
    stage = "frontend apply"
    link_withholding_started = False

    def prepare_transaction() -> None:
        nonlocal stage, link_withholding_started
        stage = "stale client link withholding"
        link_withholding_started = True
        _remove_client_link(state_dir)
        if firewall_supplied is not None:
            stage = "firewall acknowledgement"
            _ack_firewall(
                plan_path=firewall_plan_path,
                supplied=firewall_supplied,
            )
        stage = "frontend apply"

    def finish_transaction(_: FrontResult) -> None:
        nonlocal stage, link_withholding_started
        if not link_withholding_started:
            stage = "stale client link withholding"
            link_withholding_started = True
            _remove_client_link(state_dir)
        stage = "failure log rotation"
        try:
            (state_dir / "last-failure.log").unlink(missing_ok=True)
        except OSError as exc:
            raise InstallerError(
                f"Не удалось удалить устаревший failure log из managed state: {exc}"
            ) from exc
        stage = "E2E probe and profile issuance"
        _run_probe_and_issue(
            handoff=handoff,
            domain=desired.domain,
            client_connect_ip=desired.client_connect_ip,
            state_dir=state_dir,
            layout=layout,
        )

    def record_failure(exc: BaseException) -> None:
        nonlocal link_withholding_started
        link_status = "not touched"
        cleanup_error: InstallerError | None = None
        if _managed_front_state(state_dir):
            link_withholding_started = True
            try:
                _remove_client_link(state_dir)
                link_status = "absent"
            except InstallerError as link_error:
                cleanup_error = link_error
                link_status = "cleanup failed"
        rollback_status = (
            "failed; inspect error"
            if "rollback неполон" in str(exc)
            else "completed or no remote mutation"
        )
        log_path = _record_front_failure(
            state_dir=state_dir,
            stage=stage,
            error=exc,
            handoff=handoff,
            rollback_status=rollback_status,
            link_status=link_status,
        )
        if log_path is not None:
            try:
                print(f"Диагностика без секретов: {log_path}", file=sys.stderr)
            except OSError:
                pass
        if cleanup_error is not None:
            raise cleanup_error from exc

    return apply_front(
        desired,
        auth=auth,
        state_dir=state_dir,
        pre_apply=prepare_transaction,
        post_apply=finish_transaction,
        on_failure=record_failure,
    )


def _run_probe_and_issue(
    *,
    handoff: Handoff,
    domain: str,
    client_connect_ip: str,
    state_dir: Path,
    layout: Layout,
) -> None:
    output = e2e_probe(
        handoff=handoff,
        domain=domain,
        front_address=client_connect_ip,
        layout=layout,
    )
    first_line = output.splitlines()[0] if output else "response received"
    print(f"E2E: OK ({first_line[:120]})")
    _save_verified_link(
        state_dir=state_dir,
        handoff=handoff,
        domain=domain,
        client_connect_ip=client_connect_ip,
    )


def _print_front_result(result: FrontResult) -> None:
    print(
        f"Frontend: root={result.root_status}, path={result.path_status}; "
        f"local backup={result.backup_dir}"
    )
    remote = [
        value
        for value in (result.remote_htaccess_backup, result.remote_index_backup)
        if value
    ]
    if remote:
        print("Remote rollback files: " + ", ".join(remote))


def wizard_exit() -> int:
    desired = _collect_exit()
    layout = Layout()
    _show_plan("План выхода", build_exit_plan(desired, layout))
    _confirm_apply("EXIT")
    apply_exit(desired, layout=layout)
    print(f"\nВыход настроен. Handoff для шага front: {layout.handoff}")
    print(f"Firewall пока не применён автоматически: {layout.firewall_plan}")
    print("Ссылка ещё не выдана: frontend и полный E2E не проверены.")
    return 0


def wizard_front() -> int:
    handoff_path = Path(
        _prompt("Путь к handoff.json", "/var/lib/xhttp-setup/handoff.json")
    )
    handoff = Handoff.from_dict(load_json(handoff_path))
    desired = _collect_front(handoff)
    client_handoff = handoff.with_pinned_peer_cert(desired.pinned_peer_cert_sha256)
    _show_plan("План frontend", build_front_plan(desired))
    check_front_dns(desired.domain, desired.dns_ipv4)
    check_public_tls(
        desired.domain,
        connect_ip=desired.client_connect_ip,
        pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
    )
    _ack_provider()
    _confirm_apply(desired.domain)
    _require_linux_apply()
    auth = _collect_auth()
    state_dir = _default_state(desired.domain)
    probe_layout = Layout(root=state_dir / "probe-runtime")
    result = _apply_front_and_issue(
        desired=desired,
        auth=auth,
        state_dir=state_dir,
        handoff=client_handoff,
        layout=probe_layout,
        firewall_supplied=False,
    )
    _print_front_result(result)
    return 0


def wizard_full() -> int:
    desired_exit = _collect_exit()
    preview_handoff = Handoff(
        exit_address=desired_exit.public_address,
        exit_port=desired_exit.listen_port,
        client_id=desired_exit.client_id,
        xhttp_path=desired_exit.xhttp_path,
        encryption="pending-vless-encryption-material-xxxxxxxx",
        label=desired_exit.label,
        expected_egress_ip=desired_exit.expected_egress_ip,
        tls_fingerprint=desired_exit.tls_fingerprint,
    ).validate()
    desired_front = _collect_front(preview_handoff)
    _show_plan(
        "План полной установки",
        build_exit_plan(desired_exit, Layout()) + build_front_plan(desired_front),
    )
    print(
        "\nFull запускается на выходном VPS. Если SFTP shared-hosting недоступен с его IP, "
        "используйте exit и front раздельно, а front запускайте с разрешённого российского IP."
    )
    check_front_dns(desired_front.domain, desired_front.dns_ipv4)
    check_public_tls(
        desired_front.domain,
        connect_ip=desired_front.client_connect_ip,
        pinned_peer_cert_sha256=desired_front.pinned_peer_cert_sha256,
    )
    _ack_provider()
    _confirm_apply(desired_front.domain)
    auth = _collect_auth()
    handoff = apply_exit(desired_exit)
    client_handoff = handoff.with_pinned_peer_cert(
        desired_front.pinned_peer_cert_sha256
    )
    desired_front = FrontDesired(
        **{
            **desired_front.__dict__,
            "exit_address": handoff.exit_address,
            "exit_port": handoff.exit_port,
            "xhttp_path": handoff.xhttp_path,
        }
    ).validate()
    state_dir = _default_state(desired_front.domain)
    try:
        result = _apply_front_and_issue(
            desired=desired_front,
            auth=auth,
            state_dir=state_dir,
            handoff=client_handoff,
            layout=Layout(),
            firewall_plan_path=Layout().firewall_plan,
            firewall_supplied=False,
        )
        _print_front_result(result)
    except Exception:
        print(
            "\nВыход уже настроен, но frontend/E2E не завершён. Ссылка не создана. "
            "Исправьте доступ и повторите режим front с /var/lib/xhttp-setup/handoff.json.",
            file=sys.stderr,
        )
        raise
    return 0


def _managed_exit_present(layout: Layout) -> bool:
    return any(
        path.exists() for path in (layout.config, layout.handoff, layout.receipt)
    )


def wizard_doctor() -> int:
    domain = _validated_prompt("Frontend domain", normalize_domain)
    client_connect_ip = _validated_prompt(
        "IPv4 подключения клиента (адрес в VLESS URI)", validate_ipv4
    )
    dns_ipv4 = _validated_prompt(
        "IPv4 в DNS A домена", validate_ipv4, client_connect_ip
    )
    path = _validated_prompt("XHTTP path", validate_xhttp_path)
    _, pinned_peer_cert_sha256 = _collect_front_tls_policy()
    checks = doctor_front(
        domain,
        path,
        client_connect_ip=client_connect_ip,
        dns_ipv4=dns_ipv4,
        pinned_peer_cert_sha256=pinned_peer_cert_sha256,
    )
    exit_layout = Layout()
    if os.name == "posix" and _managed_exit_present(exit_layout):
        checks.extend(doctor_exit(exit_layout))
    return _print_checks(checks)


def wizard() -> int:
    print(f"XHTTP Setup {__version__}\n")
    print("1. Полная установка: frontend + выход на текущем VPS")
    print("2. Только выход на текущем VPS")
    print("3. Только frontend по готовому handoff.json")
    print("4. Doctor (только чтение)")
    choice = _prompt("Выберите режим")
    actions = {
        "1": wizard_full,
        "2": wizard_exit,
        "3": wizard_front,
        "4": wizard_doctor,
    }
    if choice not in actions:
        raise InstallerError("Неизвестный режим")
    return actions[choice]()


def _print_checks(checks: list[Check]) -> int:
    for check in checks:
        print(f"{'OK' if check.ok else 'FAIL':4}  {check.name}: {check.detail}")
    return 0 if checks and all(check.ok for check in checks) else 2


def _exit_from_args(args: argparse.Namespace) -> int:
    layout = Layout()
    existing: dict = {}
    if layout.secrets.exists():
        existing = load_json(layout.secrets)
    if args.client_id_file:
        credential_path = Path(args.client_id_file)
        if not credential_path.is_file():
            raise InstallerError(f"Файл UUID не найден: {credential_path}")
        if os.name == "posix" and credential_path.stat().st_mode & 0o077:
            raise InstallerError("Файл UUID должен иметь права 0600")
        client_id = credential_path.read_text("utf-8").strip()
    else:
        client_id = str(existing.get("client_id") or uuid.uuid4())
    path = args.path or str(
        existing.get("xhttp_path") or ("/api/" + secrets.token_urlsafe(24))
    )
    desired = ExitDesired(
        public_address=args.public_address,
        listen_port=args.port,
        front_egress_ip=args.front_egress_ip,
        xhttp_path=path,
        client_id=client_id,
        label=args.label,
        expected_egress_ip=args.expected_egress_ip or args.public_address,
        tls_fingerprint=args.tls_fingerprint,
    ).validate()
    _show_plan("План выхода", build_exit_plan(desired, layout))
    if not args.apply:
        print("\nПлан завершён; изменений нет. Добавьте --apply и подтверждение.")
        return 0
    _confirm_apply("EXIT", args.confirm)
    apply_exit(desired, layout=layout)
    print(f"Handoff: {layout.handoff}")
    return 0


def _frontend_ips_from_args(args: argparse.Namespace) -> tuple[str, str]:
    legacy = getattr(args, "front_public_ip", None)
    client_connect_ip = getattr(args, "client_connect_ip", None) or legacy
    dns_ipv4 = getattr(args, "dns_ipv4", None) or legacy
    if not client_connect_ip or not dns_ipv4:
        raise InstallerError(
            "Для frontend нужны отдельные --client-connect-ip и --dns-ipv4"
        )
    return validate_ipv4(client_connect_ip), validate_ipv4(dns_ipv4)


def _front_from_args(args: argparse.Namespace) -> int:
    handoff = Handoff.from_dict(load_json(Path(args.handoff)))
    client_connect_ip, dns_ipv4 = _frontend_ips_from_args(args)
    tls_mode, pinned_peer_cert_sha256 = validate_front_tls(
        args.tls_mode, args.tls_cert_sha256
    )
    desired = FrontDesired(
        domain=args.domain,
        client_connect_ip=client_connect_ip,
        dns_ipv4=dns_ipv4,
        sftp_host=args.sftp_host,
        sftp_port=args.sftp_port,
        sftp_user=args.sftp_user,
        document_root=args.document_root,
        ssh_host_key_sha256=args.fingerprint,
        exit_address=handoff.exit_address,
        exit_port=handoff.exit_port,
        xhttp_path=handoff.xhttp_path,
        placeholder_mode=args.placeholder,
        tls_mode=tls_mode,
        pinned_peer_cert_sha256=pinned_peer_cert_sha256,
    ).validate()
    client_handoff = handoff.with_pinned_peer_cert(pinned_peer_cert_sha256)
    _show_plan("План frontend", build_front_plan(desired))
    if not args.apply:
        print("\nПлан завершён; изменений нет. Добавьте --apply и подтверждение.")
        return 0
    _ack_provider(args.ack_provider_rules)
    _confirm_apply(desired.domain, args.confirm)
    _require_linux_apply()
    if args.auth_method == "key":
        auth = SSHAuth("key", private_key=args.identity).validate()
    else:
        if not sys.stdin.isatty():
            raise InstallerError(
                "Password auth разрешён только в интерактивном терминале"
            )
        auth = SSHAuth(
            "password", password=getpass.getpass("SFTP password: ")
        ).validate()
    state_dir = (
        Path(args.state_dir).expanduser().resolve()
        if args.state_dir
        else _default_state(desired.domain)
    )
    result = _apply_front_and_issue(
        desired=desired,
        auth=auth,
        state_dir=state_dir,
        handoff=client_handoff,
        layout=Layout(root=state_dir / "probe-runtime"),
        firewall_supplied=args.ack_firewall,
    )
    _print_front_result(result)
    return 0


def _doctor_from_args(args: argparse.Namespace) -> int:
    checks: list[Check] = []
    if args.scope in {"front", "full"}:
        if (
            not args.domain
            or not args.path
            or not args.client_connect_ip
            or not args.dns_ipv4
        ):
            raise InstallerError(
                "Для doctor front нужны --domain, --path, "
                "--client-connect-ip и --dns-ipv4"
            )
        _, pinned_peer_cert_sha256 = validate_front_tls(
            args.tls_mode, args.tls_cert_sha256
        )
        checks.extend(
            doctor_front(
                normalize_domain(args.domain),
                validate_xhttp_path(args.path),
                client_connect_ip=validate_ipv4(args.client_connect_ip),
                dns_ipv4=validate_ipv4(args.dns_ipv4),
                pinned_peer_cert_sha256=pinned_peer_cert_sha256,
            )
        )
    if args.scope in {"exit", "full"}:
        checks.extend(doctor_exit())
    return _print_checks(checks)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="xhttp-setup",
        description="Standalone wizard: TLS frontend on shared hosting -> VLESS/XHTTP exit",
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("wizard", help="интерактивное меню")

    exit_parser = sub.add_parser("exit", help="план/настройка изолированного выхода")
    exit_parser.add_argument("--public-address", required=True)
    exit_parser.add_argument("--front-egress-ip", required=True)
    exit_parser.add_argument("--expected-egress-ip")
    exit_parser.add_argument("--port", type=int, default=8083)
    exit_parser.add_argument("--path")
    exit_parser.add_argument(
        "--client-id-file", help="0600-файл с UUID; по умолчанию UUID генерируется"
    )
    exit_parser.add_argument("--label", default="XHTTP TLS")
    exit_parser.add_argument(
        "--tls-fingerprint",
        choices=tuple(sorted(TLS_FINGERPRINTS)),
        default=DEFAULT_TLS_FINGERPRINT,
        help=f"uTLS fingerprint клиента (по умолчанию: {DEFAULT_TLS_FINGERPRINT})",
    )
    exit_parser.add_argument("--apply", action="store_true")
    exit_parser.add_argument("--confirm")

    front_parser = sub.add_parser("front", help="план/настройка существующего сайта")
    front_parser.add_argument("--handoff", required=True)
    front_parser.add_argument("--domain", required=True)
    front_parser.add_argument(
        "--client-connect-ip",
        help="IPv4, который попадёт в адрес VLESS-ссылки",
    )
    front_parser.add_argument(
        "--dns-ipv4",
        help="единственный ожидаемый IPv4 в DNS A домена",
    )
    front_parser.add_argument(
        "--front-public-ip",
        help="устаревший общий IP; используется для обеих ролей, если новые флаги не заданы",
    )
    front_parser.add_argument("--sftp-host", required=True)
    front_parser.add_argument("--sftp-port", type=int, default=22)
    front_parser.add_argument("--sftp-user", required=True)
    front_parser.add_argument("--document-root", required=True)
    front_parser.add_argument("--fingerprint", required=True)
    front_parser.add_argument(
        "--tls-mode",
        choices=tuple(sorted(TLS_MODES)),
        default=TLS_MODE_PUBLIC,
        help="public: системный CA+hostname; pinned: точный SHA-256 leaf-сертификата",
    )
    front_parser.add_argument(
        "--tls-cert-sha256",
        help="64-hex SHA-256 текущего leaf-сертификата; нужен только для --tls-mode pinned",
    )
    front_parser.add_argument(
        "--placeholder", choices=("keep", "neutral"), default="keep"
    )
    front_parser.add_argument(
        "--auth-method", choices=("key", "password"), default="key"
    )
    front_parser.add_argument("--identity", default="~/.ssh/id_ed25519")
    front_parser.add_argument("--state-dir")
    front_parser.add_argument("--ack-provider-rules", action="store_true")
    front_parser.add_argument("--ack-firewall", action="store_true")
    front_parser.add_argument("--apply", action="store_true")
    front_parser.add_argument("--confirm")

    doctor_parser = sub.add_parser("doctor", help="read-only проверки")
    doctor_parser.add_argument(
        "--scope", choices=("front", "exit", "full"), default="full"
    )
    doctor_parser.add_argument("--domain")
    doctor_parser.add_argument("--path")
    doctor_parser.add_argument("--client-connect-ip")
    doctor_parser.add_argument("--dns-ipv4")
    doctor_parser.add_argument(
        "--tls-mode", choices=tuple(sorted(TLS_MODES)), default=TLS_MODE_PUBLIC
    )
    doctor_parser.add_argument("--tls-cert-sha256")
    return parser


def main(argv: list[str] | None = None) -> int:
    if os.name == "nt":
        for stream in (sys.stdout, sys.stderr):
            if hasattr(stream, "reconfigure"):
                stream.reconfigure(encoding="utf-8")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command in {None, "wizard"}:
            return wizard()
        if args.command == "exit":
            return _exit_from_args(args)
        if args.command == "front":
            return _front_from_args(args)
        if args.command == "doctor":
            return _doctor_from_args(args)
        parser.error("unknown command")
        return 2
    except KeyboardInterrupt:
        print("\nОтменено пользователем", file=sys.stderr)
        return 130
    except InstallerError as exc:
        print(f"Ошибка: {exc}", file=sys.stderr)
        return 1
