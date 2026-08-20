from __future__ import annotations

import argparse
import datetime
import getpass
import json
import os
import platform
import re
import secrets
import stat
import sys
import urllib.parse
import uuid
from pathlib import Path
from typing import Callable, TypeVar

from . import __version__
from .credential_parser import (
    ExitCredentials,
    RegRuCredentials,
    parse_exit_credentials,
    parse_regru_credentials,
    validate_regru_panel_url,
)
from .doctor import Check, doctor_exit, doctor_front, e2e_probe
from .errors import InstallerError, ValidationError
from .exit_installer import Layout, apply_exit, build_exit_plan
from .front import (
    FrontRollbackError,
    FrontResult,
    apply_front,
    build_front_plan,
    check_front_dns,
    check_public_tls,
)
from .hidden_input import read_hidden_block
from .ispmanager import inspect_site, panel_login_url_to_endpoint
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
from .osutil import atomic_write_text, exclusive_lock, load_json
from .pc_orchestrator import (
    apply_pc_exit,
    front_for_handoff,
)
from .pc_autosetup import (
    PcBridgeAccess,
    PcBridgeInputs,
    PcUserInputs,
    clear_pending_pc_exit,
    open_pc_bridge,
    prepare_pc_install,
    validate_pc_secret,
    write_pending_pc_exit,
)
from .remote_exit import RemoteExitTarget
from .remote_front import RemoteFrontTarget
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
_MAX_STDIN_SECRET_BYTES = 4095  # SSH transport adds one trailing LF.
_PC_PHASES = frozenset(
    {
        "preparing",
        "front_probe_in_progress",
        "exit_applying",
        "exit_ready",
        "front_in_progress",
        "complete",
    }
)
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


def _disable_pc_core_dumps() -> None:
    """Keep imported credentials out of process core files on Linux/WSL."""

    if platform.system() != "Linux":
        return
    try:
        import resource

        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    except (ImportError, OSError, ValueError):
        raise InstallerError(
            "Не удалось запретить core dump перед вводом credentials"
        ) from None


def _read_password_stdin() -> str:
    """Read one bounded password line from an already encrypted transport."""

    if sys.stdin.isatty():
        raise InstallerError("password-stdin разрешён только через закрытый stdin")
    value = sys.stdin.readline(_MAX_STDIN_SECRET_BYTES + 2)
    if not value:
        raise InstallerError("SFTP password не получен через stdin")
    if value.endswith("\n"):
        value = value[:-1]
    if not value or "\n" in value or "\r" in value or "\x00" in value:
        raise InstallerError(
            "SFTP password через stdin должен быть одной непустой строкой"
        )
    if len(value.encode("utf-8")) > _MAX_STDIN_SECRET_BYTES:
        raise InstallerError("SFTP password через stdin слишком длинный")
    if sys.stdin.read(1):
        raise InstallerError("После SFTP password через stdin получены лишние данные")
    return value


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


def _collect_exit(
    *, remote: bool = False, public_address_default: str | None = None
) -> ExitDesired:
    if remote:
        print("\nВыходной VPS (настройщик подключится с этого компьютера)")
    else:
        print("\nВыходной VPS (настройка выполняется на текущей Linux-машине)")
    public_address = _validated_prompt(
        "Публичный IPv4 выхода", validate_ipv4, public_address_default
    )
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


def _collect_front(
    handoff: Handoff,
    *,
    allow_panel_inspection: bool = True,
    regru_credentials: RegRuCredentials | None = None,
) -> FrontDesired:
    print("\nFrontend shared-hosting")
    domain = _validated_prompt(
        "FQDN/SNI существующего сайта frontend", normalize_domain
    )
    hosting_ipv4_default = (
        regru_credentials.ftp_server_ip if regru_credentials is not None else None
    )
    client_connect_ip = _validated_prompt(
        "IPv4 подключения клиента (адрес в VLESS URI)",
        validate_ipv4,
        hosting_ipv4_default,
    )
    dns_ipv4 = _validated_prompt(
        "IPv4 в DNS A домена (для сайта и ACME)",
        validate_ipv4,
        client_connect_ip,
    )
    tls_mode, pinned_peer_cert_sha256 = _collect_front_tls_policy()
    if regru_credentials is None:
        sftp_host = _validated_prompt("SFTP hostname/IP", validate_host)
        sftp_port = _validated_prompt("SFTP port", validate_port, "22")
        sftp_user = _validated_prompt("SFTP user", validate_ssh_user)
    else:
        parsed_panel_url = urllib.parse.urlsplit(regru_credentials.panel_url)
        if not parsed_panel_url.hostname:  # Already enforced by the strict parser.
            raise InstallerError("В адресе панели REG.RU отсутствует hostname")
        sftp_host = validate_host(parsed_panel_url.hostname)
        sftp_port = 22
        sftp_user = validate_ssh_user(regru_credentials.panel_login)
        print(
            "Из блока REG.RU определены SFTP host, port 22 и основной пользователь. "
            "IP сервера предложен только как входной IPv4 и будет проверен по "
            "DNS/TLS; пароли FTP/MySQL не используются."
        )
    if allow_panel_inspection and _yes_no(
        "Получить document root read-only запросом к ISPmanager API?"
    ):
        if regru_credentials is None:
            endpoint = _prompt(
                "ISPmanager endpoint", f"https://{sftp_host}:1500/ispmgr"
            )
            panel_user = _prompt("ISPmanager user", sftp_user)
            panel_password = getpass.getpass("ISPmanager password (не сохраняется): ")
        else:
            endpoint = panel_login_url_to_endpoint(regru_credentials.panel_url)
            panel_user = regru_credentials.panel_login
            panel_password = regru_credentials.panel_password
            print(
                "Выполняется HTTPS-запрос только к импортированному узлу REG.RU; "
                "операция ISPmanager read-only."
            )
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


def _collect_auth(label: str = "SFTP") -> SSHAuth:
    use_key = _yes_no(
        f"{label}: использовать отдельный SSH-ключ вместо пароля?", default=True
    )
    if use_key:
        identity = _prompt("Путь к приватному ключу", "~/.ssh/id_ed25519")
        return SSHAuth(method="key", private_key=identity).validate()
    password = getpass.getpass(f"{label} password (не сохраняется): ")
    return SSHAuth(method="password", password=password).validate()


def _collect_remote_exit_target() -> RemoteExitTarget:
    print("\nSSH-доступ к выходному VPS")
    return RemoteExitTarget(
        host=_validated_prompt("IP/hostname выхода", validate_host),
        port=_validated_prompt("SSH port выхода", validate_port, "22"),
        user=_validated_prompt("SSH user выхода", validate_ssh_user, "root"),
        host_key_sha256=_validated_prompt(
            "Проверенный SSH host-key fingerprint выхода SHA256",
            validate_fingerprint,
        ),
    ).validate()


def _collect_remote_front_target() -> RemoteFrontTarget:
    print("\nДоверенный российский SSH bridge")
    return RemoteFrontTarget(
        host=_validated_prompt("IP/hostname bridge", validate_host),
        port=_validated_prompt("SSH port bridge", validate_port, "22"),
        user=_validated_prompt("SSH user bridge", validate_ssh_user, "root"),
        host_key_sha256=_validated_prompt(
            "Проверенный SSH host-key fingerprint bridge SHA256",
            validate_fingerprint,
        ),
    ).validate()


def _read_exit_credentials_block(label: str) -> ExitCredentials:
    block = read_hidden_block(label, minimum_data_lines=3)
    try:
        return parse_exit_credentials(block)
    finally:
        block = ""


def _read_regru_credentials_block() -> RegRuCredentials:
    block = read_hidden_block("Блок «Логины и пароли» REG.RU")
    try:
        credentials = parse_regru_credentials(block)
    finally:
        block = ""
    if credentials.panel_login != credentials.ftp_login:
        raise InstallerError(
            "В блоке REG.RU различаются логины панели и FTP; отключите импорт и "
            "укажите проверенные SFTP-данные вручную"
        )
    print(
        "Блок REG.RU распознан. Пароль панели получен скрыто; данные FTP/MySQL "
        "не будут использоваться для входа."
    )
    return credentials


def _collect_pc_exit_access() -> tuple[RemoteExitTarget, SSHAuth | None]:
    if not _yes_no(
        "Вставить готовый блок выхода (IPv4, root, password)?", default=True
    ):
        return _collect_remote_exit_target(), None
    credentials = _read_exit_credentials_block("Три строки данных выходного VPS")
    try:
        target = RemoteExitTarget(
            host=credentials.ip,
            port=_validated_prompt("SSH port выхода", validate_port, "22"),
            user=credentials.username,
            host_key_sha256=_validated_prompt(
                "Проверенный SSH host-key fingerprint выхода SHA256",
                validate_fingerprint,
            ),
        ).validate()
        auth = SSHAuth(method="password", password=credentials.password).validate()
    finally:
        credentials = None
    print("Блок выхода распознан; root password получен скрыто.")
    return target, auth


def _collect_pc_minimal_inputs() -> PcUserInputs:
    """Collect only credentials and the domain; everything else is discovered."""

    print(
        "\nВведите только данные доступа. Пароли вводятся скрыто и не сохраняются."
    )
    exit_host = _validated_prompt("IPv4 выходного сервера", validate_ipv4)
    exit_port = _validated_prompt("SSH port выхода", validate_port, "22")
    exit_user = _validated_prompt("SSH login выхода", validate_ssh_user, "root")
    exit_password = _validated_secret_prompt(
        "SSH password выхода: ", "SSH password выхода"
    )
    bridge: PcBridgeInputs | None = None
    if _yes_no("Использовать мост для входа?", default=False):
        bridge = PcBridgeInputs(
            host=_validated_prompt("IPv4 моста", validate_ipv4),
            user=_validated_prompt("SSH login моста", validate_ssh_user, "root"),
            password=_validated_secret_prompt(
                "SSH password моста: ", "SSH password моста"
            ),
        ).validate()
    panel_url = _validated_prompt(
        "HTTPS-адрес панели REG.RU (например https://vip123.hosting.reg.ru:1500/)",
        validate_regru_panel_url,
    )
    panel_user = _validated_prompt("Логин REG.RU", validate_ssh_user)
    panel_password = _validated_secret_prompt(
        "Пароль панели REG.RU: ", "Пароль панели REG.RU"
    )
    front_connect_ip = _validated_prompt(
        "IPv4 подключения REG.RU (поле «IP-адрес сервера»)", validate_ipv4
    )
    domain = _validated_prompt("Домен frontend", normalize_domain)
    return PcUserInputs(
        exit_host=exit_host,
        exit_port=exit_port,
        exit_user=exit_user,
        exit_password=exit_password,
        panel_url=panel_url,
        panel_user=panel_user,
        panel_password=panel_password,
        front_connect_ip=front_connect_ip,
        domain=domain,
        bridge=bridge,
    ).validate()


def _validated_secret_prompt(prompt: str, label: str) -> str:
    while True:
        try:
            return validate_pc_secret(getpass.getpass(prompt), label)
        except InstallerError as exc:
            print(f"Ошибка: {exc}", file=sys.stderr)


def _collect_pc_bridge_access() -> tuple[RemoteFrontTarget, SSHAuth | None]:
    if not _yes_no(
        "Вставить готовый блок российского bridge (IPv4, root, password)?",
        default=True,
    ):
        return _collect_remote_front_target(), None
    credentials = _read_exit_credentials_block("Три строки данных российского bridge")
    try:
        target = RemoteFrontTarget(
            host=credentials.ip,
            port=_validated_prompt("SSH port bridge", validate_port, "22"),
            user=credentials.username,
            host_key_sha256=_validated_prompt(
                "Проверенный SSH host-key fingerprint bridge SHA256",
                validate_fingerprint,
            ),
        ).validate()
        auth = SSHAuth(method="password", password=credentials.password).validate()
    finally:
        credentials = None
    print("Блок bridge распознан; root password получен скрыто.")
    return target, auth


def _collect_regru_credentials_import() -> RegRuCredentials | None:
    if not _yes_no("Вставить готовый блок «Логины и пароли» REG.RU?", default=True):
        return None
    return _read_regru_credentials_block()


def _validate_bridge_sftp_password(password: str) -> str:
    if (
        not password
        or len(password.encode("utf-8")) > _MAX_STDIN_SECRET_BYTES
        or any(char in password for char in "\r\n\x00")
    ):
        raise InstallerError("SFTP password нельзя безопасно передать одной строкой")
    return password


def _collect_bridge_sftp_password() -> str:
    return _validate_bridge_sftp_password(
        getpass.getpass(
            "SFTP password frontend для одноразовой передачи через bridge: "
        )
    )


def _installer_pyz_from_runtime() -> Path:
    candidate = Path(sys.argv[0]).expanduser()
    if (
        candidate.suffix == ".pyz"
        and candidate.is_file()
        and not candidate.is_symlink()
    ):
        return candidate.resolve()

    def validate_installer(value: str) -> Path:
        path = Path(value).expanduser()
        if path.suffix != ".pyz" or path.is_symlink() or not path.is_file():
            raise ValidationError("Укажите существующий обычный .pyz-файл")
        return path.resolve()

    return _validated_prompt("Путь к текущему xhttp-setup .pyz", validate_installer)


def _pc_output_dir(domain: str) -> Path:
    return Path.home() / ".local/state/xhttp-setup/pc" / domain


def _read_pc_phase(output_dir: Path) -> str | None:
    if output_dir.is_symlink():
        raise InstallerError("Каталог PC state не может быть symlink")
    path = output_dir / "pc-phase.json"
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError("Не удалось проверить PC phase marker") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise InstallerError("PC phase marker должен быть обычным файлом")
    if metadata.st_size <= 0 or metadata.st_size > 1024:
        raise InstallerError("PC phase marker имеет недопустимый размер")
    if os.name == "posix" and (
        stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.geteuid()
    ):
        raise InstallerError("PC phase marker должен иметь owner и mode 0600")
    try:
        value = json.loads(path.read_text("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallerError("PC phase marker повреждён") from exc
    if (
        not isinstance(value, dict)
        or set(value) != {"schema_version", "phase"}
        or value.get("schema_version") != 1
        or value.get("phase") not in _PC_PHASES
    ):
        raise InstallerError("PC phase marker имеет неожиданную структуру")
    return str(value["phase"])


def _write_pc_phase(output_dir: Path, phase: str) -> None:
    if phase not in _PC_PHASES:
        raise InstallerError("Неизвестная фаза PC wizard")
    atomic_write_text(
        output_dir / "pc-phase.json",
        json.dumps(
            {"schema_version": 1, "phase": phase},
            ensure_ascii=False,
            sort_keys=True,
        )
        + "\n",
        0o600,
    )


def _has_front_rollback_error(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, FrontRollbackError):
            return True
        current = current.__cause__ or current.__context__
    return False


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
    bridge_access: PcBridgeAccess | None = None,
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
            bridge_access=bridge_access,
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

    apply_kwargs: dict[str, object] = {}
    if bridge_access is not None:
        apply_kwargs.update(
            sftp_route=bridge_access.sftp_route,
            https_route=bridge_access.front_route,
        )
    return apply_front(
        desired,
        auth=auth,
        state_dir=state_dir,
        pre_apply=prepare_transaction,
        post_apply=finish_transaction,
        on_failure=record_failure,
        **apply_kwargs,
    )


def _run_probe_and_issue(
    *,
    handoff: Handoff,
    domain: str,
    client_connect_ip: str,
    state_dir: Path,
    layout: Layout,
    bridge_access: PcBridgeAccess | None = None,
) -> None:
    probe_address = client_connect_ip
    probe_port = 443
    if bridge_access is not None:
        probe_address = bridge_access.front_route.connect_host
        probe_port = bridge_access.front_route.connect_port
    probe_kwargs: dict[str, object] = {}
    if bridge_access is not None:
        probe_kwargs["front_port"] = probe_port
    output = e2e_probe(
        handoff=handoff,
        domain=domain,
        front_address=probe_address,
        layout=layout,
        **probe_kwargs,
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


def _run_pc_install(
    *, inputs: PcUserInputs, output_dir: Path, installer_pyz: Path
) -> int:
    initial_phase = _read_pc_phase(output_dir)
    if initial_phase in {
        "front_probe_in_progress",
        "front_in_progress",
    }:
        raise InstallerError(
            "Предыдущий frontend apply был жёстко прерван или его rollback неполон; "
            "автоматическое продолжение остановлено, чтобы не потерять исходный .htaccess"
        )
    prepared = None
    bridge_session = None
    bridge_access = None
    try:
        if inputs.bridge is not None:
            bridge_session, bridge_access = open_pc_bridge(
                inputs,
                progress=lambda message: print(f"\n→ {message}"),
                password_prompt=lambda: _validated_secret_prompt(
                    "SSH password моста не подошёл. Повторите: ",
                    "SSH password моста",
                ),
            )
        prepare_kwargs: dict[str, object] = {}
        if bridge_access is not None:
            prepare_kwargs["bridge_access"] = bridge_access
        prepared = prepare_pc_install(
            inputs,
            output_dir=output_dir,
            progress=lambda message: print(f"\n→ {message}"),
            phase_callback=lambda phase: _write_pc_phase(output_dir, phase),
            exit_password_prompt=lambda: _validated_secret_prompt(
                "SSH password выхода не подошёл. Повторите: ",
                "SSH password выхода",
            ),
            panel_password_prompt=lambda: _validated_secret_prompt(
                "Пароль панели REG.RU не подошёл. Повторите: ",
                "Пароль панели REG.RU",
            ),
            sftp_password_prompt=lambda: _validated_secret_prompt(
                "Пароль SFTP REG.RU (пароль панели не подошёл): ",
                "Пароль SFTP REG.RU",
            ),
            require_exit_recovery=initial_phase
            in {"exit_applying", "exit_ready", "complete"},
            **prepare_kwargs,
        )
        inputs = None
        if prepared.existing_handoff is None:
            print("\n→ Настраиваю защищённый выход")
            write_pending_pc_exit(
                output_dir=output_dir,
                prepared=prepared,
                domain=prepared.desired_front.domain,
            )
            _write_pc_phase(output_dir, "exit_applying")
            exit_result = apply_pc_exit(
                installer_pyz=installer_pyz,
                desired=prepared.desired_exit,
                target=prepared.exit_target,
                auth=prepared.exit_auth,
                output_dir=output_dir,
            )
            handoff = Handoff.from_dict(load_json(exit_result.remote.handoff_path))
        else:
            print("\n→ Использую ранее подтверждённый защищённый выход")
            handoff = prepared.existing_handoff
        _write_pc_phase(output_dir, "exit_ready")
        clear_pending_pc_exit(output_dir)
        desired_front = front_for_handoff(prepared.desired_front, handoff)
        client_handoff = handoff.with_pinned_peer_cert(
            desired_front.pinned_peer_cert_sha256
        )
        print("\n→ Настраиваю frontend и выполняю обязательный E2E")
        front_state = output_dir / "front"
        _write_pc_phase(output_dir, "front_in_progress")
        try:
            front_kwargs: dict[str, object] = {}
            if bridge_access is not None:
                front_kwargs["bridge_access"] = bridge_access
            _apply_front_and_issue(
                desired=desired_front,
                auth=prepared.front_auth,
                state_dir=front_state,
                handoff=client_handoff,
                layout=Layout(root=front_state / "probe-runtime"),
                **front_kwargs,
            )
        except BaseException as exc:
            rollback_incomplete = _has_front_rollback_error(exc)
            if not rollback_incomplete:
                _write_pc_phase(output_dir, "exit_ready")
            print(
                "\nВыход уже защищён UFW, но frontend/E2E не завершён; "
                "client.vless не выдан. Диагностика сохранена в "
                f"{output_dir}",
                file=sys.stderr,
            )
            raise
        _write_pc_phase(output_dir, "complete")
        print("\nГотово: установка и сквозная E2E-проверка завершены.")
    finally:
        if bridge_session is not None:
            bridge_session.close()
        bridge_access = None
        bridge_session = None
        inputs = None
        prepared = None
    return 0


def wizard_pc() -> int:
    """Install both nodes from credentials only; derive every technical value."""

    _require_linux_apply()
    _disable_pc_core_dumps()
    installer_pyz = _installer_pyz_from_runtime()
    print("\nАвтоматическая установка XHTTP с персонального компьютера")
    print(
        "Первый SSH/SFTP-ключ будет принят по TOFU и закреплён. "
        "При последующей смене ключа установка остановится."
    )
    print(PROVIDER_WARNING.rstrip())
    inputs = _collect_pc_minimal_inputs()
    output_dir = _pc_output_dir(inputs.domain)
    try:
        with exclusive_lock(output_dir / "wizard.lock"):
            return _run_pc_install(
                inputs=inputs,
                output_dir=output_dir,
                installer_pyz=installer_pyz,
            )
    finally:
        inputs = None


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
    print("5. Установка exit + frontend с персонального компьютера (Linux/WSL)")
    choice = _prompt("Выберите режим")
    actions = {
        "1": wizard_full,
        "2": wizard_exit,
        "3": wizard_front,
        "4": wizard_doctor,
        "5": wizard_pc,
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
    check_front_dns(desired.domain, desired.dns_ipv4)
    check_public_tls(
        desired.domain,
        connect_ip=desired.client_connect_ip,
        pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
    )
    _ack_provider(args.ack_provider_rules)
    _confirm_apply(desired.domain, args.confirm)
    _require_linux_apply()
    if args.auth_method == "key":
        auth = SSHAuth("key", private_key=args.identity).validate()
    elif args.auth_method == "password":
        if not sys.stdin.isatty():
            raise InstallerError(
                "Password auth разрешён только в интерактивном терминале"
            )
        auth = SSHAuth(
            "password", password=getpass.getpass("SFTP password: ")
        ).validate()
    else:
        auth = SSHAuth("password", password=_read_password_stdin()).validate()
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
    sub.add_parser(
        "pc",
        help="exit + frontend с этого Linux/WSL-компьютера",
    )

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
        "--auth-method",
        choices=("key", "password", "password-stdin"),
        default="key",
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
        if args.command == "pc":
            return wizard_pc()
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
