from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import socket
import ssl
import stat
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass
from pathlib import Path

from .errors import InstallerError, VerificationError
from .models import ExitDesired, Handoff
from .osutil import (
    atomic_write,
    atomic_write_text,
    ensure_dir,
    exclusive_lock,
    load_json,
    run,
    sha256_file,
)
from .render import pretty_json, render_xray_server_config

try:
    import grp
    import pwd
except ImportError:  # pragma: no cover - Windows can still run pure planning/help
    grp = None  # type: ignore[assignment]
    pwd = None  # type: ignore[assignment]


XRAY_VERSION = "26.3.27"
XRAY_RELEASE = f"v{XRAY_VERSION}"
XRAY_ASSETS = {
    "x86_64": (
        "Xray-linux-64.zip",
        "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    ),
    "amd64": (
        "Xray-linux-64.zip",
        "23cd9af937744d97776ee35ecad4972cf4b2109d1e0fe6be9930467608f7c8ae",
    ),
    "aarch64": (
        "Xray-linux-arm64-v8a.zip",
        "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
    ),
    "arm64": (
        "Xray-linux-arm64-v8a.zip",
        "4d30283ae614e3057f730f67cd088a42be6fdf91f8639d82cb69e48cde80413c",
    ),
}


@dataclass(frozen=True)
class Layout:
    root: Path = Path("/")

    @property
    def etc(self) -> Path:
        return self.root / "etc/xhttp-setup"

    @property
    def config(self) -> Path:
        return self.etc / "xray.json"

    @property
    def state(self) -> Path:
        return self.root / "var/lib/xhttp-setup"

    @property
    def secrets(self) -> Path:
        return self.state / "secrets.json"

    @property
    def handoff(self) -> Path:
        return self.state / "handoff.json"

    @property
    def receipt(self) -> Path:
        return self.state / "current.json"

    @property
    def lock(self) -> Path:
        return self.state / "lock"

    @property
    def binary_dir(self) -> Path:
        return self.root / f"opt/xhttp-setup/xray/v{XRAY_VERSION}"

    @property
    def app_dir(self) -> Path:
        return self.root / "opt/xhttp-setup"

    @property
    def xray_root(self) -> Path:
        return self.app_dir / "xray"

    @property
    def binary(self) -> Path:
        return self.binary_dir / "xray"

    @property
    def unit(self) -> Path:
        return self.root / "etc/systemd/system/xhttp-setup-xray.service"

    @property
    def firewall_plan(self) -> Path:
        return self.state / "firewall-plan.txt"


@dataclass(frozen=True)
class _FileSnapshot:
    data: bytes
    mode: int
    uid: int
    gid: int


def build_exit_plan(desired: ExitDesired, layout: Layout) -> list[str]:
    desired = desired.validate()
    return [
        f"Установить Xray v{XRAY_VERSION} с закреплённым SHA-256 в {layout.binary_dir}",
        f"Создать изолированный сервис xhttp-setup-xray на 0.0.0.0:{desired.listen_port}",
        f"Записать managed-конфиг {layout.config}",
        "Включить VLESS Encryption; TLS завершает frontend на 443",
        f"Сформировать firewall-план: разрешить {desired.front_egress_ip}/32 -> TCP {desired.listen_port}",
        "Не изменять существующий xray.service, Docker, sysctl и default policy firewall",
    ]


def _download(url: str, destination: Path) -> None:
    parsed = urllib.parse.urlsplit(url)
    expected_prefix = f"/XTLS/Xray-core/releases/download/{XRAY_RELEASE}/"
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or not parsed.path.startswith(expected_prefix)
    ):
        raise InstallerError(
            "Разрешено скачивание Xray только из закреплённого GitHub release"
        )
    request = urllib.request.Request(url, headers={"User-Agent": "xhttp-setup/0.1"})
    context = ssl.create_default_context()
    try:
        with urllib.request.urlopen(request, context=context, timeout=60) as response:
            if response.geturl().split(":", 1)[0] != "https":
                raise InstallerError("Скачивание Xray было перенаправлено не на HTTPS")
            with destination.open("wb") as output:
                shutil.copyfileobj(response, output)
    except (OSError, urllib.error.URLError) as exc:
        raise InstallerError(f"Не удалось скачать Xray: {exc}") from exc


def _safe_extract(zip_path: Path, destination: Path) -> None:
    with zipfile.ZipFile(zip_path) as archive:
        required = {"xray", "geoip.dat", "geosite.dat"}
        names = set(archive.namelist())
        if not required.issubset(names):
            raise InstallerError("Архив Xray не содержит обязательные файлы")
        for name in required:
            info = archive.getinfo(name)
            if info.is_dir() or "/" in name or "\\" in name:
                raise InstallerError("Небезопасная структура архива Xray")
            target = destination / name
            with archive.open(info) as source, target.open("wb") as output:
                shutil.copyfileobj(source, output)


def _lstat_optional(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError(f"Не удалось проверить metadata {path}: {exc}") from exc


def _assert_directory_metadata(path: Path, *, mode: int, uid: int, gid: int) -> None:
    file_stat = _lstat_optional(path)
    if file_stat is None:
        raise InstallerError(f"Managed-каталог отсутствует: {path}")
    if (
        not stat.S_ISDIR(file_stat.st_mode)
        or file_stat.st_uid != uid
        or file_stat.st_gid != gid
        or stat.S_IMODE(file_stat.st_mode) != mode
    ):
        raise InstallerError(
            f"Небезопасные type/owner/mode managed-каталога {path}; "
            "автоматический chmod/chown запрещён"
        )


def _assert_directory_group_transition(
    path: Path, *, mode: int, uid: int, allowed_gids: set[int]
) -> None:
    file_stat = _lstat_optional(path)
    if file_stat is None:
        raise InstallerError(f"Managed-каталог отсутствует: {path}")
    if (
        not stat.S_ISDIR(file_stat.st_mode)
        or file_stat.st_uid != uid
        or file_stat.st_gid not in allowed_gids
        or stat.S_IMODE(file_stat.st_mode) != mode
    ):
        raise InstallerError(
            f"Небезопасный owner/mode managed-каталога {path}; "
            "автоматический захват namespace запрещён"
        )


def _assert_regular_file_metadata(path: Path, *, mode: int, uid: int, gid: int) -> None:
    file_stat = _lstat_optional(path)
    if file_stat is None:
        raise InstallerError(f"Managed-файл отсутствует: {path}")
    if (
        not stat.S_ISREG(file_stat.st_mode)
        or file_stat.st_uid != uid
        or file_stat.st_gid != gid
        or stat.S_IMODE(file_stat.st_mode) != mode
    ):
        raise InstallerError(
            f"Небезопасные type/owner/mode managed-файла {path}; "
            "автоматический chmod/chown запрещён"
        )


def _verify_installed_xray(
    layout: Layout,
    *,
    architecture: str,
    asset: str,
    expected_sha256: str,
) -> None:
    strict_root = layout.root == Path("/")
    if strict_root:
        for directory in (layout.app_dir, layout.xray_root, layout.binary_dir):
            _assert_directory_metadata(directory, mode=0o755, uid=0, gid=0)
        for path, mode in (
            (layout.binary_dir / "manifest.json", 0o644),
            (layout.binary, 0o755),
            (layout.binary_dir / "geoip.dat", 0o644),
            (layout.binary_dir / "geosite.dat", 0o644),
        ):
            _assert_regular_file_metadata(path, mode=mode, uid=0, gid=0)
        archive_checksum = layout.binary_dir / "archive.sha256"
        if _lstat_optional(archive_checksum) is not None:
            _assert_regular_file_metadata(archive_checksum, mode=0o644, uid=0, gid=0)
            try:
                checksum_text = archive_checksum.read_text("utf-8")
            except OSError as exc:
                raise InstallerError(
                    f"Не удалось прочитать {archive_checksum}: {exc}"
                ) from exc
            if checksum_text != expected_sha256 + "\n":
                raise InstallerError("Повреждён archive.sha256 managed Xray")

    manifest_path = layout.binary_dir / "manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise InstallerError("Manifest managed Xray должен быть обычным файлом")
    manifest = load_json(manifest_path)
    if (
        manifest.get("version") != XRAY_VERSION
        or manifest.get("architecture") != architecture
        or manifest.get("archive") != asset
        or manifest.get("archive_sha256") != expected_sha256
    ):
        raise InstallerError("Managed Xray имеет неожиданный release manifest")
    files = manifest.get("files")
    if not isinstance(files, dict):
        raise InstallerError("Повреждён manifest managed Xray")
    for name in ("xray", "geoip.dat", "geosite.dat"):
        target = layout.binary_dir / name
        if (
            target.is_symlink()
            or not target.is_file()
            or not isinstance(files.get(name), str)
            or files[name] != sha256_file(target)
        ):
            raise InstallerError(
                f"Managed Xray {name} изменён после установки; автоматический запуск запрещён"
            )


def install_xray_binary(layout: Layout) -> None:
    architecture = platform.machine().lower()
    if architecture not in XRAY_ASSETS:
        raise InstallerError(f"Архитектура {architecture!r} пока не поддерживается")
    asset, expected_sha256 = XRAY_ASSETS[architecture]
    manifest_path = layout.binary_dir / "manifest.json"
    strict_root = layout.root == Path("/")
    if strict_root:
        for directory in (layout.app_dir, layout.xray_root, layout.binary_dir):
            if _lstat_optional(directory) is not None:
                _assert_directory_metadata(directory, mode=0o755, uid=0, gid=0)
    if _lstat_optional(manifest_path) is not None:
        _verify_installed_xray(
            layout,
            architecture=architecture,
            asset=asset,
            expected_sha256=expected_sha256,
        )
        return
    ensure_dir(layout.app_dir, 0o755)
    ensure_dir(layout.xray_root, 0o755)
    ensure_dir(layout.binary_dir, 0o755)
    with tempfile.TemporaryDirectory(prefix="xhttp-setup-xray-") as temp:
        temp_dir = Path(temp)
        archive = temp_dir / asset
        url = f"https://github.com/XTLS/Xray-core/releases/download/{XRAY_RELEASE}/{asset}"
        _download(url, archive)
        actual = sha256_file(archive)
        if actual != expected_sha256:
            raise InstallerError("SHA-256 архива Xray не совпал; установка отменена")
        _safe_extract(archive, temp_dir)
        file_hashes: dict[str, str] = {}
        for name, mode in (
            ("xray", 0o755),
            ("geoip.dat", 0o644),
            ("geosite.dat", 0o644),
        ):
            data = (temp_dir / name).read_bytes()
            atomic_write(layout.binary_dir / name, data, mode)
            file_hashes[name] = hashlib.sha256(data).hexdigest()
        atomic_write_text(
            layout.binary_dir / "archive.sha256", expected_sha256 + "\n", 0o644
        )
        atomic_write_text(
            manifest_path,
            pretty_json(
                {
                    "version": XRAY_VERSION,
                    "architecture": architecture,
                    "archive": asset,
                    "archive_sha256": expected_sha256,
                    "files": file_hashes,
                }
            ),
            0o644,
        )
    _verify_installed_xray(
        layout,
        architecture=architecture,
        asset=asset,
        expected_sha256=expected_sha256,
    )


def _parse_vlessenc(output: str) -> tuple[str, str]:
    matches = re.findall(
        r'"decryption"\s*:\s*"([^"]+)"\s*\r?\n"encryption"\s*:\s*"([^"]+)"',
        output,
    )
    if not matches:
        raise InstallerError("Xray vlessenc вернул неподдерживаемый формат")
    decryption, encryption = matches[0]
    if len(decryption) < 32 or len(encryption) < 32:
        raise InstallerError("Xray vlessenc вернул слишком короткий ключ")
    return decryption, encryption


def _ensure_service_user() -> tuple[int, int]:
    if pwd is None or grp is None:
        raise InstallerError("Создание сервиса поддерживается только на Linux")
    try:
        account = pwd.getpwnam("xhttp-setup")
    except KeyError:
        try:
            grp.getgrnam("xhttp-setup")
        except KeyError:
            pass
        else:
            raise InstallerError(
                "Группа xhttp-setup уже существует без одноимённого service account; "
                "автоматическое использование запрещено"
            ) from None
        run(
            [
                "useradd",
                "--system",
                "--home-dir",
                "/var/lib/xhttp-setup",
                "--shell",
                "/usr/sbin/nologin",
                "--user-group",
                "xhttp-setup",
            ]
        )
        try:
            account = pwd.getpwnam("xhttp-setup")
        except KeyError as exc:
            raise InstallerError(
                "useradd завершился без создания service account xhttp-setup"
            ) from exc
    try:
        group = grp.getgrnam("xhttp-setup")
    except KeyError as exc:
        raise InstallerError(
            "Для service account xhttp-setup отсутствует одноимённая группа"
        ) from exc
    if account.pw_uid == 0 or account.pw_uid >= 1000:
        raise InstallerError(
            "xhttp-setup должен быть непривилегированным системным account с UID 1..999"
        )
    if group.gr_gid == 0 or account.pw_gid != group.gr_gid:
        raise InstallerError(
            "Primary GID xhttp-setup не совпадает с одноимённой непривилегированной группой"
        )
    if account.pw_dir != "/var/lib/xhttp-setup":
        raise InstallerError(
            "Service account xhttp-setup имеет неожиданный home directory"
        )
    if account.pw_shell not in {"/usr/sbin/nologin", "/sbin/nologin"}:
        raise InstallerError(
            "Service account xhttp-setup должен использовать nologin shell"
        )
    try:
        all_group_ids = set(os.getgrouplist(account.pw_name, account.pw_gid))
    except (AttributeError, OSError) as exc:
        raise InstallerError(
            "Не удалось безопасно проверить supplementary groups account xhttp-setup"
        ) from exc
    if all_group_ids != {account.pw_gid}:
        raise InstallerError(
            "Service account xhttp-setup состоит в дополнительных группах; "
            "автоматический запуск запрещён"
        )
    return account.pw_uid, account.pw_gid


def _verify_service_namespace(layout: Layout, *, has_managed_unit: bool) -> None:
    result = run(
        [
            "systemctl",
            "show",
            "xhttp-setup-xray.service",
            "--property=LoadState",
            "--property=FragmentPath",
            "--no-pager",
        ],
        check=False,
    )
    if result.returncode != 0:
        raise InstallerError(
            "Не удалось проверить namespace systemd unit xhttp-setup-xray.service"
        )

    properties: dict[str, str] = {}
    expected_keys = {"LoadState", "FragmentPath"}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if not separator or key not in expected_keys:
            continue
        if key in properties:
            raise InstallerError(
                "systemctl show вернул неоднозначные свойства managed unit"
            )
        properties[key] = value.strip()
    if set(properties) != expected_keys:
        raise InstallerError(
            "systemctl show не вернул LoadState/FragmentPath managed unit"
        )

    load_state = properties["LoadState"]
    fragment = properties["FragmentPath"]
    if load_state == "not-found":
        if fragment or has_managed_unit:
            raise InstallerError(
                "Состояние systemd namespace не согласовано с managed unit на диске"
            )
        return
    if load_state != "loaded" or not fragment or not has_managed_unit:
        raise InstallerError(
            "Имя xhttp-setup-xray.service уже занято неизвестным или некорректным unit"
        )
    if not os.path.isabs(fragment) or os.path.normpath(fragment) != os.path.normpath(
        str(layout.unit)
    ):
        raise InstallerError(
            f"xhttp-setup-xray.service загружен из чужого FragmentPath: {fragment}"
        )


def _service_unit(layout: Layout) -> str:
    return f"""[Unit]
Description=Managed Xray XHTTP exit
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=xhttp-setup
Group=xhttp-setup
Environment=XRAY_LOCATION_ASSET={layout.binary_dir}
ExecStart={layout.binary} run -c {layout.config}
Restart=on-failure
RestartSec=3s
NoNewPrivileges=true
PrivateDevices=true
PrivateTmp=true
ProtectControlGroups=true
ProtectHome=true
ProtectKernelModules=true
ProtectKernelTunables=true
ProtectSystem=strict
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=true
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
"""


def _check_port_available(port: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("0.0.0.0", port))
        except OSError as exc:
            active = run(["systemctl", "is-active", "xhttp-setup-xray"], check=False)
            if active.returncode != 0:
                raise InstallerError(
                    f"TCP-порт {port} уже занят неизвестным процессом"
                ) from exc


def _firewall_plan(desired: ExitDesired) -> str:
    return f"""# Review before running. Installer intentionally does not reset or enable UFW.
# Public site IP may differ from the real outbound IP of shared hosting.
# Expected frontend egress: {desired.front_egress_ip}
sudo ufw insert 1 allow from {desired.front_egress_ip} to any port {desired.listen_port} proto tcp comment 'xhttp-setup frontend'
sudo ufw insert 2 deny to any port {desired.listen_port} proto tcp comment 'xhttp-setup backend'
sudo ufw status numbered
"""


def _snapshot_optional(path: Path) -> _FileSnapshot | None:
    try:
        file_stat = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError(f"Не удалось прочитать metadata {path}: {exc}") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise InstallerError(f"Managed-путь должен быть обычным файлом: {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InstallerError(
            f"Не удалось прочитать managed-файл {path}: {exc}"
        ) from exc
    return _FileSnapshot(
        data=data,
        mode=stat.S_IMODE(file_stat.st_mode),
        uid=file_stat.st_uid,
        gid=file_stat.st_gid,
    )


def _normalize_managed_file(path: Path, *, mode: int, uid: int, gid: int) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise InstallerError(
            f"Не удалось безопасно открыть managed-файл {path}: {exc}"
        ) from exc
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise InstallerError(f"Managed-путь должен быть обычным файлом: {path}")
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        after = os.fstat(descriptor)
        if (
            after.st_uid != uid
            or after.st_gid != gid
            or stat.S_IMODE(after.st_mode) != mode
        ):
            raise VerificationError(
                f"Не удалось подтвердить owner/mode managed-файла {path}"
            )
    except OSError as exc:
        raise InstallerError(
            f"Не удалось нормализовать owner/mode managed-файла {path}: {exc}"
        ) from exc
    finally:
        os.close(descriptor)


def _requires_atomic_rewrite(
    previous: _FileSnapshot | None,
    expected: bytes,
    *,
    mode: int,
    uid: int,
    gid: int,
) -> bool:
    return previous is None or (
        previous.data != expected
        or previous.mode != mode
        or previous.uid != uid
        or previous.gid != gid
    )


def _snapshot_json_object(path: Path, snapshot: _FileSnapshot) -> dict:
    try:
        value = json.loads(snapshot.data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise InstallerError(f"Не удалось прочитать {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise InstallerError(f"Ожидался JSON object в {path}")
    return value


def _restore_optional(path: Path, previous: _FileSnapshot | None) -> None:
    if previous is None:
        path.unlink(missing_ok=True)
        return
    atomic_write(path, previous.data, previous.mode)
    _normalize_managed_file(
        path,
        mode=previous.mode,
        uid=previous.uid,
        gid=previous.gid,
    )


def _record_rollback_command(command: list[str], errors: list[str]) -> None:
    rendered = " ".join(command)
    try:
        result = run(command, check=False)
    except Exception as exc:
        errors.append(f"{rendered}: {exc}")
        return
    if result.returncode != 0:
        errors.append(rendered)


def apply_exit(desired: ExitDesired, *, layout: Layout | None = None) -> Handoff:
    desired = desired.validate()
    layout = layout or Layout()
    strict_root = layout.root == Path("/")
    if strict_root:
        if platform.system() != "Linux":
            raise InstallerError("Настройка выхода поддерживается только на Linux")
        if os.geteuid() != 0:
            raise InstallerError("Для настройки выхода запустите команду через sudo")
        # The lock itself is state. Establish a root-only directory before
        # exclusive_lock opens any attacker-controlled pathname inside it.
        ensure_dir(layout.state, 0o700)
        _assert_directory_metadata(layout.state, mode=0o700, uid=0, gid=0)
    with exclusive_lock(layout.lock):
        ensure_dir(layout.state, 0o700)
        _uid, gid = _ensure_service_user()
        ensure_dir(layout.etc, 0o750)
        if strict_root:
            _assert_directory_group_transition(
                layout.etc, mode=0o750, uid=0, allowed_gids={0, gid}
            )
            os.chown(layout.etc, 0, gid)
            _assert_directory_metadata(layout.etc, mode=0o750, uid=0, gid=gid)
        else:
            os.chown(layout.etc, 0, gid)
            os.chmod(layout.etc, 0o750)

        managed_paths = (
            layout.secrets,
            layout.config,
            layout.unit,
            layout.handoff,
            layout.receipt,
            layout.firewall_plan,
        )
        for path in managed_paths:
            if path.is_symlink():
                raise InstallerError(f"Managed-файл не может быть symlink: {path}")
        previous = {path: _snapshot_optional(path) for path in managed_paths}
        old_unit_snapshot = previous[layout.unit]
        old_unit = old_unit_snapshot.data if old_unit_snapshot is not None else None
        if old_unit is not None and b"Managed Xray XHTTP exit" not in old_unit:
            raise InstallerError(
                f"{layout.unit} не принадлежит xhttp-setup; автоматическая замена запрещена"
            )
        _verify_service_namespace(layout, has_managed_unit=old_unit is not None)
        _check_port_available(desired.listen_port)
        install_xray_binary(layout)

        secrets_snapshot = previous[layout.secrets]
        if secrets_snapshot is not None:
            secrets_data = _snapshot_json_object(layout.secrets, secrets_snapshot)
            if (
                secrets_data.get("client_id") != desired.client_id
                or secrets_data.get("xhttp_path") != desired.xhttp_path
            ):
                raise InstallerError(
                    "Найдены существующие credentials. Их ротация требует отдельной команды; apply остановлен"
                )
            decryption = str(secrets_data.get("decryption", ""))
            encryption = str(secrets_data.get("encryption", ""))
        else:
            generated = run([str(layout.binary), "vlessenc"])
            decryption, encryption = _parse_vlessenc(generated.stdout)
            secrets_data = {
                "schema_version": 1,
                "client_id": desired.client_id,
                "xhttp_path": desired.xhttp_path,
                "decryption": decryption,
                "encryption": encryption,
            }
        secrets_text = pretty_json(secrets_data)

        # Validate every secret-bearing artifact before changing systemd state.
        handoff = Handoff(
            exit_address=desired.public_address,
            exit_port=desired.listen_port,
            client_id=desired.client_id,
            xhttp_path=desired.xhttp_path,
            encryption=encryption,
            label=desired.label,
            expected_egress_ip=desired.expected_egress_ip,
            tls_fingerprint=desired.tls_fingerprint,
        ).validate()
        config = render_xray_server_config(
            client_id=desired.client_id,
            decryption=decryption,
            port=desired.listen_port,
            path=desired.xhttp_path,
        )
        config_text = pretty_json(config)
        receipt = {
            "schema_version": 1,
            "xray_version": XRAY_VERSION,
            "config_sha256": hashlib.sha256(config_text.encode()).hexdigest(),
            "public_address": desired.public_address,
            "listen_port": desired.listen_port,
            "front_egress_ip": desired.front_egress_ip,
            "expected_egress_ip": desired.expected_egress_ip,
            "xhttp_path_sha256": hashlib.sha256(
                desired.xhttp_path.encode()
            ).hexdigest(),
            "client_id_sha256": hashlib.sha256(desired.client_id.encode()).hexdigest(),
            "service": "xhttp-setup-xray.service",
        }
        receipt_text = pretty_json(receipt)
        firewall_text = _firewall_plan(desired)

        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=layout.state,
            prefix="xray.",
            suffix=".json",
            delete=False,
        ) as candidate:
            candidate.write(config_text)
            candidate_path = Path(candidate.name)
        try:
            os.chmod(candidate_path, 0o600)
            run([str(layout.binary), "run", "-test", "-c", str(candidate_path)])
        finally:
            candidate_path.unlink(missing_ok=True)

        unit_text = _service_unit(layout)
        secrets_bytes = secrets_text.encode("utf-8")
        config_bytes = config_text.encode("utf-8")
        unit_bytes = unit_text.encode("utf-8")
        config_content_changed = (
            previous[layout.config] is None
            or previous[layout.config].data != config_bytes
        )
        unit_content_changed = old_unit != unit_bytes
        secrets_rewrite = _requires_atomic_rewrite(
            secrets_snapshot,
            secrets_bytes,
            mode=0o600,
            uid=0,
            gid=0,
        )
        config_rewrite = _requires_atomic_rewrite(
            previous[layout.config],
            config_bytes,
            mode=0o640,
            uid=0,
            gid=gid,
        )
        unit_rewrite = _requires_atomic_rewrite(
            old_unit_snapshot,
            unit_bytes,
            mode=0o644,
            uid=0,
            gid=0,
        )
        was_active = (
            run(
                ["systemctl", "is-active", "xhttp-setup-xray"], check=False
            ).stdout.strip()
            == "active"
        )
        enabled_probe = run(
            ["systemctl", "is-enabled", "xhttp-setup-xray"], check=False
        )
        was_enabled = enabled_probe.stdout.strip() == "enabled"
        if old_unit is None and (was_active or enabled_probe.returncode == 0):
            raise InstallerError(
                "Обнаружен загруженный или enabled unit xhttp-setup-xray без managed-файла"
            )

        systemd_touched = False
        try:
            if secrets_rewrite:
                atomic_write(layout.secrets, secrets_bytes, 0o600)
            _normalize_managed_file(layout.secrets, mode=0o600, uid=0, gid=0)
            if config_rewrite:
                atomic_write(layout.config, config_bytes, 0o640)
            _normalize_managed_file(layout.config, mode=0o640, uid=0, gid=gid)
            if unit_rewrite:
                atomic_write(layout.unit, unit_bytes, 0o644)
            _normalize_managed_file(layout.unit, mode=0o644, uid=0, gid=0)
            if unit_rewrite:
                systemd_touched = True
                run(["systemctl", "daemon-reload"])
            if not was_enabled:
                systemd_touched = True
                run(["systemctl", "enable", "xhttp-setup-xray"])
            if was_active:
                if config_content_changed or unit_content_changed:
                    systemd_touched = True
                    run(["systemctl", "restart", "xhttp-setup-xray"])
            else:
                systemd_touched = True
                run(["systemctl", "start", "xhttp-setup-xray"])

            deadline = time.monotonic() + 10
            listening = False
            while time.monotonic() < deadline:
                active = run(
                    ["systemctl", "is-active", "xhttp-setup-xray"], check=False
                )
                if active.returncode != 0 or active.stdout.strip() != "active":
                    time.sleep(0.25)
                    continue
                try:
                    with socket.create_connection(
                        ("127.0.0.1", desired.listen_port), timeout=0.5
                    ):
                        listening = True
                        break
                except OSError:
                    time.sleep(0.25)
            if not listening:
                raise VerificationError(
                    "Сервис xhttp-setup-xray не открыл managed TCP-порт за 10 секунд"
                )
            time.sleep(1)
            active = run(["systemctl", "is-active", "xhttp-setup-xray"], check=False)
            if active.returncode != 0 or active.stdout.strip() != "active":
                raise VerificationError("Xray завершился сразу после открытия порта")

            atomic_write_text(layout.handoff, pretty_json(handoff.to_dict()), 0o600)
            atomic_write_text(layout.receipt, receipt_text, 0o600)
            atomic_write_text(layout.firewall_plan, firewall_text, 0o600)
        except Exception as original:
            rollback_errors: list[str] = []

            if systemd_touched:
                _record_rollback_command(
                    ["systemctl", "stop", "xhttp-setup-xray"], rollback_errors
                )
                if old_unit is None:
                    _record_rollback_command(
                        ["systemctl", "disable", "xhttp-setup-xray"],
                        rollback_errors,
                    )
            for path in managed_paths:
                try:
                    _restore_optional(path, previous[path])
                except Exception as rollback_error:
                    rollback_errors.append(f"restore {path}: {rollback_error}")
            if systemd_touched:
                _record_rollback_command(
                    ["systemctl", "daemon-reload"], rollback_errors
                )
                if old_unit is not None:
                    _record_rollback_command(
                        [
                            "systemctl",
                            "enable" if was_enabled else "disable",
                            "xhttp-setup-xray",
                        ],
                        rollback_errors,
                    )
                    _record_rollback_command(
                        [
                            "systemctl",
                            "start" if was_active else "stop",
                            "xhttp-setup-xray",
                        ],
                        rollback_errors,
                    )
            if rollback_errors:
                raise InstallerError(
                    "Применение не удалось, rollback неполон: "
                    + "; ".join(rollback_errors)
                ) from original
            raise
        return handoff


def load_handoff(layout: Layout | None = None) -> Handoff:
    layout = layout or Layout()
    return Handoff.from_dict(load_json(layout.handoff))
