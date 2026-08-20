from __future__ import annotations

import concurrent.futures
import hashlib
import ipaddress
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
import time
import urllib.parse
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .errors import InstallerError, VerificationError
from .credential_parser import validate_regru_panel_url
from .front import FrontRollbackError, https_status
from .front_probe import run_with_temporary_front_route
from .ispmanager import (
    ISPmanagerAuthenticationError,
    inspect_site,
    panel_login_url_to_endpoint,
)
from .models import (
    DEFAULT_TLS_FINGERPRINT,
    ExitDesired,
    FrontDesired,
    Handoff,
    TLS_MODE_PINNED,
)
from .osutil import ensure_dir, load_json, sha256_file
from .remote_exit import RemoteExitTarget
from .ssh_transport import (
    SFTPClient,
    SSHAuth,
    SSHAuthenticationError,
    SSHClient,
    sftp_quote,
)
from .validate import (
    normalize_domain,
    validate_host,
    validate_ipv4,
    validate_port,
    validate_ssh_user,
)


_PROBE_CAPTURE_SECONDS = 25
_PROBE_REQUESTS = 8
_MAX_PASSWORD_ATTEMPTS = 3
_PROBE_PORT_MIN = 20000
_PROBE_PORT_SPAN = 40000
_PROBE_PORT_ATTEMPTS = 24
_MAX_LOCAL_HANDOFF_BYTES = 64 * 1024
_MANAGED_EXIT_HANDOFF = "/var/lib/xhttp-setup/handoff.json"
_MANAGED_EXIT_SERVICE = "xhttp-setup-xray.service"
_PENDING_EXIT_NAME = "pending-exit.json"
_EXIT_DESIRED_PAYLOAD_KEYS = frozenset(
    {
        "public_address",
        "listen_port",
        "front_egress_ip",
        "xhttp_path",
        "client_id",
        "label",
        "expected_egress_ip",
        "tls_fingerprint",
    }
)
_TCPDUMP_SOURCE = re.compile(
    r"\bIP\s+((?:[0-9]{1,3}\.){3}[0-9]{1,3})\.([0-9]{1,5})\s+>"
)
_CAPTURE_SCRIPT = (
    'umask 077; : > "$1"; touch "$1"; '
    'exec timeout --signal=INT 25 tcpdump -nn -l -Q in -i any -c 48 '
    '"tcp dst port $2 and tcp[tcpflags] & tcp-syn != 0 and '
    'tcp[tcpflags] & tcp-ack = 0"'
)


@dataclass(frozen=True)
class PcUserInputs:
    exit_host: str
    exit_port: int
    exit_user: str
    exit_password: str = field(repr=False, compare=False)
    panel_url: str
    panel_user: str
    panel_password: str = field(repr=False, compare=False)
    front_connect_ip: str
    domain: str

    def validate(self) -> "PcUserInputs":
        exit_auth = SSHAuth("password", password=self.exit_password).validate()
        del exit_auth
        panel_password = validate_pc_secret(
            self.panel_password, "Пароль ISPmanager"
        )
        panel_user = validate_ssh_user(self.panel_user)
        return PcUserInputs(
            exit_host=validate_ipv4(self.exit_host),
            exit_port=validate_port(self.exit_port),
            exit_user=validate_ssh_user(self.exit_user),
            exit_password=self.exit_password,
            panel_url=validate_regru_panel_url(self.panel_url),
            panel_user=panel_user,
            panel_password=panel_password,
            front_connect_ip=validate_ipv4(self.front_connect_ip),
            domain=normalize_domain(self.domain),
        )


@dataclass(frozen=True)
class PcPreparedInstall:
    exit_target: RemoteExitTarget
    exit_auth: SSHAuth = field(repr=False, compare=False)
    desired_exit: ExitDesired
    desired_front: FrontDesired
    front_auth: SSHAuth = field(repr=False, compare=False)
    existing_handoff: Handoff | None = field(
        default=None, repr=False, compare=False
    )
    pending_exit_recovery: bool = False


@dataclass(frozen=True)
class PcExitResume:
    desired: ExitDesired
    handoff: Handoff = field(repr=False, compare=False)


def validate_pc_secret(value: str, label: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > 4096
        or any(char in value for char in "\r\n\x00")
    ):
        raise InstallerError(f"{label} должен быть одной непустой строкой")
    return value


def _public_ipv4(value: str, *, label: str) -> str:
    address = validate_ipv4(value)
    if not ipaddress.ip_address(address).is_global:
        raise VerificationError(f"{label} не является публичным IPv4")
    return address


def _remote_port_is_free(ssh: SSHClient, port: int) -> bool:
    result = ssh.command(
        ["ss", "-H", "-lnt", f"sport = :{validate_port(port)}"],
        check=False,
        timeout=20,
    )
    if result.returncode != 0:
        raise InstallerError("Не удалось проверить свободный TCP-порт на exit")
    return not result.stdout.strip()


def _select_front_probe_port(
    ssh: SSHClient, *, backend_port: int, ssh_port: int, seed: str
) -> int:
    excluded = {validate_port(backend_port), validate_port(ssh_port)}
    start = int.from_bytes(
        hashlib.sha256(seed.encode("utf-8")).digest()[:8], "big"
    ) % _PROBE_PORT_SPAN
    for offset in range(_PROBE_PORT_ATTEMPTS):
        candidate = _PROBE_PORT_MIN + ((start + offset) % _PROBE_PORT_SPAN)
        if candidate in excluded:
            continue
        if _remote_port_is_free(ssh, candidate):
            return candidate
    raise InstallerError("Не удалось выбрать свободный временный TCP-порт frontend probe")


def _front_rollback_incomplete(error: BaseException) -> bool:
    seen: set[int] = set()
    current: BaseException | None = error
    while current is not None and id(current) not in seen:
        seen.add(id(current))
        if isinstance(current, FrontRollbackError):
            return True
        current = current.__cause__ or current.__context__
    return False


def _validated_local_resume_artifact(path: Path, *, label: str) -> Path | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError(f"Не удалось проверить локальный {label}") from exc
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise InstallerError(f"Локальный {label} должен быть обычным файлом")
    if metadata.st_size <= 0 or metadata.st_size > _MAX_LOCAL_HANDOFF_BYTES:
        raise InstallerError(f"Некорректный размер локального {label}")
    if os.name == "posix" and (
        stat.S_IMODE(metadata.st_mode) != 0o600 or metadata.st_uid != os.geteuid()
    ):
        raise InstallerError(f"Локальный {label} должен иметь owner и mode 0600")
    return path


def _exit_desired_payload(desired: ExitDesired) -> dict[str, object]:
    desired = desired.validate()
    return {
        "public_address": desired.public_address,
        "listen_port": desired.listen_port,
        "front_egress_ip": desired.front_egress_ip,
        "xhttp_path": desired.xhttp_path,
        "client_id": desired.client_id,
        "label": desired.label,
        "expected_egress_ip": desired.expected_egress_ip,
        "tls_fingerprint": desired.tls_fingerprint,
    }


def write_pending_pc_exit(
    *, output_dir: Path, prepared: PcPreparedInstall, domain: str
) -> Path:
    """Persist the exact private exit intent before the remote transaction."""

    target = prepared.exit_target.validate()
    payload = {
        "schema_version": 1,
        "domain": normalize_domain(domain),
        "exit_target": {
            "host": target.host,
            "port": target.port,
            "user": target.user,
            "host_key_sha256": target.host_key_sha256,
        },
        "desired_exit": _exit_desired_payload(prepared.desired_exit),
    }
    path = output_dir / _PENDING_EXIT_NAME
    serialized = (
        json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n"
    ).encode("utf-8")
    ensure_dir(output_dir, 0o700)
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{_PENDING_EXIT_NAME}.", dir=output_dir
        )
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            existing = _validated_local_resume_artifact(
                path, label="pending exit marker"
            )
            if existing is None:  # pragma: no cover - FileExists invariant
                raise InstallerError("Pending exit marker исчез во время проверки")
            try:
                existing_payload = existing.read_bytes()
            except OSError as exc:
                raise InstallerError(
                    "Не удалось проверить существующий pending exit marker"
                ) from exc
            if existing_payload != serialized:
                raise InstallerError(
                    "Pending exit marker уже закрепляет другую транзакцию"
                )
            return existing
        directory_fd = os.open(output_dir, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except InstallerError:
        raise
    except OSError as exc:
        raise InstallerError("Не удалось записать pending exit marker") from exc
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
    return path


def clear_pending_pc_exit(output_dir: Path) -> None:
    path = _validated_local_resume_artifact(
        output_dir / _PENDING_EXIT_NAME, label="pending exit marker"
    )
    if path is None:
        return
    try:
        path.unlink()
    except OSError as exc:
        raise InstallerError("Не удалось удалить подтверждённый pending exit marker") from exc
    if path.exists() or path.is_symlink():
        raise InstallerError("Pending exit marker остался после удаления")


def _load_pending_pc_exit(
    *,
    output_dir: Path,
    inputs: PcUserInputs,
    exit_target: RemoteExitTarget,
) -> ExitDesired | None:
    path = _validated_local_resume_artifact(
        output_dir / _PENDING_EXIT_NAME, label="pending exit marker"
    )
    if path is None:
        return None
    value = load_json(path)
    if set(value) != {"schema_version", "domain", "exit_target", "desired_exit"}:
        raise InstallerError("Pending exit marker имеет неожиданную структуру")
    if value.get("schema_version") != 1 or value.get("domain") != inputs.domain:
        raise InstallerError("Pending exit marker относится к другой установке")
    target_payload = value.get("exit_target")
    if not isinstance(target_payload, dict) or set(target_payload) != {
        "host",
        "port",
        "user",
        "host_key_sha256",
    }:
        raise InstallerError("Pending exit target повреждён")
    try:
        pending_target = RemoteExitTarget(**target_payload).validate()
    except (TypeError, InstallerError) as exc:
        raise InstallerError("Pending exit target повреждён") from exc
    if pending_target != exit_target:
        raise InstallerError("Pending exit marker относится к другому SSH endpoint")
    desired_payload = value.get("desired_exit")
    if (
        not isinstance(desired_payload, dict)
        or set(desired_payload) != _EXIT_DESIRED_PAYLOAD_KEYS
    ):
        raise InstallerError("Pending exit desired state повреждён")
    try:
        desired = ExitDesired(**desired_payload).validate()
    except (TypeError, InstallerError) as exc:
        raise InstallerError("Pending exit desired state повреждён") from exc
    if desired.public_address != inputs.exit_host or desired.listen_port != 8083:
        raise InstallerError("Pending exit desired state относится к другому серверу")
    return desired


def _remote_managed_file(
    ssh: SSHClient,
    *,
    path: str,
    include_content: bool = False,
    expected_owner: str = "root",
    expected_group: str = "root",
    expected_mode: str = "600",
) -> tuple[str, str | None]:
    metadata = ssh.command(
        [
            "env",
            "LC_ALL=C",
            "LANG=C",
            "stat",
            "--format=%U:%G:%a:%F:%s",
            "--",
            path,
        ],
        check=False,
        timeout=30,
    )
    fields = metadata.stdout.strip().split(":", 4)
    if (
        metadata.returncode != 0
        or len(fields) != 5
        or fields[:4]
        != [expected_owner, expected_group, expected_mode, "regular file"]
    ):
        raise InstallerError("Remote managed-файл имеет неожиданные metadata")
    try:
        size = int(fields[4])
    except ValueError as exc:
        raise InstallerError("Remote managed-файл имеет неожиданный размер") from exc
    if size <= 0 or size > _MAX_LOCAL_HANDOFF_BYTES:
        raise InstallerError("Remote managed-файл имеет неожиданный размер")

    digest = ssh.command(
        ["sha256sum", "--", path],
        check=False,
        timeout=30,
    )
    digest_fields = digest.stdout.strip().split()
    if (
        digest.returncode != 0
        or len(digest_fields) != 2
        or not re.fullmatch(r"[0-9a-f]{64}", digest_fields[0])
        or digest_fields[1].lstrip("*") != path
    ):
        raise InstallerError("Не удалось подтвердить SHA-256 remote managed-файла")
    content: str | None = None
    if include_content:
        payload = ssh.command(["cat", "--", path], check=False, timeout=30)
        if payload.returncode != 0 or len(payload.stdout.encode("utf-8")) != size:
            raise InstallerError("Не удалось прочитать remote managed-файл")
        content = payload.stdout
    return digest_fields[0], content


def inspect_existing_pc_exit(
    ssh: SSHClient,
    *,
    output_dir: Path,
    exit_address: str,
    ssh_port: int,
    pending_desired: ExitDesired | None = None,
) -> PcExitResume | None:
    """Verify and reconstruct only an exit previously completed by this PC flow."""

    from .exit_installer import XRAY_VERSION, _firewall_plan
    from .exit_network import ExitNetworkProfile
    from .remote_network import preflight_remote_exit_network
    from .remote_prepare import measure_remote_exit_egress

    local_handoff = _validated_local_resume_artifact(
        output_dir / "handoff.json", label="handoff для продолжения"
    )
    local_firewall = _validated_local_resume_artifact(
        output_dir / "firewall-plan.txt", label="firewall-plan для продолжения"
    )
    expected_address = validate_ipv4(exit_address)
    if validate_port(ssh_port) == 8083:
        raise InstallerError("Backend-порт совпадает с SSH-портом выхода")
    if local_handoff is None and local_firewall is None:
        return None
    if local_handoff is None or local_firewall is None:
        if pending_desired is None:
            raise InstallerError("Локальные exit-артефакты для продолжения неполны")
        pending_desired = pending_desired.validate()
        if (
            pending_desired.public_address != expected_address
            or pending_desired.listen_port != 8083
        ):
            raise InstallerError(
                "Pending exit не соответствует неполным локальным артефактам"
            )
        if local_handoff is not None:
            partial_handoff = Handoff.from_dict(load_json(local_handoff))
            if (
                partial_handoff.exit_address != pending_desired.public_address
                or partial_handoff.exit_port != pending_desired.listen_port
                or partial_handoff.client_id != pending_desired.client_id
                or partial_handoff.xhttp_path != pending_desired.xhttp_path
                or partial_handoff.label != pending_desired.label
                or partial_handoff.expected_egress_ip
                != pending_desired.expected_egress_ip
                or partial_handoff.tls_fingerprint
                != pending_desired.tls_fingerprint
                or partial_handoff.pinned_peer_cert_sha256 is not None
            ):
                raise InstallerError(
                    "Неполный handoff не соответствует pending exit"
                )
        if local_firewall is not None:
            try:
                partial_firewall = local_firewall.read_text("utf-8")
            except (OSError, UnicodeError) as exc:
                raise InstallerError(
                    "Неполный firewall-plan не является UTF-8"
                ) from exc
            if partial_firewall != _firewall_plan(pending_desired):
                raise InstallerError(
                    "Неполный firewall-plan не соответствует pending exit"
                )
        return None

    handoff = Handoff.from_dict(load_json(local_handoff))
    if handoff.exit_address != expected_address or handoff.exit_port != 8083:
        raise InstallerError("Локальный handoff относится к другому exit")

    remote_handoff_sha, _ = _remote_managed_file(
        ssh, path=_MANAGED_EXIT_HANDOFF
    )
    remote_firewall_sha, _ = _remote_managed_file(
        ssh, path="/var/lib/xhttp-setup/firewall-plan.txt"
    )
    _, receipt_text = _remote_managed_file(
        ssh, path="/var/lib/xhttp-setup/current.json", include_content=True
    )
    if (
        remote_handoff_sha != sha256_file(local_handoff)
        or remote_firewall_sha != sha256_file(local_firewall)
    ):
        raise InstallerError("Локальные и remote exit-артефакты различаются")
    try:
        receipt = json.loads(receipt_text or "")
    except json.JSONDecodeError as exc:
        raise InstallerError("Remote current.json повреждён") from exc
    expected_keys = {
        "schema_version",
        "xray_version",
        "config_sha256",
        "public_address",
        "listen_port",
        "front_egress_ip",
        "expected_egress_ip",
        "xhttp_path_sha256",
        "client_id_sha256",
        "service",
    }
    if not isinstance(receipt, dict) or set(receipt) != expected_keys:
        raise InstallerError("Remote current.json имеет неожиданную структуру")
    if (
        receipt.get("schema_version") != 1
        or receipt.get("xray_version") != XRAY_VERSION
        or receipt.get("service") != _MANAGED_EXIT_SERVICE
        or receipt.get("public_address") != expected_address
        or receipt.get("listen_port") != handoff.exit_port
        or receipt.get("expected_egress_ip") != handoff.expected_egress_ip
        or receipt.get("xhttp_path_sha256")
        != hashlib.sha256(handoff.xhttp_path.encode()).hexdigest()
        or receipt.get("client_id_sha256")
        != hashlib.sha256(handoff.client_id.encode()).hexdigest()
    ):
        raise InstallerError("Remote current.json не соответствует handoff")
    config_sha256 = receipt.get("config_sha256")
    if not isinstance(config_sha256, str) or not re.fullmatch(
        r"[0-9a-f]{64}", config_sha256
    ):
        raise InstallerError("Remote current.json содержит некорректный config SHA-256")
    remote_config_sha, _ = _remote_managed_file(
        ssh,
        path="/etc/xhttp-setup/xray.json",
        expected_group="xhttp-setup",
        expected_mode="640",
    )
    if remote_config_sha != config_sha256:
        raise InstallerError("Remote Xray config не соответствует current.json")

    active = ssh.command(
        ["systemctl", "is-active", _MANAGED_EXIT_SERVICE],
        check=False,
        timeout=30,
    )
    enabled = ssh.command(
        ["systemctl", "is-enabled", _MANAGED_EXIT_SERVICE],
        check=False,
        timeout=30,
    )
    main_pid = ssh.command(
        ["systemctl", "show", "--property=MainPID", "--value", _MANAGED_EXIT_SERVICE],
        check=False,
        timeout=30,
    )
    listener = ssh.command(
        ["ss", "-H", "-lntp", f"sport = :{handoff.exit_port}"],
        check=False,
        timeout=30,
    )
    if (
        active.returncode != 0
        or active.stdout.strip() != "active"
        or enabled.returncode != 0
        or enabled.stdout.strip() != "enabled"
        or main_pid.returncode != 0
        or not re.fullmatch(r"[1-9][0-9]*", main_pid.stdout.strip())
        or listener.returncode != 0
    ):
        raise InstallerError("Managed Xray service не подтверждён")
    listener_lines = [line for line in listener.stdout.splitlines() if line.strip()]
    pid = main_pid.stdout.strip()
    if (
        len(listener_lines) != 1
        or '("xray",pid=' not in listener_lines[0]
        or f"pid={pid}," not in listener_lines[0]
    ):
        raise InstallerError("TCP/8083 не принадлежит managed Xray service")

    front_egress = validate_ipv4(str(receipt.get("front_egress_ip", "")))
    desired = ExitDesired(
        public_address=expected_address,
        listen_port=handoff.exit_port,
        front_egress_ip=front_egress,
        xhttp_path=handoff.xhttp_path,
        client_id=handoff.client_id,
        label=handoff.label,
        expected_egress_ip=handoff.expected_egress_ip,
        tls_fingerprint=handoff.tls_fingerprint,
    ).validate()
    try:
        local_firewall_text = local_firewall.read_text("utf-8")
    except (OSError, UnicodeError) as exc:
        raise InstallerError("Локальный firewall-plan не является UTF-8") from exc
    if local_firewall_text != _firewall_plan(desired):
        raise InstallerError("Firewall-plan не соответствует managed exit")
    profile = ExitNetworkProfile(
        frontend_ipv4=desired.front_egress_ip,
        backend_port=desired.listen_port,
    ).validate()
    network = preflight_remote_exit_network(ssh, profile)
    if not network.ufw_allow_indices or not network.ufw_deny_indices:
        raise InstallerError("Managed UFW allow/deny pair отсутствует")
    if measure_remote_exit_egress(ssh) != handoff.expected_egress_ip:
        raise InstallerError("Исходящий IPv4 managed exit изменился")
    if pending_desired is not None and desired != pending_desired.validate():
        raise InstallerError("Managed exit не соответствует pending транзакции")
    return PcExitResume(desired=desired, handoff=handoff)


def _wait_capture_ready(
    ssh: SSHClient,
    ready_path: str,
    future: concurrent.futures.Future[subprocess.CompletedProcess[str]],
) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if future.done():
            result = future.result()
            raise InstallerError(
                f"tcpdump frontend probe завершился до старта: код {result.returncode}"
            )
        ready = ssh.command(["test", "-f", ready_path], check=False, timeout=10)
        if ready.returncode == 0:
            time.sleep(0.5)
            return
        time.sleep(0.2)
    raise InstallerError("tcpdump frontend probe не подтвердил готовность")


def _trigger_front_requests(desired: FrontDesired) -> None:
    def request(number: int) -> None:
        try:
            https_status(
                f"https://{desired.domain}{desired.xhttp_path}/probe-{number}",
                connect_ip=desired.client_connect_ip,
                pinned_peer_cert_sha256=desired.pinned_peer_cert_sha256,
                timeout=5,
            )
        except Exception:
            # The backend port is intentionally blocked.  Incoming SYN packets,
            # not an HTTP response, are the measurement result.
            return

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_PROBE_REQUESTS
    ) as requests:
        list(requests.map(request, range(_PROBE_REQUESTS)))


def parse_front_egress_capture(output: str) -> str:
    endpoints: set[tuple[str, int]] = set()
    for match in _TCPDUMP_SOURCE.finditer(output):
        address = validate_ipv4(match.group(1))
        source_port = int(match.group(2))
        if 0 < source_port <= 65535:
            endpoints.add((address, source_port))
    if len(endpoints) < 3:
        raise VerificationError(
            "Frontend egress probe не увидел достаточно независимых соединений"
        )
    addresses = {address for address, _ in endpoints}
    if len(addresses) != 1:
        raise VerificationError(
            "Shared-hosting использует несколько исходящих IPv4; один /32 небезопасен"
        )
    return _public_ipv4(addresses.pop(), label="Frontend egress")


def measure_front_egress(
    *,
    ssh: SSHClient,
    temporary_front: FrontDesired,
    front_auth: SSHAuth,
    state_dir: Path,
) -> str:
    """Measure Apache source IPv4 without opening the temporary port in UFW."""

    temporary_front = temporary_front.validate()
    if not _remote_port_is_free(ssh, temporary_front.exit_port):
        raise InstallerError("Временный frontend probe port уже занят на exit")
    available = ssh.command(["command", "-v", "tcpdump"], check=False, timeout=20)
    if available.returncode != 0:
        raise InstallerError("На exit отсутствует tcpdump после автоматической подготовки")

    token = secrets.token_hex(16)
    ready_path = f"/tmp/xhttp-front-probe.{token}.ready"
    capture_result: subprocess.CompletedProcess[str] | None = None
    cleanup_error: BaseException | None = None
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as capture_pool:
        future = capture_pool.submit(
            ssh.command,
            [
                "sh",
                "-c",
                _CAPTURE_SCRIPT,
                "xhttp-front-probe",
                ready_path,
                str(temporary_front.exit_port),
            ],
            check=False,
            timeout=_PROBE_CAPTURE_SECONDS + 15,
        )
        try:
            _wait_capture_ready(ssh, ready_path, future)
            run_with_temporary_front_route(
                temporary_front,
                auth=front_auth,
                state_dir=state_dir,
                operation=lambda: _trigger_front_requests(temporary_front),
            )
            try:
                capture_result = future.result(timeout=_PROBE_CAPTURE_SECONDS + 10)
            except concurrent.futures.TimeoutError as exc:
                raise InstallerError(
                    "tcpdump frontend probe не завершился за отведённое время"
                ) from exc
        finally:
            try:
                removed = ssh.command(
                    ["rm", "-f", "--", ready_path], check=False, timeout=20
                )
                if removed.returncode != 0:
                    raise InstallerError(
                        "Не удалось удалить marker временного frontend probe"
                    )
            except BaseException as exc:
                cleanup_error = exc
            if not future.done():
                try:
                    future.result(timeout=_PROBE_CAPTURE_SECONDS + 10)
                except BaseException:
                    pass
    if cleanup_error is not None:
        raise cleanup_error
    if capture_result is None or capture_result.returncode not in {0, 124}:
        code = capture_result.returncode if capture_result is not None else "unknown"
        raise InstallerError(f"tcpdump frontend probe завершился с кодом {code}")
    return parse_front_egress_capture(capture_result.stdout)


def prepare_pc_install(
    inputs: PcUserInputs,
    *,
    output_dir: Path,
    progress: Callable[[str], None] | None = None,
    phase_callback: Callable[[str], None] | None = None,
    exit_password_prompt: Callable[[], str] | None = None,
    panel_password_prompt: Callable[[], str] | None = None,
    sftp_password_prompt: Callable[[], str] | None = None,
    require_exit_recovery: bool = False,
) -> PcPreparedInstall:
    """Discover every non-credential value needed by the existing transactions."""

    # Imports are intentionally local while the bounded discovery components
    # remain independently testable.
    from .front_discovery import discover_front_tls_policy, resolve_front_dns
    from .remote_prepare import measure_remote_exit_egress, prepare_remote_exit
    from .ssh_transport import trust_host_key_tofu

    inputs = inputs.validate()
    output_candidate = output_dir.expanduser()
    if output_candidate.is_symlink():
        raise InstallerError("Каталог PC state не может быть symlink")
    output = output_candidate.resolve(strict=False)
    ensure_dir(output, 0o700)
    trust_dir = Path.home() / ".local/state/xhttp-setup/trust/ssh"

    def step(message: str) -> None:
        if progress is not None:
            progress(message)

    step("Проверяю SSH выхода и закрепляю первый ключ")
    exit_known_hosts, exit_fingerprint = trust_host_key_tofu(
        host=inputs.exit_host,
        port=inputs.exit_port,
        trust_dir=trust_dir,
    )
    exit_target = RemoteExitTarget(
        host=inputs.exit_host,
        port=inputs.exit_port,
        user=inputs.exit_user,
        host_key_sha256=exit_fingerprint,
    ).validate()
    exit_password = inputs.exit_password
    exit_ssh: SSHClient | None = None
    exit_auth: SSHAuth | None = None
    for attempt in range(_MAX_PASSWORD_ATTEMPTS):
        exit_auth = SSHAuth("password", password=exit_password).validate()
        exit_ssh = SSHClient(
            host=exit_target.host,
            port=exit_target.port,
            user=exit_target.user,
            known_hosts=exit_known_hosts,
            auth=exit_auth,
        )
        try:
            identity = exit_ssh.command(["id", "-u"], check=False, timeout=30)
        except SSHAuthenticationError:
            if exit_password_prompt is None or attempt + 1 >= _MAX_PASSWORD_ATTEMPTS:
                raise
            exit_password = validate_pc_secret(
                exit_password_prompt(), "SSH password выхода"
            )
            continue
        if identity.returncode != 0 or identity.stdout.strip() != "0":
            raise InstallerError("Для exit нужен успешный прямой SSH-вход root")
        break
    if exit_ssh is None or exit_auth is None:  # pragma: no cover - loop invariant
        raise InstallerError("Не удалось создать SSH transport выхода")
    exit_password = ""

    step("Проверяю существующий сайт в ISPmanager")
    endpoint = panel_login_url_to_endpoint(inputs.panel_url)
    panel_password = inputs.panel_password
    for attempt in range(_MAX_PASSWORD_ATTEMPTS):
        try:
            site = inspect_site(
                endpoint=endpoint,
                username=inputs.panel_user,
                password=panel_password,
                domain=inputs.domain,
            )
        except ISPmanagerAuthenticationError:
            if panel_password_prompt is None or attempt + 1 >= _MAX_PASSWORD_ATTEMPTS:
                raise
            panel_password = validate_pc_secret(
                panel_password_prompt(), "Пароль панели REG.RU"
            )
            continue
        break
    client_connect_ip = inputs.front_connect_ip
    dns_ipv4 = resolve_front_dns(inputs.domain)

    parsed_panel = urllib.parse.urlsplit(endpoint)
    if not parsed_panel.hostname:
        raise InstallerError("В URL ISPmanager отсутствует hostname")
    sftp_host = validate_host(parsed_panel.hostname)
    # ISPmanager's primary account normally uses the panel password for SFTP.
    # Ask for a separate password only when the SSH authentication itself says
    # that this credential was rejected.
    front_auth = SSHAuth("password", password=panel_password).validate()
    step("Проверяю SFTP и закрепляю первый ключ")
    sftp_known_hosts, sftp_fingerprint = trust_host_key_tofu(
        host=sftp_host,
        port=22,
        trust_dir=trust_dir,
    )
    def check_sftp(auth: SSHAuth) -> subprocess.CompletedProcess[str]:
        return SFTPClient(
            host=sftp_host,
            port=22,
            user=inputs.panel_user,
            known_hosts=sftp_known_hosts,
            auth=auth,
        ).batch([f"cd {sftp_quote(site.docroot)}", "pwd"], check=False)

    for attempt in range(_MAX_PASSWORD_ATTEMPTS):
        try:
            access = check_sftp(front_auth)
        except SSHAuthenticationError:
            if sftp_password_prompt is None or attempt + 1 >= _MAX_PASSWORD_ATTEMPTS:
                raise
            fallback_password = validate_pc_secret(
                sftp_password_prompt(), "Пароль SFTP REG.RU"
            )
            front_auth = SSHAuth("password", password=fallback_password).validate()
            fallback_password = ""
            continue
        break
    panel_password = ""
    if access.returncode != 0:
        raise InstallerError("REG.RU SFTP login или доступ к сайту не подтверждён")

    step("Автоматически проверяю TLS/SNI сайта")
    tls_discovery = discover_front_tls_policy(
        inputs.domain,
        client_connect_ip,
        state_dir=output / "tls-trust",
    )
    tls_mode = tls_discovery.tls_mode
    cert_pin = tls_discovery.pinned_peer_cert_sha256

    # Every frontend check above is read-only.  Do not mutate even a clean exit
    # until the site, DNS, SFTP access, and TLS endpoint have all been proven.
    backend_port = 8083
    pending_desired = _load_pending_pc_exit(
        output_dir=output,
        inputs=inputs,
        exit_target=exit_target,
    )
    step("Проверяю, нет ли подтверждённой незавершённой установки")
    resume = inspect_existing_pc_exit(
        exit_ssh,
        output_dir=output,
        exit_address=inputs.exit_host,
        ssh_port=exit_target.port,
        pending_desired=pending_desired,
    )
    if require_exit_recovery and resume is None and pending_desired is None:
        raise InstallerError(
            "PC phase требует восстановить прежний exit, но точного recovery state нет"
        )
    if resume is not None:
        step("Безопасно продолжаю ранее подтверждённый managed exit")
        expected_egress = resume.desired.expected_egress_ip
        xhttp_path = resume.handoff.xhttp_path
    elif pending_desired is not None:
        step("Повторяю прерванную exit-транзакцию с теми же UUID и XHTTP path")
        if measure_remote_exit_egress(exit_ssh) != pending_desired.expected_egress_ip:
            raise InstallerError("Исходящий IPv4 exit изменился после прерванного apply")
        expected_egress = pending_desired.expected_egress_ip
        xhttp_path = pending_desired.xhttp_path
    else:
        if not _remote_port_is_free(exit_ssh, backend_port):
            raise InstallerError(
                "TCP/8083 занят: это не подтверждённый managed exit текущей установки"
            )
        step("Автоматически готовлю чистый exit и UFW")
        prepare_remote_exit(exit_ssh, ssh_port=exit_target.port)
        expected_egress = measure_remote_exit_egress(exit_ssh)
        xhttp_path = "/api/" + secrets.token_urlsafe(24)

    probe_port = _select_front_probe_port(
        exit_ssh,
        backend_port=backend_port,
        ssh_port=exit_target.port,
        seed=f"{inputs.domain}|{exit_target.host}|{exit_target.port}",
    )
    step(f"Временный frontend probe использует TCP/{probe_port}")
    temporary_front = FrontDesired(
        domain=inputs.domain,
        client_connect_ip=client_connect_ip,
        dns_ipv4=dns_ipv4,
        sftp_host=sftp_host,
        sftp_port=22,
        sftp_user=inputs.panel_user,
        document_root=site.docroot,
        ssh_host_key_sha256=sftp_fingerprint,
        exit_address=validate_ipv4(inputs.exit_host),
        exit_port=probe_port,
        xhttp_path=xhttp_path,
        placeholder_mode="keep",
        tls_mode=tls_mode,
        pinned_peer_cert_sha256=cert_pin,
    ).validate()

    step("Измеряю фактический исходящий IP Apache")
    if phase_callback is not None:
        phase_callback("front_probe_in_progress")
    try:
        front_egress = measure_front_egress(
            ssh=exit_ssh,
            temporary_front=temporary_front,
            front_auth=front_auth,
            state_dir=output / "front-egress-probe",
        )
    except BaseException as exc:
        if phase_callback is not None and not _front_rollback_incomplete(exc):
            phase_callback("preparing")
        raise
    if phase_callback is not None:
        phase_callback("preparing")
    step(f"Подтверждён исходящий IPv4 Apache REG.RU: {front_egress}")

    if resume is None and pending_desired is None:
        desired_exit = ExitDesired(
            public_address=validate_ipv4(inputs.exit_host),
            listen_port=backend_port,
            front_egress_ip=front_egress,
            xhttp_path=xhttp_path,
            client_id=str(uuid.uuid4()),
            label="XHTTP TLS",
            expected_egress_ip=expected_egress,
            tls_fingerprint=DEFAULT_TLS_FINGERPRINT,
        ).validate()
    else:
        recovered_desired = (
            resume.desired if resume is not None else pending_desired
        )
        if recovered_desired is None:  # pragma: no cover - branch invariant
            raise InstallerError("Recovery desired state отсутствует")
        if front_egress != recovered_desired.front_egress_ip:
            raise VerificationError(
                "Исходящий IPv4 REG.RU изменился; автоматическая смена managed UFW /32 запрещена"
            )
        desired_exit = recovered_desired

    desired_front = FrontDesired(
        domain=temporary_front.domain,
        client_connect_ip=temporary_front.client_connect_ip,
        dns_ipv4=temporary_front.dns_ipv4,
        sftp_host=temporary_front.sftp_host,
        sftp_port=temporary_front.sftp_port,
        sftp_user=temporary_front.sftp_user,
        document_root=temporary_front.document_root,
        ssh_host_key_sha256=temporary_front.ssh_host_key_sha256,
        exit_address=desired_exit.public_address,
        exit_port=desired_exit.listen_port,
        xhttp_path=desired_exit.xhttp_path,
        placeholder_mode="keep",
        tls_mode=temporary_front.tls_mode,
        pinned_peer_cert_sha256=temporary_front.pinned_peer_cert_sha256,
    ).validate()
    if desired_front.tls_mode == TLS_MODE_PINNED and not cert_pin:
        raise VerificationError("Pinned TLS policy не содержит exact leaf SHA-256")
    return PcPreparedInstall(
        exit_target=exit_target,
        exit_auth=exit_auth,
        desired_exit=desired_exit,
        desired_front=desired_front,
        front_auth=front_auth,
        existing_handoff=(resume.handoff if resume is not None else None),
        pending_exit_recovery=(resume is None and pending_desired is not None),
    )
