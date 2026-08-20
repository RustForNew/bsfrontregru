"""Bounded preparation of a clean Debian/Ubuntu exit host.

The normal PC wizard uses this module before the existing remote installer.  It
only installs an explicit package allow-list and, when UFW is pristine and
inactive, enables it behind a timed rollback guard.  The final frontend /32
allow and backend deny rules remain owned by :mod:`xhttp_setup.remote_network`.
"""

from __future__ import annotations

import ipaddress
import re
import shlex
import subprocess
import time
from dataclasses import dataclass
from typing import Protocol, Sequence

from .errors import InstallerError, VerificationError
from .ssh_transport import SSHClient
from .validate import validate_port


_READ_TIMEOUT = 25
_APT_TIMEOUT = 900
_APT_LOCK_SECONDS = 180
_MUTATION_TIMEOUT = 45
_SYSTEMD_READY_SECONDS = 120
_SYSTEMD_POLL_SECONDS = 2
_EGRESS_URL = "https://www.cloudflare.com/cdn-cgi/trace"
_PACKAGES = (
    "ca-certificates",
    "curl",
    "iproute2",
    "nftables",
    "python3",
    "tcpdump",
    "ufw",
)
_STANDARD_UFW_DEFAULTS = {
    "DEFAULT_INPUT_POLICY": "DROP",
    "DEFAULT_OUTPUT_POLICY": "ACCEPT",
    "DEFAULT_FORWARD_POLICY": "DROP",
    "DEFAULT_APPLICATION_POLICY": "SKIP",
    "MANAGE_BUILTINS": "no",
}
_BASE_FILTER_CHAINS = frozenset({"INPUT", "OUTPUT", "FORWARD"})
_CONTAINER_MARKER = re.compile(
    r"(?:^|[^a-z0-9])(docker|containerd|podman|cni|kube)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_NFT_TABLE = re.compile(r"^table\s+(\S+)\s+(\S+)\s*\{$")
_NFT_CHAIN = re.compile(r"^chain\s+(\S+)\s*\{$")
_IPTABLES_CHAIN = re.compile(r"^:(\S+)\s+(\S+)\s+\[[0-9]+:[0-9]+\]$")


@dataclass(frozen=True)
class RemoteExitPreparation:
    os_id: str
    version_id: str
    newly_installed_packages: tuple[str, ...]
    ufw_was_active: bool
    ufw_enabled: bool
    ssh_rule_comment: str
    ssh_rule_added: bool


class UfwRollbackGuard(Protocol):
    """A guard that restores an initially inactive UFW configuration."""

    def is_armed(self, ssh: SSHClient, *, ssh_port: int) -> bool: ...

    def arm(self, ssh: SSHClient, *, ssh_port: int) -> None: ...

    def disarm(self, ssh: SSHClient, *, ssh_port: int) -> None: ...


def _invoke(
    ssh: SSHClient,
    argv: Sequence[str],
    *,
    timeout: int = _READ_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        return ssh.command(list(argv), check=False, timeout=timeout)
    except Exception as exc:
        raise InstallerError("Удалённая SSH-команда не завершилась") from exc


def _must(
    ssh: SSHClient,
    argv: Sequence[str],
    *,
    operation: str,
    timeout: int = _READ_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    result = _invoke(ssh, argv, timeout=timeout)
    if result.returncode != 0:
        raise InstallerError(f"{operation}: код {result.returncode}")
    return result


def _require_root(ssh: SSHClient) -> None:
    result = _must(
        ssh,
        ["id", "-u"],
        operation="Не удалось проверить UID удалённого пользователя",
    )
    if result.stdout.strip() != "0":
        raise InstallerError("Автоподготовка выхода требует прямой SSH-вход root")


def _require_systemd(ssh: SSHClient) -> None:
    pid_one = _must(
        ssh,
        ["cat", "/proc/1/comm"],
        operation="Не удалось определить init удалённого сервера",
    )
    if pid_one.stdout.strip() != "systemd":
        raise InstallerError("Автоподготовка поддерживает только systemd-сервер")
    deadline = time.monotonic() + _SYSTEMD_READY_SECONDS
    while True:
        state = _invoke(ssh, ["systemctl", "is-system-running"])
        value = state.stdout.strip().lower()
        if (state.returncode, value) in {(0, "running"), (1, "degraded")}:
            return
        if value == "starting" and state.returncode in {0, 1}:
            if time.monotonic() >= deadline:
                raise InstallerError(
                    "systemd удалённого сервера не завершил запуск за 120 секунд"
                )
            time.sleep(_SYSTEMD_POLL_SECONDS)
            continue
        raise InstallerError("systemd удалённого сервера не находится в рабочем состоянии")


def _parse_os_release(payload: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in payload.splitlines():
        key, separator, raw_value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            continue
        value = raw_value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
            value = value[1:-1]
        values[key] = value
    return values


def _version_tuple(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", value):
        raise VerificationError("Некорректный VERSION_ID в /etc/os-release")
    return tuple(int(part) for part in value.split("."))


def _require_supported_os(ssh: SSHClient) -> tuple[str, str]:
    result = _must(
        ssh,
        ["cat", "/etc/os-release"],
        operation="Не удалось прочитать /etc/os-release",
    )
    values = _parse_os_release(result.stdout)
    os_id = values.get("ID", "").lower()
    version_id = values.get("VERSION_ID", "")
    version = _version_tuple(version_id)
    minimum = {"debian": (12,), "ubuntu": (22, 4)}.get(os_id)
    if minimum is None or version < minimum:
        raise InstallerError(
            "Автоподготовка поддерживает Debian 12+ или Ubuntu 22.04+"
        )
    return os_id, version_id


def _reject_container_runtime(ssh: SSHClient) -> None:
    result = _must(
        ssh,
        [
            "systemctl",
            "list-unit-files",
            "docker.service",
            "docker.socket",
            "containerd.service",
            "--no-legend",
            "--no-pager",
        ],
        operation="Не удалось проверить Docker/containerd unit-файлы",
    )
    expected = {"docker.service", "docker.socket", "containerd.service"}
    found = {
        fields[0]
        for line in result.stdout.splitlines()
        if (fields := line.split()) and fields[0] in expected
    }
    if found:
        raise InstallerError(
            "Обнаружены Docker/containerd unit-файлы; автоподготовка отказалась"
        )


def _systemd_unit_state(
    ssh: SSHClient, operation: str, unit: str
) -> tuple[int, str]:
    result = _invoke(ssh, ["systemctl", operation, unit])
    state = result.stdout.strip().lower()
    if "\n" in state or "\r" in state:
        raise VerificationError(f"systemctl вернул неоднозначное состояние {unit}")
    return result.returncode, state


def _reject_standalone_nftables_service(ssh: SSHClient) -> None:
    active_code, active = _systemd_unit_state(
        ssh, "is-active", "nftables.service"
    )
    if active_code == 0 or active == "active":
        raise InstallerError("Обнаружен активный nftables.service")
    # systemd releases differ here: is-active reports an inactive or missing
    # unit with 1, 3, or 4.  The textual state is the stable part of the
    # interface; a zero exit status is never accepted for these states.
    if active_code not in {1, 3, 4} or active not in {
        "inactive",
        "unknown",
        "not-found",
    }:
        raise InstallerError("Не удалось однозначно проверить nftables.service")
    enabled_code, enabled = _systemd_unit_state(
        ssh, "is-enabled", "nftables.service"
    )
    if enabled_code == 0 or enabled in {"enabled", "enabled-runtime", "static"}:
        raise InstallerError("Обнаружен enabled nftables.service")
    if enabled_code not in {1, 4} or enabled not in {
        "disabled",
        "masked",
        "not-found",
    }:
        raise InstallerError(
            "Не удалось однозначно проверить nftables.service enablement"
        )


def _tool_exists(ssh: SSHClient, name: str) -> bool:
    result = _invoke(ssh, ["command", "-v", name])
    if result.returncode == 0 and result.stdout.strip():
        return True
    if result.returncode == 1 and not result.stdout.strip():
        return False
    raise InstallerError(f"Не удалось однозначно найти удалённую команду {name}")


def _validate_nft_ruleset(payload: str, *, allow_ufw: bool) -> None:
    current_table: tuple[str, str] | None = None
    current_chain: str | None = None
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _CONTAINER_MARKER.search(line):
            raise InstallerError("Обнаружены container-managed nftables rules")
        table_match = _NFT_TABLE.fullmatch(line)
        if table_match:
            if current_table is not None or current_chain is not None:
                raise InstallerError("Неоднозначная вложенность nftables ruleset")
            family, name = table_match.groups()
            if not allow_ufw or family not in {"ip", "ip6"} or name != "filter":
                raise InstallerError("Обнаружена custom nftables table")
            current_table = (family, name)
            continue
        chain_match = _NFT_CHAIN.fullmatch(line)
        if chain_match:
            if current_table is None or current_chain is not None:
                raise InstallerError("Неоднозначная nftables chain")
            current_chain = chain_match.group(1)
            if current_chain not in _BASE_FILTER_CHAINS and not current_chain.startswith(
                "ufw-"
            ):
                raise InstallerError("Обнаружена custom nftables chain")
            continue
        if line == "}":
            if current_chain is not None:
                current_chain = None
            elif current_table is not None:
                current_table = None
            else:
                raise InstallerError("Лишняя скобка в nftables ruleset")
            continue
        if current_chain is None:
            raise InstallerError("Обнаружена custom nftables конструкция")
        if current_chain in _BASE_FILTER_CHAINS:
            declaration = line.startswith("type filter hook ")
            ufw_dispatch = bool(
                re.search(r"\b(?:jump|goto)\s+ufw-[A-Za-z0-9_-]+\b", line)
            )
            if not (declaration or ufw_dispatch):
                raise InstallerError("Обнаружена custom nftables base-chain rule")
    if current_table is not None or current_chain is not None:
        raise InstallerError("Незавершённый nftables ruleset")


def _validate_iptables_save(payload: str, *, allow_ufw: bool) -> None:
    table_open = False
    chains: set[str] = set()
    for raw_line in payload.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if _CONTAINER_MARKER.search(line):
            raise InstallerError("Обнаружены container-managed iptables rules")
        if line.startswith("*"):
            if table_open or line != "*filter":
                raise InstallerError("Обнаружена custom iptables table")
            table_open = True
            continue
        chain_match = _IPTABLES_CHAIN.fullmatch(line)
        if chain_match:
            if not table_open:
                raise InstallerError("Некорректный iptables-save")
            chain, policy = chain_match.groups()
            if chain not in _BASE_FILTER_CHAINS and not (
                allow_ufw and chain.startswith("ufw-")
            ):
                raise InstallerError("Обнаружена custom iptables chain")
            if not allow_ufw and policy != "ACCEPT":
                raise InstallerError("Обнаружена custom iptables policy")
            chains.add(chain)
            continue
        if line == "COMMIT":
            if not table_open:
                raise InstallerError("Некорректный iptables-save COMMIT")
            table_open = False
            chains.clear()
            continue
        if line.startswith("-A "):
            fields = shlex.split(line)
            if len(fields) < 4 or fields[1] not in chains:
                raise InstallerError("Некорректная iptables rule")
            chain = fields[1]
            dispatches_to_ufw = any(
                fields[index] in {"-j", "-g"}
                and index + 1 < len(fields)
                and fields[index + 1].startswith("ufw-")
                for index in range(len(fields))
            )
            if chain in _BASE_FILTER_CHAINS and not (
                allow_ufw and dispatches_to_ufw
            ):
                raise InstallerError("Обнаружена custom iptables base-chain rule")
            continue
        raise InstallerError("Обнаружена custom iptables конструкция")
    if table_open:
        raise InstallerError("Незавершённый iptables-save")


def _ufw_status(ssh: SSHClient) -> bool:
    result = _must(
        ssh,
        ["env", "LC_ALL=C", "LANG=C", "ufw", "status", "numbered"],
        operation="Не удалось прочитать состояние UFW",
    )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if lines and lines[0] == "Status: active":
        return True
    if lines == ["Status: inactive"]:
        return False
    raise VerificationError("UFW вернул неоднозначное состояние")


def _inspect_firewall(ssh: SSHClient, *, ufw_active: bool) -> None:
    _reject_standalone_nftables_service(ssh)
    has_nft = _tool_exists(ssh, "nft")
    if has_nft:
        nft = _must(
            ssh,
            ["nft", "list", "ruleset"],
            operation="Не удалось прочитать nftables ruleset",
        )
        _validate_nft_ruleset(nft.stdout, allow_ufw=ufw_active)
    has_iptables_save = _tool_exists(ssh, "iptables-save")
    if has_iptables_save:
        iptables = _must(
            ssh,
            ["iptables-save"],
            operation="Не удалось прочитать iptables ruleset",
        )
        _validate_iptables_save(iptables.stdout, allow_ufw=ufw_active)
    else:
        for proc_path in (
            "/proc/net/ip_tables_names",
            "/proc/net/ip6_tables_names",
        ):
            result = _invoke(ssh, ["cat", proc_path])
            if result.returncode == 0 and result.stdout.strip():
                raise InstallerError(
                    "Обнаружены legacy iptables tables без безопасного инспектора"
                )
            if result.returncode not in {0, 1}:
                raise InstallerError("Не удалось проверить legacy iptables tables")


def _read_ufw_defaults(ssh: SSHClient) -> None:
    result = _must(
        ssh,
        ["cat", "/etc/default/ufw"],
        operation="Не удалось прочитать /etc/default/ufw",
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, raw_value = line.partition("=")
        if separator:
            values[key.strip()] = raw_value.strip().strip("\"'")
    changed = [
        name
        for name, expected in _STANDARD_UFW_DEFAULTS.items()
        if values.get(name) != expected
    ]
    if changed:
        raise InstallerError(
            "UFW inactive, но его defaults не стандартные: " + ", ".join(changed)
        )


def _ufw_added_commands(ssh: SSHClient) -> list[list[str]]:
    result = _must(
        ssh,
        ["env", "LC_ALL=C", "LANG=C", "ufw", "show", "added"],
        operation="Не удалось прочитать сохранённые UFW rules",
    )
    commands: list[list[str]] = []
    for line in result.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("ufw "):
            try:
                commands.append(shlex.split(stripped))
            except ValueError as exc:
                raise VerificationError("Некорректный вывод ufw show added") from exc
    return commands


def _require_pristine_inactive_ufw(ssh: SSHClient) -> None:
    _read_ufw_defaults(ssh)
    if _ufw_added_commands(ssh):
        raise InstallerError(
            "UFW inactive, но содержит foreign rules; автоподготовка отказалась"
        )


def _missing_packages(ssh: SSHClient) -> tuple[str, ...]:
    missing: list[str] = []
    for package in _PACKAGES:
        result = _invoke(
            ssh,
            ["dpkg-query", "--show", "--showformat=${db:Status-Abbrev}", package],
        )
        if result.returncode == 0 and result.stdout == "ii ":
            continue
        if result.returncode == 1:
            missing.append(package)
            continue
        raise InstallerError(f"Не удалось проверить пакет {package}")
    return tuple(missing)


def _install_packages(ssh: SSHClient, packages: tuple[str, ...]) -> None:
    if not packages:
        return
    environment = [
        "env",
        "DEBIAN_FRONTEND=noninteractive",
        "APT_LISTCHANGES_FRONTEND=none",
    ]
    _must(
        ssh,
        [
            *environment,
            "apt-get",
            "-o",
            f"DPkg::Lock::Timeout={_APT_LOCK_SECONDS}",
            "update",
        ],
        operation="apt-get update не завершился",
        timeout=_APT_TIMEOUT,
    )
    _must(
        ssh,
        [
            *environment,
            "apt-get",
            "-o",
            f"DPkg::Lock::Timeout={_APT_LOCK_SECONDS}",
            "install",
            "--yes",
            "--no-install-recommends",
            "--",
            *packages,
        ],
        operation="Не удалось установить системные зависимости",
        timeout=_APT_TIMEOUT,
    )
    still_missing = _missing_packages(ssh)
    if still_missing:
        raise VerificationError(
            "После apt отсутствуют пакеты: " + ", ".join(still_missing)
        )


def _verify_python(ssh: SSHClient) -> None:
    result = _must(
        ssh,
        [
            "python3",
            "-c",
            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
        ],
        operation="Не удалось проверить Python на сервере",
    )
    version = _version_tuple(result.stdout.strip())
    if version < (3, 10):
        raise InstallerError("На сервере нужен Python 3.10+")


def _ssh_rule_comment(ssh_port: int) -> str:
    return f"xhttp-setup-ssh-guard-{ssh_port}"


def _expected_ssh_rule(ssh_port: int) -> list[str]:
    return [
        "ufw",
        "allow",
        f"{ssh_port}/tcp",
        "comment",
        _ssh_rule_comment(ssh_port),
    ]


class _SystemdUfwRollbackGuard:
    _ROLLBACK_SECONDS = 120
    _SCRIPT = (
        "import subprocess,sys;"
        "port=sys.argv[1];"
        "null=subprocess.DEVNULL;"
        "subprocess.run(['/usr/sbin/ufw','--force','disable'],"
        "stdout=null,stderr=null,check=False);"
        "subprocess.run(['/usr/sbin/ufw','--force','delete','allow',port+'/tcp'],"
        "stdout=null,stderr=null,check=False)"
    )

    @staticmethod
    def _unit(ssh_port: int) -> str:
        return f"xhttp-setup-ufw-rollback-{ssh_port}"

    @classmethod
    def _units(cls, ssh_port: int) -> tuple[str, str]:
        unit = cls._unit(ssh_port)
        return f"{unit}.timer", f"{unit}.service"

    @staticmethod
    def _state_is_running(code: int, state: str, *, unit: str) -> bool:
        running = {"active", "activating", "deactivating", "reloading"}
        terminal = {"inactive", "failed", "unknown", "not-found"}
        if code == 0 and state in running:
            return True
        if code in {1, 3, 4} and state in terminal:
            return False
        raise VerificationError(f"Состояние UFW rollback unit {unit} неоднозначно")

    def is_armed(self, ssh: SSHClient, *, ssh_port: int) -> bool:
        states = []
        for unit in self._units(ssh_port):
            code, state = _systemd_unit_state(ssh, "is-active", unit)
            states.append(self._state_is_running(code, state, unit=unit))
        return any(states)

    def arm(self, ssh: SSHClient, *, ssh_port: int) -> None:
        unit = self._unit(ssh_port)
        _must(
            ssh,
            [
                "systemd-run",
                "--quiet",
                "--collect",
                f"--unit={unit}",
                f"--on-active={self._ROLLBACK_SECONDS}s",
                "/usr/bin/python3",
                "-c",
                self._SCRIPT,
                str(ssh_port),
            ],
            operation="Не удалось включить автоматический UFW rollback guard",
            timeout=_MUTATION_TIMEOUT,
        )

    def disarm(self, ssh: SSHClient, *, ssh_port: int) -> None:
        timer, service = self._units(ssh_port)
        # Stop both units in one systemd transaction.  Stopping only the timer
        # is racy: it may already have activated the rollback service.
        _invoke(
            ssh,
            ["systemctl", "stop", timer, service],
            timeout=_MUTATION_TIMEOUT,
        )
        if self.is_armed(ssh, ssh_port=ssh_port):
            raise VerificationError("UFW rollback guard остался активным")


def _remove_inactive_managed_ssh_rule(ssh: SSHClient, *, ssh_port: int) -> None:
    _must(
        ssh,
        [
            "env",
            "LC_ALL=C",
            "LANG=C",
            "ufw",
            "--force",
            "delete",
            "allow",
            f"{ssh_port}/tcp",
        ],
        operation="Не удалось удалить SSH rule после UFW guard recovery",
        timeout=_MUTATION_TIMEOUT,
    )
    if _ufw_status(ssh) or _ufw_added_commands(ssh):
        raise VerificationError("UFW guard recovery не вернул pristine inactive state")


def _reconcile_orphaned_inactive_ssh_rule(
    ssh: SSHClient,
    *,
    ssh_port: int,
) -> bool:
    """Remove the exact owned rule left by a kill before guard arming."""

    rules = _ufw_added_commands(ssh)
    if rules != [_expected_ssh_rule(ssh_port)]:
        return False
    _read_ufw_defaults(ssh)
    _remove_inactive_managed_ssh_rule(ssh, ssh_port=ssh_port)
    return True


def _recover_stale_ufw_guard(
    ssh: SSHClient,
    *,
    ssh_port: int,
    guard: UfwRollbackGuard,
) -> bool:
    """Quiesce an owned stale guard and return the resulting UFW active state."""

    # This is a genuinely fresh SSH process.  Do not cancel the safety timer
    # merely because the original process resumed locally.
    _require_root(ssh)
    before_active = _ufw_status(ssh)
    before_rules = _ufw_added_commands(ssh)
    expected = [_expected_ssh_rule(ssh_port)]
    safe_before = (
        (before_active and before_rules == expected)
        or (not before_active and before_rules in ([], expected))
    )
    if not safe_before:
        raise InstallerError(
            "Обнаружен stale UFW rollback guard с неожиданными rules; "
            "он оставлен для безопасного rollback"
        )
    _inspect_firewall(ssh, ufw_active=before_active)

    # disarm() stops both the timer and an already-running service.  The
    # commands below then prove that nothing raced with that stop.
    guard.disarm(ssh, ssh_port=ssh_port)
    _require_root(ssh)
    after_active = _ufw_status(ssh)
    after_rules = _ufw_added_commands(ssh)
    safe_after = (
        (after_active and after_rules == expected)
        or (not after_active and after_rules in ([], expected))
    )
    if not safe_after:
        raise InstallerError(
            "UFW rollback service успел изменить firewall; повторите запуск "
            "после проверки доступа по SSH"
        )
    _inspect_firewall(ssh, ufw_active=after_active)
    if after_active:
        return True
    if after_rules == expected:
        _remove_inactive_managed_ssh_rule(ssh, ssh_port=ssh_port)
    return False


def _rollback_new_ufw(
    ssh: SSHClient,
    *,
    ssh_port: int,
    guard: UfwRollbackGuard,
    guard_armed: bool,
    enable_attempted: bool,
) -> bool:
    try:
        if enable_attempted:
            _must(
                ssh,
                ["env", "LC_ALL=C", "LANG=C", "ufw", "--force", "disable"],
                operation="Не удалось отключить UFW при rollback",
                timeout=_MUTATION_TIMEOUT,
            )
        _must(
            ssh,
            [
                "env",
                "LC_ALL=C",
                "LANG=C",
                "ufw",
                "--force",
                "delete",
                "allow",
                f"{ssh_port}/tcp",
            ],
            operation="Не удалось удалить SSH rule при rollback",
            timeout=_MUTATION_TIMEOUT,
        )
        if _ufw_status(ssh):
            raise VerificationError("UFW остался active после rollback")
        if _ufw_added_commands(ssh):
            raise VerificationError("SSH rule осталась после UFW rollback")
        if guard_armed:
            guard.disarm(ssh, ssh_port=ssh_port)
        return True
    except Exception:
        return False


def _enable_pristine_ufw(
    ssh: SSHClient,
    *,
    ssh_port: int,
    rollback_guard: UfwRollbackGuard,
) -> None:
    comment = _ssh_rule_comment(ssh_port)
    _must(
        ssh,
        [
            "env",
            "LC_ALL=C",
            "LANG=C",
            "ufw",
            "allow",
            f"{ssh_port}/tcp",
            "comment",
            comment,
        ],
        operation="Не удалось добавить временно защищающую SSH rule",
        timeout=_MUTATION_TIMEOUT,
    )
    added = _ufw_added_commands(ssh)
    if added != [_expected_ssh_rule(ssh_port)]:
        rolled_back = _rollback_new_ufw(
            ssh,
            ssh_port=ssh_port,
            guard=rollback_guard,
            guard_armed=False,
            enable_attempted=False,
        )
        if not rolled_back:
            raise InstallerError(
                "UFW не подтвердил managed SSH rule; rollback неполон"
            )
        raise VerificationError("UFW не подтвердил единственную managed SSH rule")

    guard_armed = False
    enable_attempted = False
    try:
        rollback_guard.arm(ssh, ssh_port=ssh_port)
        guard_armed = True
        enable_attempted = True
        _must(
            ssh,
            ["env", "LC_ALL=C", "LANG=C", "ufw", "--force", "enable"],
            operation="Не удалось включить UFW",
            timeout=_MUTATION_TIMEOUT,
        )
        # SSHClient opens a new OpenSSH process for every command.
        _require_root(ssh)
        if not _ufw_status(ssh):
            raise VerificationError("UFW не стал active после enable")
        if _ufw_added_commands(ssh) != [_expected_ssh_rule(ssh_port)]:
            raise VerificationError("После enable UFW содержит не только managed SSH rule")
        rollback_guard.disarm(ssh, ssh_port=ssh_port)
        guard_armed = False
        # The timer may have activated its service at the disarm boundary.
        # Prove the post-quiescence firewall state with another fresh SSH
        # process before reporting success.
        _require_root(ssh)
        if not _ufw_status(ssh):
            raise VerificationError("UFW стал inactive во время остановки rollback guard")
        if _ufw_added_commands(ssh) != [_expected_ssh_rule(ssh_port)]:
            raise VerificationError(
                "Rollback service изменил managed SSH rule во время остановки"
            )
        _inspect_firewall(ssh, ufw_active=True)
    except Exception as original:
        rolled_back = _rollback_new_ufw(
            ssh,
            ssh_port=ssh_port,
            guard=rollback_guard,
            guard_armed=guard_armed,
            enable_attempted=enable_attempted,
        )
        if rolled_back:
            raise InstallerError(
                "UFW enable не прошёл проверку; исходное inactive-состояние восстановлено"
            ) from original
        raise InstallerError(
            "UFW enable не прошёл проверку; автоматический rollback guard оставлен активным"
        ) from original


def prepare_remote_exit(
    ssh: SSHClient,
    *,
    ssh_port: int,
    rollback_guard: UfwRollbackGuard | None = None,
) -> RemoteExitPreparation:
    """Prepare only a supported, container-free, conservatively clean exit."""

    ssh_port = validate_port(ssh_port)
    _require_root(ssh)
    _require_systemd(ssh)

    # Reconcile a guard left by a killed previous run before any long package
    # operation.  Otherwise its timer could disable an otherwise successful
    # firewall later in this run.
    guard = rollback_guard or _SystemdUfwRollbackGuard()
    guard_armed = guard.is_armed(ssh, ssh_port=ssh_port)
    ufw_present = _tool_exists(ssh, "ufw")
    if guard_armed:
        if not ufw_present:
            raise InstallerError(
                "Обнаружен UFW rollback guard, но команда ufw отсутствует"
            )
        _recover_stale_ufw_guard(
            ssh,
            ssh_port=ssh_port,
            guard=guard,
        )

    os_id, version_id = _require_supported_os(ssh)
    _reject_container_runtime(ssh)

    ufw_was_active = _ufw_status(ssh) if ufw_present else False
    _inspect_firewall(ssh, ufw_active=ufw_was_active)
    if ufw_present and not ufw_was_active:
        _reconcile_orphaned_inactive_ssh_rule(ssh, ssh_port=ssh_port)
        _require_pristine_inactive_ufw(ssh)

    missing = _missing_packages(ssh)
    _install_packages(ssh, missing)
    _verify_python(ssh)

    ufw_active = _ufw_status(ssh)
    _inspect_firewall(ssh, ufw_active=ufw_active)
    if ufw_active:
        return RemoteExitPreparation(
            os_id=os_id,
            version_id=version_id,
            newly_installed_packages=missing,
            ufw_was_active=ufw_was_active,
            ufw_enabled=False,
            ssh_rule_comment=_ssh_rule_comment(ssh_port),
            ssh_rule_added=False,
        )

    _require_pristine_inactive_ufw(ssh)
    _enable_pristine_ufw(ssh, ssh_port=ssh_port, rollback_guard=guard)
    return RemoteExitPreparation(
        os_id=os_id,
        version_id=version_id,
        newly_installed_packages=missing,
        ufw_was_active=ufw_was_active,
        ufw_enabled=True,
        ssh_rule_comment=_ssh_rule_comment(ssh_port),
        ssh_rule_added=True,
    )


def _parse_cloudflare_trace_ipv4(payload: str) -> str:
    values = [
        line.partition("=")[2].strip()
        for line in payload.splitlines()
        if line.partition("=")[:2] == ("ip", "=")
    ]
    if len(values) != 1:
        raise VerificationError("Cloudflare trace должен вернуть ровно одну строку ip=")
    try:
        address = ipaddress.ip_address(values[0])
    except ValueError as exc:
        raise VerificationError("Cloudflare trace вернул некорректный IP") from exc
    if address.version != 4 or not address.is_global:
        raise VerificationError("Egress probe вернул не глобальный IPv4")
    return str(address)


def measure_remote_exit_egress(
    ssh: SSHClient,
    *,
    sample_count: int = 3,
) -> str:
    """Measure a stable direct IPv4 egress with proxy settings fully disabled."""

    if not 2 <= sample_count <= 5:
        raise InstallerError("Egress probe требует 2..5 samples")
    clean_environment: list[str] = ["env"]
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
    ):
        clean_environment.extend(["-u", name])
    command = [
        *clean_environment,
        "curl",
        "--disable",
        "--ipv4",
        "--fail",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "10",
        "--max-time",
        "20",
        "--noproxy",
        "*",
        "--proxy",
        "",
        _EGRESS_URL,
    ]
    observed: list[str] = []
    for _ in range(sample_count):
        result = _must(
            ssh,
            command,
            operation="Прямой Cloudflare egress probe не прошёл",
            timeout=30,
        )
        observed.append(_parse_cloudflare_trace_ipv4(result.stdout))
    unique = set(observed)
    if len(unique) != 1:
        raise VerificationError("Прямой egress IPv4 меняется между запросами")
    return observed[0]
