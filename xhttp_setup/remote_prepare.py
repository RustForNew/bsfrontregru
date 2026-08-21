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
from pathlib import PurePosixPath
from typing import Protocol, Sequence

from .command_output import english_words, parse_ufw_status
from .errors import InstallerError, VerificationError
from .ssh_transport import SSHCommand
from .validate import validate_port


_READ_TIMEOUT = 25
_APT_TIMEOUT = 900
_APT_LOCK_SECONDS = 180
_MUTATION_TIMEOUT = 45
_SYSTEMD_READY_SECONDS = 120
_SYSTEMD_POLL_SECONDS = 2
_GUARD_STOP_SECONDS = 10
_GUARD_STOP_POLL_SECONDS = 0.25
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
_NFT_BASE_DECLARATION = re.compile(
    r"^type filter hook (input|output|forward) priority (?:filter|0); "
    r"policy (accept|drop);$"
)
_NFT_UFW_DISPATCH = re.compile(
    r"^(?:counter packets [0-9]+ bytes [0-9]+ )?"
    r"(?:jump|goto) ([A-Za-z0-9_-]+)$"
)
_HUMAN_DIAGNOSTIC_WORD = re.compile(r"[^\W_]+(?:-[^\W_]+)*")
_NFT_COUNTER = re.compile(r"\bcounter packets [0-9]+ bytes [0-9]+\b")
_IPTABLES_COUNTER = re.compile(r"\[[0-9]+:[0-9]+\]")
_UFW_SHOW_ADDED_HEADER = "Added user rules (see 'ufw status' for running firewall):"
_UFW_SHOW_ADDED_EMPTY = "(None)"
_NFTABLES_MISSING_UNIT_DIAGNOSTIC_WORDS = frozenset(
    {
        english_words(
            "Failed to get unit file state for nftables.service: "
            "No such file or directory"
        ),
        english_words("Unit file nftables.service does not exist."),
    }
)


@dataclass(frozen=True)
class RemoteExitPreparation:
    os_id: str
    version_id: str
    newly_installed_packages: tuple[str, ...]
    ufw_was_active: bool
    ufw_enabled: bool
    ssh_rule_comment: str
    ssh_rule_added: bool


@dataclass(frozen=True)
class _FirewallSnapshot:
    nft: str | None
    iptables_v4: str | None
    iptables_v6: str | None
    iptables_legacy_v4: str | None
    iptables_legacy_v6: str | None


@dataclass(frozen=True)
class _UfwRollbackOutcome:
    restored: bool
    guard_is_armed: bool | None


class UfwRollbackGuard(Protocol):
    """A guard that restores an initially inactive UFW configuration."""

    def is_armed(self, ssh: SSHCommand, *, ssh_port: int) -> bool: ...

    def arm(self, ssh: SSHCommand, *, ssh_port: int) -> None: ...

    def disarm(self, ssh: SSHCommand, *, ssh_port: int) -> None: ...


def _invoke(
    ssh: SSHCommand,
    argv: Sequence[str],
    *,
    timeout: int = _READ_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        return ssh.command(list(argv), check=False, timeout=timeout)
    except InstallerError:
        # SSHTransportError already contains a bounded, secret-redacted
        # OpenSSH diagnostic.  Do not replace it with an opaque wrapper.
        raise
    except Exception as exc:
        raise InstallerError("Удалённая SSH-команда не завершилась") from exc


def _must(
    ssh: SSHCommand,
    argv: Sequence[str],
    *,
    operation: str,
    timeout: int = _READ_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    result = _invoke(ssh, argv, timeout=timeout)
    if result.returncode != 0:
        raise InstallerError(f"{operation}: код {result.returncode}")
    return result


def _require_root(ssh: SSHCommand, *, fresh: bool = False) -> None:
    if fresh:
        result = ssh.fresh_command(["id", "-u"], check=False, timeout=_READ_TIMEOUT)
        if result.returncode != 0:
            raise InstallerError(
                f"Не удалось проверить UID через новое SSH-соединение: "
                f"код {result.returncode}"
            )
    else:
        result = _must(
            ssh,
            ["id", "-u"],
            operation="Не удалось проверить UID удалённого пользователя",
        )
    if result.stdout.strip() != "0":
        raise InstallerError("Автоподготовка выхода требует прямой SSH-вход root")


def _require_systemd(ssh: SSHCommand) -> None:
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
        raise InstallerError(
            "systemd удалённого сервера не находится в рабочем состоянии"
        )


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


def _require_supported_os(ssh: SSHCommand) -> tuple[str, str]:
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
        raise InstallerError("Автоподготовка поддерживает Debian 12+ или Ubuntu 22.04+")
    return os_id, version_id


def _reject_container_runtime(ssh: SSHCommand) -> None:
    result = _invoke(
        ssh,
        [
            "systemctl",
            "list-unit-files",
            "--no-legend",
            "--no-pager",
            "docker.service",
            "docker.socket",
            "containerd.service",
        ],
    )
    # systemctl returns 1, with no output, when none of the exact patterns
    # matches a unit file.  That is the expected clean-host result, not a
    # failure to perform the check.
    if (
        result.returncode == 1
        and not result.stdout.strip()
        and not result.stderr.strip()
    ):
        return
    if result.returncode != 0:
        raise InstallerError(
            "Не удалось проверить Docker/containerd unit-файлы: "
            f"код {result.returncode}"
        )
    if result.stderr.strip():
        raise VerificationError(
            "systemctl вернул неоднозначную диагностику Docker/containerd"
        )
    expected = {"docker.service", "docker.socket", "containerd.service"}
    lines = [line.split() for line in result.stdout.splitlines() if line.strip()]
    if not lines or any(
        len(fields) < 2 or fields[0] not in expected for fields in lines
    ):
        raise VerificationError(
            "systemctl вернул неоднозначный список Docker/containerd unit-файлов"
        )
    found = {fields[0] for fields in lines}
    if found:
        raise InstallerError(
            "Обнаружены Docker/containerd unit-файлы; автоподготовка отказалась"
        )


def _systemd_unit_state(ssh: SSHCommand, operation: str, unit: str) -> tuple[int, str]:
    result = _invoke(ssh, ["systemctl", operation, unit])
    state = result.stdout.strip().lower()
    if result.stderr.strip() or "\n" in state or "\r" in state:
        raise VerificationError(f"systemctl вернул неоднозначное состояние {unit}")
    return result.returncode, state


def _nftables_unit_state(ssh: SSHCommand, operation: str) -> tuple[int, str, str]:
    result = _invoke(
        ssh,
        [
            "env",
            "LC_ALL=C",
            "LANG=C",
            "systemctl",
            operation,
            "nftables.service",
        ],
    )
    state = result.stdout.strip().lower()
    diagnostic = result.stderr.strip()
    if any(char in state or char in diagnostic for char in "\r\n"):
        raise VerificationError(
            "systemctl вернул неоднозначное состояние nftables.service"
        )
    return result.returncode, state, diagnostic


def _reject_standalone_nftables_service(ssh: SSHCommand) -> None:
    active_code, active, active_diagnostic = _nftables_unit_state(ssh, "is-active")
    if active_code == 0 or active == "active":
        raise InstallerError("Обнаружен активный nftables.service")
    # systemd releases differ here: is-active reports an inactive or missing
    # unit with 1, 3, or 4.  The textual state is the stable part of the
    # interface; a zero exit status is never accepted for these states.
    if (
        active_diagnostic
        or active_code not in {1, 3, 4}
        or active
        not in {
            "inactive",
            "unknown",
            "not-found",
        }
    ):
        raise InstallerError("Не удалось однозначно проверить nftables.service")
    enabled_code, enabled, enabled_diagnostic = _nftables_unit_state(ssh, "is-enabled")
    if enabled_code == 0 or enabled in {"enabled", "enabled-runtime", "static"}:
        raise InstallerError("Обнаружен enabled nftables.service")
    disabled = (
        enabled_code in {1, 4}
        and enabled in {"disabled", "masked", "not-found"}
        and not enabled_diagnostic
    )
    missing = (
        enabled_code == 1
        and not enabled
        and english_words(enabled_diagnostic) in _NFTABLES_MISSING_UNIT_DIAGNOSTIC_WORDS
    )
    if not (disabled or missing):
        raise InstallerError(
            "Не удалось однозначно проверить nftables.service enablement"
        )


def _tool_exists(ssh: SSHCommand, name: str) -> bool:
    result = _invoke(ssh, ["command", "-v", name])
    if result.returncode == 0 and result.stdout.strip():
        return True
    if result.returncode == 1 and not result.stdout.strip():
        return False
    raise InstallerError(f"Не удалось однозначно найти удалённую команду {name}")


def _ufw_prefix_for_family(family: str) -> str:
    if family == "ip":
        return "ufw-"
    if family == "ip6":
        return "ufw6-"
    raise InstallerError("Неизвестное семейство UFW ruleset")


def _validate_nft_ruleset(
    payload: str,
    *,
    allow_ufw: bool,
    allow_inactive_ufw_scaffold: bool = False,
) -> None:
    """Validate empty, active-UFW, or harmless inactive-UFW nft state."""

    if allow_ufw and allow_inactive_ufw_scaffold:
        raise ValueError("active and inactive UFW modes are mutually exclusive")
    ufw_mode = allow_ufw or allow_inactive_ufw_scaffold
    current_table: tuple[str, str] | None = None
    current_chain: str | None = None
    seen_tables: set[tuple[str, str]] = set()
    base_chains: set[str] = set()
    base_declarations: set[str] = set()
    ufw_chains: set[str] = set()
    dispatch_targets: set[str] = set()

    def finish_table() -> None:
        if current_table is None:
            return
        if base_chains != set(_BASE_FILTER_CHAINS):
            raise InstallerError("UFW nftables table не содержит точные base chains")
        if base_declarations != set(_BASE_FILTER_CHAINS):
            raise InstallerError("UFW nftables base-chain declaration неоднозначна")
        if not ufw_chains or not dispatch_targets:
            raise InstallerError("UFW nftables table не содержит framework chains")
        if not dispatch_targets.issubset(ufw_chains):
            raise InstallerError("UFW nftables dispatch указывает в неизвестную chain")

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
            table = (family, name)
            if (
                not ufw_mode
                or family not in {"ip", "ip6"}
                or name != "filter"
                or table in seen_tables
            ):
                raise InstallerError("Обнаружена custom nftables table")
            seen_tables.add(table)
            current_table = table
            base_chains = set()
            base_declarations = set()
            ufw_chains = set()
            dispatch_targets = set()
            continue
        chain_match = _NFT_CHAIN.fullmatch(line)
        if chain_match:
            if current_table is None or current_chain is not None:
                raise InstallerError("Неоднозначная nftables chain")
            current_chain = chain_match.group(1)
            prefix = _ufw_prefix_for_family(current_table[0])
            if current_chain in _BASE_FILTER_CHAINS:
                base_chains.add(current_chain)
            elif current_chain.startswith(prefix):
                ufw_chains.add(current_chain)
            else:
                raise InstallerError("Обнаружена custom nftables chain")
            continue
        if line == "}":
            if current_chain is not None:
                current_chain = None
            elif current_table is not None:
                finish_table()
                current_table = None
            else:
                raise InstallerError("Лишняя скобка в nftables ruleset")
            continue
        if current_chain is None or current_table is None:
            raise InstallerError("Обнаружена custom nftables конструкция")
        if current_chain in _BASE_FILTER_CHAINS:
            declaration = _NFT_BASE_DECLARATION.fullmatch(line)
            if declaration:
                hook, policy = declaration.groups()
                if hook != current_chain.lower():
                    raise InstallerError("UFW nftables hook не совпадает с base chain")
                if allow_inactive_ufw_scaffold and policy != "accept":
                    raise InstallerError("Inactive UFW оставил не-ACCEPT policy")
                if current_chain in base_declarations:
                    raise InstallerError("Повторная nftables base-chain declaration")
                base_declarations.add(current_chain)
                continue
            dispatch = _NFT_UFW_DISPATCH.fullmatch(line)
            if dispatch:
                target = dispatch.group(1)
                prefix = _ufw_prefix_for_family(current_table[0])
                if not target.startswith(prefix):
                    raise InstallerError("Cross-family UFW nftables dispatch")
                dispatch_targets.add(target)
                continue
            raise InstallerError("Обнаружена custom nftables base-chain rule")
        if allow_inactive_ufw_scaffold:
            raise InstallerError("Inactive UFW chain содержит выполняемое правило")
    if current_table is not None or current_chain is not None:
        raise InstallerError("Незавершённый nftables ruleset")


def _validate_iptables_save(
    payload: str,
    *,
    allow_ufw: bool,
    ufw_prefix: str = "ufw-",
    allow_inactive_ufw_scaffold: bool = False,
) -> None:
    if allow_ufw and allow_inactive_ufw_scaffold:
        raise ValueError("active and inactive UFW modes are mutually exclusive")
    ufw_mode = allow_ufw or allow_inactive_ufw_scaffold
    table_open = False
    chains: set[str] = set()
    base_chains: set[str] = set()
    ufw_chains: set[str] = set()
    dispatch_targets: set[str] = set()
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
            if chain in _BASE_FILTER_CHAINS:
                if policy not in {"ACCEPT", "DROP"}:
                    raise InstallerError("Обнаружена custom iptables policy")
                if not allow_ufw and policy != "ACCEPT":
                    raise InstallerError("Обнаружена custom iptables policy")
                if allow_inactive_ufw_scaffold and policy != "ACCEPT":
                    raise InstallerError("Inactive UFW оставил не-ACCEPT policy")
                base_chains.add(chain)
            elif ufw_mode and chain.startswith(ufw_prefix):
                if policy != "-":
                    raise InstallerError("Некорректная UFW iptables chain policy")
                ufw_chains.add(chain)
            else:
                raise InstallerError("Обнаружена custom iptables chain")
            chains.add(chain)
            continue
        if line == "COMMIT":
            if not table_open:
                raise InstallerError("Некорректный iptables-save COMMIT")
            if base_chains != set(_BASE_FILTER_CHAINS):
                raise InstallerError("iptables-save не содержит точные base chains")
            if ufw_mode and ufw_chains:
                if not dispatch_targets or not dispatch_targets.issubset(ufw_chains):
                    raise InstallerError("UFW iptables dispatch неоднозначен")
            elif ufw_mode and dispatch_targets:
                raise InstallerError("UFW iptables dispatch без framework chains")
            elif allow_ufw and not ufw_chains:
                raise InstallerError("Active UFW не представлен в iptables-save")
            table_open = False
            chains.clear()
            base_chains.clear()
            ufw_chains.clear()
            dispatch_targets.clear()
            continue
        if line.startswith("-A "):
            fields = shlex.split(line)
            if len(fields) < 4 or fields[1] not in chains:
                raise InstallerError("Некорректная iptables rule")
            chain = fields[1]
            if chain in _BASE_FILTER_CHAINS:
                exact_dispatch = (
                    len(fields) == 4
                    and fields[2] in {"-j", "-g"}
                    and fields[3].startswith(ufw_prefix)
                )
                if not ufw_mode or not exact_dispatch:
                    raise InstallerError("Обнаружена custom iptables base-chain rule")
                dispatch_targets.add(fields[3])
            elif allow_inactive_ufw_scaffold:
                raise InstallerError("Inactive UFW iptables chain содержит rule")
            continue
        raise InstallerError("Обнаружена custom iptables конструкция")
    if table_open:
        raise InstallerError("Незавершённый iptables-save")


def _canonical_nft(payload: str) -> str:
    return "\n".join(
        _NFT_COUNTER.sub("counter packets 0 bytes 0", line.strip())
        for line in payload.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _validate_nft_diagnostics(payload: str, diagnostic: str) -> None:
    """Allow only nft's bounded iptables-nft ownership notices.

    Ubuntu's nft inspector writes one human-readable notice per ip/ip6 filter
    table to stderr even though the command and ruleset are valid.  Match the
    semantic words instead of punctuation and bind every notice to the exact
    set of filter tables already accepted from stdout.
    """

    if not diagnostic.strip():
        return
    expected_tables = {
        match.groups()
        for raw_line in payload.splitlines()
        if (match := _NFT_TABLE.fullmatch(raw_line.strip())) is not None
    }
    warned_tables: list[tuple[str, str]] = []
    expected_words = (
        "warning",
        "table",
        None,
        None,
        "is",
        "managed",
        "by",
        "iptables-nft",
        "do",
        "not",
        "touch",
    )
    for raw_line in diagnostic.splitlines():
        if not raw_line.strip():
            continue
        words = tuple(
            word.casefold() for word in _HUMAN_DIAGNOSTIC_WORD.findall(raw_line)
        )
        if len(words) != len(expected_words) or any(
            expected is not None and actual != expected
            for actual, expected in zip(words, expected_words, strict=True)
        ):
            raise VerificationError("nft вернул неоднозначную диагностику")
        family, name = words[2:4]
        if family not in {"ip", "ip6"} or name != "filter":
            raise VerificationError("nft вернул неоднозначную диагностику")
        warned_tables.append((family, name))
    if (
        not warned_tables
        or len(warned_tables) != len(set(warned_tables))
        or set(warned_tables) != expected_tables
    ):
        raise VerificationError("nft вернул неоднозначную диагностику")


def _canonical_iptables(payload: str) -> str:
    return "\n".join(
        _IPTABLES_COUNTER.sub("[0:0]", line.strip())
        for line in payload.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    )


def _ufw_status(ssh: SSHCommand) -> bool:
    result = _must(
        ssh,
        ["env", "LC_ALL=C", "LANG=C", "ufw", "status", "numbered"],
        operation="Не удалось прочитать состояние UFW",
    )
    if result.stderr.strip():
        raise VerificationError("ufw status numbered вернул предупреждение")
    try:
        return parse_ufw_status(result.stdout)
    except ValueError as exc:
        raise VerificationError("UFW вернул неоднозначное состояние") from exc


def _inspect_firewall(
    ssh: SSHCommand,
    *,
    ufw_active: bool,
    allow_inactive_ufw_scaffold: bool = False,
) -> _FirewallSnapshot:
    _reject_standalone_nftables_service(ssh)
    has_nft = _tool_exists(ssh, "nft")
    nft_payload: str | None = None
    if has_nft:
        nft = _must(
            ssh,
            ["env", "LC_ALL=C", "LANG=C", "nft", "list", "ruleset"],
            operation="Не удалось прочитать nftables ruleset",
        )
        nft_payload = nft.stdout
        _validate_nft_ruleset(
            nft_payload,
            allow_ufw=ufw_active,
            allow_inactive_ufw_scaffold=allow_inactive_ufw_scaffold,
        )
        _validate_nft_diagnostics(nft_payload, nft.stderr)
    has_iptables_save = _tool_exists(ssh, "iptables-save")
    has_ip6tables_save = _tool_exists(ssh, "ip6tables-save")
    if has_iptables_save != has_ip6tables_save:
        raise InstallerError("Доступен только один из IPv4/IPv6 firewall inspectors")
    iptables_v4_payload: str | None = None
    iptables_v6_payload: str | None = None
    if has_iptables_save:
        iptables = _must(
            ssh,
            ["iptables-save"],
            operation="Не удалось прочитать iptables ruleset",
        )
        ip6tables = _must(
            ssh,
            ["ip6tables-save"],
            operation="Не удалось прочитать ip6tables ruleset",
        )
        if iptables.stderr.strip() or ip6tables.stderr.strip():
            raise VerificationError("xtables inspector вернул предупреждение")
        iptables_v4_payload = iptables.stdout
        iptables_v6_payload = ip6tables.stdout
        _validate_iptables_save(
            iptables_v4_payload,
            allow_ufw=ufw_active,
            ufw_prefix="ufw-",
            allow_inactive_ufw_scaffold=allow_inactive_ufw_scaffold,
        )
        _validate_iptables_save(
            iptables_v6_payload,
            allow_ufw=ufw_active,
            ufw_prefix="ufw6-",
            allow_inactive_ufw_scaffold=allow_inactive_ufw_scaffold,
        )
    else:
        for proc_path in (
            "/proc/net/ip_tables_names",
            "/proc/net/ip6_tables_names",
        ):
            exists = _invoke(ssh, ["test", "-e", proc_path])
            if (
                exists.returncode not in {0, 1}
                or exists.stdout.strip()
                or exists.stderr.strip()
            ):
                raise InstallerError("Не удалось проверить legacy iptables tables")
            if exists.returncode == 1:
                continue
            result = _invoke(ssh, ["cat", proc_path])
            if result.returncode != 0 or result.stderr.strip():
                raise InstallerError("Не удалось проверить legacy iptables tables")
            if result.stdout.strip():
                raise InstallerError(
                    "Обнаружены legacy iptables tables без безопасного инспектора"
                )
    return _FirewallSnapshot(
        nft=_canonical_nft(nft_payload) if nft_payload is not None else None,
        iptables_v4=(
            _canonical_iptables(iptables_v4_payload)
            if iptables_v4_payload is not None
            else None
        ),
        iptables_v6=(
            _canonical_iptables(iptables_v6_payload)
            if iptables_v6_payload is not None
            else None
        ),
        iptables_legacy_v4=None,
        iptables_legacy_v6=None,
    )


def _read_ufw_defaults(ssh: SSHCommand) -> None:
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


def _verify_ufw_package_integrity(ssh: SSHCommand) -> None:
    result = _invoke(
        ssh,
        ["env", "LC_ALL=C", "LANG=C", "dpkg", "--verify", "ufw"],
    )
    if result.returncode != 0 or result.stderr.strip():
        raise InstallerError("Не удалось проверить package-owned файлы UFW")
    # Minimal cloud images commonly remove only documentation and man pages.
    # dpkg separates the status and path with padding whose width is not an API.
    # Parse that separator, but keep the status and normalized path allow-list
    # exact so a changed/missing executable or configuration remains fatal.
    harmless_missing_roots = (
        PurePosixPath("/usr/share/doc/ufw"),
        PurePosixPath("/usr/share/man"),
    )

    def harmless_missing(line: str) -> bool:
        fields = line.split(maxsplit=1)
        if len(fields) != 2 or fields[0] != "missing":
            return False
        path = PurePosixPath(fields[1])
        if not path.is_absolute() or ".." in path.parts:
            return False
        return any(root in path.parents for root in harmless_missing_roots)

    unexpected = [
        line.strip()
        for line in result.stdout.splitlines()
        if line.strip() and not harmless_missing(line.strip())
    ]
    if unexpected:
        raise InstallerError("Package-owned UFW configuration изменена")


def _official_empty_ufw_rewrites(prefix: str) -> frozenset[tuple[str, ...]]:
    """Return the complete empty-rule files emitted by upstream UFW 0.36.x."""

    limit = "-m limit --limit 3/min --limit-burst 10"

    def logging_rule(
        chain: str,
        *,
        insert: bool = False,
        prefix_text: str | None = None,
        before_log: str = "",
        after_log: str = "",
        target: str = "LOG",
    ) -> str:
        operation = "-I" if insert else "-A"
        fields = [operation, chain]
        if before_log:
            fields.append(before_log)
        fields.extend(["-j", target])
        if prefix_text is not None:
            fields.extend(["--log-prefix", f'"[{prefix_text}] "'])
        if after_log:
            fields.append(after_log)
        return " ".join(fields)

    after_input = f"{prefix}-after-logging-input"
    after_output = f"{prefix}-after-logging-output"
    after_forward = f"{prefix}-after-logging-forward"
    logging_deny = f"{prefix}-logging-deny"
    logging_allow = f"{prefix}-logging-allow"
    before = tuple(
        f"{prefix}-before-logging-{direction}"
        for direction in ("input", "output", "forward")
    )

    logging_by_level = {
        "off": tuple(
            f"-I {prefix}-user-logging-{direction} -j RETURN"
            for direction in ("input", "output", "forward")
        ),
        "low": (
            logging_rule(after_input, prefix_text="UFW BLOCK", after_log=limit),
            logging_rule(after_forward, prefix_text="UFW BLOCK", after_log=limit),
            logging_rule(
                logging_deny,
                insert=True,
                before_log="-m conntrack --ctstate INVALID",
                target="RETURN",
                after_log=limit,
            ),
            logging_rule(logging_deny, prefix_text="UFW BLOCK", after_log=limit),
            logging_rule(logging_allow, prefix_text="UFW ALLOW", after_log=limit),
        ),
        "medium": (
            logging_rule(after_input, prefix_text="UFW BLOCK", after_log=limit),
            logging_rule(after_output, prefix_text="UFW ALLOW", after_log=limit),
            logging_rule(after_forward, prefix_text="UFW BLOCK", after_log=limit),
            logging_rule(
                logging_deny,
                before_log="-m conntrack --ctstate INVALID",
                prefix_text="UFW AUDIT INVALID",
                after_log=limit,
            ),
            logging_rule(logging_deny, prefix_text="UFW BLOCK", after_log=limit),
            logging_rule(logging_allow, prefix_text="UFW ALLOW", after_log=limit),
            *(
                logging_rule(
                    chain,
                    insert=True,
                    prefix_text="UFW AUDIT",
                    after_log=f"-m conntrack --ctstate NEW {limit}",
                )
                for chain in before
            ),
        ),
        "high": (
            logging_rule(after_input, prefix_text="UFW BLOCK"),
            logging_rule(after_output, prefix_text="UFW ALLOW"),
            logging_rule(after_forward, prefix_text="UFW BLOCK"),
            logging_rule(
                logging_deny,
                before_log="-m conntrack --ctstate INVALID",
                prefix_text="UFW AUDIT INVALID",
            ),
            logging_rule(logging_deny, prefix_text="UFW BLOCK"),
            logging_rule(logging_allow, prefix_text="UFW ALLOW"),
            *(
                logging_rule(
                    chain,
                    insert=True,
                    prefix_text="UFW AUDIT",
                    after_log=limit,
                )
                for chain in before
            ),
        ),
        "full": (
            logging_rule(after_input, prefix_text="UFW BLOCK"),
            logging_rule(after_output, prefix_text="UFW ALLOW"),
            logging_rule(after_forward, prefix_text="UFW BLOCK"),
            logging_rule(
                logging_deny,
                before_log="-m conntrack --ctstate INVALID",
                prefix_text="UFW AUDIT INVALID",
            ),
            logging_rule(logging_deny, prefix_text="UFW BLOCK"),
            logging_rule(logging_allow, prefix_text="UFW ALLOW"),
            *(
                logging_rule(chain, insert=True, prefix_text="UFW AUDIT")
                for chain in before
            ),
        ),
    }

    ordinary_chains = tuple(
        f":{prefix}-{name} - [0:0]"
        for name in (
            "user-input",
            "user-output",
            "user-forward",
            "before-logging-input",
            "before-logging-output",
            "before-logging-forward",
            "user-logging-input",
            "user-logging-output",
            "user-logging-forward",
            "after-logging-input",
            "after-logging-output",
            "after-logging-forward",
            "logging-deny",
            "logging-allow",
        )
    )
    variants: set[tuple[str, ...]] = set()
    for level, logging in logging_by_level.items():
        for has_rate_limiting in (False, True):
            lines = ["*filter", *ordinary_chains]
            if has_rate_limiting:
                lines.extend(
                    (
                        f":{prefix}-user-limit - [0:0]",
                        f":{prefix}-user-limit-accept - [0:0]",
                    )
                )
            lines.extend(
                (
                    "### RULES ###",
                    "",
                    "### END RULES ###",
                    "",
                    "### LOGGING ###",
                    *logging,
                    "### END LOGGING ###",
                )
            )
            if has_rate_limiting:
                lines.extend(("", "### RATE LIMITING ###"))
                if level != "off":
                    lines.append(
                        f"-A {prefix}-user-limit -m limit --limit 3/minute "
                        '-j LOG --log-prefix "[UFW LIMIT BLOCK] "'
                    )
                lines.extend(
                    (
                        f"-A {prefix}-user-limit -j REJECT",
                        f"-A {prefix}-user-limit-accept -j ACCEPT",
                        "### END RATE LIMITING ###",
                    )
                )
            lines.append("COMMIT")
            variants.add(tuple(lines))
    return frozenset(variants)


def _require_empty_ufw_user_rule_section(
    ssh: SSHCommand,
    path: str,
    *,
    template_path: str,
) -> None:
    layouts = {
        (
            "/etc/ufw/user.rules",
            "/usr/share/ufw/iptables/user.rules",
        ): "ufw",
        (
            "/etc/ufw/user6.rules",
            "/usr/share/ufw/iptables/user6.rules",
        ): "ufw6",
    }
    prefix = layouts.get((path, template_path))
    if prefix is None:
        raise InstallerError(f"{path} содержит dormant user rules")

    result = _must(
        ssh,
        ["cat", path],
        operation=f"Не удалось прочитать {path}",
    )
    if result.stderr.strip():
        raise VerificationError(f"{path} вернул неоднозначную диагностику")
    lines = result.stdout.splitlines()
    starts = [index for index, line in enumerate(lines) if line == "### RULES ###"]
    ends = [index for index, line in enumerate(lines) if line == "### END RULES ###"]
    if len(starts) != 1:
        raise VerificationError(f"{path} не содержит однозначный UFW RULES section")

    # A rewritten UFW 0.36.x file contains executable logging and rate-limit
    # sections outside RULES.  Accept only complete upstream-generated empty
    # layouts; checking the delimited body alone would miss dormant rules.
    if ends:
        if len(ends) != 1 or starts[0] >= ends[0]:
            raise VerificationError(f"{path} не содержит однозначный UFW RULES section")
        if tuple(lines) not in _official_empty_ufw_rewrites(prefix):
            raise InstallerError(f"{path} содержит dormant user rules")
        return

    # Fresh UFW 0.36.x package seeds have no END marker.  Their IPv4 seed also
    # contains three built-in rate-limit rules, so a generic "empty after
    # START" check is both wrong and unsafe.  Compare against the pristine
    # template installed by this exact distro package; dpkg --verify has
    # already checked that package-owned file against local dpkg metadata.
    template = _must(
        ssh,
        ["cat", template_path],
        operation=f"Не удалось прочитать штатный шаблон {template_path}",
    )
    if template.stderr.strip():
        raise VerificationError(f"{template_path} вернул неоднозначную диагностику")
    if result.stdout != template.stdout:
        raise InstallerError(f"{path} содержит dormant user rules")


def _ufw_added_commands(ssh: SSHCommand) -> list[list[str]]:
    result = _must(
        ssh,
        ["env", "LC_ALL=C", "LANG=C", "ufw", "show", "added"],
        operation="Не удалось прочитать сохранённые UFW rules",
    )
    if result.stderr.strip():
        raise VerificationError("ufw show added вернул неоднозначную диагностику")
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines or english_words(lines[0]) != english_words(_UFW_SHOW_ADDED_HEADER):
        raise VerificationError("ufw show added не вернул ожидаемый заголовок")
    body = lines[1:]
    # UFW 0.36.x emits a literal `(None)` for an empty saved-rule set.  The
    # marker carries the same meaning as the historical header-only form, but
    # it must never be accepted alongside commands or other data.
    if len(body) == 1 and english_words(body[0]) == english_words(
        _UFW_SHOW_ADDED_EMPTY
    ):
        return []
    commands: list[list[str]] = []
    for line in body:
        try:
            command = shlex.split(line)
        except ValueError as exc:
            raise VerificationError("Некорректный вывод ufw show added") from exc
        if not command or command[0] != "ufw":
            raise VerificationError("ufw show added содержит неизвестную строку")
        commands.append(command)
    return commands


def _require_owned_active_ufw(ssh: SSHCommand, *, ssh_port: int) -> None:
    if _ufw_added_commands(ssh) != [_expected_ssh_rule(ssh_port)]:
        raise InstallerError(
            "UFW active, но не содержит единственную exact managed SSH rule "
            "текущего порта"
        )


def _require_pristine_inactive_ufw(ssh: SSHCommand) -> None:
    _verify_ufw_package_integrity(ssh)
    _read_ufw_defaults(ssh)
    if _ufw_added_commands(ssh):
        raise InstallerError(
            "UFW inactive, но содержит foreign rules; автоподготовка отказалась"
        )
    _require_empty_ufw_user_rule_section(
        ssh,
        "/etc/ufw/user.rules",
        template_path="/usr/share/ufw/iptables/user.rules",
    )
    _require_empty_ufw_user_rule_section(
        ssh,
        "/etc/ufw/user6.rules",
        template_path="/usr/share/ufw/iptables/user6.rules",
    )


def _missing_packages(ssh: SSHCommand) -> tuple[str, ...]:
    missing: list[str] = []
    for package in _PACKAGES:
        result = _invoke(
            ssh,
            [
                "env",
                "LC_ALL=C",
                "LANG=C",
                "dpkg-query",
                "--show",
                "--showformat=${db:Status-Abbrev}",
                package,
            ],
        )
        if result.returncode == 0 and not result.stderr:
            if result.stdout == "ii ":
                continue
            # Known to dpkg, but never installed: desired=unknown,
            # status=not-installed, error=blank.
            if result.stdout == "un ":
                missing.append(package)
                continue
        not_known = (
            result.returncode == 1
            and not result.stdout
            and bool(result.stderr.strip())
            and not any(char in result.stderr.strip() for char in "\r\n")
        )
        if not_known:
            missing.append(package)
            continue
        raise InstallerError(f"Не удалось проверить пакет {package}")
    return tuple(missing)


def _install_packages(ssh: SSHCommand, packages: tuple[str, ...]) -> None:
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


def _verify_python(ssh: SSHCommand) -> None:
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
        "null=subprocess.DEVNULL;"
        "result=subprocess.run(['/usr/sbin/ufw','--force','disable'],"
        "stdout=null,stderr=null,check=False);"
        "sys.exit(result.returncode)"
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

    def is_armed(self, ssh: SSHCommand, *, ssh_port: int) -> bool:
        states = []
        for unit in self._units(ssh_port):
            code, state = _systemd_unit_state(ssh, "is-active", unit)
            states.append(self._state_is_running(code, state, unit=unit))
        return any(states)

    def arm(self, ssh: SSHCommand, *, ssh_port: int) -> None:
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
            ],
            operation="Не удалось включить автоматический UFW rollback guard",
            timeout=_MUTATION_TIMEOUT,
        )

    def disarm(self, ssh: SSHCommand, *, ssh_port: int) -> None:
        timer, service = self._units(ssh_port)
        # Stop both units in one systemd transaction.  Stopping only the timer
        # is racy: it may already have activated the rollback service.
        _invoke(
            ssh,
            ["systemctl", "stop", timer, service],
            timeout=_MUTATION_TIMEOUT,
        )
        deadline = time.monotonic() + _GUARD_STOP_SECONDS
        while self.is_armed(ssh, ssh_port=ssh_port):
            if time.monotonic() >= deadline:
                raise VerificationError("UFW rollback guard остался активным")
            time.sleep(_GUARD_STOP_POLL_SECONDS)


def _remove_inactive_managed_ssh_rule(ssh: SSHCommand, *, ssh_port: int) -> None:
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
            "comment",
            _ssh_rule_comment(ssh_port),
        ],
        operation="Не удалось удалить SSH rule после UFW guard recovery",
        timeout=_MUTATION_TIMEOUT,
    )
    if _ufw_status(ssh) or _ufw_added_commands(ssh):
        raise VerificationError("UFW guard recovery не вернул pristine inactive state")


def _reconcile_orphaned_inactive_ssh_rule(
    ssh: SSHCommand,
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
    ssh: SSHCommand,
    *,
    ssh_port: int,
    guard: UfwRollbackGuard,
) -> bool:
    """Quiesce an owned stale guard and return the resulting UFW active state."""

    # This is a genuinely fresh SSH process.  Do not cancel the safety timer
    # merely because the original process resumed locally.
    _require_root(ssh, fresh=True)
    before_active = _ufw_status(ssh)
    before_rules = _ufw_added_commands(ssh)
    expected = [_expected_ssh_rule(ssh_port)]
    safe_before = (before_active and before_rules == expected) or (
        not before_active and before_rules in ([], expected)
    )
    if not safe_before:
        raise InstallerError(
            "Обнаружен stale UFW rollback guard с неожиданными rules; "
            "он оставлен для безопасного rollback"
        )
    _inspect_firewall(
        ssh,
        ufw_active=before_active,
        allow_inactive_ufw_scaffold=not before_active,
    )

    # disarm() stops both the timer and an already-running service.  The
    # commands below then prove that nothing raced with that stop.
    guard.disarm(ssh, ssh_port=ssh_port)
    _require_root(ssh, fresh=True)
    after_active = _ufw_status(ssh)
    after_rules = _ufw_added_commands(ssh)
    safe_after = (after_active and after_rules == expected) or (
        not after_active and after_rules in ([], expected)
    )
    if not safe_after:
        raise InstallerError(
            "UFW rollback service успел изменить firewall; повторите запуск "
            "после проверки доступа по SSH"
        )
    _inspect_firewall(
        ssh,
        ufw_active=after_active,
        allow_inactive_ufw_scaffold=not after_active,
    )
    if after_active:
        return True
    if after_rules == expected:
        _remove_inactive_managed_ssh_rule(ssh, ssh_port=ssh_port)
    return False


def _rollback_new_ufw(
    ssh: SSHCommand,
    *,
    ssh_port: int,
    guard: UfwRollbackGuard,
    guard_armed: bool,
    allow_attempted: bool,
    enable_attempted: bool,
) -> _UfwRollbackOutcome:
    try:
        if enable_attempted:
            _must(
                ssh,
                ["env", "LC_ALL=C", "LANG=C", "ufw", "--force", "disable"],
                operation="Не удалось отключить UFW при rollback",
                timeout=_MUTATION_TIMEOUT,
            )
        if allow_attempted:
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
                    "comment",
                    _ssh_rule_comment(ssh_port),
                ],
                operation="Не удалось удалить SSH rule при rollback",
                timeout=_MUTATION_TIMEOUT,
            )
        if _ufw_status(ssh):
            raise VerificationError("UFW остался active после rollback")
        if _ufw_added_commands(ssh):
            raise VerificationError("SSH rule осталась после UFW rollback")
        _require_pristine_inactive_ufw(ssh)
        # The first enable/disable cycle legitimately turns a fresh package
        # seed into UFW's generated empty user-rule files and can leave an
        # inert ACCEPT-policy framework in the kernel.  Exact snapshot
        # equality would reject that representation-only transition.  The
        # validators above and below prove the stronger recovery contract:
        # no saved user rules, only official empty files, and no executable
        # rule outside a harmless inactive UFW scaffold.
        _inspect_firewall(
            ssh,
            ufw_active=False,
            allow_inactive_ufw_scaffold=True,
        )
        if guard_armed:
            guard.disarm(ssh, ssh_port=ssh_port)
        # A timer may already have activated its service when disarm starts.
        # disarm() waits for both units to stop, but that service can mutate
        # UFW while being stopped.  Prove the complete recovery contract once
        # more through a genuinely fresh SSH process after the guard is
        # quiescent; the pre-disarm proof alone is racy.
        _require_root(ssh, fresh=True)
        if _ufw_status(ssh):
            raise VerificationError("UFW снова стал active после остановки guard")
        if _ufw_added_commands(ssh):
            raise VerificationError("SSH rule появилась после остановки guard")
        _require_pristine_inactive_ufw(ssh)
        _inspect_firewall(
            ssh,
            ufw_active=False,
            allow_inactive_ufw_scaffold=True,
        )
        return _UfwRollbackOutcome(restored=True, guard_is_armed=False)
    except Exception:
        try:
            actual_guard_state = guard.is_armed(ssh, ssh_port=ssh_port)
        except Exception:
            actual_guard_state = None
        return _UfwRollbackOutcome(
            restored=False,
            guard_is_armed=actual_guard_state,
        )


def _enable_pristine_ufw(
    ssh: SSHCommand,
    *,
    ssh_port: int,
    rollback_guard: UfwRollbackGuard,
) -> None:
    comment = _ssh_rule_comment(ssh_port)
    _inspect_firewall(
        ssh,
        ufw_active=False,
        allow_inactive_ufw_scaffold=True,
    )
    guard_armed = False
    allow_attempted = False
    enable_attempted = False
    stage = "guard-arm"
    try:
        # Arm before the first UFW mutation: a timed-out allow command may have
        # already persisted one IP family even when its SSH result is unknown.
        guard_armed = True
        rollback_guard.arm(ssh, ssh_port=ssh_port)
        stage = "guard-verify"
        if not rollback_guard.is_armed(ssh, ssh_port=ssh_port):
            raise VerificationError(
                "UFW rollback guard не подтвердил active timer до firewall mutation"
            )
        stage = "ssh-rule-add"
        allow_attempted = True
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
        stage = "ssh-rule-verify"
        added = _ufw_added_commands(ssh)
        if added != [_expected_ssh_rule(ssh_port)]:
            raise VerificationError("UFW не подтвердил единственную managed SSH rule")
        stage = "ufw-enable"
        enable_attempted = True
        _must(
            ssh,
            ["env", "LC_ALL=C", "LANG=C", "ufw", "--force", "enable"],
            operation="Не удалось включить UFW",
            timeout=_MUTATION_TIMEOUT,
        )
        # A mux session would otherwise reuse the pre-firewall TCP connection.
        # Keep it alive for rollback, but prove that a genuinely new SSH
        # connection can enter through the enabled firewall.
        stage = "fresh-ssh-after-enable"
        _require_root(ssh, fresh=True)
        stage = "ufw-status-after-enable"
        if not _ufw_status(ssh):
            raise VerificationError("UFW не стал active после enable")
        stage = "ufw-rules-after-enable"
        if _ufw_added_commands(ssh) != [_expected_ssh_rule(ssh_port)]:
            raise VerificationError(
                "После enable UFW содержит не только managed SSH rule"
            )
        stage = "guard-disarm"
        rollback_guard.disarm(ssh, ssh_port=ssh_port)
        guard_armed = False
        # The timer may have activated its service at the disarm boundary.
        # Prove the post-quiescence firewall state with another fresh SSH
        # process before reporting success.
        stage = "fresh-ssh-after-guard"
        _require_root(ssh, fresh=True)
        stage = "ufw-status-after-guard"
        if not _ufw_status(ssh):
            raise VerificationError(
                "UFW стал inactive во время остановки rollback guard"
            )
        stage = "ufw-rules-after-guard"
        if _ufw_added_commands(ssh) != [_expected_ssh_rule(ssh_port)]:
            raise VerificationError(
                "Rollback service изменил managed SSH rule во время остановки"
            )
        stage = "firewall-inspect-after-guard"
        _inspect_firewall(ssh, ufw_active=True)
    except BaseException as original:
        rollback = _rollback_new_ufw(
            ssh,
            ssh_port=ssh_port,
            guard=rollback_guard,
            guard_armed=guard_armed,
            allow_attempted=allow_attempted,
            enable_attempted=enable_attempted,
        )
        if rollback.restored:
            raise InstallerError(
                "UFW enable не прошёл проверку на этапе "
                f"{stage}; исходное inactive-состояние восстановлено"
            ) from original
        if rollback.guard_is_armed is True:
            recovery = "автоматический rollback guard оставлен активным"
        elif rollback.guard_is_armed is False:
            recovery = "rollback не подтверждён; rollback guard не активен"
        else:
            recovery = "rollback не подтверждён; состояние rollback guard неизвестно"
        raise InstallerError(
            f"UFW enable не прошёл проверку на этапе {stage}; {recovery}"
        ) from original


def prepare_remote_exit(
    ssh: SSHCommand,
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
    if ufw_present and not ufw_was_active:
        _reconcile_orphaned_inactive_ssh_rule(ssh, ssh_port=ssh_port)
        _require_pristine_inactive_ufw(ssh)
    elif ufw_was_active:
        _require_owned_active_ufw(ssh, ssh_port=ssh_port)
    _inspect_firewall(
        ssh,
        ufw_active=ufw_was_active,
        allow_inactive_ufw_scaffold=ufw_present and not ufw_was_active,
    )

    missing = _missing_packages(ssh)
    _install_packages(ssh, missing)
    _verify_python(ssh)

    ufw_active = _ufw_status(ssh)
    if not ufw_active:
        _require_pristine_inactive_ufw(ssh)
    else:
        _require_owned_active_ufw(ssh, ssh_port=ssh_port)
    _inspect_firewall(
        ssh,
        ufw_active=ufw_active,
        allow_inactive_ufw_scaffold=not ufw_active,
    )
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
    values = []
    for line in payload.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().casefold() == "ip":
            values.append(value.strip())
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
    ssh: SSHCommand,
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
