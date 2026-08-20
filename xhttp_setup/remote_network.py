"""Conservative remote UFW management for a clean exit host.

This module intentionally manages only two numbered UFW rules.  It never
enables UFW, changes its defaults, edits SSH access, starts services, or applies
the broader optional network profile from :mod:`xhttp_setup.exit_network`.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from typing import Sequence

from .errors import InstallerError, ValidationError, VerificationError
from .exit_network import ExitNetworkProfile
from .ssh_transport import SSHClient


_READ_TIMEOUT = 20
_MUTATION_TIMEOUT = 30
_MANAGED_ALLOW_PREFIX = "xhttp-setup-allow-"
_MANAGED_DENY_PREFIX = "xhttp-setup-deny-"
_NUMBERED_UFW_LINE = re.compile(r"^\s*\[\s*(\d+)\]\s+(.*)$")
_NFT_TABLE = re.compile(r"^table\s+(\S+)\s+(\S+)\s*\{$")
_NFT_CHAIN = re.compile(r"^chain\s+(\S+)\s*\{$")
_CONTAINER_MARKER = re.compile(
    r"(?:^|[^a-z0-9])(docker|containerd|podman|cni|kube)(?:[^a-z0-9]|$)",
    re.IGNORECASE,
)
_BASE_FILTER_CHAINS = frozenset({"INPUT", "OUTPUT", "FORWARD"})


@dataclass(frozen=True)
class RemoteExitNetworkState:
    os_id: str
    ufw_allow_indices: tuple[int, ...]
    ufw_deny_indices: tuple[int, ...]


@dataclass(frozen=True)
class RemoteExitNetworkApplyResult:
    profile: ExitNetworkProfile
    allow_comment: str
    deny_comment: str
    ufw_allow_added: bool
    ufw_deny_added: bool


@dataclass(frozen=True)
class RemoteExitNetworkRollbackResult:
    ufw_allow_removed: bool
    ufw_deny_removed: bool


@dataclass(frozen=True)
class _UfwState:
    active: bool
    allow_indices: tuple[int, ...]
    deny_indices: tuple[int, ...]


def _allow_comment(profile: ExitNetworkProfile) -> str:
    return f"{_MANAGED_ALLOW_PREFIX}{profile.backend_port}-{profile.frontend_ipv4}"


def _deny_comment(profile: ExitNetworkProfile) -> str:
    return f"{_MANAGED_DENY_PREFIX}{profile.backend_port}"


def _invoke(
    ssh: SSHClient,
    argv: Sequence[str],
    *,
    timeout: int = _READ_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        return ssh.command(list(argv), check=False, timeout=timeout)
    except Exception as exc:
        # Do not propagate transport text: it can contain provider-side details.
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


def _require_remote_root(ssh: SSHClient) -> None:
    result = _must(
        ssh,
        ["id", "-u"],
        operation="Не удалось проверить UID удалённого пользователя",
    )
    if result.stdout.strip() != "0":
        raise InstallerError("Удалённый сетевой apply требует прямой SSH-вход root")


def _read_os_id(ssh: SSHClient) -> str:
    result = _must(
        ssh,
        ["cat", "/etc/os-release"],
        operation="Не удалось прочитать /etc/os-release",
    )
    os_id = ""
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip() == "ID":
            os_id = value.strip().strip("\"'").lower()
            break
    if not re.fullmatch(r"[a-z0-9._-]+", os_id):
        raise VerificationError("Удалённый /etc/os-release не содержит безопасный ID")
    if os_id not in {"debian", "ubuntu"}:
        raise InstallerError(
            "Удалённый сетевой apply поддерживает только Debian/Ubuntu"
        )
    return os_id


def _reject_docker_units(ssh: SSHClient) -> None:
    units = _must(
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
        operation="Не удалось проверить Docker unit-файлы",
    )
    found: list[str] = []
    expected = {"docker.service", "docker.socket", "containerd.service"}
    for line in units.stdout.splitlines():
        fields = line.split()
        if fields and fields[0] in expected:
            found.append(fields[0])
    if found:
        raise InstallerError(
            "Обнаружены Docker/containerd unit-файлы; remote UFW apply отказался"
        )


def _systemd_state(
    ssh: SSHClient,
    operation: str,
) -> tuple[int, str]:
    result = _invoke(
        ssh,
        ["systemctl", operation, "nftables.service"],
    )
    state = result.stdout.strip().lower()
    if "\n" in state or "\r" in state:
        raise VerificationError("systemctl вернул неоднозначное состояние nftables")
    return result.returncode, state


def _reject_nftables_service(ssh: SSHClient) -> None:
    active_code, active = _systemd_state(ssh, "is-active")
    if active_code == 0 or active == "active":
        raise InstallerError("Обнаружен активный nftables.service")
    if active_code not in {1, 3, 4} or active not in {
        "inactive",
        "unknown",
        "not-found",
    }:
        raise InstallerError("Не удалось однозначно проверить nftables.service")

    enabled_code, enabled = _systemd_state(ssh, "is-enabled")
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


def _validate_nft_ruleset(output: str) -> None:
    """Allow only an empty ruleset or the normal iptables-nft UFW filter shape."""

    current_table: tuple[str, str] | None = None
    current_chain: str | None = None
    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if _CONTAINER_MARKER.search(line):
            raise InstallerError("Обнаружены container-managed nftables rules")
        if line.startswith("#"):
            continue

        table_match = _NFT_TABLE.fullmatch(line)
        if table_match:
            if current_table is not None or current_chain is not None:
                raise InstallerError("Неоднозначная вложенность nftables ruleset")
            family, name = table_match.groups()
            if family not in {"ip", "ip6"} or name != "filter":
                raise InstallerError("Обнаружена custom nftables table")
            current_table = (family, name)
            continue

        chain_match = _NFT_CHAIN.fullmatch(line)
        if chain_match:
            if current_table is None or current_chain is not None:
                raise InstallerError("Неоднозначная nftables chain")
            current_chain = chain_match.group(1)
            if (
                current_chain not in _BASE_FILTER_CHAINS
                and not current_chain.startswith("ufw-")
            ):
                raise InstallerError("Обнаружена custom nftables chain")
            continue

        if line == "}":
            if current_chain is not None:
                current_chain = None
            elif current_table is not None:
                current_table = None
            else:
                raise InstallerError("Лишняя закрывающая скобка nftables ruleset")
            continue

        if current_chain is None:
            raise InstallerError("Обнаружена custom nftables конструкция")
        if current_chain in _BASE_FILTER_CHAINS:
            is_base_declaration = line.startswith("type filter hook ")
            is_ufw_dispatch = bool(
                re.search(r"\b(?:jump|goto)\s+ufw-[A-Za-z0-9_-]+\b", line)
            )
            if not (is_base_declaration or is_ufw_dispatch):
                raise InstallerError("Обнаружена custom rule в base nftables chain")

    if current_chain is not None or current_table is not None:
        raise InstallerError("Незавершённый nftables ruleset")


def _reject_custom_nftables(ssh: SSHClient) -> None:
    _reject_nftables_service(ssh)
    ruleset = _must(
        ssh,
        ["nft", "list", "ruleset"],
        operation="Не удалось прочитать nftables ruleset",
    )
    _validate_nft_ruleset(ruleset.stdout)


def _ufw_command(*argv: str) -> list[str]:
    return ["env", "LC_ALL=C", "LANG=C", "ufw", *argv]


def _numbered_rule_lines(output: str, comment: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for line in output.splitlines():
        head, separator, tail = line.rpartition("#")
        if not separator or tail.strip() != comment:
            continue
        match = _NUMBERED_UFW_LINE.match(head)
        if not match:
            raise InstallerError("Некорректная managed UFW rule")
        found.append((int(match.group(1)), match.group(2).strip()))
    return found


def _inspect_ufw(ssh: SSHClient, profile: ExitNetworkProfile) -> _UfwState:
    result = _must(
        ssh,
        _ufw_command("status", "numbered"),
        operation="Не удалось прочитать состояние UFW",
    )
    status_lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    active = bool(status_lines) and status_lines[0] == "Status: active"
    if not active:
        return _UfwState(False, (), ())

    allow_comment = _allow_comment(profile)
    deny_comment = _deny_comment(profile)
    allow_lines = _numbered_rule_lines(result.stdout, allow_comment)
    deny_lines = _numbered_rule_lines(result.stdout, deny_comment)

    allow_namespace = f"{_MANAGED_ALLOW_PREFIX}{profile.backend_port}-"
    for line in result.stdout.splitlines():
        _, separator, tail = line.rpartition("#")
        comment = tail.strip() if separator else ""
        if comment.startswith(allow_namespace) and comment != allow_comment:
            raise InstallerError(
                "Обнаружена managed UFW allow rule для другого frontend IPv4"
            )

    if len(allow_lines) > 1:
        raise InstallerError("Обнаружены дубли managed UFW allow rule")
    expected_port = re.escape(str(profile.backend_port))
    expected_ip = re.escape(profile.frontend_ipv4)
    for _, rule in allow_lines:
        if not re.search(rf"(?<!\d){expected_port}/tcp\b", rule) or not re.search(
            rf"\bALLOW IN\s+{expected_ip}(?:/32)?\s*$", rule
        ):
            raise InstallerError("Managed UFW allow comment занят другой rule")
    for _, rule in deny_lines:
        if not re.search(rf"(?<!\d){expected_port}/tcp\b", rule) or not re.search(
            r"\bDENY IN\s+Anywhere(?:\s+\(v6\))?\s*$", rule
        ):
            raise InstallerError("Managed UFW deny comment занят другой rule")

    allow_indices = tuple(index for index, _ in allow_lines)
    ipv4_deny = tuple(index for index, rule in deny_lines if "(v6)" not in rule)
    ipv6_deny = tuple(index for index, rule in deny_lines if "(v6)" in rule)
    if len(ipv4_deny) > 1 or len(ipv6_deny) > 1:
        raise InstallerError("Обнаружены дубли managed UFW deny rule")
    if deny_lines and not ipv4_deny:
        raise InstallerError("Managed UFW deny rule существует только для IPv6")
    if allow_indices and allow_indices[0] != 1:
        raise InstallerError("Managed UFW frontend allow rule не стоит первой")
    if ipv4_deny:
        expected_deny_index = 2 if allow_indices else 1
        if ipv4_deny[0] != expected_deny_index:
            raise InstallerError(
                "Managed UFW backend deny rule не стоит сразу после frontend allow"
            )
    return _UfwState(
        True,
        allow_indices,
        tuple(index for index, _ in deny_lines),
    )


def preflight_remote_exit_network(
    ssh: SSHClient,
    profile: ExitNetworkProfile,
) -> RemoteExitNetworkState:
    """Read and validate remote network state without making mutations."""

    profile = profile.validate()
    _require_remote_root(ssh)
    os_id = _read_os_id(ssh)
    _reject_docker_units(ssh)
    _reject_custom_nftables(ssh)
    ufw = _inspect_ufw(ssh, profile)
    if not ufw.active:
        raise InstallerError(
            "UFW inactive/unknown: remote apply отказался включать или перенастраивать его"
        )
    return RemoteExitNetworkState(
        os_id=os_id,
        ufw_allow_indices=ufw.allow_indices,
        ufw_deny_indices=ufw.deny_indices,
    )


def _delete_comment(
    ssh: SSHClient,
    profile: ExitNetworkProfile,
    comment: str,
) -> bool:
    state = _inspect_ufw(ssh, profile)
    if not state.active:
        raise InstallerError("UFW стал inactive/unknown во время rollback")
    if comment == _allow_comment(profile):
        indices = state.allow_indices
    elif comment == _deny_comment(profile):
        indices = state.deny_indices
    else:  # pragma: no cover - internal invariant
        raise ValidationError("Неизвестный managed UFW comment")
    if not indices:
        return False
    for index in sorted(indices, reverse=True):
        _must(
            ssh,
            _ufw_command("--force", "delete", str(index)),
            operation=f"Не удалось удалить managed UFW rule {comment}",
            timeout=_MUTATION_TIMEOUT,
        )
    after = _inspect_ufw(ssh, profile)
    remaining = (
        after.allow_indices
        if comment == _allow_comment(profile)
        else after.deny_indices
    )
    if remaining:
        raise VerificationError(f"Managed UFW rule {comment} осталась после rollback")
    return True


def _rollback_actions(
    ssh: SSHClient,
    profile: ExitNetworkProfile,
    comments: Sequence[tuple[str, str]],
) -> tuple[bool, bool]:
    allow_removed = False
    deny_removed = False
    errors: list[str] = []
    for name, comment in reversed(comments):
        try:
            removed = _delete_comment(ssh, profile, comment)
            if comment == _allow_comment(profile):
                allow_removed = allow_removed or removed
            else:
                deny_removed = deny_removed or removed
        except Exception:
            errors.append(name)
    if errors:
        raise InstallerError("rollback неполон: " + ", ".join(errors))
    return allow_removed, deny_removed


def apply_remote_exit_network(
    ssh: SSHClient,
    profile: ExitNetworkProfile,
) -> RemoteExitNetworkApplyResult:
    """Insert only the exact managed UFW allow/deny pair and verify SSH survives."""

    profile = profile.validate()
    before = preflight_remote_exit_network(ssh, profile)
    allow_comment = _allow_comment(profile)
    deny_comment = _deny_comment(profile)
    attempted: list[tuple[str, str]] = []
    allow_added = False
    deny_added = False
    try:
        if not before.ufw_allow_indices:
            attempted.append(("UFW frontend allow", allow_comment))
            _must(
                ssh,
                _ufw_command(
                    "insert",
                    "1",
                    "allow",
                    "from",
                    f"{profile.frontend_ipv4}/32",
                    "to",
                    "any",
                    "port",
                    str(profile.backend_port),
                    "proto",
                    "tcp",
                    "comment",
                    allow_comment,
                ),
                operation="Не удалось добавить UFW frontend allow rule",
                timeout=_MUTATION_TIMEOUT,
            )
            allow_added = True

        after_allow = _inspect_ufw(ssh, profile)
        if not after_allow.allow_indices:
            raise VerificationError("UFW не подтвердил managed frontend allow rule")
        if not after_allow.deny_indices:
            attempted.append(("UFW backend deny", deny_comment))
            insert_at = after_allow.allow_indices[0] + 1
            _must(
                ssh,
                _ufw_command(
                    "insert",
                    str(insert_at),
                    "deny",
                    "to",
                    "any",
                    "port",
                    str(profile.backend_port),
                    "proto",
                    "tcp",
                    "comment",
                    deny_comment,
                ),
                operation="Не удалось добавить UFW backend deny rule",
                timeout=_MUTATION_TIMEOUT,
            )
            deny_added = True

        verified = _inspect_ufw(ssh, profile)
        if not verified.allow_indices or not verified.deny_indices:
            raise VerificationError("UFW не подтвердил обе managed rules")
        if allow_added or deny_added:
            # This is intentionally a new SSH command after the firewall mutation.
            _require_remote_root(ssh)
    except Exception as original:
        try:
            _rollback_actions(ssh, profile, attempted)
        except Exception as rollback_error:
            raise InstallerError(
                "Remote UFW apply не удался, rollback неполон"
            ) from rollback_error
        raise original

    return RemoteExitNetworkApplyResult(
        profile=profile,
        allow_comment=allow_comment,
        deny_comment=deny_comment,
        ufw_allow_added=allow_added,
        ufw_deny_added=deny_added,
    )


def rollback_remote_exit_network(
    ssh: SSHClient,
    result: RemoteExitNetworkApplyResult,
) -> RemoteExitNetworkRollbackResult:
    """Remove only rules that the successful ``apply`` call reported as added."""

    profile = result.profile.validate()
    if result.allow_comment != _allow_comment(
        profile
    ) or result.deny_comment != _deny_comment(profile):
        raise ValidationError("Remote network result содержит чужие managed comments")
    _require_remote_root(ssh)
    comments: list[tuple[str, str]] = []
    if result.ufw_allow_added:
        comments.append(("UFW frontend allow", result.allow_comment))
    if result.ufw_deny_added:
        comments.append(("UFW backend deny", result.deny_comment))
    allow_removed, deny_removed = _rollback_actions(ssh, profile, comments)
    if comments:
        _require_remote_root(ssh)
    return RemoteExitNetworkRollbackResult(
        ufw_allow_removed=allow_removed,
        ufw_deny_removed=deny_removed,
    )
