"""Conservative remote UFW management for a clean exit host.

This module intentionally manages only two numbered UFW rules.  It never
enables UFW, changes its defaults, edits SSH access, starts services, or applies
the broader optional network profile from :mod:`xhttp_setup.exit_network`.
"""

from __future__ import annotations

import re
import subprocess
from collections import Counter
from dataclasses import dataclass
from typing import Sequence

from .command_output import english_words, parse_ufw_status
from .errors import InstallerError, ValidationError, VerificationError
from .exit_network import ExitNetworkProfile
from .remote_prepare import (
    _expected_ssh_rule,
    _ssh_rule_comment,
    _ufw_added_commands,
    _validate_nft_diagnostics,
    _validate_iptables_save as _validate_prepared_iptables_save,
)
from .remote_prepare import _validate_nft_ruleset as _validate_prepared_nft_ruleset
from .ssh_transport import SSHCommand, SSHTransportError
from .validate import validate_port


_READ_TIMEOUT = 20
_MUTATION_TIMEOUT = 30
_MANAGED_ALLOW_PREFIX = "xhttp-setup-allow-"
_MANAGED_DENY_PREFIX = "xhttp-setup-deny-"
_NUMBERED_UFW_LINE = re.compile(r"^\s*\[\s*(\d+)\]\s+(.*)$")
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
class RemoteExitNetworkState:
    os_id: str
    ufw_allow_indices: tuple[int, ...]
    ufw_deny_indices: tuple[int, ...]


@dataclass(frozen=True)
class RemoteExitNetworkApplyResult:
    profile: ExitNetworkProfile
    ssh_port: int
    allow_comment: str
    deny_comment: str
    ufw_allow_added: bool
    ufw_deny_added: bool


@dataclass(frozen=True)
class RemoteExitNetworkRollbackResult:
    ufw_allow_removed: bool
    ufw_deny_removed: bool


@dataclass(frozen=True)
class RemoteExitNetworkRecovery:
    """Exact owned comments whose mutation outcome needs reconciliation."""

    profile: ExitNetworkProfile
    ssh_port: int
    attempted_comments: tuple[tuple[str, str], ...]


class RemoteExitNetworkError(InstallerError):
    """Transport-only mutation failure carrying a bounded reconciliation journal."""

    def __init__(
        self,
        *,
        recovery: RemoteExitNetworkRecovery,
        recovery_completed: bool = False,
    ) -> None:
        state = "succeeded" if recovery_completed else "required"
        super().__init__(
            f"Remote UFW mutation transport failed; exact_reconciliation={state}"
        )
        self.recovery = recovery
        self.recovery_completed = recovery_completed


@dataclass(frozen=True)
class _UfwState:
    active: bool
    guard_indices: tuple[int, ...]
    allow_indices: tuple[int, ...]
    deny_indices: tuple[int, ...]


def _allow_comment(profile: ExitNetworkProfile) -> str:
    return f"{_MANAGED_ALLOW_PREFIX}{profile.backend_port}-{profile.frontend_ipv4}"


def _deny_comment(profile: ExitNetworkProfile) -> str:
    return f"{_MANAGED_DENY_PREFIX}{profile.backend_port}"


def _validated_network_target(
    profile: ExitNetworkProfile,
    ssh_port: int,
) -> tuple[ExitNetworkProfile, int]:
    profile = profile.validate()
    ssh_port = validate_port(ssh_port)
    if profile.backend_port == ssh_port:
        raise ValidationError("Backend-порт совпадает с SSH-портом выхода")
    return profile, ssh_port


def _invoke(
    ssh: SSHCommand,
    argv: Sequence[str],
    *,
    timeout: int = _READ_TIMEOUT,
) -> subprocess.CompletedProcess[str]:
    try:
        return ssh.command(list(argv), check=False, timeout=timeout)
    except InstallerError:
        # Preserve the transport layer's bounded, redacted diagnostic.
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


def _require_remote_root(ssh: SSHCommand, *, fresh: bool = False) -> None:
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
        raise InstallerError("Удалённый сетевой apply требует прямой SSH-вход root")


def _read_os_id(ssh: SSHCommand) -> str:
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


def _reject_docker_units(ssh: SSHCommand) -> None:
    units = _invoke(
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
    if units.returncode == 1 and not units.stdout.strip() and not units.stderr.strip():
        return
    if units.returncode != 0:
        raise InstallerError(
            f"Не удалось проверить Docker unit-файлы: код {units.returncode}"
        )
    if units.stderr.strip():
        raise VerificationError(
            "systemctl вернул неоднозначную диагностику Docker/containerd"
        )
    expected = {"docker.service", "docker.socket", "containerd.service"}
    lines = [line.split() for line in units.stdout.splitlines() if line.strip()]
    if not lines or any(
        len(fields) < 2 or fields[0] not in expected for fields in lines
    ):
        raise VerificationError(
            "systemctl вернул неоднозначный список Docker/containerd unit-файлов"
        )
    found = [fields[0] for fields in lines]
    if found:
        raise InstallerError(
            "Обнаружены Docker/containerd unit-файлы; remote UFW apply отказался"
        )


def _systemd_state(
    ssh: SSHCommand,
    operation: str,
) -> tuple[int, str, str]:
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
        raise VerificationError("systemctl вернул неоднозначное состояние nftables")
    return result.returncode, state, diagnostic


def _reject_nftables_service(ssh: SSHCommand) -> None:
    active_code, active, active_diagnostic = _systemd_state(ssh, "is-active")
    if active_code == 0 or active == "active":
        raise InstallerError("Обнаружен активный nftables.service")
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

    enabled_code, enabled, enabled_diagnostic = _systemd_state(ssh, "is-enabled")
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


def _validate_nft_ruleset(output: str) -> None:
    """Allow only an empty ruleset or the normal iptables-nft UFW filter shape."""
    _validate_prepared_nft_ruleset(output, allow_ufw=True)


def _reject_custom_nftables(ssh: SSHCommand) -> None:
    _reject_nftables_service(ssh)
    ruleset = _must(
        ssh,
        ["env", "LC_ALL=C", "LANG=C", "nft", "list", "ruleset"],
        operation="Не удалось прочитать nftables ruleset",
    )
    _validate_nft_ruleset(ruleset.stdout)
    _validate_nft_diagnostics(ruleset.stdout, ruleset.stderr)
    iptables = _must(
        ssh,
        ["iptables-save"],
        operation="Не удалось прочитать IPv4 iptables ruleset",
    )
    ip6tables = _must(
        ssh,
        ["ip6tables-save"],
        operation="Не удалось прочитать IPv6 iptables ruleset",
    )
    if iptables.stderr.strip() or ip6tables.stderr.strip():
        raise VerificationError("xtables inspector вернул предупреждение")
    _validate_prepared_iptables_save(
        iptables.stdout,
        allow_ufw=True,
        ufw_prefix="ufw-",
    )
    _validate_prepared_iptables_save(
        ip6tables.stdout,
        allow_ufw=True,
        ufw_prefix="ufw6-",
    )


def _ufw_command(*argv: str) -> list[str]:
    return ["env", "LC_ALL=C", "LANG=C", "ufw", *argv]


def _numbered_rules(output: str) -> list[tuple[int, str, str]]:
    found: list[tuple[int, str, str]] = []
    for raw_line in output.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            continue
        match = _NUMBERED_UFW_LINE.match(raw_line)
        if match is None:
            fields = tuple(stripped.split())
            words = english_words(stripped)
            is_separator = len(fields) == 3 and all(
                re.fullmatch(r"-+", field) for field in fields
            )
            if (
                words
                in {
                    ("status", "active"),
                    ("to", "action", "from"),
                }
                or is_separator
            ):
                continue
            raise VerificationError("Некорректный вывод ufw status numbered")
        body = match.group(2).strip()
        rule, separator, comment = body.rpartition("#")
        if not separator or not comment.strip():
            raise InstallerError("UFW содержит rule без managed comment")
        found.append((int(match.group(1)), rule.strip(), comment.strip()))
    indices = tuple(index for index, _rule, _comment in found)
    if indices != tuple(range(1, len(found) + 1)):
        raise VerificationError("UFW вернул неоднозначную нумерацию rules")
    return found


def _added_rule_comment(command: list[str]) -> str:
    if command.count("comment") != 1:
        raise InstallerError("UFW show added содержит rule без exact comment")
    marker = command.index("comment")
    if marker + 2 != len(command) or not command[marker + 1]:
        raise InstallerError("UFW show added содержит неоднозначный comment")
    return command[marker + 1]


def _inspect_ufw(
    ssh: SSHCommand,
    profile: ExitNetworkProfile,
    *,
    ssh_port: int,
) -> _UfwState:
    result = _must(
        ssh,
        _ufw_command("status", "numbered"),
        operation="Не удалось прочитать состояние UFW",
    )
    if result.stderr.strip():
        raise VerificationError("ufw status numbered вернул предупреждение")
    try:
        active = parse_ufw_status(result.stdout)
    except ValueError as exc:
        raise VerificationError("UFW вернул неоднозначное состояние") from exc
    if not active:
        return _UfwState(False, (), (), ())

    guard_comment = _ssh_rule_comment(ssh_port)
    allow_comment = _allow_comment(profile)
    deny_comment = _deny_comment(profile)
    numbered = _numbered_rules(result.stdout)
    allowed_comments = {guard_comment, allow_comment, deny_comment}
    foreign_comments = sorted(
        {
            comment
            for _index, _rule, comment in numbered
            if comment not in allowed_comments
        }
    )
    if foreign_comments:
        raise InstallerError("UFW содержит foreign rules")

    guard_lines = [
        (index, rule) for index, rule, comment in numbered if comment == guard_comment
    ]
    allow_lines = [
        (index, rule) for index, rule, comment in numbered if comment == allow_comment
    ]
    deny_lines = [
        (index, rule) for index, rule, comment in numbered if comment == deny_comment
    ]

    allow_namespace = f"{_MANAGED_ALLOW_PREFIX}{profile.backend_port}-"
    for _index, _rule, comment in numbered:
        if comment.startswith(allow_namespace) and comment != allow_comment:
            raise InstallerError(
                "Обнаружена managed UFW allow rule для другого frontend IPv4"
            )

    escaped_ssh_port = re.escape(str(ssh_port))
    ipv4_guard = tuple(
        index
        for index, rule in guard_lines
        if re.fullmatch(
            rf"{escaped_ssh_port}/tcp\s+ALLOW IN\s+Anywhere",
            rule,
        )
    )
    ipv6_guard = tuple(
        index
        for index, rule in guard_lines
        if re.fullmatch(
            rf"{escaped_ssh_port}/tcp\s+\(v6\)\s+ALLOW IN\s+Anywhere\s+\(v6\)",
            rule,
        )
    )
    if (
        len(ipv4_guard) != 1
        or len(ipv6_guard) > 1
        or len(guard_lines) != len(ipv4_guard) + len(ipv6_guard)
    ):
        raise InstallerError("UFW не содержит exact managed SSH guard текущего порта")

    if len(allow_lines) > 1:
        raise InstallerError("Обнаружены дубли managed UFW allow rule")
    expected_port = re.escape(str(profile.backend_port))
    expected_ip = re.escape(profile.frontend_ipv4)
    for _, rule in allow_lines:
        if not re.fullmatch(
            rf"{expected_port}/tcp\s+ALLOW IN\s+{expected_ip}(?:/32)?",
            rule,
        ):
            raise InstallerError("Managed UFW allow comment занят другой rule")
    for _, rule in deny_lines:
        if not re.fullmatch(
            rf"{expected_port}/tcp\s+DENY IN\s+Anywhere",
            rule,
        ) and not re.fullmatch(
            rf"{expected_port}/tcp\s+\(v6\)\s+DENY IN\s+Anywhere\s+\(v6\)",
            rule,
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

    added_commands = _ufw_added_commands(ssh)
    added_comments = [_added_rule_comment(command) for command in added_commands]
    expected_comments = [guard_comment]
    if allow_indices:
        expected_comments.append(allow_comment)
    if ipv4_deny:
        expected_comments.append(deny_comment)
    if Counter(added_comments) != Counter(expected_comments):
        raise InstallerError("UFW show added не совпадает с exact managed rules")
    guard_commands = [
        command
        for command, comment in zip(added_commands, added_comments, strict=True)
        if comment == guard_comment
    ]
    if guard_commands != [_expected_ssh_rule(ssh_port)]:
        raise InstallerError("UFW SSH guard не совпадает с exact managed rule")

    return _UfwState(
        True,
        tuple(index for index, _rule in guard_lines),
        allow_indices,
        tuple(index for index, _ in deny_lines),
    )


def preflight_remote_exit_network(
    ssh: SSHCommand,
    profile: ExitNetworkProfile,
    *,
    ssh_port: int,
) -> RemoteExitNetworkState:
    """Read and validate remote network state without making mutations."""

    profile, ssh_port = _validated_network_target(profile, ssh_port)
    _require_remote_root(ssh)
    os_id = _read_os_id(ssh)
    _reject_docker_units(ssh)
    _reject_custom_nftables(ssh)
    ufw = _inspect_ufw(ssh, profile, ssh_port=ssh_port)
    if not ufw.active:
        raise InstallerError(
            "UFW inactive/unknown: remote apply отказался включать или перенастраивать его"
        )
    if bool(ufw.allow_indices) != bool(ufw.deny_indices):
        raise InstallerError("UFW содержит неполную managed backend пару")
    return RemoteExitNetworkState(
        os_id=os_id,
        ufw_allow_indices=ufw.allow_indices,
        ufw_deny_indices=ufw.deny_indices,
    )


def _delete_comment(
    ssh: SSHCommand,
    profile: ExitNetworkProfile,
    comment: str,
    *,
    ssh_port: int,
) -> bool:
    state = _inspect_ufw(ssh, profile, ssh_port=ssh_port)
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
    if comment == _allow_comment(profile):
        delete = _ufw_command(
            "--force",
            "delete",
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
            comment,
        )
    else:
        delete = _ufw_command(
            "--force",
            "delete",
            "deny",
            "to",
            "any",
            "port",
            str(profile.backend_port),
            "proto",
            "tcp",
            "comment",
            comment,
        )
    _must(
        ssh,
        delete,
        operation=f"Не удалось удалить managed UFW rule {comment}",
        timeout=_MUTATION_TIMEOUT,
    )
    after = _inspect_ufw(ssh, profile, ssh_port=ssh_port)
    remaining = (
        after.allow_indices
        if comment == _allow_comment(profile)
        else after.deny_indices
    )
    if remaining:
        raise VerificationError(f"Managed UFW rule {comment} осталась после rollback")
    return True


def _rollback_actions(
    ssh: SSHCommand,
    profile: ExitNetworkProfile,
    comments: Sequence[tuple[str, str]],
    *,
    ssh_port: int,
) -> tuple[bool, bool]:
    allow_removed = False
    deny_removed = False
    errors: list[tuple[str, Exception]] = []
    for name, comment in reversed(comments):
        try:
            removed = _delete_comment(
                ssh,
                profile,
                comment,
                ssh_port=ssh_port,
            )
            if comment == _allow_comment(profile):
                allow_removed = allow_removed or removed
            else:
                deny_removed = deny_removed or removed
        except Exception as exc:
            errors.append((name, exc))
    if errors:
        names = ", ".join(name for name, _ in errors)
        if all(isinstance(exc, SSHTransportError) for _, exc in errors):
            raise SSHTransportError(
                "SSH transport оборвался во время exact UFW rollback: " + names
            ) from errors[0][1]
        raise InstallerError("rollback неполон: " + names)
    return allow_removed, deny_removed


def _require_pair_state(
    ssh: SSHCommand,
    profile: ExitNetworkProfile,
    *,
    ssh_port: int,
    pair_present: bool,
) -> None:
    state = _inspect_ufw(ssh, profile, ssh_port=ssh_port)
    if not state.active:
        raise VerificationError("UFW стал inactive во время managed transaction")
    actual_pair = bool(state.allow_indices) and bool(state.deny_indices)
    partial_pair = bool(state.allow_indices) != bool(state.deny_indices)
    if partial_pair or actual_pair != pair_present:
        expected = "guard+pair" if pair_present else "guard-only"
        raise VerificationError(f"UFW не вернул exact {expected} state")


def _validated_recovery(
    recovery: RemoteExitNetworkRecovery,
) -> RemoteExitNetworkRecovery:
    profile, ssh_port = _validated_network_target(
        recovery.profile,
        recovery.ssh_port,
    )
    expected = (
        ("UFW frontend allow", _allow_comment(profile)),
        ("UFW backend deny", _deny_comment(profile)),
    )
    comments = tuple(recovery.attempted_comments)
    if comments != expected[: len(comments)] or len(comments) > len(expected):
        raise ValidationError(
            "Remote network recovery journal не является exact prefix"
        )
    return RemoteExitNetworkRecovery(profile, ssh_port, comments)


def recovery_for_remote_exit_network(
    result: RemoteExitNetworkApplyResult,
) -> RemoteExitNetworkRecovery:
    """Build an exact rollback journal from one successful owned apply result."""

    profile, ssh_port = _validated_network_target(result.profile, result.ssh_port)
    if result.allow_comment != _allow_comment(
        profile
    ) or result.deny_comment != _deny_comment(profile):
        raise ValidationError("Remote network result содержит чужие managed comments")
    if result.ufw_allow_added != result.ufw_deny_added:
        raise ValidationError("Remote network result содержит partial managed pair")
    comments: list[tuple[str, str]] = []
    if result.ufw_allow_added:
        comments.append(("UFW frontend allow", result.allow_comment))
    if result.ufw_deny_added:
        comments.append(("UFW backend deny", result.deny_comment))
    return _validated_recovery(
        RemoteExitNetworkRecovery(profile, ssh_port, tuple(comments))
    )


def reconcile_remote_exit_network(
    ssh: SSHCommand,
    recovery: RemoteExitNetworkRecovery,
) -> RemoteExitNetworkRollbackResult:
    """Reconcile exact attempted comments through one caller-owned fresh session."""

    recovery = _validated_recovery(recovery)
    _require_remote_root(ssh)
    allow_removed, deny_removed = _rollback_actions(
        ssh,
        recovery.profile,
        recovery.attempted_comments,
        ssh_port=recovery.ssh_port,
    )
    _require_pair_state(
        ssh,
        recovery.profile,
        ssh_port=recovery.ssh_port,
        pair_present=False,
    )
    return RemoteExitNetworkRollbackResult(
        ufw_allow_removed=allow_removed,
        ufw_deny_removed=deny_removed,
    )


def apply_remote_exit_network(
    ssh: SSHCommand,
    profile: ExitNetworkProfile,
    *,
    ssh_port: int,
) -> RemoteExitNetworkApplyResult:
    """Insert only the exact managed UFW allow/deny pair and verify SSH survives."""

    profile, ssh_port = _validated_network_target(profile, ssh_port)
    before = preflight_remote_exit_network(ssh, profile, ssh_port=ssh_port)
    baseline_pair_present = bool(before.ufw_allow_indices)
    allow_comment = _allow_comment(profile)
    deny_comment = _deny_comment(profile)
    attempted: list[tuple[str, str]] = []
    allow_added = False
    deny_added = False
    fresh_proof = False
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

        after_allow = _inspect_ufw(ssh, profile, ssh_port=ssh_port)
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

        verified = _inspect_ufw(ssh, profile, ssh_port=ssh_port)
        if not verified.allow_indices or not verified.deny_indices:
            raise VerificationError("UFW не подтвердил обе managed rules")
        if allow_added or deny_added:
            # The main mux remains available for rollback, while this proof must
            # use a genuinely new TCP/SSH connection through the changed rules.
            fresh_proof = True
            _require_remote_root(ssh, fresh=True)
            fresh_proof = False
    except BaseException as original:
        recovery = _validated_recovery(
            RemoteExitNetworkRecovery(profile, ssh_port, tuple(attempted))
        )
        if not attempted:
            # The validated baseline pair was already present and this call did
            # not issue a mutation.  A broken scoped session cannot prove that
            # baseline again, but opening a recovery session would be wrong:
            # an empty journal reconciles to guard-only and would reject the
            # pre-existing pair that this call deliberately did not own.
            raise
        if fresh_proof:
            try:
                _rollback_actions(
                    ssh,
                    profile,
                    attempted,
                    ssh_port=ssh_port,
                )
                _require_pair_state(
                    ssh,
                    profile,
                    ssh_port=ssh_port,
                    pair_present=baseline_pair_present,
                )
            except SSHTransportError as rollback_error:
                if not isinstance(original, Exception):
                    original.add_note(
                        "Remote UFW rollback после прерывания не подтверждён"
                    )
                    raise original from None
                raise RemoteExitNetworkError(recovery=recovery) from rollback_error
            except Exception as rollback_error:
                if not isinstance(original, Exception):
                    original.add_note(
                        "Remote UFW rollback после прерывания не подтверждён"
                    )
                    raise original from None
                raise InstallerError(
                    "Remote UFW fresh proof не удался, rollback неполон"
                ) from rollback_error
            raise
        if attempted and isinstance(original, SSHTransportError):
            raise RemoteExitNetworkError(recovery=recovery) from original
        try:
            _rollback_actions(
                ssh,
                profile,
                attempted,
                ssh_port=ssh_port,
            )
            _require_pair_state(
                ssh,
                profile,
                ssh_port=ssh_port,
                pair_present=baseline_pair_present,
            )
        except SSHTransportError:
            if not isinstance(original, Exception):
                original.add_note("Remote UFW rollback после прерывания не подтверждён")
                raise original from None
            raise RemoteExitNetworkError(recovery=recovery) from original
        except Exception as rollback_error:
            if not isinstance(original, Exception):
                original.add_note("Remote UFW rollback после прерывания не подтверждён")
                raise original from None
            raise InstallerError(
                "Remote UFW apply не удался, rollback неполон"
            ) from rollback_error
        raise

    return RemoteExitNetworkApplyResult(
        profile=profile,
        ssh_port=ssh_port,
        allow_comment=allow_comment,
        deny_comment=deny_comment,
        ufw_allow_added=allow_added,
        ufw_deny_added=deny_added,
    )


def rollback_remote_exit_network(
    ssh: SSHCommand,
    result: RemoteExitNetworkApplyResult,
) -> RemoteExitNetworkRollbackResult:
    """Remove only rules that the successful ``apply`` call reported as added."""

    recovery = recovery_for_remote_exit_network(result)
    _require_remote_root(ssh)
    allow_removed, deny_removed = _rollback_actions(
        ssh,
        recovery.profile,
        recovery.attempted_comments,
        ssh_port=recovery.ssh_port,
    )
    _require_pair_state(
        ssh,
        recovery.profile,
        ssh_port=recovery.ssh_port,
        pair_present=not result.ufw_allow_added,
    )
    if recovery.attempted_comments:
        _require_remote_root(ssh, fresh=True)
    return RemoteExitNetworkRollbackResult(
        ufw_allow_removed=allow_removed,
        ufw_deny_removed=deny_removed,
    )
