"""Optional exit network profile.

The API has unit coverage but has not yet been exercised on a clean live host.
TCPMSS rules are deliberately runtime-only; this module does not manage boot
persistence or overwrite iptables-persistent/rules.v4.
"""

from __future__ import annotations

import contextlib
import os
import platform
import re
import shlex
import stat
import subprocess
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass
from pathlib import Path

from .command_output import parse_ufw_status
from .errors import InstallerError, ValidationError, VerificationError
from .osutil import atomic_write, exclusive_lock, run
from .validate import validate_ipv4, validate_port


MSS = 1280
SYSCTL_VALUES = {
    "net.core.default_qdisc": "fq",
    "net.ipv4.tcp_congestion_control": "bbr",
    "net.ipv4.tcp_mtu_probing": "1",
    "net.ipv4.tcp_slow_start_after_idle": "0",
    "net.core.somaxconn": "65535",
}
SYSCTL_MARKER = "# Managed by xhttp-setup exit network profile."
_INTERFACE = re.compile(r"^[A-Za-z0-9_.:-]{1,15}$")

Runner = Callable[..., subprocess.CompletedProcess[str]]


@dataclass(frozen=True)
class ExitNetworkProfile:
    frontend_ipv4: str
    backend_port: int

    def validate(self) -> ExitNetworkProfile:
        backend_port = validate_port(self.backend_port)
        if backend_port < 1024:
            raise ValidationError(
                "Backend TCP port должен быть в диапазоне 1024..65535"
            )
        return ExitNetworkProfile(
            frontend_ipv4=validate_ipv4(self.frontend_ipv4),
            backend_port=backend_port,
        )


@dataclass(frozen=True)
class ExitNetworkLayout:
    root: Path = Path("/")

    @property
    def sysctl_file(self) -> Path:
        return self.root / "etc/sysctl.d/99-xhttp-setup-network.conf"

    @property
    def lock(self) -> Path:
        return self.root / "var/lib/xhttp-setup/network.lock"


@dataclass(frozen=True)
class NetworkCheck:
    name: str
    ok: bool
    detail: str


@dataclass(frozen=True)
class ExitNetworkPlan:
    interface: str
    steps: tuple[str, ...]
    checks: tuple[NetworkCheck, ...]


@dataclass(frozen=True)
class ExitNetworkApplyResult:
    interface: str
    ufw_allow_added: bool
    ufw_deny_added: bool
    sysctl_file_changed: bool
    sysctl_applied: bool
    mss_output_added: bool
    mss_postrouting_added: bool
    mss_runtime_only: bool


@dataclass(frozen=True)
class _FileSnapshot:
    data: bytes
    mode: int
    uid: int
    gid: int


@dataclass(frozen=True)
class _UfwState:
    active: bool
    allow_indices: tuple[int, ...]
    deny_indices: tuple[int, ...]
    output: str


def _runner(value: Runner | None) -> Runner:
    return value or run


def _invoke(
    runner: Runner,
    argv: Sequence[str],
    *,
    timeout: int = 120,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["LC_ALL"] = "C"
    environment["LANG"] = "C"
    return runner(
        list(argv),
        check=False,
        env=environment,
        timeout=timeout,
    )


def _must(
    runner: Runner,
    argv: Sequence[str],
    *,
    operation: str,
) -> subprocess.CompletedProcess[str]:
    result = _invoke(runner, argv)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip().splitlines()
        tail = detail[-1] if detail else f"код {result.returncode}"
        raise InstallerError(f"{operation}: {tail}")
    return result


def _validate_interface(value: str) -> str:
    interface = value.strip()
    if not _INTERFACE.fullmatch(interface) or interface == "lo":
        raise ValidationError("Не удалось безопасно определить default IPv4 interface")
    return interface


def _detect_default_interface(runner: Runner) -> str:
    result = _must(
        runner,
        ["ip", "-4", "route", "get", "1.1.1.1"],
        operation="Не удалось определить default IPv4 interface",
    )
    interfaces: list[str] = []
    tokens = result.stdout.split()
    for index, token in enumerate(tokens[:-1]):
        if token == "dev":
            interfaces.append(_validate_interface(tokens[index + 1]))
    unique = sorted(set(interfaces))
    if len(unique) != 1:
        raise InstallerError("ip route get не вернул ровно один default IPv4 interface")
    return unique[0]


def _allow_comment(profile: ExitNetworkProfile) -> str:
    return f"xhttp-setup-allow-{profile.backend_port}-{profile.frontend_ipv4}"


def _deny_comment(profile: ExitNetworkProfile) -> str:
    return f"xhttp-setup-deny-{profile.backend_port}"


def _numbered_rule_lines(output: str, comment: str) -> list[tuple[int, str]]:
    found: list[tuple[int, str]] = []
    for line in output.splitlines():
        head, separator, tail = line.rpartition("#")
        if not separator or tail.strip() != comment:
            continue
        match = re.match(r"^\s*\[\s*(\d+)\]\s+", head)
        if not match:
            raise InstallerError(f"Некорректная managed UFW rule: {line.strip()}")
        found.append((int(match.group(1)), head))
    return found


def _inspect_ufw(profile: ExitNetworkProfile, runner: Runner) -> _UfwState:
    result = _invoke(runner, ["ufw", "status", "numbered"])
    if result.returncode != 0:
        raise InstallerError("Не удалось прочитать состояние UFW")
    try:
        active = parse_ufw_status(result.stdout)
    except ValueError as exc:
        raise InstallerError("UFW вернул неоднозначное состояние") from exc
    if not active:
        return _UfwState(False, (), (), result.stdout)

    allow_lines = _numbered_rule_lines(result.stdout, _allow_comment(profile))
    deny_lines = _numbered_rule_lines(result.stdout, _deny_comment(profile))
    allow_namespace = f"xhttp-setup-allow-{profile.backend_port}-"
    for line in result.stdout.splitlines():
        _, separator, tail = line.rpartition("#")
        comment = tail.strip() if separator else ""
        if comment.startswith(allow_namespace) and comment != _allow_comment(profile):
            raise InstallerError(
                "Обнаружена managed UFW allow rule для другого frontend IPv4"
            )
    if len(allow_lines) > 1:
        raise InstallerError("Обнаружены дубли managed UFW allow rule")

    expected_port = re.escape(str(profile.backend_port))
    expected_ip = re.escape(profile.frontend_ipv4)
    for _, line in allow_lines:
        if not re.search(rf"(?<!\d){expected_port}/tcp\b", line) or not re.search(
            rf"\bALLOW IN\s+{expected_ip}(?:/32)?\s*$", line
        ):
            raise InstallerError("Managed UFW allow comment занят другой rule")
    for _, line in deny_lines:
        if not re.search(rf"(?<!\d){expected_port}/tcp\b", line) or not re.search(
            r"\bDENY IN\s+Anywhere(?:\s+\(v6\))?\s*$", line
        ):
            raise InstallerError("Managed UFW deny comment занят другой rule")

    allow_indices = tuple(index for index, _ in allow_lines)
    deny_indices = tuple(index for index, _ in deny_lines)
    ipv4_deny_indices = tuple(index for index, line in deny_lines if "(v6)" not in line)
    ipv6_deny_indices = tuple(index for index, line in deny_lines if "(v6)" in line)
    if len(ipv4_deny_indices) > 1 or len(ipv6_deny_indices) > 1:
        raise InstallerError("Обнаружены дубли managed UFW deny rule")
    if deny_lines and not ipv4_deny_indices:
        raise InstallerError("Managed UFW deny rule существует только для IPv6")
    if allow_indices and allow_indices[0] != 1:
        raise InstallerError("Managed UFW frontend allow rule не стоит первой")
    if ipv4_deny_indices:
        expected_deny_index = 2 if allow_indices else 1
        if ipv4_deny_indices[0] != expected_deny_index:
            raise InstallerError(
                "Managed UFW backend deny rule не стоит сразу после frontend allow"
            )
    return _UfwState(active, allow_indices, deny_indices, result.stdout)


def _sysctl_text() -> str:
    lines = [SYSCTL_MARKER]
    lines.extend(f"{key} = {value}" for key, value in SYSCTL_VALUES.items())
    return "\n".join(lines) + "\n"


def _snapshot_optional(path: Path) -> _FileSnapshot | None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise InstallerError(f"Не удалось проверить {path}: {exc}") from exc
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallerError(f"Managed sysctl path должен быть обычным файлом: {path}")
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise InstallerError(f"Не удалось прочитать {path}: {exc}") from exc
    if not data.startswith((SYSCTL_MARKER + "\n").encode("utf-8")):
        raise InstallerError(f"{path} уже существует и не принадлежит xhttp-setup")
    return _FileSnapshot(
        data=data,
        mode=stat.S_IMODE(metadata.st_mode),
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def _normalize_managed_file(path: Path, mode: int, *, strict_root: bool) -> None:
    if os.name == "posix" and strict_root:
        os.chown(path, 0, 0)
    os.chmod(path, mode)


def _restore_file(path: Path, snapshot: _FileSnapshot | None) -> None:
    if snapshot is None:
        path.unlink(missing_ok=True)
        return
    atomic_write(path, snapshot.data, snapshot.mode)
    if os.name == "posix":
        os.chown(path, snapshot.uid, snapshot.gid)
    os.chmod(path, snapshot.mode)


def _read_sysctl_values(runner: Runner) -> dict[str, str]:
    values: dict[str, str] = {}
    for key in SYSCTL_VALUES:
        result = _must(
            runner,
            ["sysctl", "-n", key],
            operation=f"Не удалось прочитать sysctl {key}",
        )
        value = result.stdout.strip()
        if not value or "\n" in value:
            raise InstallerError(f"sysctl {key} вернул неоднозначное значение")
        values[key] = value
    return values


def _verify_bbr_available(runner: Runner) -> None:
    result = _must(
        runner,
        ["sysctl", "-n", "net.ipv4.tcp_available_congestion_control"],
        operation="Не удалось проверить поддержку BBR",
    )
    if "bbr" not in result.stdout.split():
        raise InstallerError("Ядро не сообщает BBR среди доступных congestion controls")


def _mss_comment(chain: str, interface: str) -> str:
    suffix = "output" if chain == "OUTPUT" else f"postrouting-{interface}"
    return f"xhttp-setup-mss-{MSS}-{suffix}"


def _mss_rule(chain: str, interface: str) -> list[str]:
    rule = [
        "-p",
        "tcp",
        "--tcp-flags",
        "SYN,RST",
        "SYN",
    ]
    if chain == "POSTROUTING":
        rule.extend(["-o", interface])
    rule.extend(
        [
            "-m",
            "comment",
            "--comment",
            _mss_comment(chain, interface),
            "-j",
            "TCPMSS",
            "--set-mss",
            str(MSS),
        ]
    )
    return rule


def _iptables_command(action: str, chain: str, interface: str) -> list[str]:
    return ["iptables", "-w", "5", "-t", "mangle", action, chain] + _mss_rule(
        chain, interface
    )


def _rule_exists(runner: Runner, chain: str, interface: str) -> bool:
    result = _invoke(runner, _iptables_command("-C", chain, interface))
    if result.returncode == 0:
        return True
    if result.returncode == 1:
        return False
    raise InstallerError(f"Не удалось проверить iptables mangle {chain} rule")


def _inspect_mss_rules(runner: Runner, interface: str) -> dict[str, bool]:
    saved = _must(
        runner,
        ["iptables-save", "-w", "5", "-t", "mangle"],
        operation="Не удалось проверить namespace iptables mangle",
    ).stdout
    postrouting_namespace = f"xhttp-setup-mss-{MSS}-postrouting-"
    expected_postrouting = _mss_comment("POSTROUTING", interface)
    for token in re.findall(r"xhttp-setup-mss-[A-Za-z0-9_.:-]+", saved):
        if token.startswith(postrouting_namespace) and token != expected_postrouting:
            raise InstallerError(
                "Обнаружена managed TCPMSS rule для другого default interface"
            )
    result: dict[str, bool] = {}
    for chain in ("OUTPUT", "POSTROUTING"):
        exists = _rule_exists(runner, chain, interface)
        marker = _mss_comment(chain, interface)
        marker_present = marker in saved
        if marker_present != exists:
            raise InstallerError(f"Managed iptables comment {marker} занят другой rule")
        if saved.count(marker) > 1:
            raise InstallerError(f"Обнаружены дубли managed iptables rule {marker}")
        result[chain] = exists
    return result


def _read_checks(
    profile: ExitNetworkProfile,
    layout: ExitNetworkLayout,
    runner: Runner,
    *,
    interface: str,
) -> tuple[NetworkCheck, ...]:
    checks: list[NetworkCheck] = []
    ufw = _inspect_ufw(profile, runner)
    checks.append(
        NetworkCheck(
            "UFW active", ufw.active, "active" if ufw.active else "inactive/unknown"
        )
    )
    checks.append(
        NetworkCheck(
            "UFW frontend /32 allow",
            bool(ufw.allow_indices),
            _allow_comment(profile),
        )
    )
    checks.append(
        NetworkCheck(
            "UFW backend deny",
            bool(ufw.deny_indices),
            _deny_comment(profile),
        )
    )

    expected = _sysctl_text().encode("utf-8")
    try:
        snapshot = _snapshot_optional(layout.sysctl_file)
        file_ok = snapshot is not None and snapshot.data == expected
        detail = "managed content OK" if file_ok else "managed content absent/different"
    except InstallerError as exc:
        file_ok, detail = False, str(exc)
    checks.append(NetworkCheck("Managed sysctl file", file_ok, detail))

    runtime = _read_sysctl_values(runner)
    for key, wanted in SYSCTL_VALUES.items():
        checks.append(
            NetworkCheck(
                f"sysctl {key}",
                runtime[key] == wanted,
                f"{runtime[key]} (expected {wanted})",
            )
        )

    rules = _inspect_mss_rules(runner, interface)
    for chain in ("OUTPUT", "POSTROUTING"):
        checks.append(
            NetworkCheck(
                f"TCPMSS {chain}",
                rules[chain],
                f"MSS {MSS}, interface {interface}; runtime-only",
            )
        )
    return tuple(checks)


def plan_exit_network(
    profile: ExitNetworkProfile,
    *,
    layout: ExitNetworkLayout | None = None,
    runner: Runner | None = None,
) -> ExitNetworkPlan:
    """Inspect current state and return a read-only, executable network plan."""

    profile = profile.validate()
    layout = layout or ExitNetworkLayout()
    command_runner = _runner(runner)
    interface = _detect_default_interface(command_runner)
    _verify_bbr_available(command_runner)
    checks = _read_checks(
        profile,
        layout,
        command_runner,
        interface=interface,
    )
    ufw = _inspect_ufw(profile, command_runner)
    if not ufw.active:
        raise InstallerError(
            "UFW inactive/unknown: профиль не включает UFW и не меняет default policy"
        )

    allow = [
        "ufw",
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
        _allow_comment(profile),
    ]
    deny = [
        "ufw",
        "insert",
        "<after-allow>",
        "deny",
        "to",
        "any",
        "port",
        str(profile.backend_port),
        "proto",
        "tcp",
        "comment",
        _deny_comment(profile),
    ]
    steps = (
        shlex.join(allow),
        shlex.join(deny),
        f"atomic write {layout.sysctl_file} then apply only managed keys with sysctl -w",
        shlex.join(_iptables_command("-A", "OUTPUT", interface)),
        shlex.join(_iptables_command("-A", "POSTROUTING", interface)),
        "TCPMSS rules are runtime-only; no reboot persistence is installed",
        "Verify UFW, sysctl runtime values and both exact TCPMSS rules",
        "Do not enable/reset UFW, change its defaults, call nft, or overwrite rules.v4",
    )
    return ExitNetworkPlan(interface=interface, steps=steps, checks=checks)


def _delete_ufw_comment(
    profile: ExitNetworkProfile,
    runner: Runner,
    comment: str,
) -> None:
    state = _inspect_ufw(profile, runner)
    if not state.active:
        raise InstallerError("UFW стал inactive/unknown во время rollback")
    if comment == _allow_comment(profile):
        indices = state.allow_indices
    elif comment == _deny_comment(profile):
        indices = state.deny_indices
    else:  # pragma: no cover - internal invariant
        raise InstallerError("Unknown managed UFW comment")
    if not indices:
        raise InstallerError(f"Managed UFW rule {comment} не найдена при rollback")
    errors: list[str] = []
    for index in sorted(indices, reverse=True):
        try:
            _must(
                runner,
                ["ufw", "--force", "delete", str(index)],
                operation=f"Не удалось удалить managed UFW rule {comment}",
            )
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise InstallerError("; ".join(errors))
    after = _inspect_ufw(profile, runner)
    remaining = (
        after.allow_indices
        if comment == _allow_comment(profile)
        else after.deny_indices
    )
    if remaining:
        raise InstallerError(f"Managed UFW rule {comment} осталась после rollback")


def _restore_sysctl(
    layout: ExitNetworkLayout,
    runner: Runner,
    snapshot: _FileSnapshot | None,
    runtime: dict[str, str],
) -> None:
    errors: list[str] = []
    try:
        _restore_file(layout.sysctl_file, snapshot)
    except Exception as exc:
        errors.append(f"restore file: {exc}")
    for key, value in runtime.items():
        try:
            _must(
                runner,
                ["sysctl", "-w", f"{key}={value}"],
                operation=f"Не удалось восстановить runtime sysctl {key}",
            )
        except Exception as exc:
            errors.append(str(exc))
    if errors:
        raise InstallerError("; ".join(errors))


@contextlib.contextmanager
def _network_lock(layout: ExitNetworkLayout) -> Iterator[None]:
    if os.name != "posix" and layout.root != Path("/"):
        yield
        return
    layout.lock.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with exclusive_lock(layout.lock):
        yield


def apply_exit_network(
    profile: ExitNetworkProfile,
    *,
    layout: ExitNetworkLayout | None = None,
    runner: Runner | None = None,
) -> ExitNetworkApplyResult:
    """Apply the optional exit profile and rollback only this call's mutations."""

    profile = profile.validate()
    layout = layout or ExitNetworkLayout()
    command_runner = _runner(runner)
    if layout.root == Path("/"):
        if platform.system() != "Linux":
            raise InstallerError(
                "Сетевой профиль выхода поддерживается только на Linux"
            )
        if os.geteuid() != 0:
            raise InstallerError("Для сетевого профиля выхода нужны права root")

    with _network_lock(layout):
        interface = _detect_default_interface(command_runner)
        _verify_bbr_available(command_runner)
        ufw_before = _inspect_ufw(profile, command_runner)
        if not ufw_before.active:
            raise InstallerError(
                "UFW inactive/unknown: apply отказался включать или перенастраивать его"
            )
        mss_before = _inspect_mss_rules(command_runner, interface)
        sysctl_snapshot = _snapshot_optional(layout.sysctl_file)
        sysctl_before = _read_sysctl_values(command_runner)
        sysctl_expected = _sysctl_text().encode("utf-8")
        strict_root = layout.root == Path("/")

        rollback: list[tuple[str, Callable[[], None]]] = []
        allow_added = False
        deny_added = False
        sysctl_file_changed = (
            sysctl_snapshot is None
            or sysctl_snapshot.data != sysctl_expected
            or (os.name == "posix" and sysctl_snapshot.mode != 0o644)
            or (strict_root and (sysctl_snapshot.uid != 0 or sysctl_snapshot.gid != 0))
        )
        sysctl_applied = False
        output_added = False
        postrouting_added = False
        try:
            if not ufw_before.allow_indices:
                _must(
                    command_runner,
                    [
                        "ufw",
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
                        _allow_comment(profile),
                    ],
                    operation="Не удалось добавить UFW frontend allow rule",
                )
                allow_added = True
                rollback.append(
                    (
                        "UFW frontend allow",
                        lambda: _delete_ufw_comment(
                            profile, command_runner, _allow_comment(profile)
                        ),
                    )
                )

            ufw_after_allow = _inspect_ufw(profile, command_runner)
            if not ufw_after_allow.allow_indices:
                raise VerificationError("UFW не подтвердил managed frontend allow rule")
            if not ufw_after_allow.deny_indices:
                insert_at = ufw_after_allow.allow_indices[0] + 1
                _must(
                    command_runner,
                    [
                        "ufw",
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
                        _deny_comment(profile),
                    ],
                    operation="Не удалось добавить UFW backend deny rule",
                )
                deny_added = True
                rollback.append(
                    (
                        "UFW backend deny",
                        lambda: _delete_ufw_comment(
                            profile, command_runner, _deny_comment(profile)
                        ),
                    )
                )
            ufw_after = _inspect_ufw(profile, command_runner)
            if not ufw_after.allow_indices or not ufw_after.deny_indices:
                raise VerificationError("UFW не подтвердил обе managed rules")

            if sysctl_file_changed or sysctl_before != SYSCTL_VALUES:
                rollback.append(
                    (
                        "sysctl file/runtime",
                        lambda: _restore_sysctl(
                            layout,
                            command_runner,
                            sysctl_snapshot,
                            sysctl_before,
                        ),
                    )
                )
                if sysctl_file_changed:
                    layout.sysctl_file.parent.mkdir(parents=True, exist_ok=True)
                    atomic_write(layout.sysctl_file, sysctl_expected, 0o644)
                    _normalize_managed_file(
                        layout.sysctl_file,
                        0o644,
                        strict_root=strict_root,
                    )
                for key, value in SYSCTL_VALUES.items():
                    _must(
                        command_runner,
                        ["sysctl", "-w", f"{key}={value}"],
                        operation=f"Не удалось применить managed sysctl {key}",
                    )
                sysctl_applied = True
                runtime_after = _read_sysctl_values(command_runner)
                if runtime_after != SYSCTL_VALUES:
                    raise VerificationError(
                        "Runtime sysctl values не совпали с managed profile"
                    )

            for chain in ("OUTPUT", "POSTROUTING"):
                if mss_before[chain]:
                    continue
                _must(
                    command_runner,
                    _iptables_command("-A", chain, interface),
                    operation=f"Не удалось добавить TCPMSS {chain} rule",
                )
                if chain == "OUTPUT":
                    output_added = True
                else:
                    postrouting_added = True
                rollback.append(
                    (
                        f"TCPMSS {chain}",
                        lambda selected=chain: _must(
                            command_runner,
                            _iptables_command("-D", selected, interface),
                            operation=f"Не удалось удалить TCPMSS {selected} rule",
                        ),
                    )
                )
                if not _rule_exists(command_runner, chain, interface):
                    raise VerificationError(
                        f"iptables не подтвердил TCPMSS {chain} rule"
                    )

            verified_rules = _inspect_mss_rules(command_runner, interface)
            if not all(verified_rules.values()):
                raise VerificationError("Не подтверждены обе managed TCPMSS rules")
        except Exception as original:
            rollback_errors: list[str] = []
            for name, action in reversed(rollback):
                try:
                    action()
                except Exception as exc:
                    rollback_errors.append(f"{name}: {exc}")
            if rollback_errors:
                raise InstallerError(
                    "Применение сетевого профиля не удалось, rollback неполон: "
                    + "; ".join(rollback_errors)
                ) from original
            raise

        return ExitNetworkApplyResult(
            interface=interface,
            ufw_allow_added=allow_added,
            ufw_deny_added=deny_added,
            sysctl_file_changed=sysctl_file_changed,
            sysctl_applied=sysctl_applied,
            mss_output_added=output_added,
            mss_postrouting_added=postrouting_added,
            mss_runtime_only=True,
        )


def doctor_exit_network(
    profile: ExitNetworkProfile,
    *,
    layout: ExitNetworkLayout | None = None,
    runner: Runner | None = None,
) -> list[NetworkCheck]:
    """Return read-only checks; operational failures become failed checks."""

    profile = profile.validate()
    layout = layout or ExitNetworkLayout()
    command_runner = _runner(runner)
    try:
        interface = _detect_default_interface(command_runner)
    except InstallerError as exc:
        return [NetworkCheck("Default IPv4 interface", False, str(exc))]
    checks = [NetworkCheck("Default IPv4 interface", True, interface)]
    try:
        _verify_bbr_available(command_runner)
        checks.append(NetworkCheck("BBR available", True, "bbr"))
    except InstallerError as exc:
        checks.append(NetworkCheck("BBR available", False, str(exc)))
    try:
        checks.extend(
            _read_checks(
                profile,
                layout,
                command_runner,
                interface=interface,
            )
        )
    except InstallerError as exc:
        checks.append(NetworkCheck("Exit network profile", False, str(exc)))
    return checks
