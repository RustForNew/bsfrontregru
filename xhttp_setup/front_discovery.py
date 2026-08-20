from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import ssl
import stat
from dataclasses import dataclass
from pathlib import Path

from .errors import InstallerError, VerificationError
from .front import https_status
from .models import TLS_MODE_PINNED, TLS_MODE_PUBLIC
from .osutil import atomic_write_text, ensure_dir
from .ssh_transport import TCPRoute
from .validate import normalize_domain, validate_ipv4


_TLS_PORT = 443
_PIN_SCHEMA_VERSION = 1


@dataclass(frozen=True)
class FrontTLSDiscovery:
    """TLS policy ready to be copied into ``FrontDesired``."""

    tls_mode: str
    pinned_peer_cert_sha256: str | None


def resolve_front_dns(domain: str) -> str:
    """Return the frontend's single IPv4 address and reject any IPv6 path."""

    domain = normalize_domain(domain)
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    try:
        answers = socket.getaddrinfo(
            domain,
            _TLS_PORT,
            family=socket.AF_UNSPEC,
            type=socket.SOCK_STREAM,
        )
    except socket.gaierror as exc:
        raise VerificationError(f"DNS {domain} не разрешается: {exc}") from exc

    for family, _, _, _, sockaddr in answers:
        if family == socket.AF_INET:
            ipv4.add(str(sockaddr[0]))
        elif family == socket.AF_INET6:
            ipv6.add(str(sockaddr[0]))

    if ipv6:
        raise VerificationError(
            f"Для frontend {domain} обнаружена AAAA-запись: "
            f"{', '.join(sorted(ipv6))}. Удалите AAAA перед установкой"
        )
    if len(ipv4) != 1:
        actual = ", ".join(sorted(ipv4)) or "A-записей нет"
        raise VerificationError(
            f"DNS {domain} должен содержать ровно один IPv4-адрес; получено: {actual}"
        )
    return next(iter(ipv4))


def _leaf_certificate(
    domain: str,
    connect_ip: str,
    *,
    verify_public_identity: bool,
    timeout: int,
    route: TCPRoute | None = None,
) -> bytes:
    if verify_public_identity:
        context = ssl.create_default_context()
    else:
        # This context is used only to learn a candidate leaf. The candidate is
        # accepted only after a second identical handshake and an HTTPS request
        # that checks its exact SHA-256; callers never receive an allowInsecure
        # policy.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

    transport = route.validate() if route is not None else None
    endpoint = (
        (transport.connect_host, transport.connect_port)
        if transport is not None
        else (connect_ip, _TLS_PORT)
    )
    with socket.create_connection(endpoint, timeout=timeout) as raw:
        with context.wrap_socket(raw, server_hostname=domain) as tls:
            certificate_der = tls.getpeercert(binary_form=True)
    if not certificate_der:
        raise VerificationError(
            f"TLS endpoint {connect_ip}:443 для {domain} не предоставил leaf-сертификат"
        )
    return certificate_der


def _certificate_error(domain: str, connect_ip: str, exc: BaseException) -> str:
    return f"TLS для {domain} через {connect_ip}:443 не прошёл проверку: {exc}"


def _reject_symlink_components(path: Path) -> None:
    candidate = path.absolute()
    while True:
        try:
            metadata = candidate.lstat()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise InstallerError(f"Не удалось проверить state path {candidate}: {exc}") from exc
        else:
            if stat.S_ISLNK(metadata.st_mode):
                raise InstallerError(f"State path не может содержать symlink: {candidate}")
        parent = candidate.parent
        if parent == candidate:
            break
        candidate = parent


def _pin_file(state_dir: Path, domain: str, connect_ip: str) -> Path:
    expanded = state_dir.expanduser()
    _reject_symlink_components(expanded)
    if expanded.exists():
        if not expanded.is_dir():
            raise InstallerError(f"Ожидался state-каталог: {expanded}")
    else:
        ensure_dir(expanded, 0o700)

    pins_dir = expanded / "front-tls-pins"
    _reject_symlink_components(pins_dir)
    ensure_dir(pins_dir, 0o700)
    # One record per domain, with the exact endpoint bound inside the record.
    # A changed connect IP therefore cannot create a new independent TOFU slot
    # and silently retrust a different endpoint for the same domain.
    key = hashlib.sha256(domain.encode("utf-8")).hexdigest()
    return pins_dir / f"{key}.json"


def _load_persisted_leaf(
    state_dir: Path | None, domain: str, connect_ip: str
) -> tuple[Path | None, str | None]:
    if state_dir is None:
        return None, None
    path = _pin_file(state_dir, domain, connect_ip)
    _reject_symlink_components(path)
    if not path.exists():
        return path, None

    try:
        metadata = path.lstat()
        if not stat.S_ISREG(metadata.st_mode):
            raise InstallerError(f"TLS pin должен быть обычным файлом: {path}")
        if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
            raise InstallerError(
                f"Права TLS pin {path}: {stat.S_IMODE(metadata.st_mode):04o}, "
                "ожидалось 0600"
            )
        raw = json.loads(path.read_text("utf-8"))
    except InstallerError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InstallerError(f"Не удалось прочитать TLS pin {path}: {exc}") from exc

    expected_identity = {
        "schemaVersion": _PIN_SCHEMA_VERSION,
        "domain": domain,
        "connectIp": connect_ip,
        "port": _TLS_PORT,
    }
    if not isinstance(raw, dict) or any(
        raw.get(name) != value for name, value in expected_identity.items()
    ):
        raise InstallerError(f"TLS pin {path} имеет некорректную endpoint identity")
    leaf_sha256 = raw.get("leafSha256")
    if not isinstance(leaf_sha256, str) or len(leaf_sha256) != 64:
        raise InstallerError(f"TLS pin {path} не содержит корректный leaf SHA-256")
    try:
        bytes.fromhex(leaf_sha256)
    except ValueError as exc:
        raise InstallerError(
            f"TLS pin {path} не содержит корректный leaf SHA-256"
        ) from exc
    return path, leaf_sha256.lower()


def _enforce_or_persist_leaf(
    *,
    path: Path | None,
    persisted_leaf_sha256: str | None,
    domain: str,
    connect_ip: str,
    leaf_sha256: str,
) -> None:
    if persisted_leaf_sha256 is not None:
        if not hmac.compare_digest(persisted_leaf_sha256, leaf_sha256):
            raise VerificationError(
                f"TLS leaf для {domain} через {connect_ip}:443 изменился: "
                f"ожидался сохранённый {persisted_leaf_sha256}, получен {leaf_sha256}"
            )
        return
    if path is None:
        return

    _reject_symlink_components(path)
    payload = {
        "schemaVersion": _PIN_SCHEMA_VERSION,
        "domain": domain,
        "connectIp": connect_ip,
        "port": _TLS_PORT,
        "leafSha256": leaf_sha256,
    }
    atomic_write_text(
        path,
        json.dumps(payload, ensure_ascii=True, sort_keys=True) + "\n",
        0o600,
    )
    _reject_symlink_components(path)
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode):
        raise InstallerError(f"TLS pin должен быть обычным файлом: {path}")
    if os.name == "posix" and stat.S_IMODE(metadata.st_mode) != 0o600:
        raise InstallerError(f"TLS pin записан с небезопасными правами: {path}")


def discover_front_tls_policy(
    domain: str,
    connect_ip: str,
    *,
    state_dir: Path | None = None,
    timeout: int = 12,
    route: TCPRoute | None = None,
) -> FrontTLSDiscovery:
    """Choose public validation or a stable exact leaf pin for one endpoint.

    Falling back to pinning is permitted only after the normal CA/hostname
    handshake specifically reports certificate-verification failure. Transport
    and TLS protocol failures remain hard errors.
    """

    domain = normalize_domain(domain)
    connect_ip = validate_ipv4(connect_ip)
    if timeout <= 0:
        raise VerificationError("TLS timeout должен быть положительным")
    route_kwargs: dict[str, TCPRoute] = {}
    if route is not None:
        route_kwargs["route"] = route

    try:
        _leaf_certificate(
            domain,
            connect_ip,
            verify_public_identity=True,
            timeout=timeout,
            **route_kwargs,
        )
    except ssl.SSLCertVerificationError:
        # A CA/hostname-verified public certificate may rotate normally and is
        # never leaf-pinned.  Persistent exact-leaf state belongs only to the
        # explicit-pin fallback policy.
        path, persisted_leaf = _load_persisted_leaf(
            state_dir, domain, connect_ip
        )
        try:
            first = _leaf_certificate(
                domain,
                connect_ip,
                verify_public_identity=False,
                timeout=timeout,
                **route_kwargs,
            )
            second = _leaf_certificate(
                domain,
                connect_ip,
                verify_public_identity=False,
                timeout=timeout,
                **route_kwargs,
            )
        except (OSError, ssl.SSLError, VerificationError) as exc:
            raise VerificationError(_certificate_error(domain, connect_ip, exc)) from exc
        if not first or not second or not hmac.compare_digest(first, second):
            raise VerificationError(
                f"TLS leaf для {domain} через {connect_ip}:443 нестабилен; "
                "автоматическое закрепление запрещено"
            )
        leaf_sha256 = hashlib.sha256(first).hexdigest()
        _enforce_or_persist_leaf(
            path=None,
            persisted_leaf_sha256=persisted_leaf,
            domain=domain,
            connect_ip=connect_ip,
            leaf_sha256=leaf_sha256,
        )
        # This performs an actual HTTPS request using SNI=domain while checking
        # the exact candidate leaf before any request bytes are sent.
        https_status(
            f"https://{domain}/",
            connect_ip=connect_ip,
            pinned_peer_cert_sha256=leaf_sha256,
            timeout=timeout,
            **route_kwargs,
        )
        _enforce_or_persist_leaf(
            path=path,
            persisted_leaf_sha256=persisted_leaf,
            domain=domain,
            connect_ip=connect_ip,
            leaf_sha256=leaf_sha256,
        )
        return FrontTLSDiscovery(TLS_MODE_PINNED, leaf_sha256)
    except (OSError, ssl.SSLError, VerificationError) as exc:
        raise VerificationError(_certificate_error(domain, connect_ip, exc)) from exc

    return FrontTLSDiscovery(TLS_MODE_PUBLIC, None)
