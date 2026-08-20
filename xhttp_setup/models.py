from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field, replace
from typing import Any

from .errors import ValidationError
from .validate import (
    normalize_domain,
    validate_fingerprint,
    validate_host,
    validate_ipv4,
    validate_port,
    validate_remote_dir,
    validate_ssh_user,
    validate_uuid,
    validate_xhttp_path,
)


SCHEMA_VERSION = 3
DEFAULT_TLS_FINGERPRINT = "edge"
TLS_MODE_PUBLIC = "public"
TLS_MODE_PINNED = "pinned"
TLS_MODES = frozenset({TLS_MODE_PUBLIC, TLS_MODE_PINNED})
TLS_FINGERPRINTS = frozenset(
    {
        "360",
        "android",
        "chrome",
        "edge",
        "firefox",
        "ios",
        "qq",
        "random",
        "randomized",
        "safari",
    }
)


def validate_tls_fingerprint(value: str) -> str:
    fingerprint = value.strip().lower()
    if fingerprint not in TLS_FINGERPRINTS:
        allowed = ", ".join(sorted(TLS_FINGERPRINTS))
        raise ValidationError(f"TLS fingerprint должен быть одним из: {allowed}")
    return fingerprint


def validate_cert_sha256(value: str) -> str:
    """Normalize an X.509 certificate SHA-256 to Xray's 64-hex form."""

    if not isinstance(value, str):
        raise ValidationError("SHA-256 сертификата должен быть строкой")
    fingerprint = value.strip()
    if fingerprint.lower().startswith("sha256:"):
        fingerprint = fingerprint[7:]
    fingerprint = fingerprint.replace(":", "")
    if not re.fullmatch(r"[0-9A-Fa-f]{64}", fingerprint):
        raise ValidationError(
            "SHA-256 сертификата должен содержать ровно 64 hex-символа "
            "(двоеточия и префикс SHA256: допустимы)"
        )
    return fingerprint.lower()


def validate_front_tls(
    mode: str, pinned_peer_cert_sha256: str | None
) -> tuple[str, str | None]:
    if not isinstance(mode, str):
        raise ValidationError("tls_mode должен быть строкой")
    normalized_mode = mode.strip().lower()
    if normalized_mode not in TLS_MODES:
        raise ValidationError("tls_mode должен быть public или pinned")
    if normalized_mode == TLS_MODE_PUBLIC:
        if pinned_peer_cert_sha256 is not None and pinned_peer_cert_sha256 != "":
            raise ValidationError(
                "Для tls_mode=public pin не задаётся; выберите tls_mode=pinned"
            )
        return normalized_mode, None
    if not pinned_peer_cert_sha256:
        raise ValidationError(
            "Для tls_mode=pinned нужен SHA-256 текущего leaf-сертификата"
        )
    return normalized_mode, validate_cert_sha256(pinned_peer_cert_sha256)


@dataclass(frozen=True)
class Handoff:
    exit_address: str
    exit_port: int
    client_id: str = field(repr=False)
    xhttp_path: str
    encryption: str = field(repr=False)
    label: str = "XHTTP TLS"
    expected_egress_ip: str | None = None
    tls_fingerprint: str = DEFAULT_TLS_FINGERPRINT
    pinned_peer_cert_sha256: str | None = None
    schema_version: int = SCHEMA_VERSION

    def validate(self) -> "Handoff":
        if self.schema_version != SCHEMA_VERSION:
            raise ValidationError(
                f"Неподдерживаемая schema_version: {self.schema_version}"
            )
        if self.encryption == "none":
            raise ValidationError("MVP не разрешает VLESS encryption=none")
        if len(self.encryption) < 32 or any(ch.isspace() for ch in self.encryption):
            raise ValidationError("Некорректный материал VLESS Encryption")
        return Handoff(
            exit_address=validate_ipv4(self.exit_address),
            exit_port=validate_port(self.exit_port),
            client_id=validate_uuid(self.client_id),
            xhttp_path=validate_xhttp_path(self.xhttp_path),
            encryption=self.encryption,
            label=self.label.strip()[:80] or "XHTTP TLS",
            expected_egress_ip=validate_ipv4(
                self.expected_egress_ip or self.exit_address
            ),
            tls_fingerprint=validate_tls_fingerprint(self.tls_fingerprint),
            pinned_peer_cert_sha256=(
                validate_cert_sha256(self.pinned_peer_cert_sha256)
                if self.pinned_peer_cert_sha256 is not None
                else None
            ),
            schema_version=SCHEMA_VERSION,
        )

    def with_pinned_peer_cert(self, value: str | None) -> "Handoff":
        return replace(self, pinned_peer_cert_sha256=value).validate()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Handoff":
        payload = dict(data)
        schema_version = payload.get("schema_version", 1)
        legacy_schema = schema_version == 1 or schema_version == 2
        if legacy_schema and "pinned_peer_cert_sha256" in payload:
            raise ValidationError(
                "Legacy handoff не может содержать pinned_peer_cert_sha256"
            )
        if schema_version == 1:
            # Legacy schema v1 hard-coded Chrome in the smoke client and URI.
            # Preserve that behaviour when an older protected handoff is reused.
            payload["tls_fingerprint"] = "chrome"
        if legacy_schema:
            payload["pinned_peer_cert_sha256"] = None
            payload["schema_version"] = SCHEMA_VERSION
        try:
            return cls(**payload).validate()
        except TypeError as exc:
            raise ValidationError("Некорректная структура handoff.json") from exc


@dataclass(frozen=True)
class ExitDesired:
    public_address: str
    listen_port: int
    front_egress_ip: str
    xhttp_path: str
    client_id: str = field(repr=False)
    label: str = "XHTTP TLS"
    expected_egress_ip: str | None = None
    tls_fingerprint: str = DEFAULT_TLS_FINGERPRINT

    def validate(self) -> "ExitDesired":
        listen_port = validate_port(self.listen_port)
        if listen_port < 1024:
            raise ValidationError(
                "Managed Xray работает без root; выберите порт 1024..65535"
            )
        return ExitDesired(
            public_address=validate_ipv4(self.public_address),
            listen_port=listen_port,
            front_egress_ip=validate_ipv4(self.front_egress_ip),
            xhttp_path=validate_xhttp_path(self.xhttp_path),
            client_id=validate_uuid(self.client_id),
            label=self.label.strip()[:80] or "XHTTP TLS",
            expected_egress_ip=validate_ipv4(
                self.expected_egress_ip or self.public_address
            ),
            tls_fingerprint=validate_tls_fingerprint(self.tls_fingerprint),
        )


@dataclass(frozen=True)
class FrontDesired:
    domain: str
    client_connect_ip: str
    dns_ipv4: str
    sftp_host: str
    sftp_port: int
    sftp_user: str
    document_root: str
    ssh_host_key_sha256: str
    exit_address: str
    exit_port: int
    xhttp_path: str
    placeholder_mode: str = "keep"
    tls_mode: str = TLS_MODE_PUBLIC
    pinned_peer_cert_sha256: str | None = None

    def validate(self) -> "FrontDesired":
        if self.placeholder_mode not in {"keep", "neutral"}:
            raise ValidationError("placeholder_mode должен быть keep или neutral")
        tls_mode, pinned_peer_cert_sha256 = validate_front_tls(
            self.tls_mode, self.pinned_peer_cert_sha256
        )
        return FrontDesired(
            domain=normalize_domain(self.domain),
            client_connect_ip=validate_ipv4(self.client_connect_ip),
            dns_ipv4=validate_ipv4(self.dns_ipv4),
            sftp_host=validate_host(self.sftp_host),
            sftp_port=validate_port(self.sftp_port),
            sftp_user=validate_ssh_user(self.sftp_user),
            document_root=validate_remote_dir(self.document_root),
            ssh_host_key_sha256=validate_fingerprint(self.ssh_host_key_sha256),
            exit_address=validate_ipv4(self.exit_address),
            exit_port=validate_port(self.exit_port),
            xhttp_path=validate_xhttp_path(self.xhttp_path),
            placeholder_mode=self.placeholder_mode,
            tls_mode=tls_mode,
            pinned_peer_cert_sha256=pinned_peer_cert_sha256,
        )
