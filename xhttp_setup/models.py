from __future__ import annotations

from dataclasses import asdict, dataclass, field
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


SCHEMA_VERSION = 2
DEFAULT_TLS_FINGERPRINT = "edge"
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
            schema_version=SCHEMA_VERSION,
        )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Handoff":
        payload = dict(data)
        if payload.get("schema_version", 1) == 1:
            # Legacy schema v1 hard-coded Chrome in the smoke client and URI.
            # Preserve that behaviour when an older protected handoff is reused.
            payload["tls_fingerprint"] = "chrome"
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

    def validate(self) -> "FrontDesired":
        if self.placeholder_mode not in {"keep", "neutral"}:
            raise ValidationError("placeholder_mode должен быть keep или neutral")
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
        )
