from __future__ import annotations

import ipaddress
import re
import uuid
from pathlib import PurePosixPath

from .errors import ValidationError


_HOST_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_XHTTP_PATH = re.compile(r"^/[A-Za-z0-9_-]+(?:/[A-Za-z0-9_-]+)*$")
_REMOTE_PATH = re.compile(r"^/[A-Za-z0-9._@/+\-]+$")
_SSH_USER = re.compile(r"^[A-Za-z_][A-Za-z0-9_.@-]{0,63}$")
_FINGERPRINT = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}=?$")


def normalize_domain(value: str) -> str:
    raw = value.strip().rstrip(".")
    if not raw:
        raise ValidationError("Домен не задан")
    try:
        domain = raw.encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValidationError("Некорректное IDN-имя домена") from exc
    if len(domain) > 253 or "." not in domain:
        raise ValidationError("Нужен полный домен, например front.example.org")
    labels = domain.split(".")
    if any(not _HOST_LABEL.fullmatch(label) for label in labels):
        raise ValidationError("Некорректное имя домена")
    return domain


def validate_host(value: str) -> str:
    raw = value.strip().rstrip(".")
    try:
        return str(ipaddress.ip_address(raw))
    except ValueError:
        return normalize_domain(raw)


def validate_ipv4(value: str) -> str:
    try:
        address = ipaddress.ip_address(value.strip())
    except ValueError as exc:
        raise ValidationError("Ожидался IPv4-адрес") from exc
    if address.version != 4 or address.is_unspecified:
        raise ValidationError("Нужен конкретный IPv4-адрес")
    return str(address)


def validate_port(value: int | str) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise ValidationError("Порт должен быть числом") from exc
    if not 1 <= port <= 65535:
        raise ValidationError("Порт должен быть в диапазоне 1..65535")
    return port


def validate_xhttp_path(value: str) -> str:
    path = value.strip()
    if not _XHTTP_PATH.fullmatch(path):
        raise ValidationError(
            "XHTTP path должен начинаться с / и содержать только буквы, цифры, _ и -"
        )
    if len(path) < 12 or len(path) > 180:
        raise ValidationError("XHTTP path должен иметь длину 12..180 символов")
    return path


def validate_uuid(value: str) -> str:
    try:
        parsed = uuid.UUID(value.strip())
    except (ValueError, AttributeError) as exc:
        raise ValidationError("Некорректный UUID") from exc
    return str(parsed)


def validate_remote_dir(value: str) -> str:
    path = value.strip().rstrip("/")
    if not path or not _REMOTE_PATH.fullmatch(path):
        raise ValidationError("Некорректный абсолютный путь document root")
    pure = PurePosixPath(path)
    if not pure.is_absolute() or ".." in pure.parts:
        raise ValidationError("Document root должен быть абсолютным и не содержать ..")
    return str(pure)


def validate_ssh_user(value: str) -> str:
    user = value.strip()
    if not _SSH_USER.fullmatch(user):
        raise ValidationError("Некорректное имя SSH/SFTP-пользователя")
    return user


def validate_fingerprint(value: str) -> str:
    fingerprint = value.strip()
    if not _FINGERPRINT.fullmatch(fingerprint):
        raise ValidationError("Нужен SSH fingerprint вида SHA256:...")
    return fingerprint.rstrip("=")
