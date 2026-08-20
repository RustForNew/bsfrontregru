from __future__ import annotations

import ipaddress
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import SplitResult, urlsplit, urlunsplit

from .errors import ValidationError
from .validate import validate_host, validate_ipv4


_EXIT_MAX_CHARS = 4096
_EXIT_MAX_LINE_CHARS = 1024
_REGRU_MAX_CHARS = 64 * 1024
_REGRU_MAX_LINES = 512
_REGRU_MAX_LINE_CHARS = 2048
_MAX_LOGIN_CHARS = 256
_MAX_PASSWORD_CHARS = 1024
_MAX_URL_CHARS = 2048

_FIELD_LINE = re.compile(r"^\s*(?P<label>[^:\r\n]{1,96})\s*:\s*(?P<value>.*?)\s*$")
_MARKDOWN_LINK = re.compile(r"^\[([^\]\r\n]+)\]\(([^()\s]+)\)$")
_REGRU_PANEL_HOST = re.compile(r"^vip[0-9]+\.hosting\.reg\.ru$")
_DASHES = str.maketrans(
    {
        "\N{HYPHEN}": "-",
        "\N{NON-BREAKING HYPHEN}": "-",
        "\N{FIGURE DASH}": "-",
        "\N{EN DASH}": "-",
        "\N{EM DASH}": "-",
        "\N{MINUS SIGN}": "-",
    }
)

_SECTIONS = {
    "доступ в панель управления хостингом": "panel",
    "доступ к ftp": "ftp",
    "доступ к mysql": "mysql",
}
_FIELDS = {
    "panel": {
        "логин": "panel_login",
        "пароль": "panel_password",
        "ваша панель управления": "panel_kind",
        "адрес панели управления": "panel_url",
        "адрес панели управления хостингом": "panel_url",
    },
    "ftp": {
        "логин": "ftp_login",
        "пароль": "ftp_password",
        "ip-адрес сервера": "ftp_server_ip",
    },
    "mysql": {
        "логин": "mysql_login",
        "пароль": "mysql_password",
        "имя базы": "mysql_database",
        "host": "mysql_host",
        "хост": "mysql_host",
    },
}
_REQUIRED_REGRU_FIELDS = (
    "panel_login",
    "panel_password",
    "panel_url",
    "ftp_login",
    "ftp_password",
    "ftp_server_ip",
)
_REQUIRED_REGRU_PARSE_FIELDS = (*_REQUIRED_REGRU_FIELDS, "panel_kind")
_STORED_REGRU_FIELDS = frozenset(
    {
        "panel_login",
        "panel_password",
        "panel_url",
        "panel_kind",
        "ftp_login",
        "ftp_server_ip",
    }
)


@dataclass(frozen=True, slots=True)
class ExitCredentials:
    ip: str
    username: str
    password: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class RegRuCredentials:
    panel_login: str
    panel_password: str = field(repr=False)
    panel_url: str
    ftp_login: str
    ftp_server_ip: str


def _reject_unsafe_characters(value: str, *, input_name: str) -> None:
    for character in value:
        if character in "\r\n":
            continue
        category = unicodedata.category(character)
        if category in {"Cc", "Cf", "Cs"} or character in "\v\f\x85\u2028\u2029":
            raise ValidationError(f"{input_name} содержит управляющие символы")


def _physical_lines(value: str) -> list[str]:
    normalized = value.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def parse_exit_credentials(value: str) -> ExitCredentials:
    """Parse the literal three-line ``IPv4 / root / password`` handoff."""

    if not isinstance(value, str) or not value:
        raise ValidationError("Данные выхода не заданы")
    if len(value) > _EXIT_MAX_CHARS:
        raise ValidationError("Блок данных выхода слишком большой")
    _reject_unsafe_characters(value, input_name="Блок данных выхода")

    lines = _physical_lines(value)
    if len(lines) != 3 or any(not line.strip() for line in lines):
        raise ValidationError(
            "Данные выхода должны содержать ровно три непустые строки: IP, root, пароль"
        )
    if any(len(line) > _EXIT_MAX_LINE_CHARS for line in lines):
        raise ValidationError("Строка в данных выхода слишком длинная")

    ip = validate_ipv4(lines[0])
    if not ipaddress.IPv4Address(ip).is_global:
        raise ValidationError("В первой строке нужен публичный IPv4 выхода")
    username = lines[1].strip()
    if username != "root":
        raise ValidationError("Во второй строке данных выхода должен быть root")
    password = lines[2]
    if len(password) > _MAX_PASSWORD_CHARS:
        raise ValidationError("Пароль выхода слишком длинный")
    return ExitCredentials(ip=ip, username=username, password=password)


def _normalized_label(value: str) -> str:
    normalized = unicodedata.normalize("NFKC", value).translate(_DASHES)
    normalized = " ".join(normalized.split()).casefold().strip().rstrip(":").strip()
    return re.sub(r"\s*-\s*", "-", normalized)


def _normalized_value(value: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", value).split()).casefold()


def _section_name(line: str) -> str | None:
    return _SECTIONS.get(_normalized_label(line))


def _field_from_line(line: str, section: str) -> tuple[str, str] | None:
    match = _FIELD_LINE.fullmatch(line)
    if match:
        label = _normalized_label(match.group("label"))
        field_name = _FIELDS[section].get(label)
        if field_name:
            return field_name, match.group("value")
        return None
    label = _normalized_label(line)
    field_name = _FIELDS[section].get(label)
    if field_name:
        return field_name, ""
    return None


def _next_nonempty_value(
    lines: list[str], start: int, *, current_section: str
) -> tuple[str, int]:
    index = start
    while index < len(lines) and not lines[index].strip():
        index += 1
    if index >= len(lines):
        raise ValidationError("В блоке REG.RU есть поле без значения")
    candidate = lines[index]
    if _section_name(candidate) is not None:
        raise ValidationError("В блоке REG.RU есть поле без значения")
    if _field_from_line(candidate, current_section) is not None:
        raise ValidationError("В блоке REG.RU есть поле без значения")
    return candidate.strip(), index + 1


def _validate_login(value: str, *, field_name: str) -> str:
    login = value.strip()
    if (
        not login
        or len(login) > _MAX_LOGIN_CHARS
        or any(char.isspace() for char in login)
    ):
        raise ValidationError(f"Некорректное поле {field_name} в блоке REG.RU")
    return login


def _validate_password(value: str, *, field_name: str) -> str:
    password = value.strip()
    if not password or len(password) > _MAX_PASSWORD_CHARS:
        raise ValidationError(f"Некорректное поле {field_name} в блоке REG.RU")
    return password


def _validated_url_parts(value: str) -> tuple[str, SplitResult]:
    url = value.strip()
    if (
        not url
        or len(url) > _MAX_URL_CHARS
        or "\\" in url
        or "?" in url
        or "#" in url
        or any(char.isspace() for char in url)
    ):
        raise ValidationError("Некорректный HTTPS-адрес панели REG.RU")
    try:
        parsed = urlsplit(url)
    except ValueError:
        raise ValidationError("Некорректный HTTPS-адрес панели REG.RU") from None
    if (
        parsed.scheme.casefold() != "https"
        or not parsed.netloc
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise ValidationError(
            "Адрес панели REG.RU должен быть HTTPS URL без логина, пароля и query"
        )
    try:
        port = parsed.port
        validate_host(parsed.hostname)
    except (ValueError, ValidationError):
        raise ValidationError("Некорректный HTTPS-адрес панели REG.RU") from None
    if port is not None and not 1 <= port <= 65535:  # pragma: no cover - urlsplit
        raise ValidationError("Некорректный порт панели REG.RU")
    return url, parsed


def _url_identity(parsed: SplitResult) -> tuple[str, str, int | None, str]:
    host = validate_host(parsed.hostname or "")
    path = parsed.path or "/"
    return parsed.scheme.casefold(), host, parsed.port, path.rstrip("/") or "/"


def _normalized_regru_panel_url(parsed: SplitResult) -> str:
    host = validate_host(parsed.hostname or "")
    if not _REGRU_PANEL_HOST.fullmatch(host):
        raise ValidationError("Адрес панели не относится к узлу хостинга REG.RU")
    if parsed.port != 1500:
        raise ValidationError("Для панели REG.RU ожидался HTTPS-порт 1500")
    path = parsed.path or "/"
    if path.rstrip("/") not in {"", "/ispmgr", "/manager/ispmgr"}:
        raise ValidationError("Неожиданный путь в адресе панели REG.RU")
    return urlunsplit(("https", f"{host}:1500", path, "", ""))


def _validate_panel_url(value: str) -> str:
    candidate = value.strip()
    markdown = _MARKDOWN_LINK.fullmatch(candidate)
    if markdown:
        display = markdown.group(1).strip()
        candidate = markdown.group(2).strip()
        url, parsed = _validated_url_parts(candidate)
        if display.casefold().startswith("https://"):
            _, display_parsed = _validated_url_parts(display)
            if _url_identity(display_parsed) != _url_identity(parsed):
                raise ValidationError(
                    "В Markdown-ссылке панели REG.RU различаются адреса"
                )
        return _normalized_regru_panel_url(parsed)
    _, parsed = _validated_url_parts(candidate)
    return _normalized_regru_panel_url(parsed)


def _parse_regru_fields(lines: list[str]) -> tuple[dict[str, str], set[str]]:
    values: dict[str, str] = {}
    seen_fields: set[str] = set()
    seen_sections: set[str] = set()
    current_section: str | None = None
    index = 0
    while index < len(lines):
        line = lines[index]
        section = _section_name(line)
        if section is not None:
            if section in seen_sections:
                raise ValidationError("В блоке REG.RU повторяется раздел")
            seen_sections.add(section)
            current_section = section
            index += 1
            continue

        normalized = _normalized_label(line)
        if normalized.startswith(("доступ к ", "доступ в ")):
            current_section = None
            index += 1
            continue
        if current_section is None:
            index += 1
            continue

        parsed_field = _field_from_line(line, current_section)
        if parsed_field is None:
            index += 1
            continue
        field_name, raw_value = parsed_field
        if field_name in seen_fields:
            raise ValidationError("В блоке REG.RU повторяется поле")
        seen_fields.add(field_name)
        if raw_value:
            field_value = raw_value.strip()
            index += 1
        else:
            field_value, index = _next_nonempty_value(
                lines, index + 1, current_section=current_section
            )
        if not field_value:
            raise ValidationError("В блоке REG.RU есть поле без значения")
        # Provider metadata and MySQL credentials are recognized only to keep
        # section scoping unambiguous. The installer does not need or retain them.
        if field_name in _STORED_REGRU_FIELDS:
            values[field_name] = field_value
    return values, seen_fields


def parse_regru_credentials(value: str) -> RegRuCredentials:
    """Extract panel and FTP fields from a copied REG.RU credential block.

    MySQL fields are recognized while scanning so that they cannot be confused with
    panel or FTP credentials. MySQL credentials and the FTP password are deliberately
    omitted from the result. The FTP login/IP retain their provider labels; callers
    must not assume that the FTP password is an SFTP credential.
    """

    if not isinstance(value, str) or not value:
        raise ValidationError("Блок REG.RU не задан")
    if len(value) > _REGRU_MAX_CHARS:
        raise ValidationError("Блок REG.RU слишком большой")
    _reject_unsafe_characters(value, input_name="Блок REG.RU")
    lines = _physical_lines(value)
    if len(lines) > _REGRU_MAX_LINES:
        raise ValidationError("В блоке REG.RU слишком много строк")
    if any(len(line) > _REGRU_MAX_LINE_CHARS for line in lines):
        raise ValidationError("Строка в блоке REG.RU слишком длинная")

    values, seen_fields = _parse_regru_fields(lines)
    if any(
        field_name not in seen_fields for field_name in _REQUIRED_REGRU_PARSE_FIELDS
    ):
        raise ValidationError("В блоке REG.RU найдены не все данные панели и FTP")
    if _normalized_value(values["panel_kind"]) != "ispmanager":
        raise ValidationError("Поддерживается только панель ISPmanager")

    return RegRuCredentials(
        panel_login=_validate_login(values["panel_login"], field_name="логин панели"),
        panel_password=_validate_password(
            values["panel_password"], field_name="пароль панели"
        ),
        panel_url=_validate_panel_url(values["panel_url"]),
        ftp_login=_validate_login(values["ftp_login"], field_name="логин FTP"),
        ftp_server_ip=validate_ipv4(values["ftp_server_ip"]),
    )
