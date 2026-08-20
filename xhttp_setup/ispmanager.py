from __future__ import annotations

import ssl
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

from .errors import InstallerError, VerificationError
from .validate import normalize_domain, validate_remote_dir


@dataclass(frozen=True)
class SiteInfo:
    name: str
    docroot: str
    ipaddr: str | None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def validate_panel_endpoint(value: str) -> str:
    endpoint = value.strip().rstrip("/")
    parsed = urlsplit(endpoint)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
    ):
        raise InstallerError(
            "ISPmanager endpoint должен быть HTTPS URL без credentials"
        )
    if parsed.path not in {"/ispmgr", "/manager/ispmgr"}:
        raise InstallerError("Ожидался endpoint, заканчивающийся на /ispmgr")
    if parsed.query or parsed.fragment:
        raise InstallerError("ISPmanager endpoint не должен содержать query/fragment")
    return endpoint


def panel_login_url_to_endpoint(value: str) -> str:
    """Convert a provider login URL into the read-only ISPmanager API endpoint."""

    try:
        parsed = urlsplit(value.strip())
        hostname = parsed.hostname
        port = parsed.port
    except (AttributeError, ValueError):
        raise InstallerError("Некорректный HTTPS-адрес панели ISPmanager") from None
    if (
        parsed.scheme.casefold() != "https"
        or not hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
    ):
        raise InstallerError(
            "Адрес панели ISPmanager должен быть HTTPS URL без credentials/query"
        )
    if parsed.path in {"", "/"}:
        path = "/ispmgr"
    elif parsed.path.rstrip("/") in {"/ispmgr", "/manager/ispmgr"}:
        path = parsed.path.rstrip("/")
    else:
        raise InstallerError("Неожиданный путь в адресе панели ISPmanager")
    netloc = hostname if port is None else f"{hostname}:{port}"
    return validate_panel_endpoint(urlunsplit(("https", netloc, path, "", "")))


def _xml_post(
    endpoint: str, fields: dict[str, str], *, timeout: int = 20
) -> ET.Element:
    data = urllib.parse.urlencode(fields).encode("utf-8")
    request = urllib.request.Request(
        endpoint,
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": "xhttp-setup/0.1",
        },
    )
    try:
        opener = urllib.request.build_opener(
            _NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context()),
        )
        with opener.open(request, timeout=timeout) as response:
            payload = response.read(2 * 1024 * 1024)
    except (OSError, urllib.error.URLError) as exc:
        raise VerificationError(
            f"ISPmanager API недоступен с валидным TLS: {exc}"
        ) from exc
    upper_payload = payload.upper()
    if b"<!DOCTYPE" in upper_payload or b"<!ENTITY" in upper_payload:
        raise VerificationError("ISPmanager XML содержит запрещённый DTD/entity")
    try:
        root = ET.fromstring(payload)  # noqa: S314 - DTD/entities rejected; size is bounded.
    except ET.ParseError as exc:
        raise VerificationError("ISPmanager вернул не XML") from exc
    error = root.find(".//error")
    if error is not None:
        message = " ".join(text.strip() for text in error.itertext() if text.strip())
        raise VerificationError(f"ISPmanager API: {message or 'unknown error'}")
    return root


def parse_site_list(root: ET.Element, domain: str) -> SiteInfo:
    expected = normalize_domain(domain)
    for element in root.iter("elem"):
        fields = {child.tag: (child.text or "").strip() for child in list(element)}
        name = fields.get("name", "").rstrip(".").lower()
        if name == expected:
            docroot = fields.get("docroot", "")
            if not docroot:
                raise VerificationError(
                    "ISPmanager не вернул docroot существующего сайта"
                )
            return SiteInfo(
                name=expected,
                docroot=validate_remote_dir(docroot),
                ipaddr=fields.get("ipaddr") or None,
            )
    raise VerificationError(f"Сайт {expected} не найден в ISPmanager")


def inspect_site(
    *, endpoint: str, username: str, password: str, domain: str
) -> SiteInfo:
    endpoint = validate_panel_endpoint(endpoint)
    if not username.strip() or not password:
        raise InstallerError("Пустой логин или пароль ISPmanager")
    try:
        auth_root = _xml_post(
            endpoint,
            {
                "func": "auth",
                "username": username.strip(),
                "password": password,
                "out": "xml",
                "lang": "en",
            },
        )
        auth = auth_root.find(".//auth")
        session_id = auth.attrib.get("id", "") if auth is not None else ""
        if not session_id:
            raise VerificationError("ISPmanager не вернул session id")
        sites = _xml_post(
            endpoint,
            {
                "func": "webdomain",
                "auth": session_id,
                "out": "xml",
                "lang": "en",
            },
        )
        return parse_site_list(sites, domain)
    except InstallerError as exc:
        detail = str(exc).replace(password, "[REDACTED]")
        raise VerificationError(detail) from None
