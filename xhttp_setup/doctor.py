from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import dataclass
from pathlib import Path

from .errors import InstallerError, VerificationError
from .exit_installer import Layout, XRAY_ASSETS, XRAY_VERSION, install_xray_binary
from .front import check_public_tls, https_status
from .models import Handoff
from .osutil import (
    atomic_write_text,
    command_exists,
    ensure_dir,
    load_json,
    run,
    sha256_file,
)
from .render import pretty_json, render_xray_client_config
from .validate import validate_ipv4, validate_port


@dataclass(frozen=True)
class Check:
    name: str
    ok: bool
    detail: str


def resolve_front(domain: str) -> tuple[list[str], list[str]]:
    ipv4: set[str] = set()
    ipv6: set[str] = set()
    try:
        for family, _, _, _, sockaddr in socket.getaddrinfo(domain, 443):
            if family == socket.AF_INET:
                ipv4.add(sockaddr[0])
            elif family == socket.AF_INET6:
                ipv6.add(sockaddr[0])
    except socket.gaierror as exc:
        raise VerificationError(f"DNS {domain} не разрешается: {exc}") from exc
    return sorted(ipv4), sorted(ipv6)


def doctor_front(
    domain: str,
    path: str,
    *,
    client_connect_ip: str | None = None,
    dns_ipv4: str | None = None,
    pinned_peer_cert_sha256: str | None = None,
) -> list[Check]:
    checks: list[Check] = []
    try:
        ipv4, ipv6 = resolve_front(domain)
        dns_ok = ipv4 == [dns_ipv4] if dns_ipv4 else bool(ipv4)
        dns_detail = ", ".join(ipv4) or "A-записей нет"
        if dns_ipv4:
            dns_detail = f"ожидался {dns_ipv4}; получено: {dns_detail}"
        checks.append(Check("DNS A", dns_ok, dns_detail))
        checks.append(
            Check(
                "DNS AAAA",
                not ipv6,
                "AAAA отсутствует" if not ipv6 else f"обнаружено: {', '.join(ipv6)}",
            )
        )
    except VerificationError as exc:
        checks.append(Check("DNS", False, str(exc)))
    try:
        certificate = check_public_tls(
            domain,
            connect_ip=client_connect_ip,
            pinned_peer_cert_sha256=pinned_peer_cert_sha256,
        )
        endpoint = client_connect_ip or domain
        tls_policy = (
            f"leaf pin {certificate['leafSha256']} OK; "
            "обычные CA/SAN/срок/revocation не проверены; "
            "pcs не доказывает выбор правильного HTTPS vhost"
            if pinned_peer_cert_sha256
            else "SNI/hostname/CA OK"
        )
        checks.append(
            Check(
                "TLS",
                True,
                f"{endpoint}:443, {tls_policy}, expires {certificate['notAfter']}",
            )
        )
    except VerificationError as exc:
        checks.append(Check("TLS", False, str(exc)))
    try:
        status = https_status(
            f"https://{domain}/",
            connect_ip=client_connect_ip,
            pinned_peer_cert_sha256=pinned_peer_cert_sha256,
        )
        checks.append(Check("HTTPS root", status < 500, f"HTTP {status}"))
    except VerificationError as exc:
        checks.append(Check("HTTPS root", False, str(exc)))
    try:
        status = https_status(
            f"https://{domain}{path}/doctor",
            connect_ip=client_connect_ip,
            pinned_peer_cert_sha256=pinned_peer_cert_sha256,
        )
        checks.append(
            Check(
                "XHTTP route",
                status not in {500, 502, 503, 504},
                f"HTTP {status}; правильный vhost окончательно подтверждает только E2E",
            )
        )
    except VerificationError as exc:
        checks.append(Check("XHTTP route", False, str(exc)))
    return checks


def doctor_exit(layout: Layout | None = None) -> list[Check]:
    layout = layout or Layout()
    checks: list[Check] = []
    architecture = __import__("platform").machine().lower()
    expected = XRAY_ASSETS.get(architecture, (None, None))[1]
    if layout.binary.exists() and expected:
        manifest_path = layout.binary_dir / "manifest.json"
        try:
            manifest = json.loads(manifest_path.read_text("utf-8"))
            if not isinstance(manifest, dict):
                raise ValueError("manifest is not an object")
            files = manifest.get("files")
            if not isinstance(files, dict):
                raise ValueError("manifest files is not an object")
            required = ("xray", "geoip.dat", "geosite.dat")
            intact = (
                manifest.get("archive_sha256") == expected
                and all(isinstance(files.get(name), str) for name in required)
                and all(
                    (layout.binary_dir / name).is_file()
                    and files[name] == sha256_file(layout.binary_dir / name)
                    for name in required
                )
            )
            detail = (
                f"v{XRAY_VERSION}, archive {manifest.get('archive_sha256', 'missing')}"
            )
        except (OSError, ValueError):
            intact, detail = False, "manifest отсутствует или повреждён"
        checks.append(Check("Xray supply chain", intact, detail))
    else:
        checks.append(Check("Xray binary", False, f"не найден {layout.binary}"))
    if layout.config.exists() and layout.binary.exists():
        result = run(
            [str(layout.binary), "run", "-test", "-c", str(layout.config)], check=False
        )
        checks.append(
            Check(
                "Xray config",
                result.returncode == 0,
                "Configuration OK" if result.returncode == 0 else "config test failed",
            )
        )
    else:
        checks.append(Check("Xray config", False, "managed config отсутствует"))
    if layout.root == Path("/") and command_exists("systemctl"):
        result = run(["systemctl", "is-active", "xhttp-setup-xray"], check=False)
        checks.append(
            Check("systemd", result.stdout.strip() == "active", result.stdout.strip())
        )
        if layout.receipt.exists():
            try:
                port = int(load_json(layout.receipt)["listen_port"])
                with socket.create_connection(("127.0.0.1", port), timeout=1):
                    pass
                checks.append(Check("Xray listener", True, f"127.0.0.1:{port}"))
            except (KeyError, TypeError, ValueError, OSError, InstallerError) as exc:
                checks.append(Check("Xray listener", False, str(exc)))
    for path, required_mode in ((layout.secrets, 0o600), (layout.handoff, 0o600)):
        if path.exists():
            actual_mode = path.stat().st_mode & 0o777
            checks.append(
                Check(
                    f"permissions {path.name}",
                    actual_mode == required_mode,
                    f"{actual_mode:04o}",
                )
            )
        else:
            checks.append(Check(f"permissions {path.name}", False, "файл отсутствует"))
    return checks


def _free_tcp_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.bind(("127.0.0.1", 0))
        return int(server.getsockname()[1])


def _parse_cloudflare_trace_ip(payload: str) -> str:
    for line in payload.splitlines():
        key, separator, value = line.partition("=")
        if separator and key.strip().casefold() == "ip":
            return validate_ipv4(value.strip())
    raise VerificationError("E2E endpoint не вернул строку ip=...")


def _curl_through_socks(*, socks_port: int, url: str):
    clean_env = os.environ.copy()
    for key in list(clean_env):
        if key.lower() in {"http_proxy", "https_proxy", "all_proxy", "no_proxy"}:
            clean_env.pop(key, None)
    return run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--max-time",
            "25",
            "--noproxy",
            "",
            "--socks5-hostname",
            f"127.0.0.1:{socks_port}",
            url,
        ],
        env=clean_env,
        check=False,
        timeout=35,
    )


def _redact_probe_text(text: str, handoff: Handoff) -> str:
    redacted = text
    for secret in (handoff.encryption, handoff.client_id, handoff.xhttp_path):
        encoded = urllib.parse.quote(secret, safe="")
        encoded_plus = urllib.parse.quote_plus(secret, safe="")
        json_escaped = secret.replace("\\", "\\\\").replace("/", "\\/")
        for representation in {secret, json_escaped}:
            if representation:
                redacted = redacted.replace(representation, "[REDACTED]")
        for representation in {encoded, encoded_plus}:
            if representation:
                redacted = re.sub(
                    re.escape(representation),
                    "[REDACTED]",
                    redacted,
                    flags=re.IGNORECASE,
                )
    return re.sub(
        r"vless://\S+",
        "[REDACTED VLESS URI]",
        redacted,
        flags=re.IGNORECASE,
    )


def _preserve_probe_failure(
    *,
    log_path: Path,
    failure_path: Path,
    error: BaseException,
    handoff: Handoff,
) -> Path | None:
    try:
        runtime_log = log_path.read_text("utf-8", errors="replace")
    except OSError:
        runtime_log = ""
    detail = " ".join(str(error).splitlines()).strip() or type(error).__name__
    safe_detail = _redact_probe_text(detail, handoff)
    safe_runtime_log = _redact_probe_text(runtime_log, handoff)
    content = (
        f"error_type={type(error).__name__}\n"
        f"error={safe_detail}\n"
        "xray_log_tail:\n"
        f"{safe_runtime_log[-16384:]}"
    )
    try:
        atomic_write_text(failure_path, content.rstrip() + "\n", 0o600)
    except OSError:
        return None
    return failure_path


def e2e_probe(
    *,
    handoff: Handoff,
    domain: str,
    front_address: str,
    layout: Layout,
    probe_url: str = "https://www.cloudflare.com/cdn-cgi/trace",
    front_port: int = 443,
) -> str:
    if not command_exists("curl"):
        raise InstallerError("Для E2E-проверки нужен curl")
    if not layout.binary.exists():
        install_xray_binary(layout)
    port = _free_tcp_port()
    config = render_xray_client_config(
        handoff=handoff,
        domain=domain,
        socks_port=port,
        front_address=front_address,
        front_port=validate_port(front_port),
    )
    ensure_dir(layout.state, 0o700)
    descriptor, name = tempfile.mkstemp(
        prefix="probe-", suffix=".json", dir=layout.state
    )
    config_path = Path(name)
    log_path = layout.state / f"probe-{os.getpid()}.log"
    failure_path = layout.state / "probe-failure.log"
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(pretty_json(config))
        os.chmod(config_path, 0o600)
        run([str(layout.binary), "run", "-test", "-c", str(config_path)])
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [str(layout.binary), "run", "-c", str(config_path)],
                stdin=subprocess.DEVNULL,
                stdout=log,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        try:
            deadline = time.monotonic() + 8
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise VerificationError(
                        "Диагностический Xray завершился до запуска SOCKS"
                    )
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.25):
                        break
                except OSError:
                    time.sleep(0.2)
            else:
                raise VerificationError(
                    "Диагностический SOCKS не открыл локальный порт"
                )
            result = _curl_through_socks(socks_port=port, url=probe_url)
            if result.returncode != 0 or not result.stdout.strip():
                raise VerificationError("E2E-запрос через XHTTP/TLS не прошёл")
            observed_ip = _parse_cloudflare_trace_ip(result.stdout)
            expected_ip = handoff.expected_egress_ip or handoff.exit_address
            if observed_ip != expected_ip:
                raise VerificationError(
                    f"E2E прошёл через неожиданный egress {observed_ip}; ожидался {expected_ip}"
                )
            probe_result = f"ip={observed_ip}"
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=3)
    except BaseException as exc:
        saved_failure = _preserve_probe_failure(
            log_path=log_path,
            failure_path=failure_path,
            error=exc,
            handoff=handoff,
        )
        if isinstance(exc, Exception):
            safe_detail = _redact_probe_text(str(exc), handoff)
            log_detail = (
                f"; диагностический лог без секретов: {saved_failure}"
                if saved_failure is not None
                else "; диагностический лог сохранить не удалось"
            )
            raise VerificationError(f"{safe_detail}{log_detail}") from None
        raise
    else:
        failure_path.unlink(missing_ok=True)
        return probe_result
    finally:
        config_path.unlink(missing_ok=True)
        log_path.unlink(missing_ok=True)
