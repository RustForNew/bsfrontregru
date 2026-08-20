import contextlib
import hashlib
import io
import ssl
import unittest
from types import SimpleNamespace
from unittest.mock import call, patch

from xhttp_setup.cli import _collect_front, _frontend_ips_from_args
from xhttp_setup.doctor import doctor_front
from xhttp_setup.errors import VerificationError
from xhttp_setup.front import (
    _client_tls_context,
    build_front_plan,
    check_public_tls,
    https_status,
)
from xhttp_setup.ispmanager import SiteInfo
from xhttp_setup.models import FrontDesired, Handoff
from xhttp_setup.ssh_transport import TCPRoute


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef0123456789abcdef"
ENCRYPTION = (
    "mlkem768x25519plus.native.0rtt.yFAUa9gUf_hlvbaqG6nYRyTqpfo2kE-BYoFqCqq6vQ4"
)
FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
CERT_DER = b"test leaf certificate der"
CERT_SHA256 = hashlib.sha256(CERT_DER).hexdigest()


def front_desired() -> FrontDesired:
    return FrontDesired(
        domain="front.example.org",
        client_connect_ip="198.51.100.20",
        dns_ipv4="192.0.2.30",
        sftp_host="sftp.example.org",
        sftp_port=22,
        sftp_user="site_user",
        document_root="/var/www/site",
        ssh_host_key_sha256=FINGERPRINT,
        exit_address="203.0.113.10",
        exit_port=8083,
        xhttp_path=PATH,
    ).validate()


class _ContextObject:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _FakeTLS(_ContextObject):
    def __init__(self):
        self.sent = b""

    def getpeercert(self, binary_form=False):
        if binary_form:
            return CERT_DER
        return {
            "subject": ((("commonName", "front.example.org"),),),
            "notAfter": "date",
        }

    def cipher(self):
        return ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)

    def sendall(self, payload):
        self.sent += payload


class _FakeContext:
    def __init__(self):
        self.server_name = None
        self.tls = _FakeTLS()

    def wrap_socket(self, raw, *, server_hostname):
        self.server_name = server_hostname
        return self.tls


class _FakeResponse:
    status = 204

    def __init__(self, tls):
        self.tls = tls

    def begin(self):
        return None

    def close(self):
        return None


class FrontAddressRoleTests(unittest.TestCase):
    def test_model_and_plan_keep_three_ip_roles_distinct(self):
        desired = front_desired()
        self.assertEqual(desired.client_connect_ip, "198.51.100.20")
        self.assertEqual(desired.dns_ipv4, "192.0.2.30")
        plan = "\n".join(build_front_plan(desired))
        self.assertIn("DNS A=192.0.2.30", plan)
        self.assertIn("клиентском адресе 198.51.100.20", plan)

    def test_tls_connects_to_client_ip_but_verifies_domain_sni(self):
        context = _FakeContext()
        with (
            patch(
                "xhttp_setup.front.socket.create_connection",
                return_value=_ContextObject(),
            ) as create_connection,
            patch("xhttp_setup.front.ssl.create_default_context", return_value=context),
        ):
            certificate = check_public_tls(
                "front.example.org", connect_ip="198.51.100.20"
            )

        create_connection.assert_called_once_with(("198.51.100.20", 443), timeout=12)
        self.assertEqual(context.server_name, "front.example.org")
        self.assertEqual(certificate["cipher"], "TLS_AES_256_GCM_SHA384")

    def test_pinned_tls_requires_exact_leaf_hash_and_keeps_sni(self):
        context = _FakeContext()
        with (
            patch(
                "xhttp_setup.front.socket.create_connection",
                return_value=_ContextObject(),
            ),
            patch("xhttp_setup.front._client_tls_context", return_value=context),
        ):
            certificate = check_public_tls(
                "front.example.org",
                connect_ip="198.51.100.20",
                pinned_peer_cert_sha256=CERT_SHA256.upper(),
            )
        self.assertEqual(context.server_name, "front.example.org")
        self.assertEqual(certificate["leafSha256"], CERT_SHA256)

        with (
            patch(
                "xhttp_setup.front.socket.create_connection",
                return_value=_ContextObject(),
            ),
            patch("xhttp_setup.front._client_tls_context", return_value=context),
            self.assertRaises(VerificationError),
        ):
            check_public_tls(
                "front.example.org",
                connect_ip="198.51.100.20",
                pinned_peer_cert_sha256="00" * 32,
            )

    def test_only_pinned_context_disables_ca_and_hostname_validation(self):
        pinned = _client_tls_context(CERT_SHA256)
        self.assertFalse(pinned.check_hostname)
        self.assertEqual(pinned.verify_mode, ssl.CERT_NONE)
        with patch("xhttp_setup.front.ssl.create_default_context") as create_default:
            _client_tls_context(None)
        create_default.assert_called_once_with()

    def test_https_status_uses_client_ip_with_domain_sni_and_host(self):
        context = _FakeContext()
        with (
            patch(
                "xhttp_setup.front.socket.create_connection",
                return_value=_ContextObject(),
            ) as create_connection,
            patch("xhttp_setup.front.ssl.create_default_context", return_value=context),
            patch("xhttp_setup.front.http.client.HTTPResponse", _FakeResponse),
        ):
            status = https_status(
                "https://front.example.org/api/check?probe=1",
                connect_ip="198.51.100.20",
            )

        self.assertEqual(status, 204)
        create_connection.assert_called_once_with(("198.51.100.20", 443), timeout=15)
        self.assertEqual(context.server_name, "front.example.org")
        request = context.tls.sent.decode("ascii")
        self.assertIn("GET /api/check?probe=1 HTTP/1.1\r\n", request)
        self.assertIn("Host: front.example.org\r\n", request)

    def test_https_route_uses_loopback_transport_but_original_sni_and_host(self):
        context = _FakeContext()
        route = TCPRoute("127.0.0.1", 43126)
        with (
            patch(
                "xhttp_setup.front.socket.create_connection",
                return_value=_ContextObject(),
            ) as create_connection,
            patch("xhttp_setup.front.ssl.create_default_context", return_value=context),
            patch("xhttp_setup.front.http.client.HTTPResponse", _FakeResponse),
        ):
            status = https_status(
                "https://front.example.org/api/check",
                connect_ip="198.51.100.20",
                route=route,
            )

        self.assertEqual(status, 204)
        create_connection.assert_called_once_with(("127.0.0.1", 43126), timeout=15)
        self.assertEqual(context.server_name, "front.example.org")
        self.assertIn("Host: front.example.org\r\n", context.tls.sent.decode("ascii"))

    def test_https_status_checks_pin_before_request_and_preserves_host(self):
        context = _FakeContext()
        with (
            patch(
                "xhttp_setup.front.socket.create_connection",
                return_value=_ContextObject(),
            ),
            patch("xhttp_setup.front._client_tls_context", return_value=context),
            patch("xhttp_setup.front.http.client.HTTPResponse", _FakeResponse),
        ):
            status = https_status(
                "https://front.example.org/api/check",
                connect_ip="198.51.100.20",
                pinned_peer_cert_sha256=CERT_SHA256,
            )
        self.assertEqual(status, 204)
        self.assertEqual(context.server_name, "front.example.org")
        self.assertIn("Host: front.example.org\r\n", context.tls.sent.decode("ascii"))

    def test_doctor_checks_dns_and_client_endpoint_independently(self):
        certificate = {"subject": "", "notAfter": "date", "cipher": "cipher"}
        with (
            patch(
                "xhttp_setup.doctor.resolve_front",
                return_value=(["192.0.2.30"], []),
            ),
            patch(
                "xhttp_setup.doctor.check_public_tls", return_value=certificate
            ) as tls,
            patch("xhttp_setup.doctor.https_status", side_effect=(200, 404)) as status,
        ):
            checks = doctor_front(
                "front.example.org",
                PATH,
                client_connect_ip="198.51.100.20",
                dns_ipv4="192.0.2.30",
            )

        self.assertTrue(all(check.ok for check in checks))
        tls.assert_called_once_with(
            "front.example.org",
            connect_ip="198.51.100.20",
            pinned_peer_cert_sha256=None,
        )
        self.assertEqual(
            status.call_args_list,
            [
                call(
                    "https://front.example.org/",
                    connect_ip="198.51.100.20",
                    pinned_peer_cert_sha256=None,
                ),
                call(
                    f"https://front.example.org{PATH}/doctor",
                    connect_ip="198.51.100.20",
                    pinned_peer_cert_sha256=None,
                ),
            ],
        )

    def test_doctor_verifies_pinned_leaf_for_tls_and_http_checks(self):
        certificate = {
            "subject": "",
            "notAfter": "unknown",
            "cipher": "cipher",
            "leafSha256": CERT_SHA256,
        }
        with (
            patch(
                "xhttp_setup.doctor.resolve_front",
                return_value=(["192.0.2.30"], []),
            ),
            patch(
                "xhttp_setup.doctor.check_public_tls", return_value=certificate
            ) as tls,
            patch("xhttp_setup.doctor.https_status", side_effect=(200, 404)) as status,
        ):
            checks = doctor_front(
                "front.example.org",
                PATH,
                client_connect_ip="198.51.100.20",
                dns_ipv4="192.0.2.30",
                pinned_peer_cert_sha256=CERT_SHA256,
            )
        self.assertTrue(all(check.ok for check in checks))
        self.assertIn("leaf pin", next(c.detail for c in checks if c.name == "TLS"))
        tls.assert_called_once_with(
            "front.example.org",
            connect_ip="198.51.100.20",
            pinned_peer_cert_sha256=CERT_SHA256,
        )
        self.assertTrue(
            all(
                call_.kwargs["pinned_peer_cert_sha256"] == CERT_SHA256
                for call_ in status.call_args_list
            )
        )

    def test_ispmanager_assigned_ip_mismatch_is_informational(self):
        handoff = Handoff("203.0.113.10", 8083, UUID, PATH, ENCRYPTION).validate()
        prompts = [
            "front.example.org",
            "198.51.100.20",
            "192.0.2.30",
            "sftp.example.org",
            22,
            "site_user",
            FINGERPRINT,
        ]
        site = SiteInfo("front.example.org", "/var/www/site", "192.0.2.99")
        output = io.StringIO()
        with (
            patch("xhttp_setup.cli._validated_prompt", side_effect=prompts),
            patch("xhttp_setup.cli._yes_no", side_effect=(False, True, False)),
            patch(
                "xhttp_setup.cli._prompt",
                side_effect=("https://panel.example.org:1500/ispmgr", "site_user"),
            ),
            patch("xhttp_setup.cli.getpass.getpass", return_value="not-stored"),
            patch("xhttp_setup.cli.inspect_site", return_value=site),
            contextlib.redirect_stdout(output),
        ):
            desired = _collect_front(handoff)

        self.assertEqual(desired.client_connect_ip, "198.51.100.20")
        self.assertEqual(desired.dns_ipv4, "192.0.2.30")
        self.assertIn("не блокирует установку", output.getvalue())

    def test_legacy_cli_ip_remains_compatible_but_new_roles_can_differ(self):
        self.assertEqual(
            _frontend_ips_from_args(
                SimpleNamespace(
                    client_connect_ip="198.51.100.20",
                    dns_ipv4="192.0.2.30",
                    front_public_ip=None,
                )
            ),
            ("198.51.100.20", "192.0.2.30"),
        )
        self.assertEqual(
            _frontend_ips_from_args(
                SimpleNamespace(
                    client_connect_ip=None,
                    dns_ipv4=None,
                    front_public_ip="198.51.100.20",
                )
            ),
            ("198.51.100.20", "198.51.100.20"),
        )


if __name__ == "__main__":
    unittest.main()
