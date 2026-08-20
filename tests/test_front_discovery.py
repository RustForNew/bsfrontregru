from __future__ import annotations

import json
import os
import socket
import ssl
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import call, patch

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.front_discovery import (
    _leaf_certificate,
    discover_front_tls_policy,
    resolve_front_dns,
)
from xhttp_setup.models import TLS_MODE_PINNED, TLS_MODE_PUBLIC


DOMAIN = "front.example.org"
CONNECT_IP = "198.51.100.20"
LEAF = b"stable leaf DER"


def _portable_atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.test-temp")
    temporary.write_text(text, encoding="utf-8")
    os.chmod(temporary, mode)
    os.replace(temporary, path)


class _ContextObject:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False


class _TLS(_ContextObject):
    def getpeercert(self, binary_form=False):
        return LEAF if binary_form else {}


class _TLSContext:
    def __init__(self):
        self.server_hostname = None

    def wrap_socket(self, raw, *, server_hostname):
        self.server_hostname = server_hostname
        return _TLS()


class FrontDNSDiscoveryTests(unittest.TestCase):
    def test_returns_exact_single_a_while_ignoring_duplicate_answers(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (CONNECT_IP, 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (CONNECT_IP, 443)),
        ]
        with patch("xhttp_setup.front_discovery.socket.getaddrinfo", return_value=answers):
            self.assertEqual(resolve_front_dns(DOMAIN), CONNECT_IP)

    def test_rejects_aaaa_even_when_a_is_exact(self):
        answers = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (CONNECT_IP, 443)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::20", 443, 0, 0)),
        ]
        with (
            patch("xhttp_setup.front_discovery.socket.getaddrinfo", return_value=answers),
            self.assertRaisesRegex(VerificationError, "AAAA"),
        ):
            resolve_front_dns(DOMAIN)

    def test_rejects_zero_or_multiple_a_records(self):
        multiple = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", (CONNECT_IP, 443)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("198.51.100.21", 443)),
        ]
        for answers in ([], multiple):
            with self.subTest(answers=answers), patch(
                "xhttp_setup.front_discovery.socket.getaddrinfo", return_value=answers
            ), self.assertRaisesRegex(VerificationError, "ровно один"):
                resolve_front_dns(DOMAIN)

    def test_wraps_dns_failure(self):
        with (
            patch(
                "xhttp_setup.front_discovery.socket.getaddrinfo",
                side_effect=socket.gaierror("not found"),
            ),
            self.assertRaisesRegex(VerificationError, "не разрешается"),
        ):
            resolve_front_dns(DOMAIN)


class FrontTLSDiscoveryTests(unittest.TestCase):
    def test_leaf_handshake_uses_exact_connect_ip_and_domain_sni(self):
        context = _TLSContext()
        with (
            patch(
                "xhttp_setup.front_discovery.socket.create_connection",
                return_value=_ContextObject(),
            ) as connect,
            patch(
                "xhttp_setup.front_discovery.ssl.create_default_context",
                return_value=context,
            ),
        ):
            actual = _leaf_certificate(
                DOMAIN,
                CONNECT_IP,
                verify_public_identity=True,
                timeout=11,
            )

        self.assertEqual(actual, LEAF)
        connect.assert_called_once_with((CONNECT_IP, 443), timeout=11)
        self.assertEqual(context.server_hostname, DOMAIN)

    def test_public_ca_and_hostname_returns_public_policy(self):
        with (
            patch("xhttp_setup.front_discovery._leaf_certificate", return_value=LEAF) as leaf,
            patch("xhttp_setup.front_discovery.https_status") as https,
        ):
            result = discover_front_tls_policy(DOMAIN, CONNECT_IP, timeout=9)

        self.assertEqual(result.tls_mode, TLS_MODE_PUBLIC)
        self.assertIsNone(result.pinned_peer_cert_sha256)
        leaf.assert_called_once_with(
            DOMAIN,
            CONNECT_IP,
            verify_public_identity=True,
            timeout=9,
        )
        https.assert_not_called()

    def test_stable_self_signed_leaf_is_pinned_and_https_verified(self):
        verify_error = ssl.SSLCertVerificationError(1, "self signed")
        with (
            patch(
                "xhttp_setup.front_discovery._leaf_certificate",
                side_effect=(verify_error, LEAF, LEAF),
            ) as leaf,
            patch("xhttp_setup.front_discovery.https_status", return_value=200) as https,
        ):
            result = discover_front_tls_policy(DOMAIN, CONNECT_IP, timeout=7)

        expected = __import__("hashlib").sha256(LEAF).hexdigest()
        self.assertEqual(result.tls_mode, TLS_MODE_PINNED)
        self.assertEqual(result.pinned_peer_cert_sha256, expected)
        self.assertEqual(
            leaf.call_args_list,
            [
                call(DOMAIN, CONNECT_IP, verify_public_identity=True, timeout=7),
                call(DOMAIN, CONNECT_IP, verify_public_identity=False, timeout=7),
                call(DOMAIN, CONNECT_IP, verify_public_identity=False, timeout=7),
            ],
        )
        https.assert_called_once_with(
            f"https://{DOMAIN}/",
            connect_ip=CONNECT_IP,
            pinned_peer_cert_sha256=expected,
            timeout=7,
        )

    def test_unstable_unverified_leaf_is_never_pinned(self):
        with (
            patch(
                "xhttp_setup.front_discovery._leaf_certificate",
                side_effect=(
                    ssl.SSLCertVerificationError(1, "self signed"),
                    b"leaf one",
                    b"leaf two",
                ),
            ),
            patch("xhttp_setup.front_discovery.https_status") as https,
            self.assertRaisesRegex(VerificationError, "нестабилен"),
        ):
            discover_front_tls_policy(DOMAIN, CONNECT_IP)
        https.assert_not_called()

    def test_network_or_protocol_failure_never_enters_unverified_fallback(self):
        for failure in (OSError("connection refused"), ssl.SSLError("wrong version")):
            with self.subTest(failure=failure), patch(
                "xhttp_setup.front_discovery._leaf_certificate", side_effect=failure
            ) as leaf, patch(
                "xhttp_setup.front_discovery.https_status"
            ) as https, self.assertRaises(VerificationError):
                discover_front_tls_policy(DOMAIN, CONNECT_IP)
            self.assertEqual(leaf.call_count, 1)
            https.assert_not_called()

    def test_pinned_https_failure_is_not_silently_accepted(self):
        with (
            patch(
                "xhttp_setup.front_discovery._leaf_certificate",
                side_effect=(
                    ssl.SSLCertVerificationError(1, "self signed"),
                    LEAF,
                    LEAF,
                ),
            ),
            patch(
                "xhttp_setup.front_discovery.https_status",
                side_effect=VerificationError("not HTTP"),
            ),
            self.assertRaisesRegex(VerificationError, "not HTTP"),
        ):
            discover_front_tls_policy(DOMAIN, CONNECT_IP)

    def test_public_leaf_rotation_is_not_persisted_or_blocked(self):
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp) / "state"
            with patch(
                "xhttp_setup.front_discovery._leaf_certificate", return_value=LEAF
            ):
                first = discover_front_tls_policy(
                    DOMAIN, CONNECT_IP, state_dir=state_dir
                )
            self.assertEqual(first.tls_mode, TLS_MODE_PUBLIC)
            self.assertFalse(state_dir.exists())

            with patch(
                "xhttp_setup.front_discovery._leaf_certificate",
                return_value=b"replacement leaf",
            ):
                second = discover_front_tls_policy(
                    DOMAIN, CONNECT_IP, state_dir=state_dir
                )
            self.assertEqual(second.tls_mode, TLS_MODE_PUBLIC)
            self.assertFalse(state_dir.exists())

    def test_persisted_pinned_leaf_allows_first_use_and_blocks_change(self):
        verify_error = ssl.SSLCertVerificationError(1, "self signed")
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp) / "state"
            with (
                patch(
                    "xhttp_setup.front_discovery._leaf_certificate",
                    side_effect=(verify_error, LEAF, LEAF),
                ),
                patch("xhttp_setup.front_discovery.https_status", return_value=200),
                patch(
                    "xhttp_setup.front_discovery.atomic_write_text",
                    side_effect=_portable_atomic_write_text,
                ),
            ):
                first = discover_front_tls_policy(
                    DOMAIN, CONNECT_IP, state_dir=state_dir
                )
            self.assertEqual(first.tls_mode, TLS_MODE_PINNED)

            files = list((state_dir / "front-tls-pins").glob("*.json"))
            self.assertEqual(len(files), 1)
            record = json.loads(files[0].read_text("utf-8"))
            self.assertEqual(record["domain"], DOMAIN)
            self.assertEqual(record["connectIp"], CONNECT_IP)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)

            with (
                patch(
                    "xhttp_setup.front_discovery._leaf_certificate",
                    side_effect=(verify_error, b"replacement leaf", b"replacement leaf"),
                ),
                patch("xhttp_setup.front_discovery.https_status"),
                self.assertRaisesRegex(VerificationError, "изменился"),
            ):
                discover_front_tls_policy(DOMAIN, CONNECT_IP, state_dir=state_dir)

            with (
                patch(
                    "xhttp_setup.front_discovery._leaf_certificate",
                    side_effect=verify_error,
                ),
                self.assertRaisesRegex(InstallerError, "endpoint identity"),
            ):
                discover_front_tls_policy(
                    DOMAIN, "198.51.100.99", state_dir=state_dir
                )

    @unittest.skipUnless(os.name == "posix", "POSIX symlink semantics")
    def test_persistence_rejects_symlink_state_and_pin_file(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            real = root / "real"
            real.mkdir(mode=0o700)
            state_link = root / "state-link"
            state_link.symlink_to(real, target_is_directory=True)
            verify_error = ssl.SSLCertVerificationError(1, "self signed")
            with patch(
                "xhttp_setup.front_discovery._leaf_certificate",
                side_effect=verify_error,
            ), self.assertRaisesRegex(InstallerError, "symlink"):
                discover_front_tls_policy(DOMAIN, CONNECT_IP, state_dir=state_link)

            state = root / "state"
            with (
                patch(
                    "xhttp_setup.front_discovery._leaf_certificate",
                    side_effect=(verify_error, LEAF, LEAF),
                ),
                patch("xhttp_setup.front_discovery.https_status", return_value=200),
            ):
                discover_front_tls_policy(DOMAIN, CONNECT_IP, state_dir=state)
            pin = next((state / "front-tls-pins").glob("*.json"))
            pin.unlink()
            pin.symlink_to(root / "missing-target")
            with patch(
                "xhttp_setup.front_discovery._leaf_certificate",
                side_effect=verify_error,
            ), self.assertRaisesRegex(InstallerError, "symlink"):
                discover_front_tls_policy(DOMAIN, CONNECT_IP, state_dir=state)


if __name__ == "__main__":
    unittest.main()
