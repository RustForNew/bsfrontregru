import http.server
import os
import socket
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.doctor import (
    _curl_through_socks,
    _preserve_probe_failure,
    _redact_probe_text,
    e2e_probe,
)
from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.exit_installer import Layout
from xhttp_setup.models import Handoff
from xhttp_setup.osutil import command_exists


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef0123456789abcdef"
ENCRYPTION = (
    "mlkem768x25519plus.native.0rtt.yFAUa9gUf_hlvbaqG6nYRyTqpfo2kE-BYoFqCqq6vQ4"
)


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ip=203.0.113.20\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class E2EGuardTests(unittest.TestCase):
    def test_probe_exception_chain_suppresses_raw_secret(self):
        handoff = Handoff(
            "203.0.113.10", 8083, UUID, PATH, ENCRYPTION, "Test"
        ).validate()
        with tempfile.TemporaryDirectory() as temp:
            layout = Layout(root=Path(temp))
            layout.binary.parent.mkdir(parents=True)
            layout.binary.write_bytes(b"test binary placeholder")
            raw_error = InstallerError(f"raw config error: {ENCRYPTION}")
            with (
                mock.patch("xhttp_setup.doctor.command_exists", return_value=True),
                mock.patch("xhttp_setup.doctor.run", side_effect=raw_error),
            ):
                with self.assertRaises(VerificationError) as raised:
                    e2e_probe(
                        handoff=handoff,
                        domain="front.example.org",
                        front_address="198.51.100.20",
                        layout=layout,
                    )

            self.assertNotIn(ENCRYPTION, str(raised.exception))
            self.assertIsNone(raised.exception.__cause__)
            self.assertTrue(raised.exception.__suppress_context__)
            failure = layout.state / "probe-failure.log"
            self.assertTrue(failure.is_file())
            self.assertNotIn(ENCRYPTION, failure.read_text("utf-8"))

    def test_preserved_probe_log_redacts_handoff_secrets_and_uri(self):
        handoff = Handoff(
            "203.0.113.10", 8083, UUID, PATH, ENCRYPTION, "Test"
        ).validate()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw = root / "raw.log"
            failure = root / "probe-failure.log"
            raw.write_text(
                f"uuid={UUID}\npath={PATH}\n"
                "json_path=\\/api\\/0123456789abcdef0123456789abcdef\n"
                f"encryption={ENCRYPTION}\n"
                f"vless://{UUID}@front.example.org:443?encryption={ENCRYPTION}\n",
                encoding="utf-8",
            )
            with mock.patch(
                "xhttp_setup.doctor.atomic_write_text",
                side_effect=lambda path, text, mode: path.write_text(
                    text, encoding="utf-8"
                ),
            ):
                saved = _preserve_probe_failure(
                    log_path=raw,
                    failure_path=failure,
                    error=RuntimeError(f"request for {PATH} failed"),
                    handoff=handoff,
                )

            self.assertEqual(saved, failure)
            content = failure.read_text("utf-8")
            self.assertIn("error_type=RuntimeError", content)
            self.assertIn("[REDACTED]", content)
            self.assertNotIn(UUID, content)
            self.assertNotIn(PATH, content)
            self.assertNotIn("\\/api", content)
            self.assertNotIn(ENCRYPTION, content)
            self.assertNotIn("vless://", content)

            console_detail = _redact_probe_text(
                f"failed {UUID} {PATH} %2fapi%2F0123456789abcdef0123456789abcdef "
                f"{ENCRYPTION}",
                handoff,
            )
            self.assertNotIn(UUID, console_detail)
            self.assertNotIn(PATH, console_detail)
            self.assertNotIn("%2fapi", console_detail.lower())
            self.assertNotIn(ENCRYPTION, console_detail)

    def test_probe_log_redacts_before_tail_boundary_is_applied(self):
        handoff = Handoff(
            "203.0.113.10", 8083, UUID, PATH, ENCRYPTION, "Test"
        ).validate()
        partial_suffix = ENCRYPTION[-10:]
        runtime = ENCRYPTION + ("Z" * (16384 - len(partial_suffix)))
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            raw = root / "raw.log"
            failure = root / "probe-failure.log"
            raw.write_text(runtime, encoding="utf-8")
            with mock.patch(
                "xhttp_setup.doctor.atomic_write_text",
                side_effect=lambda path, text, mode: path.write_text(
                    text, encoding="utf-8"
                ),
            ):
                saved = _preserve_probe_failure(
                    log_path=raw,
                    failure_path=failure,
                    error=RuntimeError("probe failed"),
                    handoff=handoff,
                )

            self.assertEqual(saved, failure)
            content = failure.read_text("utf-8")
            self.assertNotIn(ENCRYPTION, content)
            self.assertNotIn(partial_suffix, content)
            self.assertIn("[REDACTED]", content)

    def test_no_proxy_star_cannot_bypass_explicit_socks(self):
        if not command_exists("curl"):
            self.skipTest("curl not installed")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            unreachable_socks = unused.getsockname()[1]
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            with mock.patch.dict(os.environ, {"NO_PROXY": "*"}, clear=False):
                result = _curl_through_socks(
                    socks_port=unreachable_socks,
                    url=url,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
