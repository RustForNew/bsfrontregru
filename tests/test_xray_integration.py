import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from xhttp_setup.exit_installer import _parse_vlessenc
from xhttp_setup.models import Handoff
from xhttp_setup.render import render_xray_client_config, render_xray_server_config


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef0123456789abcdef"
DECRYPTION = (
    "mlkem768x25519plus.native.600s.yG0oHVjWspYtXKNwHbdHMcZSWMHCyPeyOm9CNhSBCVU"
)
ENCRYPTION = (
    "mlkem768x25519plus.native.0rtt.yFAUa9gUf_hlvbaqG6nYRyTqpfo2kE-BYoFqCqq6vQ4"
)


class XrayIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("XRAY_TEST_BINARY")
        if not value or not Path(value).is_file():
            raise unittest.SkipTest("set XRAY_TEST_BINARY to pinned Xray v26.3.27")
        cls.binary = value

    def _assert_config_ok(self, data):
        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".json", delete=False
        ) as stream:
            json.dump(data, stream)
            name = stream.name
        try:
            result = subprocess.run(
                [self.binary, "run", "-test", "-c", name],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn("Configuration OK", result.stdout)
        finally:
            Path(name).unlink(missing_ok=True)

    def test_generated_server_config(self):
        self._assert_config_ok(
            render_xray_server_config(
                client_id=UUID, decryption=DECRYPTION, port=8083, path=PATH
            )
        )

    def test_generated_client_config(self):
        handoff = Handoff("203.0.113.10", 8083, UUID, PATH, ENCRYPTION).validate()
        self._assert_config_ok(
            render_xray_client_config(
                handoff=handoff,
                domain="front.example.org",
                socks_port=10808,
                front_address="198.51.100.20",
            )
        )

    def test_pinned_vlessenc_pair_builds_valid_server_and_client(self):
        generated = subprocess.run(
            [self.binary, "vlessenc"],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=30,
            check=False,
        )
        self.assertEqual(generated.returncode, 0, generated.stdout)
        decryption, encryption = _parse_vlessenc(generated.stdout)
        self._assert_config_ok(
            render_xray_server_config(
                client_id=UUID,
                decryption=decryption,
                port=8083,
                path=PATH,
            )
        )
        handoff = Handoff("203.0.113.10", 8083, UUID, PATH, encryption).validate()
        self._assert_config_ok(
            render_xray_client_config(
                handoff=handoff,
                domain="front.example.org",
                socks_port=10808,
                front_address="198.51.100.20",
            )
        )


if __name__ == "__main__":
    unittest.main()
