import unittest
from contextlib import redirect_stdout
from io import StringIO
from unittest.mock import patch

from xhttp_setup.cli import _collect_front, _collect_pc_exit_access
from xhttp_setup.credential_parser import ExitCredentials, RegRuCredentials
from xhttp_setup.ispmanager import SiteInfo
from xhttp_setup.models import Handoff
from xhttp_setup.ssh_transport import SSHAuth


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef"
FINGERPRINT = "SHA256:" + ("A" * 43)
PANEL_SECRET = "FakePanelSecret_42"
EXIT_SECRET = "FakeExitSecret_73"


def handoff() -> Handoff:
    return Handoff(
        exit_address="8.8.8.8",
        exit_port=8083,
        client_id=UUID,
        xhttp_path=PATH,
        encryption="mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx",
        expected_egress_ip="8.8.8.8",
    ).validate()


def regru_credentials() -> RegRuCredentials:
    return RegRuCredentials(
        panel_login="u1234567",
        panel_password=PANEL_SECRET,
        panel_url="https://vip999.hosting.reg.ru:1500/",
        ftp_login="u1234567",
        ftp_server_ip="192.0.2.30",
    )


class PcCredentialImportTests(unittest.TestCase):
    def test_exit_block_builds_pinned_root_target_without_echoing_password(self):
        def prompt(label, _validator, default=None):
            if "SSH port" in label:
                return 22
            if "fingerprint" in label:
                return FINGERPRINT
            raise AssertionError((label, default))

        output = StringIO()
        with (
            patch("xhttp_setup.cli._yes_no", return_value=True),
            patch(
                "xhttp_setup.cli._read_exit_credentials_block",
                return_value=ExitCredentials("8.8.8.8", "root", EXIT_SECRET),
            ),
            patch("xhttp_setup.cli._validated_prompt", side_effect=prompt),
            redirect_stdout(output),
        ):
            target, auth = _collect_pc_exit_access()

        self.assertEqual(target.host, "8.8.8.8")
        self.assertEqual(target.user, "root")
        self.assertEqual(auth, SSHAuth("password", password=EXIT_SECRET))
        self.assertNotIn(EXIT_SECRET, output.getvalue())
        self.assertNotIn(EXIT_SECRET, repr(auth))

    def test_regru_import_maps_host_and_verified_address_candidate(self):
        prompts: list[tuple[str, object]] = []

        def prompt(label, validator, default=None):
            prompts.append((label, default))
            if label.startswith("FQDN"):
                return validator("front.example.org")
            if label.startswith("IPv4 подключения"):
                self.assertEqual(default, "192.0.2.30")
                return validator(default)
            if label.startswith("IPv4 в DNS"):
                self.assertEqual(default, "192.0.2.30")
                return validator(default)
            if label.startswith("Проверенный SSH host-key"):
                return validator(FINGERPRINT)
            raise AssertionError((label, default))

        site = SiteInfo(
            name="front.example.org",
            docroot="/var/www/u/data/www/front.example.org",
            ipaddr="192.0.2.30",
        )
        output = StringIO()
        with (
            patch("xhttp_setup.cli._validated_prompt", side_effect=prompt),
            patch(
                "xhttp_setup.cli._collect_front_tls_policy",
                return_value=("public", None),
            ),
            patch("xhttp_setup.cli._yes_no", side_effect=(True, False)),
            patch("xhttp_setup.cli.inspect_site", return_value=site) as inspect,
            redirect_stdout(output),
        ):
            desired = _collect_front(handoff(), regru_credentials=regru_credentials())

        self.assertEqual(desired.client_connect_ip, "192.0.2.30")
        self.assertEqual(desired.dns_ipv4, "192.0.2.30")
        self.assertEqual(desired.sftp_host, "vip999.hosting.reg.ru")
        self.assertEqual(desired.sftp_port, 22)
        self.assertEqual(desired.sftp_user, "u1234567")
        self.assertFalse(any(label.startswith("SFTP ") for label, _ in prompts))
        inspect.assert_called_once_with(
            endpoint="https://vip999.hosting.reg.ru:1500/ispmgr",
            username="u1234567",
            password=PANEL_SECRET,
            domain="front.example.org",
        )
        self.assertNotIn(PANEL_SECRET, output.getvalue())


if __name__ == "__main__":
    unittest.main()
