import json
import tempfile
import unittest
from contextlib import ExitStack, redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from xhttp_setup.cli import _collect_front, _collect_pc_exit_access, wizard_pc
from xhttp_setup.credential_parser import ExitCredentials, RegRuCredentials
from xhttp_setup.ispmanager import SiteInfo
from xhttp_setup.models import ExitDesired, FrontDesired, Handoff
from xhttp_setup.remote_exit import RemoteExitTarget
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

    def test_pc_wizard_routes_only_imported_exit_and_panel_passwords(self):
        desired_exit = ExitDesired(
            public_address="8.8.8.8",
            listen_port=8083,
            front_egress_ip="198.51.100.20",
            xhttp_path=PATH,
            client_id=UUID,
            expected_egress_ip="8.8.8.8",
        ).validate()
        desired_front = FrontDesired(
            domain="front.example.org",
            client_connect_ip="192.0.2.30",
            dns_ipv4="192.0.2.30",
            sftp_host="vip999.hosting.reg.ru",
            sftp_port=22,
            sftp_user="u1234567",
            document_root="/var/www/u/data/www/front.example.org",
            ssh_host_key_sha256=FINGERPRINT,
            exit_address="8.8.8.8",
            exit_port=8083,
            xhttp_path=PATH,
        ).validate()
        exit_target = RemoteExitTarget(
            host="8.8.8.8",
            user="root",
            port=22,
            host_key_sha256=FINGERPRINT,
        ).validate()
        exit_auth = SSHAuth("password", password=EXIT_SECRET)
        seen: dict[str, SSHAuth] = {}

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            handoff_path = root / "handoff.json"
            handoff_path.write_text(json.dumps(handoff().to_dict()), encoding="utf-8")
            firewall_plan = root / "firewall-plan.txt"

            def apply_exit(**kwargs):
                seen["exit"] = kwargs["auth"]
                return SimpleNamespace(
                    remote=SimpleNamespace(
                        handoff_path=handoff_path,
                        firewall_plan_path=firewall_plan,
                    )
                )

            def apply_front(**kwargs):
                seen["front"] = kwargs["auth"]
                return SimpleNamespace()

            output = StringIO()
            with ExitStack() as stack:
                for name in (
                    "_require_linux_apply",
                    "_disable_pc_core_dumps",
                    "_show_plan",
                    "check_front_dns",
                    "check_public_tls",
                    "_ack_provider",
                    "_confirm_apply",
                    "_print_front_result",
                ):
                    stack.enter_context(patch(f"xhttp_setup.cli.{name}"))
                stack.enter_context(
                    patch(
                        "xhttp_setup.cli._installer_pyz_from_runtime",
                        return_value=root / "setup.pyz",
                    )
                )
                stack.enter_context(
                    patch(
                        "xhttp_setup.cli._collect_pc_exit_access",
                        return_value=(exit_target, exit_auth),
                    )
                )
                stack.enter_context(
                    patch("xhttp_setup.cli._collect_exit", return_value=desired_exit)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli._yes_no", side_effect=(False, True))
                )
                stack.enter_context(
                    patch(
                        "xhttp_setup.cli._collect_regru_credentials_import",
                        return_value=regru_credentials(),
                    )
                )
                stack.enter_context(
                    patch("xhttp_setup.cli._collect_front", return_value=desired_front)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli.build_exit_plan", return_value=[])
                )
                stack.enter_context(
                    patch("xhttp_setup.cli.build_front_plan", return_value=[])
                )
                collect_auth = stack.enter_context(
                    patch("xhttp_setup.cli._collect_auth")
                )
                stack.enter_context(
                    patch("xhttp_setup.cli._pc_output_dir", return_value=root)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli.apply_pc_exit", side_effect=apply_exit)
                )
                stack.enter_context(
                    patch(
                        "xhttp_setup.cli._apply_front_and_issue",
                        side_effect=apply_front,
                    )
                )
                stack.enter_context(redirect_stdout(output))
                self.assertEqual(wizard_pc(), 0)

        collect_auth.assert_not_called()
        self.assertIs(seen["exit"], exit_auth)
        self.assertEqual(seen["front"].method, "password")
        self.assertEqual(seen["front"].password, PANEL_SECRET)
        transcript = output.getvalue()
        self.assertNotIn(EXIT_SECRET, transcript)
        self.assertNotIn(PANEL_SECRET, transcript)


if __name__ == "__main__":
    unittest.main()
