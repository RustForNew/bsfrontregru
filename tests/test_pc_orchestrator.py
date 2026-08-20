import json
import os
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xhttp_setup.cli import wizard_pc
from xhttp_setup.errors import InstallerError
from xhttp_setup.models import ExitDesired, FrontDesired, Handoff
from xhttp_setup.pc_orchestrator import (
    PcExitResult,
    apply_pc_exit,
    front_for_handoff,
    preflight_remote_front_bridge,
)
from xhttp_setup.remote_exit import RemoteExitError, RemoteExitResult, RemoteExitTarget
from xhttp_setup.remote_front import RemoteFrontResult, RemoteFrontTarget
from xhttp_setup.remote_network import RemoteExitNetworkApplyResult
from xhttp_setup.ssh_transport import SSHAuth


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef"
FINGERPRINT = "SHA256:" + ("A" * 43)


def desired_exit() -> ExitDesired:
    return ExitDesired(
        public_address="203.0.113.10",
        listen_port=8083,
        front_egress_ip="198.51.100.20",
        xhttp_path=PATH,
        client_id=UUID,
        expected_egress_ip="203.0.113.10",
    ).validate()


def desired_front() -> FrontDesired:
    return FrontDesired(
        domain="front.example.org",
        client_connect_ip="192.0.2.30",
        dns_ipv4="192.0.2.30",
        sftp_host="sftp.example.org",
        sftp_port=22,
        sftp_user="site_user",
        document_root="/var/www/site",
        ssh_host_key_sha256=FINGERPRINT,
        exit_address="203.0.113.99",
        exit_port=9000,
        xhttp_path="/old/path-value-1234",
    ).validate()


class FakeSSH:
    def command(self, argv, *, check=True, timeout=300):
        del check, timeout
        if argv == ["id", "-u"]:
            return subprocess.CompletedProcess(argv, 0, "0\n", "")
        raise AssertionError(argv)


class PcOrchestratorTests(unittest.TestCase):
    def setUp(self):
        self.target = RemoteExitTarget(
            host="exit.example.org",
            user="root",
            port=22,
            host_key_sha256=FINGERPRINT,
        )
        self.auth = SSHAuth("password", password="not-logged")

    @staticmethod
    def _installer(root: Path) -> Path:
        installer = root / "xhttp-setup.pyz"
        installer.write_bytes(b"PYZ")
        return installer

    @contextmanager
    def _environment(self, root: Path, remote_side_effect=None):
        network = RemoteExitNetworkApplyResult(
            profile=Mock(),
            allow_comment="allow",
            deny_comment="deny",
            ufw_allow_added=True,
            ufw_deny_added=True,
        )
        remote = RemoteExitResult(
            target=self.target,
            handoff_path=root / "result/handoff.json",
            firewall_plan_path=root / "result/firewall-plan.txt",
            known_hosts_path=root / "result/exit-known_hosts",
            installer_sha256="0" * 64,
        )
        events: list[str] = []

        def apply_network(*_args, **_kwargs):
            events.append("network")
            return network

        def apply_exit(*_args, **_kwargs):
            events.append("exit")
            if remote_side_effect is not None:
                raise remote_side_effect
            return remote

        with (
            patch("xhttp_setup.pc_orchestrator.platform.system", return_value="Linux"),
            patch("xhttp_setup.pc_orchestrator.pin_host_key"),
            patch("xhttp_setup.pc_orchestrator.SSHClient", return_value=FakeSSH()),
            patch(
                "xhttp_setup.pc_orchestrator.apply_remote_exit_network",
                side_effect=apply_network,
            ) as apply_network,
            patch(
                "xhttp_setup.pc_orchestrator.apply_remote_exit",
                side_effect=apply_exit,
            ) as apply_exit,
            patch(
                "xhttp_setup.pc_orchestrator.rollback_remote_exit_network"
            ) as rollback,
        ):
            if os.name == "posix":
                os.chmod(root, 0o700)

            def call():
                return apply_pc_exit(
                    installer_pyz=self._installer(root),
                    desired=desired_exit(),
                    target=self.target,
                    auth=self.auth,
                    output_dir=root / "result",
                )

            yield SimpleNamespace(
                call=call,
                apply_network=apply_network,
                apply_exit=apply_exit,
                rollback=rollback,
                network=network,
                remote=remote,
                events=events,
            )

    def test_success_applies_network_before_existing_remote_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(Path(temp)) as env:
                result = env.call()

        self.assertIs(result.network, env.network)
        self.assertIs(result.remote, env.remote)
        self.assertEqual(env.events, ["network", "exit"])
        env.rollback.assert_not_called()

    def test_known_failed_remote_apply_rolls_back_only_network_result(self):
        failure = RemoteExitError(
            stage="remote_apply",
            remote_status="failed",
            artifact_status="not_saved",
            cleanup_status="succeeded",
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(Path(temp), failure) as env:
                with self.assertRaises(RemoteExitError):
                    env.call()

        env.rollback.assert_called_once_with(unittest.mock.ANY, env.network)

    def test_backend_port_cannot_match_exit_ssh_port(self):
        conflicting = RemoteExitTarget(
            host=self.target.host,
            user=self.target.user,
            port=8083,
            host_key_sha256=self.target.host_key_sha256,
        )
        with (
            tempfile.TemporaryDirectory() as temp,
            patch("xhttp_setup.pc_orchestrator.platform.system", return_value="Linux"),
            patch("xhttp_setup.pc_orchestrator.pin_host_key") as pin,
            patch("xhttp_setup.pc_orchestrator.apply_remote_exit_network") as network,
        ):
            with self.assertRaisesRegex(InstallerError, "SSH-портом"):
                apply_pc_exit(
                    installer_pyz=self._installer(Path(temp)),
                    desired=desired_exit(),
                    target=conflicting,
                    auth=self.auth,
                    output_dir=Path(temp) / "result",
                )
        pin.assert_not_called()
        network.assert_not_called()

    def test_unknown_or_successful_remote_state_keeps_restrictive_rules(self):
        for status in ("unknown", "succeeded"):
            with self.subTest(status=status), tempfile.TemporaryDirectory() as temp:
                failure = RemoteExitError(
                    stage="artifact_download",
                    remote_status=status,
                    artifact_status="not_saved",
                    cleanup_status="succeeded",
                )
                with self._environment(Path(temp), failure) as env:
                    with self.assertRaises(RemoteExitError):
                        env.call()
                    env.rollback.assert_not_called()

    def test_bridge_preflight_requires_uid_zero(self):
        bridge = RemoteFrontTarget(
            host="bridge.example.org",
            user="root",
            host_key_sha256=FINGERPRINT,
        )
        ssh = FakeSSH()
        ssh.command = Mock(
            return_value=subprocess.CompletedProcess(["id", "-u"], 0, "1000\n", "")
        )
        with (
            tempfile.TemporaryDirectory() as temp,
            patch("xhttp_setup.pc_orchestrator.platform.system", return_value="Linux"),
            patch("xhttp_setup.pc_orchestrator.pin_host_key"),
            patch("xhttp_setup.pc_orchestrator.SSHClient", return_value=ssh),
        ):
            if os.name == "posix":
                os.chmod(temp, 0o700)
            with self.assertRaisesRegex(InstallerError, "UID 0"):
                preflight_remote_front_bridge(
                    target=bridge,
                    auth=self.auth,
                    output_dir=Path(temp),
                )

    def test_front_is_rebound_to_actual_handoff(self):
        handoff = Handoff(
            exit_address="203.0.113.10",
            exit_port=8083,
            client_id=UUID,
            xhttp_path=PATH,
            encryption="mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx",
        ).validate()

        result = front_for_handoff(desired_front(), handoff)

        self.assertEqual(result.exit_address, handoff.exit_address)
        self.assertEqual(result.exit_port, handoff.exit_port)
        self.assertEqual(result.xhttp_path, handoff.xhttp_path)

    def test_pc_wizard_preflights_bridge_then_reuses_existing_server_flows(self):
        exit_target = self.target
        bridge_target = RemoteFrontTarget(
            host="bridge.example.org",
            user="root",
            host_key_sha256=FINGERPRINT,
        )
        handoff = Handoff(
            exit_address="203.0.113.10",
            exit_port=8083,
            client_id=UUID,
            xhttp_path=PATH,
            encryption="mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx",
        ).validate()
        events: list[str] = []
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            handoff_path = root / "handoff.json"
            handoff_path.write_text(
                json.dumps(handoff.to_dict()),
                encoding="utf-8",
            )
            os.chmod(handoff_path, 0o600)
            remote_exit = RemoteExitResult(
                target=exit_target,
                handoff_path=handoff_path,
                firewall_plan_path=root / "firewall-plan.txt",
                known_hosts_path=root / "exit-known_hosts",
                installer_sha256="0" * 64,
            )
            network = RemoteExitNetworkApplyResult(
                profile=Mock(),
                allow_comment="allow",
                deny_comment="deny",
                ufw_allow_added=True,
                ufw_deny_added=True,
            )
            remote_front = RemoteFrontResult(
                target=bridge_target,
                client_path=root / "client.vless",
                known_hosts_path=root / "bridge-known_hosts",
                installer_sha256="0" * 64,
            )

            def preflight(**_kwargs):
                events.append("bridge-preflight")
                return root / "bridge-known_hosts"

            def apply_exit(**_kwargs):
                events.append("exit")
                return PcExitResult(remote_exit, network)

            def apply_front(**_kwargs):
                events.append("front")
                return remote_front

            with (
                patch("xhttp_setup.cli._require_linux_apply"),
                patch(
                    "xhttp_setup.cli._installer_pyz_from_runtime",
                    return_value=root / "installer.pyz",
                ),
                patch(
                    "xhttp_setup.cli._collect_remote_exit_target",
                    return_value=exit_target,
                ),
                patch("xhttp_setup.cli._collect_exit", return_value=desired_exit()),
                patch("xhttp_setup.cli._yes_no", return_value=True),
                patch("xhttp_setup.cli._collect_front", return_value=desired_front()),
                patch(
                    "xhttp_setup.cli._collect_remote_front_target",
                    return_value=bridge_target,
                ),
                patch("xhttp_setup.cli._show_plan"),
                patch("xhttp_setup.cli._ack_provider"),
                patch("xhttp_setup.cli._confirm_apply"),
                patch(
                    "xhttp_setup.cli._collect_auth",
                    side_effect=(self.auth, self.auth),
                ),
                patch(
                    "xhttp_setup.cli._collect_bridge_sftp_password",
                    return_value="sftp-secret",
                ),
                patch("xhttp_setup.cli._pc_output_dir", return_value=root),
                patch(
                    "xhttp_setup.cli.preflight_remote_front_bridge",
                    side_effect=preflight,
                ),
                patch("xhttp_setup.cli.apply_pc_exit", side_effect=apply_exit),
                patch("xhttp_setup.cli.apply_remote_front", side_effect=apply_front),
                patch("xhttp_setup.cli.check_front_dns") as dns,
                patch("xhttp_setup.cli.check_public_tls") as tls,
                redirect_stdout(StringIO()),
            ):
                self.assertEqual(wizard_pc(), 0)

        self.assertEqual(events, ["bridge-preflight", "exit", "front"])
        dns.assert_not_called()
        tls.assert_not_called()


if __name__ == "__main__":
    unittest.main()
