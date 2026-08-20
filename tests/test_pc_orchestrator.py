import os
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from xhttp_setup.errors import InstallerError
from xhttp_setup.exit_network import ExitNetworkProfile
from xhttp_setup.models import ExitDesired, FrontDesired, Handoff
from xhttp_setup.pc_orchestrator import (
    PcExitRecoveryError,
    apply_pc_exit,
    front_for_handoff,
    preflight_remote_front_bridge,
)
from xhttp_setup.remote_exit import RemoteExitError, RemoteExitResult, RemoteExitTarget
from xhttp_setup.remote_front import RemoteFrontTarget
from xhttp_setup.remote_network import (
    RemoteExitNetworkApplyResult,
    RemoteExitNetworkError,
    RemoteExitNetworkRecovery,
)
from xhttp_setup.ssh_transport import SSHAuth, SSHTransportError


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
    def __init__(self):
        self.active = False
        self.commands = []
        self.fresh_commands = []
        self.session_events = []
        self.session_count = 0
        self.teardown_error_sessions: set[int] = set()

    @contextmanager
    def session(self):
        self.session_count += 1
        session_number = self.session_count
        self.session_events.append("open")
        self.active = True
        try:
            yield self
        finally:
            self.active = False
            self.session_events.append("close")
            if session_number in self.teardown_error_sessions:
                raise InstallerError("simulated session teardown failure")

    def command(
        self, argv, *, check=True, timeout=300, input_text=None
    ):
        del check, timeout, input_text
        self.commands.append(list(argv))
        if argv == ["id", "-u"]:
            return subprocess.CompletedProcess(argv, 0, "0\n", "")
        raise AssertionError(argv)

    def fresh_command(
        self, argv, *, check=True, timeout=300, input_text=None
    ):
        self.fresh_commands.append(list(argv))
        return self.command(
            argv,
            check=check,
            timeout=timeout,
            input_text=input_text,
        )


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
    def _environment(
        self,
        root: Path,
        remote_side_effect=None,
        *,
        network_side_effect=None,
        rollback_side_effect=None,
        cleanup_result=True,
        reconcile_side_effect=None,
        owned_network=True,
    ):
        profile = ExitNetworkProfile("198.51.100.20", 8083).validate()
        network = RemoteExitNetworkApplyResult(
            profile=profile,
            ssh_port=self.target.port,
            allow_comment="xhttp-setup-allow-8083-198.51.100.20",
            deny_comment="xhttp-setup-deny-8083",
            ufw_allow_added=owned_network,
            ufw_deny_added=owned_network,
        )
        remote = RemoteExitResult(
            target=self.target,
            handoff_path=root / "result/handoff.json",
            firewall_plan_path=root / "result/firewall-plan.txt",
            known_hosts_path=root / "result/exit-known_hosts",
            installer_sha256="0" * 64,
        )
        events: list[str] = []
        ssh = FakeSSH()

        def apply_network(runner, _profile, *, ssh_port):
            self.assertIs(runner, ssh)
            self.assertTrue(ssh.active)
            self.assertEqual(ssh_port, self.target.port)
            events.append("network")
            if network_side_effect is not None:
                raise network_side_effect
            return network

        def apply_exit(*_args, **_kwargs):
            self.assertIs(_kwargs["ssh_runner"], ssh)
            self.assertTrue(ssh.active)
            events.append("exit")
            if remote_side_effect is not None:
                raise remote_side_effect
            return remote

        def rollback_network(runner, result):
            self.assertIs(runner, ssh)
            self.assertIs(result, network)
            self.assertTrue(ssh.active)
            events.append("rollback")
            if rollback_side_effect is not None:
                raise rollback_side_effect

        def cleanup_temp(runner, remote_temp):
            self.assertIs(runner, ssh)
            self.assertTrue(ssh.active)
            self.assertEqual(remote_temp, "/tmp/xhttp-exit.A1b2C3d4E5")
            events.append("cleanup")
            return cleanup_result

        def reconcile(runner, recovery):
            self.assertIs(runner, ssh)
            self.assertTrue(ssh.active)
            events.append("reconcile")
            if reconcile_side_effect is not None:
                raise reconcile_side_effect
            return SimpleNamespace(
                ufw_allow_removed=True,
                ufw_deny_removed=True,
            )

        with (
            patch("xhttp_setup.pc_orchestrator.platform.system", return_value="Linux"),
            patch("xhttp_setup.pc_orchestrator.pin_host_key") as pin,
            patch("xhttp_setup.pc_orchestrator.SSHClient", return_value=ssh),
            patch(
                "xhttp_setup.pc_orchestrator.apply_remote_exit_network",
                side_effect=apply_network,
            ) as apply_network,
            patch(
                "xhttp_setup.pc_orchestrator.apply_remote_exit",
                side_effect=apply_exit,
            ) as apply_exit,
            patch(
                "xhttp_setup.pc_orchestrator.rollback_remote_exit_network",
                side_effect=rollback_network,
            ) as rollback,
            patch(
                "xhttp_setup.pc_orchestrator.cleanup_remote_exit_temp",
                side_effect=cleanup_temp,
            ) as cleanup,
            patch(
                "xhttp_setup.pc_orchestrator.reconcile_remote_exit_network",
                side_effect=reconcile,
            ) as reconcile,
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
                    trusted_known_hosts=root / "persistent-exit.known_hosts",
                )

            yield SimpleNamespace(
                call=call,
                apply_network=apply_network,
                apply_exit=apply_exit,
                rollback=rollback,
                cleanup=cleanup,
                reconcile=reconcile,
                pin=pin,
                network=network,
                remote=remote,
                events=events,
                ssh=ssh,
            )

    def test_success_applies_network_before_existing_remote_exit(self):
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(Path(temp)) as env:
                result = env.call()

        self.assertIs(result.network, env.network)
        self.assertIs(result.remote, env.remote)
        self.assertEqual(env.events, ["network", "exit"])
        self.assertEqual(env.ssh.commands, [["id", "-u"]])
        self.assertEqual(env.ssh.session_events, ["open", "close"])
        self.assertIs(
            env.apply_exit.call_args.kwargs["ssh_runner"],
            env.ssh,
        )
        self.assertEqual(
            env.pin.call_args.kwargs["trusted_known_hosts"],
            Path(temp) / "persistent-exit.known_hosts",
        )
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
        self.assertEqual(env.events, ["network", "exit", "rollback"])
        self.assertEqual(env.ssh.session_events, ["open", "close"])

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

    def test_preapply_transport_loss_uses_one_exact_recovery_session(self):
        failure = RemoteExitError(
            stage="upload_verify",
            remote_status="not_started",
            artifact_status="not_saved",
            cleanup_status="failed",
            remote_temp="/tmp/xhttp-exit.A1b2C3d4E5",
            transport_failure=True,
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(Path(temp), failure) as env:
                with self.assertRaises(RemoteExitError) as raised:
                    env.call()

        error = raised.exception
        self.assertEqual(error.stage, "upload_verify")
        self.assertEqual(error.remote_status, "not_started")
        self.assertEqual(error.cleanup_status, "succeeded")
        self.assertEqual(error.remote_temp, "/tmp/xhttp-exit.A1b2C3d4E5")
        self.assertTrue(error.recovery_completed)
        self.assertEqual(
            env.events,
            ["network", "exit", "cleanup", "reconcile"],
        )
        self.assertEqual(
            env.ssh.session_events,
            ["open", "close", "open", "close"],
        )
        env.apply_exit.assert_called_once()
        env.cleanup.assert_called_once()
        env.reconcile.assert_called_once()
        env.rollback.assert_not_called()

    def test_known_failed_cleanup_transport_uses_one_exact_recovery_session(self):
        failure = RemoteExitError(
            stage="remote_apply",
            remote_status="failed",
            artifact_status="not_saved",
            cleanup_status="failed",
            remote_temp="/tmp/xhttp-exit.A1b2C3d4E5",
            transport_failure=True,
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(Path(temp), failure) as env:
                with self.assertRaises(RemoteExitError) as raised:
                    env.call()

        self.assertEqual(raised.exception.stage, "remote_apply")
        self.assertEqual(raised.exception.remote_status, "failed")
        self.assertTrue(raised.exception.recovery_completed)
        self.assertEqual(
            env.events,
            ["network", "exit", "cleanup", "reconcile"],
        )
        self.assertEqual(
            env.ssh.session_events,
            ["open", "close", "open", "close"],
        )
        env.apply_exit.assert_called_once()
        env.rollback.assert_not_called()

    def test_unknown_remote_apply_never_opens_recovery_session(self):
        failure = RemoteExitError(
            stage="remote_apply",
            remote_status="unknown",
            artifact_status="not_saved",
            cleanup_status="failed",
            remote_temp="/tmp/xhttp-exit.A1b2C3d4E5",
            transport_failure=True,
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(Path(temp), failure) as env:
                with self.assertRaises(RemoteExitError) as raised:
                    env.call()

        self.assertIs(raised.exception, failure)
        self.assertEqual(env.events, ["network", "exit"])
        self.assertEqual(env.ssh.session_events, ["open", "close"])
        env.rollback.assert_not_called()
        env.cleanup.assert_not_called()
        env.reconcile.assert_not_called()
        env.apply_exit.assert_called_once()

    def test_recovery_failure_preserves_original_stage_and_status(self):
        failure = RemoteExitError(
            stage="upload_verify",
            remote_status="not_started",
            artifact_status="not_saved",
            cleanup_status="failed",
            remote_temp="/tmp/xhttp-exit.A1b2C3d4E5",
            transport_failure=True,
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(
                Path(temp), failure, cleanup_result=False
            ) as env:
                with self.assertRaises(PcExitRecoveryError) as raised:
                    env.call()

        self.assertIs(raised.exception.original_error, failure)
        self.assertEqual(raised.exception.stage, "upload_verify")
        self.assertEqual(raised.exception.remote_status, "not_started")
        self.assertEqual(
            env.events,
            ["network", "exit", "cleanup", "reconcile"],
        )
        self.assertEqual(
            env.ssh.session_events,
            ["open", "close", "open", "close"],
        )

    def test_recovery_session_teardown_failure_is_explicit_incomplete_state(self):
        failure = RemoteExitError(
            stage="upload_verify",
            remote_status="not_started",
            artifact_status="not_saved",
            cleanup_status="failed",
            remote_temp="/tmp/xhttp-exit.A1b2C3d4E5",
            transport_failure=True,
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(Path(temp), failure) as env:
                env.ssh.teardown_error_sessions.add(2)
                with self.assertRaises(PcExitRecoveryError) as raised:
                    env.call()

        self.assertIs(raised.exception.original_error, failure)
        self.assertEqual(raised.exception.stage, "upload_verify")
        self.assertEqual(raised.exception.remote_status, "not_started")
        self.assertEqual(
            env.events,
            ["network", "exit", "cleanup", "reconcile"],
        )
        self.assertEqual(env.ssh.session_count, 2)

    def test_broken_preapply_with_no_owned_state_needs_no_recovery(self):
        failure = RemoteExitError(
            stage="remote_identity",
            remote_status="not_started",
            artifact_status="not_saved",
            cleanup_status="not_needed",
            transport_failure=True,
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(
                Path(temp), failure, owned_network=False
            ) as env:
                with self.assertRaises(RemoteExitError) as raised:
                    env.call()

        self.assertIs(raised.exception, failure)
        self.assertEqual(env.ssh.session_events, ["open", "close"])
        self.assertEqual(env.events, ["network", "exit"])
        env.rollback.assert_not_called()
        env.cleanup.assert_not_called()
        env.reconcile.assert_not_called()

    def test_network_mutation_loss_is_reconciled_without_exit_replay(self):
        profile = ExitNetworkProfile("198.51.100.20", 8083).validate()
        network_failure = RemoteExitNetworkError(
            recovery=RemoteExitNetworkRecovery(
                profile,
                self.target.port,
                (
                    (
                        "UFW frontend allow",
                        "xhttp-setup-allow-8083-198.51.100.20",
                    ),
                ),
            )
        )
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(
                Path(temp), network_side_effect=network_failure
            ) as env:
                with self.assertRaises(RemoteExitNetworkError) as raised:
                    env.call()

        self.assertTrue(raised.exception.recovery_completed)
        self.assertEqual(env.events, ["network", "reconcile"])
        self.assertEqual(
            env.ssh.session_events,
            ["open", "close", "open", "close"],
        )
        env.apply_exit.assert_not_called()
        env.reconcile.assert_called_once_with(
            unittest.mock.ANY, network_failure.recovery
        )
        env.cleanup.assert_not_called()

    def test_preapply_rollback_transport_loss_uses_same_single_recovery(self):
        failure = InstallerError("local pre-apply failure")
        rollback_loss = SSHTransportError("main session is broken")
        with tempfile.TemporaryDirectory() as temp:
            with self._environment(
                Path(temp),
                failure,
                rollback_side_effect=rollback_loss,
            ) as env:
                with self.assertRaises(InstallerError) as raised:
                    env.call()

        self.assertIs(raised.exception, failure)
        self.assertEqual(
            env.events,
            ["network", "exit", "rollback", "reconcile"],
        )
        self.assertEqual(
            env.ssh.session_events,
            ["open", "close", "open", "close"],
        )
        env.apply_exit.assert_called_once()
        env.reconcile.assert_called_once()

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
        self.assertEqual(ssh.session_events, ["open", "close"])

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


if __name__ == "__main__":
    unittest.main()
