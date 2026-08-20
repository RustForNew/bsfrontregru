import json
import os
import shlex
import stat
import subprocess
import tempfile
import traceback
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from xhttp_setup.errors import InstallerError, ValidationError
from xhttp_setup.exit_installer import Layout, _firewall_plan
from xhttp_setup.models import ExitDesired, Handoff
from xhttp_setup.remote_exit import (
    RemoteExitError,
    RemoteExitTarget,
    _TeardownCapture,
    _capture_context_teardown,
    _persist_local_artifacts,
    apply_remote_exit,
)
from xhttp_setup.ssh_transport import SSHAuth, SSHTransportError


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef"
ENCRYPTION = "mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx"
FINGERPRINT = "SHA256:" + ("A" * 43)


def portable_atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / ("." + path.name + ".test-new")
    temporary.write_bytes(data)
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def portable_atomic_write_text(path: Path, text: str, mode: int = 0o600) -> None:
    portable_atomic_write(path, text.encode("utf-8"), mode)


def desired_exit() -> ExitDesired:
    return ExitDesired(
        public_address="203.0.113.10",
        listen_port=8083,
        front_egress_ip="198.51.100.20",
        xhttp_path=PATH,
        client_id=UUID,
        label="Remote XHTTP TLS",
        expected_egress_ip="203.0.113.10",
        tls_fingerprint="edge",
    ).validate()


class RemoteState:
    def __init__(self, desired: ExitDesired, *, uid: int = 0, gid: int = 0):
        self.desired = desired
        self.uid = uid
        self.gid = gid
        self.files: dict[str, bytes] = {}
        self.modes: dict[str, str] = {}
        self.commands: list[list[str]] = []
        self.ssh_session_events: list[str] = []
        self.ssh_session_count = 0
        self.teardown_error_sessions: set[int] = set()
        self.broken_session = False
        self.transport_fail_stat_once = False
        self.sftp_session_events: list[str] = []
        self.remote_temp = "/tmp/xhttp-exit.A1b2C3d4E5"
        self.corrupt_roundtrip = False
        self.bad_firewall = False
        self.fail_download = False
        self.fail_cleanup = False
        self.transport_fail_cleanup_once = False
        self.apply_returncode = 0
        self.apply_raises = False

    def write_managed_artifacts(self) -> None:
        handoff = Handoff(
            exit_address=self.desired.public_address,
            exit_port=self.desired.listen_port,
            client_id=self.desired.client_id,
            xhttp_path=self.desired.xhttp_path,
            encryption=ENCRYPTION,
            label=self.desired.label,
            expected_egress_ip=self.desired.expected_egress_ip,
            tls_fingerprint=self.desired.tls_fingerprint,
        ).validate()
        self.files[str(Layout().handoff)] = (
            json.dumps(handoff.to_dict(), ensure_ascii=False, indent=2) + "\n"
        ).encode("utf-8")
        firewall = (
            "unexpected firewall content\n"
            if self.bad_firewall
            else _firewall_plan(self.desired)
        )
        self.files[str(Layout().firewall_plan)] = firewall.encode("utf-8")


class FakeSSH:
    def __init__(self, state: RemoteState):
        self.state = state

    @contextmanager
    def session(self):
        self.state.ssh_session_count += 1
        session_number = self.state.ssh_session_count
        self.state.broken_session = False
        self.state.ssh_session_events.append("open")
        try:
            yield self
        finally:
            self.state.ssh_session_events.append("close")
            if session_number in self.state.teardown_error_sessions:
                raise InstallerError("simulated SSH session teardown failure")

    def command(
        self, argv, *, check=True, timeout=300, input_text=None
    ):
        del check, timeout, input_text
        command = list(argv)
        self.state.commands.append(command)
        if self.state.broken_session:
            raise SSHTransportError("simulated broken SSH session")
        inner = command[3:] if command[:3] == ["sudo", "-n", "--"] else command
        if inner == ["id", "-u"]:
            return subprocess.CompletedProcess(command, 0, f"{self.state.uid}\n", "")
        if inner == ["id", "-g"]:
            return subprocess.CompletedProcess(command, 0, f"{self.state.gid}\n", "")
        if inner[:5] == ["mktemp", "-d", "-p", "/tmp", "xhttp-exit.XXXXXXXXXX"]:
            return subprocess.CompletedProcess(
                command, 0, self.state.remote_temp + "\n", ""
            )
        if inner[:2] == ["chmod", "700"]:
            return subprocess.CompletedProcess(command, 0, "", "")
        if inner[:4] == ["stat", "-c", "%a", "--"]:
            if self.state.transport_fail_stat_once:
                self.state.transport_fail_stat_once = False
                self.state.broken_session = True
                raise SSHTransportError("simulated SSH loss during stat")
            mode = self.state.modes.get(inner[4], "")
            return subprocess.CompletedProcess(
                command, 0 if mode else 1, mode + ("\n" if mode else ""), ""
            )
        if inner and inner[0] == "python3" and "--apply" in inner:
            if self.state.apply_raises:
                self.state.broken_session = True
                raise SSHTransportError("simulated SSH loss with secret " + UUID)
            if self.state.apply_returncode != 0:
                return subprocess.CompletedProcess(
                    command,
                    self.state.apply_returncode,
                    UUID + "\n" + ENCRYPTION,
                    UUID,
                )
            self.state.write_managed_artifacts()
            return subprocess.CompletedProcess(command, 0, "Handoff written\n", "")
        if inner and inner[0] == "install":
            marker = inner.index("--")
            source, destination = inner[marker + 1 : marker + 3]
            if source not in self.state.files:
                return subprocess.CompletedProcess(command, 1, "", "missing")
            self.state.files[destination] = self.state.files[source]
            self.state.modes[destination] = "600"
            return subprocess.CompletedProcess(command, 0, "", "")
        if inner[:3] == ["rm", "-f", "--"]:
            if self.state.transport_fail_cleanup_once:
                self.state.transport_fail_cleanup_once = False
                self.state.broken_session = True
                raise SSHTransportError("simulated cleanup transport loss")
            if self.state.fail_cleanup:
                return subprocess.CompletedProcess(command, 1, "", "cleanup failed")
            for remote_path in inner[3:]:
                self.state.files.pop(remote_path, None)
                self.state.modes.pop(remote_path, None)
            return subprocess.CompletedProcess(command, 0, "", "")
        if inner[:2] == ["rmdir", "--"]:
            prefix = inner[2] + "/"
            has_files = any(path.startswith(prefix) for path in self.state.files)
            return subprocess.CompletedProcess(command, 1 if has_files else 0, "", "")
        raise AssertionError(f"unexpected SSH command: {command!r}")

    def fresh_command(
        self, argv, *, check=True, timeout=300, input_text=None
    ):
        return self.command(
            argv,
            check=check,
            timeout=timeout,
            input_text=input_text,
        )


class FakeSFTP:
    def __init__(self, state: RemoteState):
        self.state = state

    @contextmanager
    def session(self):
        self.state.sftp_session_events.append("open")
        try:
            yield self
        finally:
            self.state.sftp_session_events.append("close")

    def batch(self, commands, *, check=True):
        for raw in commands:
            parts = shlex.split(raw)
            if parts[0] == "put":
                self.state.files[parts[2]] = Path(parts[1]).read_bytes()
            elif parts[0] == "chmod":
                self.state.modes[parts[2]] = parts[1].lstrip("0") or "0"
            elif parts[0] == "get":
                source, destination = parts[1], Path(parts[2])
                if self.state.fail_download and source.endswith("/handoff.json"):
                    raise InstallerError("simulated artifact download failure")
                data = self.state.files[source]
                if (
                    self.state.corrupt_roundtrip
                    and source.endswith("/installer.pyz")
                    and destination.name == "installer.roundtrip.pyz"
                ):
                    data += b"corrupt"
                destination.write_bytes(data)
            else:
                raise AssertionError(f"unexpected SFTP command: {raw!r}")
        return subprocess.CompletedProcess(commands, 0, "", "")


@contextmanager
def fake_transport(state: RemoteState):
    ssh = FakeSSH(state)
    sftp = FakeSFTP(state)

    def fake_pin(*, host, port, expected_sha256, known_hosts):
        del host, port, expected_sha256
        known_hosts.write_text("exit ssh-ed25519 AAAA\n", encoding="utf-8")
        os.chmod(known_hosts, 0o600)

    with (
        patch("xhttp_setup.remote_exit.platform.system", return_value="Linux"),
        patch("xhttp_setup.remote_exit.pin_host_key", side_effect=fake_pin),
        patch("xhttp_setup.remote_exit.SSHClient", return_value=ssh),
        patch("xhttp_setup.remote_exit.SFTPClient", return_value=sftp),
        patch(
            "xhttp_setup.remote_exit.atomic_write",
            side_effect=portable_atomic_write,
        ),
        patch(
            "xhttp_setup.remote_exit.atomic_write_text",
            side_effect=portable_atomic_write_text,
        ),
    ):
        yield ssh, sftp


class RemoteExitTests(unittest.TestCase):
    def setUp(self):
        self.desired = desired_exit()
        self.target = RemoteExitTarget(
            host="exit.example.org",
            port=2222,
            user="deploy",
            host_key_sha256=FINGERPRINT,
        )
        self.auth = SSHAuth("password", password="do-not-print")

    def run_install(self, state: RemoteState, root: Path):
        installer = root / "xhttp-setup.pyz"
        installer.write_bytes(b"#!/usr/bin/env python3\nPYZ-CONTENT")
        output = root / "result"
        with fake_transport(state):
            return apply_remote_exit(
                installer_pyz=installer,
                desired=self.desired,
                target=self.target,
                auth=self.auth,
                output_dir=output,
            )

    def test_root_success_uploads_by_roundtrip_and_cleans_exact_temp(self):
        state = RemoteState(self.desired)
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_install(state, Path(temp))

            self.assertEqual(result.remote_status, "succeeded")
            self.assertEqual(result.artifact_status, "saved")
            self.assertEqual(result.cleanup_status, "succeeded")
            self.assertTrue(result.handoff_path.is_file())
            self.assertEqual(
                result.firewall_plan_path.read_text("utf-8"),
                _firewall_plan(self.desired),
            )
            if os.name == "posix":
                self.assertEqual(
                    stat.S_IMODE(result.handoff_path.stat().st_mode), 0o600
                )
                self.assertEqual(
                    stat.S_IMODE(result.firewall_plan_path.stat().st_mode), 0o600
                )

        apply_command = next(
            command for command in state.commands if "--apply" in command
        )
        self.assertEqual(
            apply_command[:2], ["python3", state.remote_temp + "/installer.pyz"]
        )
        self.assertEqual(apply_command[-2:], ["--confirm", "APPLY EXIT"])
        self.assertNotIn(UUID, apply_command)
        self.assertFalse(
            any(
                executable in {"ufw", "iptables", "nft"}
                for command in state.commands
                for executable in command
            )
        )
        self.assertFalse(
            any(path.startswith(state.remote_temp + "/") for path in state.files)
        )
        self.assertEqual(
            state.ssh_session_events,
            ["open", "close"],
        )
        self.assertEqual(
            state.sftp_session_events,
            ["open", "close", "open", "close"],
        )
        cleanup_command = next(
            command for command in state.commands if command[:3] == ["rm", "-f", "--"]
        )
        self.assertNotIn("-r", cleanup_command)
        self.assertEqual(
            set(cleanup_command[3:]),
            {
                state.remote_temp + "/installer.pyz",
                state.remote_temp + "/client-id",
                state.remote_temp + "/handoff.json",
                state.remote_temp + "/firewall-plan.txt",
            },
        )

    def test_injected_runner_reuses_caller_session_without_opening_another(self):
        state = RemoteState(self.desired)
        runner = FakeSSH(state)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer = root / "xhttp-setup.pyz"
            installer.write_bytes(b"PYZ")
            with (
                fake_transport(state),
                patch(
                    "xhttp_setup.remote_exit.SSHClient",
                    side_effect=AssertionError("must reuse injected runner"),
                ) as client,
            ):
                result = apply_remote_exit(
                    installer_pyz=installer,
                    desired=self.desired,
                    target=self.target,
                    auth=self.auth,
                    output_dir=root / "result",
                    ssh_runner=runner,
                )

        self.assertEqual(result.remote_status, "succeeded")
        client.assert_not_called()
        self.assertEqual(state.ssh_session_events, [])

    def test_non_root_uses_noninteractive_sudo_for_apply_and_artifact_stage(self):
        state = RemoteState(self.desired, uid=1001, gid=1002)
        with tempfile.TemporaryDirectory() as temp:
            self.run_install(state, Path(temp))

        privileged = [
            command
            for command in state.commands
            if "--apply" in command or "install" in command
        ]
        self.assertEqual(len(privileged), 3)
        self.assertTrue(
            all(command[:3] == ["sudo", "-n", "--"] for command in privileged)
        )

    def test_roundtrip_sha_mismatch_aborts_before_remote_apply(self):
        state = RemoteState(self.desired)
        state.corrupt_roundtrip = True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.stage, "upload_verify")
        self.assertEqual(error.remote_status, "not_started")
        self.assertEqual(error.cleanup_status, "succeeded")
        self.assertFalse(any("--apply" in command for command in state.commands))

    def test_preapply_transport_loss_recovers_temp_in_one_new_session(self):
        state = RemoteState(self.desired)
        state.transport_fail_stat_once = True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.stage, "upload_verify")
        self.assertEqual(error.remote_status, "not_started")
        self.assertEqual(error.cleanup_status, "succeeded")
        self.assertEqual(error.remote_temp, state.remote_temp)
        self.assertTrue(error.recovery_completed)
        self.assertFalse(error.recovery_failed)
        self.assertEqual(
            state.ssh_session_events,
            ["open", "close", "open", "close"],
        )
        self.assertFalse(any("--apply" in command for command in state.commands))

    def test_body_failure_stage_survives_session_teardown_failure(self):
        state = RemoteState(self.desired)
        state.corrupt_roundtrip = True
        state.teardown_error_sessions.add(1)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.stage, "upload_verify")
        self.assertEqual(error.remote_status, "not_started")
        self.assertEqual(error.cleanup_status, "succeeded")
        self.assertTrue(error.session_cleanup_failed)
        self.assertFalse(error.recovery_completed)
        self.assertEqual(state.ssh_session_count, 1)

    def test_teardown_capture_preserves_body_and_control_baseexceptions(self):
        @contextmanager
        def fails_during_teardown(error):
            try:
                yield object()
            finally:
                raise error

        ordinary_body = RuntimeError("body failure")
        capture = _TeardownCapture()
        with self.assertRaises(RuntimeError) as raised:
            with _capture_context_teardown(
                fails_during_teardown(InstallerError("teardown failure")),
                capture,
            ):
                raise ordinary_body
        self.assertIs(raised.exception, ordinary_body)
        self.assertIsNone(capture.error)

        interrupted_body = KeyboardInterrupt("body interrupted")
        capture = _TeardownCapture()
        with self.assertRaises(KeyboardInterrupt) as raised:
            with _capture_context_teardown(
                fails_during_teardown(InstallerError("teardown failure")),
                capture,
            ):
                raise interrupted_body
        self.assertIs(raised.exception, interrupted_body)
        self.assertIsNone(capture.error)

        capture = _TeardownCapture()
        with self.assertRaises(KeyboardInterrupt):
            with _capture_context_teardown(
                fails_during_teardown(KeyboardInterrupt("teardown interrupted")),
                capture,
            ):
                pass
        self.assertIsNone(capture.error)

        teardown_error = InstallerError("ordinary teardown failure")
        capture = _TeardownCapture()
        with _capture_context_teardown(
            fails_during_teardown(teardown_error), capture
        ):
            pass
        self.assertIs(capture.error, teardown_error)

    def test_successful_apply_teardown_failure_is_typed_cleanup_error(self):
        state = RemoteState(self.desired)
        state.teardown_error_sessions.add(1)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.stage, "cleanup")
        self.assertEqual(error.remote_status, "succeeded")
        self.assertEqual(error.artifact_status, "saved")
        self.assertEqual(error.cleanup_status, "succeeded")
        self.assertTrue(error.session_cleanup_failed)
        self.assertEqual(state.ssh_session_count, 1)

    def test_unexpected_mktemp_path_is_never_used_for_cleanup(self):
        state = RemoteState(self.desired)
        state.remote_temp = "/tmp/not-our-namespace"
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.stage, "remote_temp")
        self.assertEqual(error.cleanup_status, "unknown")
        self.assertIsNone(error.remote_temp)
        self.assertFalse(
            any(command and command[0] in {"rm", "rmdir"} for command in state.commands)
        )

    def test_apply_failure_does_not_echo_captured_credentials(self):
        state = RemoteState(self.desired)
        state.apply_returncode = 17
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.remote_status, "failed")
        self.assertIsNone(error.remote_applied)
        self.assertNotIn(UUID, str(error))
        self.assertNotIn(ENCRYPTION, str(error))

    def test_connection_loss_during_apply_reports_unknown_remote_state(self):
        state = RemoteState(self.desired)
        state.apply_raises = True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.remote_status, "unknown")
        self.assertIsNone(error.remote_applied)
        self.assertNotIn(UUID, str(error))
        self.assertNotIn(UUID, repr(error))
        self.assertNotIn(UUID, "".join(traceback.format_exception(error)))
        self.assertIsNone(error.__cause__)
        self.assertIsNone(error.__context__)
        self.assertEqual(
            sum("--apply" in command for command in state.commands),
            1,
        )
        self.assertEqual(state.ssh_session_events, ["open", "close"])
        self.assertEqual(error.cleanup_status, "failed")
        self.assertFalse(error.recovery_completed)
        self.assertFalse(error.recovery_failed)

    def test_known_failed_apply_cleanup_transport_uses_one_recovery_session(self):
        state = RemoteState(self.desired)
        state.apply_returncode = 17
        state.transport_fail_cleanup_once = True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.stage, "remote_apply")
        self.assertEqual(error.remote_status, "failed")
        self.assertEqual(error.cleanup_status, "succeeded")
        self.assertTrue(error.recovery_completed)
        self.assertEqual(
            state.ssh_session_events,
            ["open", "close", "open", "close"],
        )
        self.assertEqual(
            sum("--apply" in command for command in state.commands),
            1,
        )

    def test_openssh_255_reports_unknown_remote_state(self):
        state = RemoteState(self.desired)
        state.apply_returncode = 255
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))

        self.assertEqual(raised.exception.remote_status, "unknown")
        self.assertIsNone(raised.exception.remote_applied)

    def test_invalid_download_after_apply_is_explicit_partial_success(self):
        state = RemoteState(self.desired)
        state.bad_firewall = True
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result"
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))
            self.assertFalse((output / "handoff.json").exists())
            self.assertFalse((output / "firewall-plan.txt").exists())

        error = raised.exception
        self.assertEqual(error.stage, "artifact_validation")
        self.assertEqual(error.remote_status, "succeeded")
        self.assertTrue(error.remote_applied)
        self.assertEqual(error.artifact_status, "not_saved")
        self.assertEqual(error.cleanup_status, "succeeded")

    def test_cleanup_failure_keeps_valid_local_artifacts_and_reports_path(self):
        state = RemoteState(self.desired)
        state.fail_cleanup = True
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result"
            with self.assertRaises(RemoteExitError) as raised:
                self.run_install(state, Path(temp))
            self.assertTrue((output / "handoff.json").is_file())
            self.assertTrue((output / "firewall-plan.txt").is_file())

        error = raised.exception
        self.assertEqual(error.stage, "cleanup")
        self.assertEqual(error.remote_status, "succeeded")
        self.assertEqual(error.artifact_status, "saved")
        self.assertEqual(error.cleanup_status, "failed")
        self.assertEqual(error.remote_temp, state.remote_temp)
        self.assertNotIn(UUID, str(error))

    def test_local_artifact_write_rolls_back_both_previous_files(self):
        state = RemoteState(self.desired)
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            output = root / "result"
            output.mkdir(mode=0o700)
            old_handoff = b"old handoff"
            old_firewall = b"old firewall"
            (output / "handoff.json").write_bytes(old_handoff)
            (output / "firewall-plan.txt").write_bytes(old_firewall)
            failed_once = False

            def fail_second_target(path, data, mode=0o600):
                nonlocal failed_once
                if path.name == "firewall-plan.txt" and not failed_once:
                    failed_once = True
                    raise OSError("simulated local write failure")
                return portable_atomic_write(path, data, mode)

            installer = root / "xhttp-setup.pyz"
            installer.write_bytes(b"PYZ")
            with (
                fake_transport(state),
                patch(
                    "xhttp_setup.remote_exit.atomic_write",
                    side_effect=fail_second_target,
                ),
            ):
                with self.assertRaises(RemoteExitError) as raised:
                    apply_remote_exit(
                        installer_pyz=installer,
                        desired=self.desired,
                        target=self.target,
                        auth=self.auth,
                        output_dir=output,
                    )

            self.assertEqual((output / "handoff.json").read_bytes(), old_handoff)
            self.assertEqual((output / "firewall-plan.txt").read_bytes(), old_firewall)
            self.assertEqual(raised.exception.artifact_status, "not_saved")
            self.assertEqual(raised.exception.remote_status, "succeeded")

    def test_local_artifact_transaction_rolls_back_control_baseexceptions(self):
        for exception_type in (KeyboardInterrupt, SystemExit):
            with self.subTest(exception_type=exception_type.__name__):
                with tempfile.TemporaryDirectory() as temp:
                    root = Path(temp)
                    output = root / "result"
                    output.mkdir()
                    handoff_target = output / "handoff.json"
                    firewall_target = output / "firewall-plan.txt"
                    handoff_target.write_bytes(b"old-handoff")
                    firewall_target.write_bytes(b"old-firewall")
                    handoff_source = root / "handoff.download"
                    firewall_source = root / "firewall.download"
                    handoff_source.write_bytes(b"new-handoff")
                    firewall_source.write_bytes(b"new-firewall")
                    calls = 0

                    def interrupt_second_write(path, data, mode=0o600):
                        nonlocal calls
                        calls += 1
                        if calls == 2:
                            raise exception_type("interrupted local transaction")
                        portable_atomic_write(path, data, mode)

                    with (
                        patch(
                            "xhttp_setup.remote_exit.atomic_write",
                            side_effect=interrupt_second_write,
                        ),
                        self.assertRaises(exception_type),
                    ):
                        _persist_local_artifacts(
                            handoff_source=handoff_source,
                            firewall_source=firewall_source,
                            output_dir=output,
                        )

                    self.assertEqual(handoff_target.read_bytes(), b"old-handoff")
                    self.assertEqual(firewall_target.read_bytes(), b"old-firewall")

    def test_target_validation_happens_before_any_network_call(self):
        bad_target = RemoteExitTarget(
            host="bad;host",
            user="deploy",
            host_key_sha256=FINGERPRINT,
        )
        with tempfile.TemporaryDirectory() as temp:
            installer = Path(temp) / "installer.pyz"
            installer.write_bytes(b"PYZ")
            with patch("xhttp_setup.remote_exit.pin_host_key") as pin:
                with self.assertRaises(ValidationError):
                    apply_remote_exit(
                        installer_pyz=installer,
                        desired=self.desired,
                        target=bad_target,
                        auth=self.auth,
                        output_dir=Path(temp) / "output",
                    )
                pin.assert_not_called()


if __name__ == "__main__":
    unittest.main()
