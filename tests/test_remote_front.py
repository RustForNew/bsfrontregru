import hashlib
import json
import os
import shlex
import stat
import subprocess
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch

from xhttp_setup.errors import InstallerError, ValidationError
from xhttp_setup.models import FrontDesired, Handoff
from xhttp_setup.remote_front import (
    RemoteFrontError,
    RemoteFrontTarget,
    apply_remote_front,
)
from xhttp_setup.render import render_vless_uri
from xhttp_setup.ssh_transport import SSHAuth


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
XHTTP_PATH = "/api/0123456789abcdef"
ENCRYPTION = "mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx"
BRIDGE_FINGERPRINT = "SHA256:" + ("A" * 43)
SFTP_FINGERPRINT = "SHA256:" + ("B" * 43)
TLS_PIN = "c" * 64
SFTP_PASSWORD = "one-use-sftp-password"


def portable_atomic_write(path: Path, data: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.parent / ("." + path.name + ".test-new")
    temporary.write_bytes(data)
    os.chmod(temporary, mode)
    os.replace(temporary, path)


def handoff() -> Handoff:
    return Handoff(
        exit_address="203.0.113.10",
        exit_port=8083,
        client_id=UUID,
        xhttp_path=XHTTP_PATH,
        encryption=ENCRYPTION,
        label="Remote frontend",
        expected_egress_ip="203.0.113.10",
        tls_fingerprint="edge",
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
        ssh_host_key_sha256=SFTP_FINGERPRINT,
        exit_address="203.0.113.10",
        exit_port=8083,
        xhttp_path=XHTTP_PATH,
        placeholder_mode="keep",
        tls_mode="pinned",
        pinned_peer_cert_sha256=TLS_PIN,
    ).validate()


def expected_client() -> bytes:
    client_handoff = handoff().with_pinned_peer_cert(TLS_PIN)
    return (
        render_vless_uri(
            client_handoff,
            "front.example.org",
            front_address="192.0.2.30",
        )
        + "\n"
    ).encode("utf-8")


class RemoteState:
    def __init__(self, *, uid: int = 0):
        self.uid = uid
        self.files: dict[str, bytes] = {}
        self.modes: dict[str, int] = {}
        self.directories: set[str] = set()
        self.commands: list[list[str]] = []
        self.apply_input: str | None = None
        self.apply_command: list[str] | None = None
        self.remote_temp = "/tmp/xhttp-front.A1b2C3d4E5"
        self.corrupt_roundtrip = False
        self.bad_client = False
        self.fail_download = False
        self.fail_cleanup = False
        self.apply_returncode = 0
        self.apply_raises = False

    def metadata(self, path: str) -> str | None:
        if path in self.directories:
            permissions = self.modes.get(path, 0o700)
            mode = stat.S_IFDIR | permissions
            return f"{mode:x} {permissions:o} 0 0 0\n"
        if path in self.files:
            permissions = self.modes.get(path, 0o600)
            mode = stat.S_IFREG | permissions
            return f"{mode:x} {permissions:o} 0 0 {len(self.files[path])}\n"
        return None


class FakeSSH:
    def __init__(self, state: RemoteState):
        self.state = state

    def command(
        self,
        argv,
        *,
        check=True,
        timeout=300,
        input_text=None,
    ):
        del check, timeout
        command = list(argv)
        self.state.commands.append(command)
        if command == ["id", "-u"]:
            return subprocess.CompletedProcess(command, 0, f"{self.state.uid}\n", "")
        if command == [
            "mktemp",
            "-d",
            "-p",
            "/tmp",
            "xhttp-front.XXXXXXXXXX",
        ]:
            self.state.directories.add(self.state.remote_temp)
            self.state.modes[self.state.remote_temp] = 0o700
            return subprocess.CompletedProcess(
                command, 0, self.state.remote_temp + "\n", ""
            )
        if command[:3] == ["chmod", "700", "--"]:
            self.state.modes[command[3]] = 0o700
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:4] == ["stat", "-c", "%f %a %u %g %s", "--"]:
            metadata = self.state.metadata(command[4])
            return subprocess.CompletedProcess(
                command, 0 if metadata is not None else 1, metadata or "", ""
            )
        if command[:2] == ["sha256sum", "--"]:
            path = command[2]
            if path not in self.state.files:
                return subprocess.CompletedProcess(command, 1, "", "missing")
            digest = hashlib.sha256(self.state.files[path]).hexdigest()
            return subprocess.CompletedProcess(command, 0, f"{digest}  {path}\n", "")
        if command and command[0] == "python3" and "--apply" in command:
            self.state.apply_command = command
            self.state.apply_input = input_text
            if self.state.apply_raises:
                raise InstallerError(
                    "simulated SSH loss " + SFTP_PASSWORD + " " + ENCRYPTION
                )
            if self.state.apply_returncode != 0:
                return subprocess.CompletedProcess(
                    command,
                    self.state.apply_returncode,
                    expected_client().decode("utf-8"),
                    ENCRYPTION,
                )
            state_index = command.index("--state-dir")
            remote_client = command[state_index + 1] + "/client.vless"
            client = (
                b"vless://unexpected-secret\n"
                if self.state.bad_client
                else expected_client()
            )
            self.state.files[remote_client] = client
            self.state.modes[remote_client] = 0o600
            return subprocess.CompletedProcess(
                command, 0, expected_client().decode("utf-8"), ""
            )
        if command[:3] == ["rm", "-f", "--"]:
            if self.state.fail_cleanup:
                return subprocess.CompletedProcess(command, 1, "", "cleanup failed")
            for remote_path in command[3:]:
                self.state.files.pop(remote_path, None)
                self.state.modes.pop(remote_path, None)
            return subprocess.CompletedProcess(command, 0, "", "")
        if command[:2] == ["rmdir", "--"]:
            directory = command[2]
            if any(path.startswith(directory + "/") for path in self.state.files):
                return subprocess.CompletedProcess(command, 1, "", "not empty")
            self.state.directories.discard(directory)
            self.state.modes.pop(directory, None)
            return subprocess.CompletedProcess(command, 0, "", "")
        raise AssertionError(f"unexpected SSH command: {command!r}")


class FakeSFTP:
    def __init__(self, state: RemoteState):
        self.state = state

    def batch(self, commands, *, check=True):
        del check
        for raw in commands:
            parts = shlex.split(raw)
            if parts[0] == "put":
                self.state.files[parts[2]] = Path(parts[1]).read_bytes()
                self.state.modes[parts[2]] = 0o600
            elif parts[0] == "chmod":
                self.state.modes[parts[2]] = int(parts[1], 8)
            elif parts[0] == "get":
                source, destination = parts[1], Path(parts[2])
                if self.state.fail_download and source.endswith("/client.vless"):
                    raise InstallerError("simulated client download failure")
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
        known_hosts.write_text("bridge ssh-ed25519 AAAA\n", encoding="utf-8")
        os.chmod(known_hosts, 0o600)

    with (
        patch("xhttp_setup.remote_front.platform.system", return_value="Linux"),
        patch("xhttp_setup.remote_front.pin_host_key", side_effect=fake_pin),
        patch("xhttp_setup.remote_front.SSHClient", return_value=ssh),
        patch("xhttp_setup.remote_front.SFTPClient", return_value=sftp),
        patch(
            "xhttp_setup.remote_front.atomic_write",
            side_effect=portable_atomic_write,
        ),
    ):
        yield ssh, sftp


class RemoteFrontTests(unittest.TestCase):
    def setUp(self):
        self.desired = desired_front()
        self.target = RemoteFrontTarget(
            host="bridge.example.org",
            port=2222,
            user="root",
            host_key_sha256=BRIDGE_FINGERPRINT,
        )
        self.bridge_auth = SSHAuth("password", password="bridge-root-password")

    def prepare_inputs(self, root: Path) -> tuple[Path, Path, Path]:
        installer = root / "xhttp-setup.pyz"
        installer.write_bytes(b"#!/usr/bin/env python3\nPYZ-CONTENT")
        handoff_path = root / "handoff.json"
        handoff_path.write_text(
            json.dumps(handoff().to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        os.chmod(handoff_path, 0o600)
        return installer, handoff_path, root / "result"

    def run_install(self, state: RemoteState, root: Path):
        installer, handoff_path, output = self.prepare_inputs(root)
        with fake_transport(state):
            return apply_remote_front(
                installer_pyz=installer,
                handoff_path=handoff_path,
                desired=self.desired,
                target=self.target,
                bridge_auth=self.bridge_auth,
                sftp_password=SFTP_PASSWORD,
                output_dir=output,
                firewall_verified=True,
            )

    def test_success_uses_password_stdin_validates_client_and_cleans_exact_temp(self):
        state = RemoteState()
        with tempfile.TemporaryDirectory() as temp:
            result = self.run_install(state, Path(temp))
            self.assertEqual(result.client_path.read_bytes(), expected_client())
            self.assertEqual(result.remote_status, "succeeded")
            self.assertEqual(result.artifact_status, "saved")
            self.assertEqual(result.cleanup_status, "succeeded")
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(result.client_path.stat().st_mode), 0o600)
                self.assertEqual(
                    stat.S_IMODE(result.client_path.parent.stat().st_mode), 0o700
                )

        command = state.apply_command
        self.assertIsNotNone(command)
        assert command is not None
        self.assertEqual(state.apply_input, SFTP_PASSWORD + "\n")
        self.assertEqual(command[command.index("--auth-method") + 1], "password-stdin")
        self.assertIn("--ack-firewall", command)
        self.assertNotIn(SFTP_PASSWORD, repr(command))
        self.assertNotIn(UUID, repr(command))
        self.assertNotIn(ENCRYPTION, repr(command))
        cleanup = next(
            value for value in state.commands if value[:3] == ["rm", "-f", "--"]
        )
        self.assertNotIn("-r", cleanup)
        self.assertEqual(
            set(cleanup[3:]),
            {
                state.remote_temp + "/installer.pyz",
                state.remote_temp + "/handoff.json",
            },
        )
        self.assertFalse(
            any(path.startswith(state.remote_temp + "/") for path in state.files)
        )

    def test_firewall_confirmation_is_required_before_network(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer, handoff_path, output = self.prepare_inputs(root)
            with patch("xhttp_setup.remote_front.pin_host_key") as pin:
                with self.assertRaises(InstallerError):
                    apply_remote_front(
                        installer_pyz=installer,
                        handoff_path=handoff_path,
                        desired=self.desired,
                        target=self.target,
                        bridge_auth=self.bridge_auth,
                        sftp_password=SFTP_PASSWORD,
                        output_dir=output,
                        firewall_verified=False,
                    )
                pin.assert_not_called()

    def test_sftp_password_reserves_one_transport_byte_for_lf(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer, handoff_path, output = self.prepare_inputs(root)
            with patch("xhttp_setup.remote_front.pin_host_key") as pin:
                with self.assertRaises(InstallerError):
                    apply_remote_front(
                        installer_pyz=installer,
                        handoff_path=handoff_path,
                        desired=self.desired,
                        target=self.target,
                        bridge_auth=self.bridge_auth,
                        sftp_password="x" * 4096,
                        output_dir=output,
                        firewall_verified=True,
                    )
                pin.assert_not_called()

    def test_bridge_must_resolve_to_uid_zero(self):
        state = RemoteState(uid=1000)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteFrontError) as raised:
                self.run_install(state, Path(temp))

        self.assertEqual(raised.exception.stage, "remote_identity")
        self.assertEqual(raised.exception.remote_status, "not_started")
        self.assertEqual(raised.exception.cleanup_status, "not_needed")
        self.assertFalse(any("mktemp" in command for command in state.commands))

    def test_roundtrip_mismatch_aborts_before_front_apply(self):
        state = RemoteState()
        state.corrupt_roundtrip = True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteFrontError) as raised:
                self.run_install(state, Path(temp))

        self.assertEqual(raised.exception.stage, "upload_verify")
        self.assertEqual(raised.exception.remote_status, "not_started")
        self.assertEqual(raised.exception.cleanup_status, "succeeded")
        self.assertIsNone(state.apply_command)

    def test_apply_failure_reports_state_without_echoing_secrets(self):
        state = RemoteState()
        state.apply_returncode = 17
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteFrontError) as raised:
                self.run_install(state, Path(temp))

        error = raised.exception
        self.assertEqual(error.stage, "remote_apply")
        self.assertEqual(error.remote_status, "failed")
        self.assertIsNone(error.remote_applied)
        self.assertNotIn(SFTP_PASSWORD, str(error))
        self.assertNotIn(UUID, str(error))
        self.assertNotIn(ENCRYPTION, str(error))
        self.assertNotIn("vless://", str(error))

    def test_connection_loss_during_apply_is_unknown_and_redacted(self):
        state = RemoteState()
        state.apply_raises = True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteFrontError) as raised:
                self.run_install(state, Path(temp))

        self.assertEqual(raised.exception.remote_status, "unknown")
        self.assertIsNone(raised.exception.remote_applied)
        self.assertNotIn(SFTP_PASSWORD, str(raised.exception))
        self.assertNotIn(ENCRYPTION, str(raised.exception))

    def test_invalid_client_after_success_is_explicit_partial_success(self):
        state = RemoteState()
        state.bad_client = True
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result"
            with self.assertRaises(RemoteFrontError) as raised:
                self.run_install(state, Path(temp))
            self.assertFalse((output / "client.vless").exists())

        self.assertEqual(raised.exception.stage, "artifact_validation")
        self.assertEqual(raised.exception.remote_status, "succeeded")
        self.assertTrue(raised.exception.remote_applied)
        self.assertEqual(raised.exception.artifact_status, "not_saved")

    def test_client_download_failure_has_distinct_partial_state(self):
        state = RemoteState()
        state.fail_download = True
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(RemoteFrontError) as raised:
                self.run_install(state, Path(temp))

        self.assertEqual(raised.exception.stage, "artifact_download")
        self.assertEqual(raised.exception.remote_status, "succeeded")
        self.assertEqual(raised.exception.artifact_status, "not_saved")
        self.assertEqual(raised.exception.cleanup_status, "succeeded")

    def test_cleanup_failure_preserves_valid_local_client(self):
        state = RemoteState()
        state.fail_cleanup = True
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "result"
            with self.assertRaises(RemoteFrontError) as raised:
                self.run_install(state, Path(temp))
            self.assertEqual((output / "client.vless").read_bytes(), expected_client())

        self.assertEqual(raised.exception.stage, "cleanup")
        self.assertEqual(raised.exception.remote_status, "succeeded")
        self.assertEqual(raised.exception.artifact_status, "saved")
        self.assertEqual(raised.exception.cleanup_status, "failed")
        self.assertEqual(raised.exception.remote_temp, state.remote_temp)
        self.assertNotIn("vless://", str(raised.exception))

    def test_target_validation_happens_before_any_network_call(self):
        bad_target = RemoteFrontTarget(
            host="bad;host",
            user="root",
            host_key_sha256=BRIDGE_FINGERPRINT,
        )
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            installer, handoff_path, output = self.prepare_inputs(root)
            with patch("xhttp_setup.remote_front.pin_host_key") as pin:
                with self.assertRaises(ValidationError):
                    apply_remote_front(
                        installer_pyz=installer,
                        handoff_path=handoff_path,
                        desired=self.desired,
                        target=bad_target,
                        bridge_auth=self.bridge_auth,
                        sftp_password=SFTP_PASSWORD,
                        output_dir=output,
                        firewall_verified=True,
                    )
                pin.assert_not_called()


if __name__ == "__main__":
    unittest.main()
