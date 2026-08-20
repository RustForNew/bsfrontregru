from __future__ import annotations

import contextlib
import io
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError
from xhttp_setup.ssh_transport import (
    SFTPClient,
    SSHAuth,
    SSHBridgeSession,
    SSHRoute,
    TCPRoute,
    trust_host_key_tofu,
)


BRIDGE_PASSWORD = "bridge-password-only-for-test-83"
SFTP_PASSWORD = "sftp-password-only-for-test-29"
FINGERPRINT = "SHA256:" + ("B" * 43)
ED25519 = "AAAAZWQyNTUxOQ=="


def completed(argv, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class FakeMaster:
    def __init__(self, *, returncode=None, stderr=""):
        self.returncode = returncode
        self.stderr = io.StringIO(stderr)
        self.pid = 4242
        self.wait_calls = []
        self.terminate_calls = 0
        self.kill_calls = 0

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        self.wait_calls.append(timeout)
        self.returncode = 0
        return 0

    def terminate(self):
        self.terminate_calls += 1
        self.returncode = 0

    def kill(self):
        self.kill_calls += 1
        self.returncode = 0


class UnkillableMaster(FakeMaster):
    def __init__(self):
        super().__init__()
        self.unkillable = True

    def wait(self, timeout=None):
        if self.unkillable:
            self.wait_calls.append(timeout)
            raise subprocess.TimeoutExpired(["ssh"], timeout)
        return super().wait(timeout=timeout)

    def terminate(self):
        self.terminate_calls += 1

    def kill(self):
        self.kill_calls += 1


class SSHBridgeTests(unittest.TestCase):
    def test_bridge_routes_are_loopback_only(self):
        with self.assertRaisesRegex(InstallerError, "loopback-only"):
            TCPRoute("198.51.100.40", 443).validate()

    def _session(self, root: Path) -> SSHBridgeSession:
        known_hosts = root / "bridge.known_hosts"
        known_hosts.write_text(
            f"bridge.example.org ssh-ed25519 {ED25519}\n", encoding="utf-8"
        )
        return SSHBridgeSession(
            host="bridge.example.org",
            port=22,
            user="root",
            known_hosts=known_hosts,
            auth=SSHAuth("password", password=BRIDGE_PASSWORD),
            forwards={
                "front": ("192.0.2.30", 443),
                "panel": ("vip999.hosting.reg.ru", 1500),
                "sftp": ("vip999.hosting.reg.ru", 22),
            },
        )

    @contextlib.contextmanager
    def _askpass(self, password):
        self.assertEqual(password, BRIDGE_PASSWORD)
        yield {
            "SSH_ASKPASS": "/private/fifo-helper",
            "SSH_ASKPASS_REQUIRE": "force",
        }

    def test_routed_tofu_scans_loopback_but_pins_logical_endpoint(self):
        logical_host = "vip999.hosting.reg.ru"
        loopback_port = 43122
        route = SSHRoute(
            scan=TCPRoute("127.0.0.1", loopback_port),
            proxy_command="ssh -S /tmp/control -W %h:%p root@bridge.example.org",
        ).validate()
        calls = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            if argv[0] == "ssh-keyscan":
                self.assertEqual(argv[argv.index("-p") + 1], str(loopback_port))
                self.assertEqual(argv[-1], "127.0.0.1")
                return completed(
                    argv,
                    stdout=(
                        f"[127.0.0.1]:{loopback_port} "
                        f"ssh-ed25519 {ED25519}\n"
                    ),
                )
            if argv[0] == "ssh-keygen":
                return completed(
                    argv, stdout=f"256 {FINGERPRINT} endpoint (ED25519)\n"
                )
            self.fail(f"unexpected command: {argv!r}")

        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "trust"
            with mock.patch("xhttp_setup.ssh_transport.run", side_effect=fake_run):
                known_hosts, fingerprint = trust_host_key_tofu(
                    host=logical_host,
                    port=22,
                    trust_dir=trust_dir,
                    route=route,
                )
            content = known_hosts.read_text("utf-8")

        self.assertEqual(fingerprint, FINGERPRINT)
        self.assertEqual(content, f"{logical_host} ssh-ed25519 {ED25519}\n")
        self.assertNotIn("127.0.0.1", content)
        self.assertEqual([call[0] for call in calls], ["ssh-keyscan", "ssh-keygen"])

    def test_routed_password_sftp_uses_proxy_without_any_password(self):
        bridge_route = SSHRoute(
            scan=TCPRoute("127.0.0.1", 43123),
            proxy_command=(
                "ssh -F /dev/null -S /tmp/bridge-control -W %h:%p "
                "root@bridge.example.org"
            ),
        ).validate()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            known_hosts = root / "logical.known_hosts"
            known_hosts.write_text(
                f"vip999.hosting.reg.ru ssh-ed25519 {ED25519}\n",
                encoding="utf-8",
            )
            client = SFTPClient(
                host="vip999.hosting.reg.ru",
                port=22,
                user="u1234567",
                known_hosts=known_hosts,
                auth=SSHAuth("password", password=SFTP_PASSWORD),
                route=bridge_route,
            )
            argv = client._master_argv(root / "target-control")

        rendered = repr(argv)
        self.assertIn(f"UserKnownHostsFile={known_hosts}", argv)
        self.assertIn(
            f"ProxyCommand={bridge_route.proxy_command}",
            argv,
        )
        self.assertEqual(argv[-1], "u1234567@vip999.hosting.reg.ru")
        for secret in (BRIDGE_PASSWORD, SFTP_PASSWORD):
            self.assertNotIn(secret, rendered)
            self.assertNotIn(secret, bridge_route.proxy_command)
            self.assertNotIn(secret, repr(bridge_route))

    def test_open_checks_root_builds_password_free_routes_and_close_cleans_up(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            session = self._session(root)
            master = FakeMaster()
            popen_calls = []
            run_calls = []

            def fake_popen(argv, **kwargs):
                popen_calls.append((argv, kwargs))
                return master

            def fake_run(argv, **kwargs):
                run_calls.append((argv, kwargs))
                if argv[-1] == "id -u":
                    return completed(argv, stdout="0\n")
                if "-O" in argv and argv[argv.index("-O") + 1] == "exit":
                    return completed(argv)
                self.fail(f"unexpected subprocess.run: {argv!r}")

            with (
                mock.patch(
                    "xhttp_setup.ssh_transport._password_askpass",
                    side_effect=self._askpass,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport._free_loopback_port",
                    side_effect=(43124, 43125, 43126),
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                mock.patch.object(SSHBridgeSession, "_wait_for_master"),
            ):
                opened = session.open()
                temporary_path = session._temporary
                self.assertIsNotNone(temporary_path)
                route = session.ssh_route("sftp")
                self.assertIs(opened, session)
                self.assertEqual(session.tcp_route("panel").connect_host, "127.0.0.1")
                self.assertIn("-W %h:%p", route.proxy_command)
                self.assertIn("root@bridge.example.org", route.proxy_command)
                self.assertNotIn(BRIDGE_PASSWORD, route.proxy_command)
                self.assertNotIn(BRIDGE_PASSWORD, repr(route))
                self.assertNotIn(BRIDGE_PASSWORD, repr(session))
                session.close()

            self.assertFalse(temporary_path.exists())
            self.assertIsNone(session._master)
            self.assertIsNone(session._control_path)
            self.assertEqual(session._routes, {})
            with self.assertRaisesRegex(InstallerError, "больше не работает"):
                session.tcp_route("panel")

        master_argv, master_kwargs = popen_calls[0]
        self.assertEqual(len(popen_calls), 1)
        self.assertEqual(master_kwargs["stdin"], subprocess.DEVNULL)
        self.assertTrue(master_kwargs["start_new_session"])
        self.assertTrue(any(argument.startswith("127.0.0.1:") for argument in master_argv))
        self.assertNotIn("ClearAllForwardings=yes", master_argv)
        self.assertIn("ProxyCommand=/bin/false", route.proxy_command)
        self.assertTrue(any(call[0][-1] == "id -u" for call in run_calls))
        self.assertTrue(any("-O" in call[0] for call in run_calls))
        for secret in (BRIDGE_PASSWORD, SFTP_PASSWORD):
            self.assertNotIn(secret, repr(master_argv))
            self.assertNotIn(secret, repr(master_kwargs["env"]))

    def test_non_root_bridge_fails_and_cleans_exact_temporary_state(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            master = FakeMaster()
            temporary_paths = []

            def fake_run(argv, **_kwargs):
                if argv[-1] == "id -u":
                    temporary_paths.append(session._temporary)
                    return completed(argv, stdout="1000\n")
                if "-O" in argv:
                    return completed(argv)
                self.fail(f"unexpected subprocess.run: {argv!r}")

            with (
                mock.patch(
                    "xhttp_setup.ssh_transport._password_askpass",
                    side_effect=self._askpass,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport._free_loopback_port",
                    side_effect=(43127, 43128, 43129),
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen", return_value=master
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                mock.patch.object(SSHBridgeSession, "_wait_for_master"),
                self.assertRaisesRegex(InstallerError, "UID 0") as raised,
            ):
                session.open()

            self.assertIsNone(session._master)
            self.assertIsNone(session._control_path)
            self.assertEqual(session._routes, {})
            self.assertEqual(len(temporary_paths), 1)
            self.assertFalse(temporary_paths[0].exists())
            self.assertTrue(master.stderr.closed)
            self.assertNotIn(BRIDGE_PASSWORD, str(raised.exception))

    def test_start_failure_redacts_bridge_password_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            master = FakeMaster(
                returncode=255,
                stderr=f"ssh failed while handling {BRIDGE_PASSWORD}\n",
            )
            captured_temp = []

            def fake_popen(*_args, **_kwargs):
                captured_temp.append(session._temporary)
                return master

            with (
                mock.patch(
                    "xhttp_setup.ssh_transport._password_askpass",
                    side_effect=self._askpass,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport._free_loopback_port",
                    side_effect=(43130, 43131, 43132),
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                self.assertRaises(InstallerError) as raised,
            ):
                session.open()

            self.assertNotIn(BRIDGE_PASSWORD, str(raised.exception))
            self.assertIn("[REDACTED]", str(raised.exception))
            self.assertEqual(len(captured_temp), 1)
            self.assertFalse(captured_temp[0].exists())
            self.assertIsNone(session._master)
            self.assertIsNone(session._control_path)
            self.assertTrue(master.stderr.closed)

    def test_route_setup_failure_cleans_private_bridge_directory(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            captured_temp = []
            real_mkdtemp = tempfile.mkdtemp

            def make_temp(*args, **kwargs):
                path = Path(real_mkdtemp(*args, **kwargs))
                captured_temp.append(path)
                return str(path)

            body_error = KeyboardInterrupt("route allocation interrupted")
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.tempfile.mkdtemp",
                    side_effect=make_temp,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport._free_loopback_port",
                    side_effect=body_error,
                ),
                self.assertRaises(KeyboardInterrupt) as raised,
            ):
                session.open()

            self.assertIs(raised.exception, body_error)
            self.assertEqual(len(captured_temp), 1)
            self.assertFalse(captured_temp[0].exists())
            self.assertIsNone(session._temporary)
            self.assertIsNone(session._control_path)
            self.assertIsNone(session._master)

    def test_unkillable_bridge_preserves_control_state_for_retry(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            bridge_temp = Path(tempfile.mkdtemp(prefix=".bridge-close-test-"))
            control_path = bridge_temp / "c"
            control_path.touch()
            master = UnkillableMaster()
            session._temporary = bridge_temp
            session._control_path = control_path
            session._master = master
            session._routes = {"front": TCPRoute("127.0.0.1", 43140)}

            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run",
                    return_value=completed([]),
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.os.killpg",
                    side_effect=ProcessLookupError,
                    create=True,
                ),
                self.assertRaisesRegex(InstallerError, "master"),
            ):
                session.close()

            self.assertTrue(bridge_temp.exists())
            self.assertIs(session._temporary, bridge_temp)
            self.assertIs(session._control_path, control_path)
            self.assertIs(session._master, master)
            self.assertEqual(session._routes, {})

            master.unkillable = False
            with mock.patch(
                "xhttp_setup.ssh_transport.subprocess.run",
                return_value=completed([]),
            ):
                session.close()
            self.assertFalse(bridge_temp.exists())

    def test_bridge_teardown_keyboard_interrupt_propagates_and_preserves_state(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            bridge_temp = Path(tempfile.mkdtemp(prefix=".bridge-interrupt-test-"))
            control_path = bridge_temp / "c"
            control_path.touch()
            master = FakeMaster()
            session._temporary = bridge_temp
            session._control_path = control_path
            session._master = master

            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run",
                    side_effect=KeyboardInterrupt(),
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                session.close()

            self.assertTrue(bridge_temp.exists())
            self.assertIs(session._temporary, bridge_temp)
            self.assertIs(session._control_path, control_path)
            self.assertIs(session._master, master)

            with mock.patch(
                "xhttp_setup.ssh_transport.subprocess.run",
                return_value=completed([]),
            ):
                session.close()
            self.assertFalse(bridge_temp.exists())

    def test_bridge_context_body_error_remains_primary_with_safe_note(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            body_error = InstallerError("primary bridge body failure")
            cleanup_secret = "cleanup-must-not-leak"

            with (
                mock.patch.object(session, "open", return_value=session),
                mock.patch.object(
                    session,
                    "close",
                    side_effect=InstallerError(cleanup_secret),
                ),
                self.assertRaises(InstallerError) as raised,
            ):
                with session:
                    raise body_error

            self.assertIs(raised.exception, body_error)
            self.assertIn("teardown SSH-моста", repr(body_error.__notes__))
            self.assertNotIn(cleanup_secret, repr(body_error.__notes__))

    def test_bridge_open_error_remains_primary_when_cleanup_fails(self):
        with tempfile.TemporaryDirectory() as temp:
            session = self._session(Path(temp))
            master = FakeMaster()
            body_error = InstallerError("primary bridge open failure")
            cleanup_secret = "open-cleanup-must-not-leak"

            with (
                mock.patch(
                    "xhttp_setup.ssh_transport._password_askpass",
                    side_effect=self._askpass,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport._free_loopback_port",
                    side_effect=(43141, 43142, 43143),
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    return_value=master,
                ),
                mock.patch.object(
                    SSHBridgeSession,
                    "_wait_for_master",
                    side_effect=body_error,
                ),
                mock.patch.object(
                    session,
                    "close",
                    side_effect=InstallerError(cleanup_secret),
                ),
                self.assertRaises(InstallerError) as raised,
            ):
                session.open()

            self.assertIs(raised.exception, body_error)
            self.assertIn("teardown SSH-моста", repr(body_error.__notes__))
            self.assertNotIn(cleanup_secret, repr(body_error.__notes__))
            bridge_temp = session._temporary
            self.assertIsNotNone(bridge_temp)
            master.returncode = 0
            with mock.patch(
                "xhttp_setup.ssh_transport.subprocess.run",
                return_value=completed([]),
            ):
                session.close()
            self.assertFalse(bridge_temp.exists())


if __name__ == "__main__":
    unittest.main()
