import io
import os
import shutil
import socket
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError
from xhttp_setup.ssh_transport import (
    SFTPClient,
    SFTPTransportError,
    SSHAuth,
    SSHAuthenticationError,
    SSHRoute,
    TCPRoute,
    _password_askpass,
)


POSIX_FIFO = hasattr(os, "mkfifo") and hasattr(socket, "AF_UNIX")


@unittest.skipUnless(POSIX_FIFO, "requires POSIX FIFO and Unix sockets")
class PasswordAskpassTests(unittest.TestCase):
    def test_fifo_is_private_one_use_and_contains_no_regular_file_secret(self):
        secret = "p@ss '$() ; unicode-ёж"
        fifo_path: Path | None = None
        helper_path: Path | None = None
        with _password_askpass(secret) as env:
            fifo_path = Path(env["XHTTP_ASKPASS_FIFO"])
            helper_path = Path(env["SSH_ASKPASS"])
            fifo_meta = fifo_path.lstat()
            self.assertTrue(stat.S_ISFIFO(fifo_meta.st_mode))
            self.assertEqual(stat.S_IMODE(fifo_meta.st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(fifo_path.parent.stat().st_mode), 0o700)
            self.assertNotIn(secret, repr(env))
            self.assertNotIn(secret, helper_path.read_text("utf-8"))
            result = subprocess.run(
                [str(helper_path), "password:"],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
                timeout=5,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, secret + "\n")
        assert fifo_path is not None and helper_path is not None
        self.assertFalse(fifo_path.parent.exists())


class _FakeMaster:
    def __init__(
        self,
        control_path: Path,
        *,
        returncode: int | None = None,
        stderr: str | None = None,
        stoppable: bool = True,
    ):
        self.pid = 90001
        self.returncode = returncode
        self.stoppable = stoppable
        if stderr is None:
            stderr = (
                "operator@sftp.example.org: Permission denied (publickey,password).\n"
                if returncode
                else ""
            )
        self.stderr = io.StringIO(stderr)
        self._socket: socket.socket | None = None
        self.control_path = control_path
        if returncode is None:
            self._socket = socket.socket(socket.AF_UNIX)
            self._socket.bind(str(control_path))
            os.chmod(control_path, 0o600)

    def poll(self):
        return self.returncode

    def wait(self, timeout=None):
        if self.returncode is None:
            raise subprocess.TimeoutExpired("ssh", timeout)
        return self.returncode

    def stop(self):
        if not self.stoppable:
            return
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self.control_path.unlink(missing_ok=True)
        self.returncode = 0


@unittest.skipUnless(POSIX_FIFO, "requires POSIX FIFO and Unix sockets")
class SFTPPasswordMuxTests(unittest.TestCase):
    def _client(
        self, root: Path, secret: str, *, route: SSHRoute | None = None
    ) -> SFTPClient:
        known_hosts = root / "known_hosts"
        known_hosts.write_text("host ssh-ed25519 AAAA\n", encoding="utf-8")
        return SFTPClient(
            host="sftp.example.org",
            port=22,
            user="operator",
            known_hosts=known_hosts,
            auth=SSHAuth("password", password=secret),
            route=route,
        )

    def test_scoped_session_reuses_one_strict_routed_master(self):
        secret = "scoped p@ss '$() ; unicode-ёж"
        route = SSHRoute(
            scan=TCPRoute("127.0.0.1", 43123),
            proxy_command=(
                "ssh -F /dev/null -S /tmp/bridge-control -W %h:%p "
                "root@bridge.example.org"
            ),
        ).validate()
        captured: dict[str, object] = {"control_ops": [], "sftp_calls": []}
        master: _FakeMaster | None = None
        popen_count = 0

        def fake_popen(argv, **kwargs):
            nonlocal master, popen_count
            popen_count += 1
            captured["master_argv"] = argv
            captured["master_env"] = kwargs["env"]
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                captured["password"] = fifo.readline().rstrip("\n")
            control = Path(argv[argv.index("-S") + 1])
            captured["control_dir"] = control.parent
            master = _FakeMaster(control)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                captured["control_ops"].append(operation)
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "sftp":
                captured["sftp_calls"].append((argv, kwargs))
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    f"ok {secret}",
                    f"remote reflected {secret}",
                )
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret, route=route)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
            ):
                with client.session() as session:
                    captured["session_repr"] = repr(session)
                    first = session.batch(["pwd"])
                    second = session.batch(["ls -l"])

            with self.assertRaisesRegex(InstallerError, "session уже закрыта"):
                session.batch(["pwd"])

        self.assertEqual(popen_count, 1)
        self.assertEqual(captured["password"], secret)
        self.assertEqual(captured["control_ops"], ["check", "exit"])
        self.assertEqual(len(captured["sftp_calls"]), 2)
        self.assertEqual(first.stdout, "ok [REDACTED]")
        self.assertEqual(second.stderr, "remote reflected [REDACTED]")
        self.assertNotIn(secret, captured["session_repr"])
        self.assertNotIn(secret, repr(captured["master_argv"]))
        self.assertNotIn(secret, repr(captured["master_env"]))
        master_argv = captured["master_argv"]
        self.assertIn("StrictHostKeyChecking=yes", master_argv)
        self.assertIn(f"UserKnownHostsFile={client.known_hosts}", master_argv)
        self.assertIn(f"ProxyCommand={route.proxy_command}", master_argv)
        for sftp_argv, kwargs in captured["sftp_calls"]:
            self.assertIn("StrictHostKeyChecking=yes", sftp_argv)
            self.assertIn(f"UserKnownHostsFile={client.known_hosts}", sftp_argv)
            self.assertIn("ProxyCommand=/bin/false", sftp_argv)
            self.assertNotIn(f"ProxyCommand={route.proxy_command}", sftp_argv)
            self.assertIn("PasswordAuthentication=no", sftp_argv)
            self.assertNotIn(secret, repr(kwargs["env"]))
        self.assertFalse(captured["control_dir"].exists())

    def test_scoped_key_session_reuses_master_without_askpass_or_auth_fallback(self):
        captured: dict[str, object] = {"sftp_argv": []}
        master: _FakeMaster | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master
            self.assertNotIn("XHTTP_ASKPASS_FIFO", kwargs["env"])
            control = Path(argv[argv.index("-S") + 1])
            master = _FakeMaster(control)
            captured["master_argv"] = argv
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "sftp":
                captured["sftp_argv"].append(argv)
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "id_ed25519"
            key.write_text("test key material\n", encoding="utf-8")
            os.chmod(key, 0o600)
            known_hosts = root / "known_hosts"
            known_hosts.write_text("host ssh-ed25519 AAAA\n", encoding="utf-8")
            client = SFTPClient(
                host="sftp.example.org",
                port=22,
                user="operator",
                known_hosts=known_hosts,
                auth=SSHAuth("key", private_key=key),
            )
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
            ):
                with client.session() as session:
                    session.batch(["pwd"])
                    session.batch(["ls"])

        master_argv = captured["master_argv"]
        self.assertIn(str(key), master_argv)
        self.assertIn("PreferredAuthentications=publickey", master_argv)
        self.assertIn("PasswordAuthentication=no", master_argv)
        self.assertEqual(len(captured["sftp_argv"]), 2)
        for sftp_argv in captured["sftp_argv"]:
            self.assertIn("ProxyCommand=/bin/false", sftp_argv)
            self.assertIn("PasswordAuthentication=no", sftp_argv)

    def test_legacy_batch_opens_a_fresh_master_for_each_call(self):
        secret = "legacy-hidden"
        masters: dict[Path, _FakeMaster] = {}
        control_ops: list[tuple[Path, str]] = []
        sftp_calls = 0

        def fake_popen(argv, **kwargs):
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                self.assertEqual(fifo.readline(), secret + "\n")
            control = Path(argv[argv.index("-S") + 1])
            master = _FakeMaster(control)
            masters[control] = master
            return master

        def fake_run(argv, **kwargs):
            nonlocal sftp_calls
            if argv[0] == "ssh" and "-O" in argv:
                control = Path(argv[argv.index("-S") + 1])
                operation = argv[argv.index("-O") + 1]
                control_ops.append((control, operation))
                if operation == "exit":
                    masters[control].stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "sftp":
                sftp_calls += 1
                return subprocess.CompletedProcess(argv, 0, "ok", "")
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
            ):
                client.batch(["pwd"])
                client.batch(["ls"])

        self.assertEqual(len(masters), 2)
        self.assertEqual(sftp_calls, 2)
        self.assertEqual(
            [operation for _, operation in control_ops],
            [
                "check",
                "exit",
                "check",
                "exit",
            ],
        )

    def test_scoped_session_stops_master_after_batch_failure(self):
        secret = "failure-hidden"
        master: _FakeMaster | None = None
        control_dir: Path | None = None
        control_ops: list[str] = []

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                self.assertEqual(fifo.readline(), secret + "\n")
            control = Path(argv[argv.index("-S") + 1])
            control_dir = control.parent
            master = _FakeMaster(control)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                control_ops.append(operation)
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "sftp":
                return subprocess.CompletedProcess(
                    argv, 1, "", f"remote reflected {secret}"
                )
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                self.assertRaisesRegex(InstallerError, r"\[REDACTED\]"),
            ):
                with client.session() as session:
                    session.batch(["ls missing"])

        self.assertEqual(control_ops, ["check", "exit"])
        assert control_dir is not None
        self.assertFalse(control_dir.exists())

    def test_scoped_session_stops_master_after_keyboard_interrupt(self):
        secret = "interrupt-hidden"
        master: _FakeMaster | None = None
        control_dir: Path | None = None
        control_ops: list[str] = []

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                self.assertEqual(fifo.readline(), secret + "\n")
            control = Path(argv[argv.index("-S") + 1])
            control_dir = control.parent
            master = _FakeMaster(control)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                control_ops.append(operation)
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "sftp":
                raise KeyboardInterrupt()
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                self.assertRaises(KeyboardInterrupt),
            ):
                with client.session() as session:
                    session.batch(["ls"])

        self.assertEqual(control_ops, ["check", "exit"])
        assert control_dir is not None
        self.assertFalse(control_dir.exists())

    def test_stop_failure_does_not_mask_body_exception(self):
        secret = "body-failure-hidden"
        master: _FakeMaster | None = None
        control_dir: Path | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                self.assertEqual(fifo.readline(), secret + "\n")
            control = Path(argv[argv.index("-S") + 1])
            control_dir = control.parent
            master = _FakeMaster(control, stoppable=False)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

        try:
            with tempfile.TemporaryDirectory() as temp:
                client = self._client(Path(temp), secret)
                with (
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.Popen",
                        side_effect=fake_popen,
                    ),
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.run",
                        side_effect=fake_run,
                    ),
                    mock.patch("xhttp_setup.ssh_transport.os.killpg"),
                    self.assertRaisesRegex(RuntimeError, "body failure") as raised,
                ):
                    with client.session():
                        raise RuntimeError("body failure")

            self.assertEqual(
                raised.exception.__notes__,
                ["Дополнительно не завершён временный SFTP SSH master"],
            )
            self.assertNotIn(secret, repr(raised.exception.__notes__))
            assert control_dir is not None
            self.assertTrue(control_dir.exists())
            self.assertTrue((control_dir / "c").exists())
        finally:
            if master is not None:
                master.stoppable = True
                master.stop()
            if control_dir is not None:
                shutil.rmtree(control_dir, ignore_errors=True)

    def test_stop_failure_does_not_mask_body_keyboard_interrupt(self):
        secret = "body-interrupt-hidden"
        master: _FakeMaster | None = None
        control_dir: Path | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                self.assertEqual(fifo.readline(), secret + "\n")
            control = Path(argv[argv.index("-S") + 1])
            control_dir = control.parent
            master = _FakeMaster(control, stoppable=False)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

        try:
            with tempfile.TemporaryDirectory() as temp:
                client = self._client(Path(temp), secret)
                with (
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.Popen",
                        side_effect=fake_popen,
                    ),
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.run",
                        side_effect=fake_run,
                    ),
                    mock.patch("xhttp_setup.ssh_transport.os.killpg"),
                    self.assertRaises(KeyboardInterrupt) as raised,
                ):
                    with client.session():
                        raise KeyboardInterrupt()

            self.assertEqual(
                raised.exception.__notes__,
                ["Дополнительно не завершён временный SFTP SSH master"],
            )
            self.assertNotIn(secret, repr(raised.exception.__notes__))
            assert control_dir is not None
            self.assertTrue(control_dir.exists())
            self.assertTrue((control_dir / "c").exists())
        finally:
            if master is not None:
                master.stoppable = True
                master.stop()
            if control_dir is not None:
                shutil.rmtree(control_dir, ignore_errors=True)

    def test_teardown_keyboard_interrupt_propagates_and_retains_socket_dir(self):
        master: _FakeMaster | None = None
        control_dir: Path | None = None
        control_ops: list[str] = []

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            control = Path(argv[argv.index("-S") + 1])
            control_dir = control.parent
            master = _FakeMaster(control)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                control_ops.append(operation)
                if operation == "exit":
                    raise KeyboardInterrupt()
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

        try:
            with tempfile.TemporaryDirectory() as temp:
                client = self._client(Path(temp), "hidden")
                with (
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.Popen",
                        side_effect=fake_popen,
                    ),
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.run",
                        side_effect=fake_run,
                    ),
                    self.assertRaises(KeyboardInterrupt),
                ):
                    with client.session():
                        pass

            self.assertEqual(control_ops, ["check", "exit"])
            assert control_dir is not None
            self.assertTrue(control_dir.exists())
            self.assertTrue((control_dir / "c").exists())
        finally:
            if master is not None:
                master.stop()
            if control_dir is not None:
                shutil.rmtree(control_dir, ignore_errors=True)

    def test_unkillable_master_retains_private_socket_directory(self):
        master: _FakeMaster | None = None
        control_dir: Path | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            control = Path(argv[argv.index("-S") + 1])
            control_dir = control.parent
            master = _FakeMaster(control, stoppable=False)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

        try:
            with tempfile.TemporaryDirectory() as temp:
                client = self._client(Path(temp), "hidden")
                with (
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.Popen",
                        side_effect=fake_popen,
                    ),
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.run",
                        side_effect=fake_run,
                    ),
                    mock.patch("xhttp_setup.ssh_transport.os.killpg"),
                    self.assertRaisesRegex(
                        InstallerError, "Не удалось завершить временный SSH master"
                    ),
                ):
                    with client.session():
                        pass

            assert control_dir is not None
            self.assertTrue(control_dir.exists())
            self.assertTrue((control_dir / "c").exists())
        finally:
            if master is not None:
                master.stoppable = True
                master.stop()
            if control_dir is not None:
                shutil.rmtree(control_dir, ignore_errors=True)

    def test_batch_uses_authenticated_mux_without_password_fallback(self):
        secret = "batch p@ss '$() ; unicode-ёж"
        captured: dict[str, object] = {"control_ops": []}
        master: _FakeMaster | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master
            captured["master_argv"] = argv
            captured["master_env"] = kwargs["env"]
            self.assertNotIn(secret, repr(argv))
            self.assertNotIn(secret, repr(kwargs["env"]))
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                captured["password"] = fifo.readline().rstrip("\n")
            control = Path(argv[argv.index("-S") + 1])
            captured["control_dir"] = control.parent
            master = _FakeMaster(control)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                captured["control_ops"].append(operation)
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "sftp":
                captured["sftp_argv"] = argv
                captured["sftp_env"] = kwargs["env"]
                captured["batch_text"] = kwargs["input"]
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    f"ok {secret}",
                    f"remote reflected {secret}",
                )
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
            ):
                result = client.batch(["ls -l", "get file local"], check=True)

        self.assertEqual(result.stdout, "ok [REDACTED]")
        self.assertEqual(result.stderr, "remote reflected [REDACTED]")
        self.assertEqual(captured["password"], secret)
        self.assertEqual(captured["batch_text"], "ls -l\nget file local\n")
        self.assertEqual(captured["control_ops"], ["check", "exit"])
        sftp_argv = captured["sftp_argv"]
        self.assertIn("-b", sftp_argv)
        self.assertIn("ControlMaster=no", sftp_argv)
        self.assertIn("BatchMode=yes", sftp_argv)
        self.assertIn("ProxyCommand=/bin/false", sftp_argv)
        self.assertIn("PasswordAuthentication=no", sftp_argv)
        self.assertNotIn(secret, repr(sftp_argv))
        self.assertNotIn(secret, repr(captured["sftp_env"]))
        self.assertFalse(captured["control_dir"].exists())

    def test_master_auth_failure_does_not_start_sftp(self):
        secret = "wrong-but-hidden"
        calls: list[list[str]] = []

        def fake_popen(argv, **kwargs):
            control = Path(argv[argv.index("-S") + 1])
            return _FakeMaster(control, returncode=255)

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "not ready")

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                self.assertRaisesRegex(
                    SSHAuthenticationError, "аутентификация не удалась"
                ),
            ):
                client.batch(["ls"], check=False)

        self.assertFalse(any(argv and argv[0] == "sftp" for argv in calls))

    def test_master_route_timeout_is_transport_error_not_authentication(self):
        secret = "not-the-problem"
        calls: list[list[str]] = []

        def fake_popen(argv, **kwargs):
            control = Path(argv[argv.index("-S") + 1])
            return _FakeMaster(
                control,
                returncode=255,
                stderr=(
                    "channel 2: open failed: connect failed: Connection timed out\n"
                    "Connection to UNKNOWN port 65535 timed out\n"
                ),
            )

        def fake_run(argv, **kwargs):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "not ready")

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                self.assertRaisesRegex(
                    InstallerError,
                    "SSH-транспорт.*connect failed.*UNKNOWN port 65535",
                ) as raised,
            ):
                client.batch(["ls"], check=False)

        self.assertNotIsInstance(raised.exception, SSHAuthenticationError)
        self.assertNotIn(secret, str(raised.exception))
        self.assertFalse(any(argv and argv[0] == "sftp" for argv in calls))

    def test_local_permission_error_is_not_misclassified_as_bad_password(self):
        secret = "still-not-the-problem"

        def fake_popen(argv, **kwargs):
            control = Path(argv[argv.index("-S") + 1])
            return _FakeMaster(
                control,
                returncode=255,
                stderr="Control socket connect(/tmp/mux): Permission denied\n",
            )

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                self.assertRaisesRegex(
                    InstallerError, "SSH-транспорт.*Permission denied"
                ) as raised,
            ):
                client.batch(["ls"], check=False)

        self.assertNotIsInstance(raised.exception, SSHAuthenticationError)
        self.assertNotIn(secret, str(raised.exception))

    def test_batch_nonzero_is_returned_or_raised_without_losing_cleanup(self):
        secret = "hidden"

        for check in (False, True):
            with self.subTest(check=check), tempfile.TemporaryDirectory() as temp:
                master: _FakeMaster | None = None

                def fake_popen(argv, **kwargs):
                    nonlocal master
                    with open(
                        kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8"
                    ) as fifo:
                        self.assertEqual(fifo.readline(), secret + "\n")
                    control = Path(argv[argv.index("-S") + 1])
                    master = _FakeMaster(control)
                    return master

                def fake_run(argv, **kwargs):
                    if argv[0] == "ssh" and "-O" in argv:
                        operation = argv[argv.index("-O") + 1]
                        if operation == "exit":
                            assert master is not None
                            master.stop()
                        return subprocess.CompletedProcess(argv, 0, "", "")
                    if argv[0] == "sftp":
                        return subprocess.CompletedProcess(
                            argv, 1, "", "remote command failed"
                        )
                    raise AssertionError(argv)

                client = self._client(Path(temp), secret)
                with (
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.Popen",
                        side_effect=fake_popen,
                    ),
                    mock.patch(
                        "xhttp_setup.ssh_transport.subprocess.run",
                        side_effect=fake_run,
                    ),
                ):
                    if check:
                        with self.assertRaisesRegex(
                            InstallerError, "remote command failed"
                        ):
                            client.batch(["ls missing"], check=True)
                    else:
                        result = client.batch(["ls missing"], check=False)
                        self.assertEqual(result.returncode, 1)

    def test_mux_returncode_255_is_typed_transport_failure_even_without_check(self):
        secret = "hidden"
        master: _FakeMaster | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                self.assertEqual(fifo.readline(), secret + "\n")
            control = Path(argv[argv.index("-S") + 1])
            master = _FakeMaster(control)
            return master

        def fake_run(argv, **kwargs):
            if argv[0] == "ssh" and "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if argv[0] == "sftp":
                return subprocess.CompletedProcess(
                    argv, 255, "", "Control socket connect failed"
                )
            raise AssertionError(argv)

        with tempfile.TemporaryDirectory() as temp:
            client = self._client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                self.assertRaisesRegex(
                    SFTPTransportError, "SSH-транспорт оборвался"
                ),
            ):
                client.batch(["ls"], check=False)


if __name__ == "__main__":
    unittest.main()
