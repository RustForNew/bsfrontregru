import io
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError
from xhttp_setup.ssh_transport import (
    SSHAuth,
    SSHAuthenticationError,
    SSHClient,
    SSHTransportError,
)


POSIX_MUX = hasattr(os, "mkfifo") and hasattr(socket, "AF_UNIX")


class _FakeMaster:
    def __init__(
        self,
        control_path: Path,
        *,
        returncode: int | None = None,
        stderr: str = "",
        stoppable: bool = True,
    ) -> None:
        self.pid = 90002
        self.returncode = returncode
        self.stderr = io.StringIO(stderr)
        self.control_path = control_path
        self.stoppable = stoppable
        self._socket: socket.socket | None = None
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

    def stop(self) -> None:
        if not self.stoppable:
            return
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self.control_path.unlink(missing_ok=True)
        self.returncode = 0


class SSHClientTests(unittest.TestCase):
    def test_password_askpass_rejects_multiline_and_unbounded_values(self):
        for value in ("line-one\nline-two", "x" * 4097):
            with (
                self.subTest(value_length=len(value)),
                self.assertRaises(InstallerError),
            ):
                SSHAuth("password", password=value).validate()

    def test_key_command_is_one_shell_quoted_remote_argument(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "id_ed25519"
            key.write_text("test key", encoding="utf-8")
            known_hosts = root / "known_hosts"
            known_hosts.write_text("host ssh-ed25519 AAAA\n", encoding="utf-8")
            client = SSHClient(
                host="exit.example.org",
                port=2222,
                user="root",
                known_hosts=known_hosts,
                auth=SSHAuth("key", private_key=str(key)),
            )
            completed = subprocess.CompletedProcess(["ssh"], 0, "ok", "")
            with mock.patch(
                "xhttp_setup.ssh_transport.subprocess.run", return_value=completed
            ) as runner:
                result = client.command(["printf", "%s", "a b;$(id)"])

        self.assertEqual(result.stdout, "ok")
        argv = runner.call_args.args[0]
        self.assertEqual(argv[-2], "root@exit.example.org")
        self.assertEqual(argv[-1], "printf %s 'a b;$(id)'")
        self.assertNotIn("input_text", runner.call_args.kwargs)

    def test_remote_command_rejects_control_characters(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "key"
            key.write_text("test", encoding="utf-8")
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("key", private_key=str(key)),
            )
            with self.assertRaises(InstallerError):
                client.command(["printf", "unsafe\ncommand"])

    def test_command_input_rejects_nul_multiline_and_oversized_values(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "key"
            key.write_text("test", encoding="utf-8")
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("key", private_key=str(key)),
            )
            for value in (
                "secret\x00value",
                "secret\r\n",
                "line-one\nline-two",
                "x" * 4097,
                "я" * 2049,
            ):
                with (
                    self.subTest(value_length=len(value)),
                    self.assertRaises(InstallerError),
                ):
                    client.command(["true"], input_text=value)

    def test_key_command_passes_secret_only_as_input_and_redacts_error(self):
        secret_line = "remote sudo secret"
        input_text = secret_line + "\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "key"
            key.write_text("test", encoding="utf-8")
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("key", private_key=str(key)),
            )
            completed = subprocess.CompletedProcess(
                ["ssh"], 1, "", f"sudo rejected {secret_line}"
            )
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run",
                    return_value=completed,
                ) as runner,
                self.assertRaises(InstallerError) as raised,
            ):
                client.command(["sudo", "-S", "--", "true"], input_text=input_text)

        argv = runner.call_args.args[0]
        kwargs = runner.call_args.kwargs
        self.assertEqual(kwargs["input"], input_text)
        self.assertFalse(kwargs["check"])
        self.assertNotIn(secret_line, repr(kwargs["env"]))
        self.assertNotIn(secret_line, repr(argv))
        self.assertNotIn(secret_line, str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_password_is_not_placed_in_argv_or_environment(self):
        secret = "correct horse battery staple"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("password", password=secret),
            )
            captured = {}

            def fake_run(argv, **kwargs):
                captured["argv"] = argv
                captured["env"] = kwargs["env"]
                captured["kwargs"] = kwargs
                return subprocess.CompletedProcess(
                    argv,
                    0,
                    f"ok {secret}",
                    f"remote reflected {secret}",
                )

            with mock.patch(
                "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
            ):
                result = client.command(["true"])

        self.assertNotIn(secret, repr(captured["argv"]))
        self.assertNotIn(secret, repr(captured["env"]))
        self.assertNotIn("input", captured["kwargs"])
        self.assertEqual(captured["kwargs"]["stdin"], subprocess.DEVNULL)
        self.assertEqual(result.stdout, "ok [REDACTED]")
        self.assertEqual(result.stderr, "remote reflected [REDACTED]")

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_password_command_uses_separate_stdin_and_redacts_error(self):
        bridge_secret = "bridge SSH password"
        secret_line = "remote sudo password"
        input_text = secret_line + "\n"
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("password", password=bridge_secret),
            )
            captured = {}

            def fake_run(argv, **kwargs):
                captured["argv"] = argv
                captured["kwargs"] = kwargs
                return subprocess.CompletedProcess(
                    argv, 1, "", f"sudo rejected {secret_line}"
                )

            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
                ),
                self.assertRaises(InstallerError) as raised,
            ):
                client.command(["sudo", "-S", "--", "true"], input_text=input_text)

        kwargs = captured["kwargs"]
        self.assertEqual(kwargs["input"], input_text)
        self.assertNotIn("stdin", kwargs)
        self.assertNotIn(secret_line, repr(captured["argv"]))
        self.assertNotIn(secret_line, repr(kwargs["env"]))
        self.assertNotIn(bridge_secret, repr(captured["argv"]))
        self.assertNotIn(bridge_secret, repr(kwargs["env"]))
        self.assertNotIn(secret_line, str(raised.exception))
        self.assertNotIn(bridge_secret, str(raised.exception))
        self.assertIn("[REDACTED]", str(raised.exception))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_password_permission_denied_is_a_typed_auth_failure_even_without_check(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("password", password="wrong-secret"),
            )
            failure = subprocess.CompletedProcess(
                ["ssh"],
                255,
                "",
                "root@exit.example.org: Permission denied (publickey,password).\n",
            )
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", return_value=failure
                ),
                self.assertRaises(SSHAuthenticationError),
            ):
                client.command(["id", "-u"], check=False)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX FIFO")
    def test_host_key_mismatch_is_not_misclassified_as_password_failure(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("password", password="correct-secret"),
            )
            failure = subprocess.CompletedProcess(
                ["ssh"],
                255,
                "",
                "Host key verification failed.\n",
            )
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run", return_value=failure
                ),
                self.assertRaises(InstallerError) as raised,
            ):
                client.command(["id", "-u"])

        self.assertNotIsInstance(raised.exception, SSHAuthenticationError)
        self.assertIn("Host key verification failed", str(raised.exception))


@unittest.skipUnless(POSIX_MUX, "requires POSIX FIFO and Unix sockets")
class SSHScopedSessionTests(unittest.TestCase):
    def _password_client(self, root: Path, secret: str) -> SSHClient:
        known_hosts = root / "known_hosts"
        known_hosts.write_text("host ssh-ed25519 AAAA\n", encoding="utf-8")
        return SSHClient(
            host="exit.example.org",
            port=2222,
            user="root",
            known_hosts=known_hosts,
            auth=SSHAuth("password", password=secret),
        )

    def test_session_reuses_one_master_and_fresh_command_bypasses_it(self):
        secret = "scoped p@ss '$() ; unicode-ёж"
        captured: dict[str, object] = {
            "control_ops": [],
            "mux_calls": [],
            "fresh_calls": [],
        }
        master: _FakeMaster | None = None
        popen_count = 0

        def fake_popen(argv, **kwargs):
            nonlocal master, popen_count
            popen_count += 1
            captured["master_argv"] = argv
            captured["master_env"] = kwargs["env"]
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                captured["master_password"] = fifo.readline().rstrip("\n")
            control_path = Path(argv[argv.index("-S") + 1])
            captured["control_dir"] = control_path.parent
            master = _FakeMaster(control_path)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                captured["control_ops"].append(operation)
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            if any(value.startswith("ControlPath=") for value in argv):
                captured["mux_calls"].append((argv, kwargs))
                return subprocess.CompletedProcess(
                    argv, 0, f"ok {secret}", f"notice {secret}"
                )
            captured["fresh_calls"].append((argv, kwargs))
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                captured["fresh_password"] = fifo.readline().rstrip("\n")
            return subprocess.CompletedProcess(argv, 0, "fresh", "")

        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), secret)
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
                with client.session() as session:
                    captured["session_repr"] = repr(session)
                    first = session.command(["printf", "first"])
                    fresh = session.fresh_command(["printf", "fresh"])
                    second = session.command(["printf", "second"])

                with self.assertRaisesRegex(InstallerError, "session уже закрыта"):
                    session.command(["true"])
                with self.assertRaisesRegex(InstallerError, "session уже закрыта"):
                    session.fresh_command(["true"])

        self.assertEqual(popen_count, 1)
        self.assertEqual(captured["master_password"], secret)
        self.assertEqual(captured["fresh_password"], secret)
        self.assertEqual(captured["control_ops"], ["check", "exit"])
        self.assertEqual(len(captured["mux_calls"]), 2)
        self.assertEqual(len(captured["fresh_calls"]), 1)
        self.assertEqual(first.stdout, "ok [REDACTED]")
        self.assertEqual(second.stderr, "notice [REDACTED]")
        self.assertEqual(fresh.stdout, "fresh")
        self.assertNotIn(secret, captured["session_repr"])
        self.assertNotIn(secret, repr(captured["master_argv"]))
        self.assertNotIn(secret, repr(captured["master_env"]))
        self.assertIn("StrictHostKeyChecking=yes", captured["master_argv"])
        self.assertIn("ControlPersist=no", captured["master_argv"])

        for argv, kwargs in captured["mux_calls"]:
            self.assertTrue(any(value.startswith("ControlPath=") for value in argv))
            self.assertIn("ControlMaster=no", argv)
            self.assertIn("ProxyCommand=/bin/false", argv)
            self.assertIn("PasswordAuthentication=no", argv)
            self.assertIn("PubkeyAuthentication=no", argv)
            self.assertIn("KbdInteractiveAuthentication=no", argv)
            self.assertIn("HostbasedAuthentication=no", argv)
            self.assertIn("GSSAPIAuthentication=no", argv)
            self.assertIn("IdentityAgent=none", argv)
            self.assertNotIn("XHTTP_ASKPASS_FIFO", kwargs["env"])

        fresh_argv, _ = captured["fresh_calls"][0]
        self.assertFalse(
            any(value.startswith("ControlPath=") for value in fresh_argv)
        )
        self.assertNotIn("ProxyCommand=/bin/false", fresh_argv)
        self.assertFalse(captured["control_dir"].exists())

    def test_master_wrong_password_is_typed_and_never_runs_command(self):
        secret = "wrong-hidden"
        popen_count = 0
        command_calls: list[list[str]] = []

        def fake_popen(argv, **kwargs):
            nonlocal popen_count
            popen_count += 1
            with open(kwargs["env"]["XHTTP_ASKPASS_FIFO"], encoding="utf-8") as fifo:
                self.assertEqual(fifo.readline(), secret + "\n")
            control_path = Path(argv[argv.index("-S") + 1])
            return _FakeMaster(
                control_path,
                returncode=255,
                stderr=(
                    "root@exit.example.org: Permission denied "
                    "(publickey,password).\n"
                ),
            )

        def fake_run(argv, **kwargs):
            command_calls.append(argv)
            return subprocess.CompletedProcess(argv, 1, "", "not ready")

        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), secret)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.Popen",
                    side_effect=fake_popen,
                ),
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run",
                    side_effect=fake_run,
                ),
                self.assertRaisesRegex(
                    SSHAuthenticationError, "аутентификация не удалась"
                ),
            ):
                with client.session():
                    self.fail("unreachable")

        self.assertEqual(popen_count, 1)
        self.assertEqual(command_calls, [])

    def test_dead_mux_is_typed_and_never_reopens_or_falls_back(self):
        secret = "hidden"
        master: _FakeMaster | None = None
        popen_count = 0
        mux_calls: list[list[str]] = []

        def fake_popen(argv, **kwargs):
            nonlocal master, popen_count
            popen_count += 1
            control_path = Path(argv[argv.index("-S") + 1])
            master = _FakeMaster(control_path)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            mux_calls.append(argv)
            return subprocess.CompletedProcess(
                argv,
                255,
                "",
                "Control socket connect failed: Connection refused\n",
            )

        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), secret)
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
                with client.session() as session:
                    with self.assertRaisesRegex(
                        SSHTransportError,
                        "SSH-транспорт оборвался.*Connection refused",
                    ):
                        session.command(["printf", "first"], check=False)
                    with self.assertRaisesRegex(
                        SSHTransportError, "автоматический повтор запрещён"
                    ):
                        session.command(["printf", "second"], check=False)

        self.assertEqual(popen_count, 1)
        self.assertEqual(len(mux_calls), 1)
        for argv in mux_calls:
            self.assertIn("ProxyCommand=/bin/false", argv)
            self.assertIn("PasswordAuthentication=no", argv)
            self.assertIn("PubkeyAuthentication=no", argv)

    def test_concurrent_commands_are_not_serialized(self):
        secret = "hidden"
        master: _FakeMaster | None = None
        rendezvous = threading.Barrier(3)

        def fake_popen(argv, **kwargs):
            nonlocal master
            control_path = Path(argv[argv.index("-S") + 1])
            master = _FakeMaster(control_path)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            rendezvous.wait(timeout=3)
            return subprocess.CompletedProcess(argv, 0, argv[-1], "")

        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), secret)
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
                with client.session() as session, ThreadPoolExecutor(
                    max_workers=2
                ) as executor:
                    first = executor.submit(session.command, ["printf", "first"])
                    second = executor.submit(session.command, ["printf", "second"])
                    rendezvous.wait(timeout=3)
                    outputs = {first.result().stdout, second.result().stdout}

        self.assertEqual(outputs, {"printf first", "printf second"})

    def test_timeout_is_typed_and_redacts_password_and_input(self):
        password = "master-password-secret"
        input_text = "remote-input-secret\n"
        master: _FakeMaster | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master
            control_path = Path(argv[argv.index("-S") + 1])
            master = _FakeMaster(control_path)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise subprocess.TimeoutExpired(
                argv,
                5,
                output=f"stdout {input_text}",
                stderr=f"stderr {password}",
            )

        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), password)
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
                with client.session() as session:
                    with self.assertRaises(SSHTransportError) as raised:
                        session.command(
                            ["sudo", "-S", "true"],
                            timeout=5,
                            input_text=input_text,
                        )
                    with self.assertRaisesRegex(
                        SSHTransportError, "автоматический повтор запрещён"
                    ):
                        session.command(["true"])

        message = str(raised.exception)
        self.assertNotIn(password, message)
        self.assertNotIn(input_text.strip(), message)
        self.assertIn("тайм-аут 5 секунд", message)
        self.assertIn("без безопасной transport-диагностики", message)

    def test_rc255_does_not_echo_untrusted_remote_stderr(self):
        password = "hidden-password"
        remote_secret = "uuid-or-path-that-must-not-leak"
        failure = subprocess.CompletedProcess(
            ["ssh"],
            255,
            "",
            (
                f"remote application reflected {remote_secret}\n"
                f"Control socket connect(/tmp/{remote_secret}): Permission denied\n"
            ),
        )

        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), password)
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run",
                    return_value=failure,
                ),
                self.assertRaises(SSHTransportError) as raised,
            ):
                client.command(["remote-tool", remote_secret], check=False)

        message = str(raised.exception)
        self.assertNotIn(remote_secret, message)
        self.assertNotIn(password, message)
        self.assertIn("control socket недоступен", message)

    def test_spawn_oserror_is_typed_with_bounded_detail(self):
        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), "hidden")
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.subprocess.run",
                    side_effect=OSError("ssh executable unavailable"),
                ),
                self.assertRaises(SSHTransportError) as raised,
            ):
                client.command(["true"])

        self.assertIn("OSError: ssh executable unavailable", str(raised.exception))

    def test_keyboard_interrupt_stops_master_and_removes_socket_dir(self):
        secret = "hidden"
        master: _FakeMaster | None = None
        control_dir: Path | None = None
        control_ops: list[str] = []

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            control_path = Path(argv[argv.index("-S") + 1])
            control_dir = control_path.parent
            master = _FakeMaster(control_path)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                control_ops.append(operation)
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise KeyboardInterrupt()

        with tempfile.TemporaryDirectory() as temp:
            client = self._password_client(Path(temp), secret)
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
                with client.session() as session:
                    session.command(["true"])

        self.assertEqual(control_ops, ["check", "exit"])
        assert control_dir is not None
        self.assertFalse(control_dir.exists())

    def test_key_session_uses_one_key_master_without_agent_or_password_fallback(self):
        captured: dict[str, object] = {"commands": []}
        master: _FakeMaster | None = None
        popen_count = 0

        def fake_popen(argv, **kwargs):
            nonlocal master, popen_count
            popen_count += 1
            captured["master_argv"] = argv
            captured["master_env"] = kwargs["env"]
            control_path = Path(argv[argv.index("-S") + 1])
            master = _FakeMaster(control_path)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                operation = argv[argv.index("-O") + 1]
                if operation == "exit":
                    assert master is not None
                    master.stop()
                return subprocess.CompletedProcess(argv, 0, "", "")
            captured["commands"].append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, "ok", "")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "id_ed25519"
            key.write_text("test key material\n", encoding="utf-8")
            os.chmod(key, 0o600)
            client = SSHClient(
                host="exit.example.org",
                port=22,
                user="root",
                known_hosts=root / "known_hosts",
                auth=SSHAuth("key", private_key=key),
            )
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
                with client.session() as session:
                    session.command(["printf", "first"])
                    session.command(["printf", "second"])

        self.assertEqual(popen_count, 1)
        master_argv = captured["master_argv"]
        self.assertIn(str(key), master_argv)
        self.assertIn("PreferredAuthentications=publickey", master_argv)
        self.assertIn("PasswordAuthentication=no", master_argv)
        self.assertIn("KbdInteractiveAuthentication=no", master_argv)
        self.assertIn("HostbasedAuthentication=no", master_argv)
        self.assertIn("GSSAPIAuthentication=no", master_argv)
        self.assertIn("IdentityAgent=none", master_argv)
        self.assertNotIn("XHTTP_ASKPASS_FIFO", captured["master_env"])
        self.assertEqual(len(captured["commands"]), 2)

    def test_unkillable_master_retains_private_socket_directory(self):
        secret = "hidden"
        master: _FakeMaster | None = None
        control_dir: Path | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            control_path = Path(argv[argv.index("-S") + 1])
            control_dir = control_path.parent
            master = _FakeMaster(control_path, stoppable=False)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

        try:
            with tempfile.TemporaryDirectory() as temp:
                client = self._password_client(Path(temp), secret)
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

    def test_unkillable_cleanup_does_not_mask_body_exception(self):
        master: _FakeMaster | None = None
        control_dir: Path | None = None

        def fake_popen(argv, **kwargs):
            nonlocal master, control_dir
            control_path = Path(argv[argv.index("-S") + 1])
            control_dir = control_path.parent
            master = _FakeMaster(control_path, stoppable=False)
            return master

        def fake_run(argv, **kwargs):
            if "-O" in argv:
                return subprocess.CompletedProcess(argv, 0, "", "")
            raise AssertionError(argv)

        try:
            with tempfile.TemporaryDirectory() as temp:
                client = self._password_client(Path(temp), "hidden")
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
                    self.assertRaisesRegex(RuntimeError, "body failure"),
                ):
                    with client.session():
                        raise RuntimeError("body failure")

            assert control_dir is not None
            self.assertTrue(control_dir.exists())
            self.assertTrue((control_dir / "c").exists())
        finally:
            if master is not None:
                master.stoppable = True
                master.stop()
            if control_dir is not None:
                shutil.rmtree(control_dir, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
