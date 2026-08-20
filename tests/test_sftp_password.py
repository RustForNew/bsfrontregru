import io
import os
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
    SSHAuth,
    SSHAuthenticationError,
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
    def __init__(self, control_path: Path, *, returncode: int | None = None):
        self.pid = 90001
        self.returncode = returncode
        self.stderr = io.StringIO(
            "operator@sftp.example.org: Permission denied (publickey,password).\n"
            if returncode
            else ""
        )
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
        if self._socket is not None:
            self._socket.close()
            self._socket = None
        self.control_path.unlink(missing_ok=True)
        self.returncode = 0


@unittest.skipUnless(POSIX_FIFO, "requires POSIX FIFO and Unix sockets")
class SFTPPasswordMuxTests(unittest.TestCase):
    def _client(self, root: Path, secret: str) -> SFTPClient:
        known_hosts = root / "known_hosts"
        known_hosts.write_text("host ssh-ed25519 AAAA\n", encoding="utf-8")
        return SFTPClient(
            host="sftp.example.org",
            port=22,
            user="operator",
            known_hosts=known_hosts,
            auth=SSHAuth("password", password=secret),
        )

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
                result = client.batch(["ls -l", "get file local"], check=True)

        self.assertEqual(result.stdout, "ok")
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


if __name__ == "__main__":
    unittest.main()
