import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError
from xhttp_setup.ssh_transport import SSHAuth, SSHAuthenticationError, SSHClient


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
                "xhttp_setup.ssh_transport.run", return_value=completed
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
                    "xhttp_setup.ssh_transport.run", return_value=completed
                ) as runner,
                self.assertRaises(InstallerError) as raised,
            ):
                client.command(["sudo", "-S", "--", "true"], input_text=input_text)

        argv = runner.call_args.args[0]
        kwargs = runner.call_args.kwargs
        self.assertEqual(kwargs["input_text"], input_text)
        self.assertFalse(kwargs["check"])
        self.assertNotIn("env", kwargs)
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
                return subprocess.CompletedProcess(argv, 0, "ok", "")

            with mock.patch(
                "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
            ):
                client.command(["true"])

        self.assertNotIn(secret, repr(captured["argv"]))
        self.assertNotIn(secret, repr(captured["env"]))
        self.assertNotIn("input", captured["kwargs"])
        self.assertEqual(captured["kwargs"]["stdin"], subprocess.DEVNULL)

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


if __name__ == "__main__":
    unittest.main()
