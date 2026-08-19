import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError
from xhttp_setup.ssh_transport import SSHAuth, SSHClient


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
                return subprocess.CompletedProcess(argv, 0, "ok", "")

            with mock.patch(
                "xhttp_setup.ssh_transport.subprocess.run", side_effect=fake_run
            ):
                client.command(["true"])

        self.assertNotIn(secret, repr(captured["argv"]))
        self.assertNotIn(secret, repr(captured["env"]))


if __name__ == "__main__":
    unittest.main()
