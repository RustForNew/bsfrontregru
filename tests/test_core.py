import contextlib
import io
import os
import stat
import tempfile
import unittest
from pathlib import Path

from xhttp_setup.cli import _ack_provider, _managed_exit_present, main
from xhttp_setup.doctor import _parse_cloudflare_trace_ip
from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.exit_installer import Layout, _parse_vlessenc, build_exit_plan
from xhttp_setup.models import ExitDesired
from xhttp_setup.osutil import atomic_write_text, ensure_dir, exclusive_lock
from xhttp_setup.placeholder import neutral_placeholder


class CoreTests(unittest.TestCase):
    def test_vlessenc_parser_selects_one_consistent_pair(self):
        output = """Authentication: X25519
"decryption": "mlkem768x25519plus.native.600s.servermaterialxxxxxxxx"
"encryption": "mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx"

Authentication: ML-KEM
"decryption": "second-server-material-xxxxxxxxxxxxxxxx"
"encryption": "second-client-material-xxxxxxxxxxxxxxxx"
"""
        self.assertEqual(
            _parse_vlessenc(output),
            (
                "mlkem768x25519plus.native.600s.servermaterialxxxxxxxx",
                "mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx",
            ),
        )

    def test_exit_plan_contains_no_credentials(self):
        desired = ExitDesired(
            "203.0.113.10",
            8083,
            "198.51.100.20",
            "/api/0123456789abcdef",
            "d342d11e-d424-4583-b36e-524ab1f0afa4",
        ).validate()
        plan = "\n".join(build_exit_plan(desired, Layout(root=Path("/tmp/test"))))
        self.assertNotIn(desired.client_id, plan)
        self.assertIn("не изменять", plan.lower())

    def test_placeholder_is_transparent_and_does_not_embed_rufox(self):
        html = neutral_placeholder("front.example.org")
        self.assertIn('href="https://rufox.ru/"', html)
        self.assertIn("не является сайтом RuFox", html)
        self.assertNotIn("iframe", html.lower())
        self.assertNotIn("<script", html.lower())

    def test_atomic_secret_mode_on_posix(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "secret"
            atomic_write_text(path, "secret", 0o600)
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_atomic_write_preserves_existing_parent_mode(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions")
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "managed-parent"
            parent.mkdir(mode=0o750)
            os.chmod(parent, 0o750)
            atomic_write_text(parent / "file", "value", 0o640)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o750)

    def test_ensure_dir_refuses_to_chmod_existing_directory(self):
        if os.name != "posix":
            self.skipTest("POSIX permissions")
        with tempfile.TemporaryDirectory() as temp:
            parent = Path(temp) / "existing"
            parent.mkdir(mode=0o755)
            os.chmod(parent, 0o755)
            with self.assertRaises(InstallerError):
                ensure_dir(parent, 0o700)
            self.assertEqual(parent.stat().st_mode & 0o777, 0o755)

    def test_exclusive_lock_creates_private_regular_file(self):
        if os.name != "posix":
            self.skipTest("POSIX lock semantics")
        with tempfile.TemporaryDirectory() as temp:
            lock_path = Path(temp) / "apply.lock"
            with exclusive_lock(lock_path):
                metadata = lock_path.stat()
                self.assertTrue(stat.S_ISREG(metadata.st_mode))
                self.assertEqual(stat.S_IMODE(metadata.st_mode), 0o600)
                self.assertEqual(metadata.st_uid, os.geteuid())
                with self.assertRaises(InstallerError):
                    with exclusive_lock(lock_path):
                        self.fail("second nonblocking lock must not be acquired")

    def test_exclusive_lock_rejects_symlink(self):
        if os.name != "posix":
            self.skipTest("POSIX symlink semantics")
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "target"
            target.write_text("unchanged", encoding="utf-8")
            os.chmod(target, 0o600)
            lock_path = root / "apply.lock"
            lock_path.symlink_to(target)

            with self.assertRaises(InstallerError):
                with exclusive_lock(lock_path):
                    self.fail("symlink lock must not be acquired")
            self.assertEqual(target.read_text(encoding="utf-8"), "unchanged")

    def test_exit_without_apply_is_read_only(self):
        args = [
            "exit",
            "--public-address",
            "203.0.113.10",
            "--front-egress-ip",
            "198.51.100.20",
        ]
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(main(args), 0)
        self.assertIn("изменений нет", output.getvalue())

    def test_provider_warning_is_informational_and_non_blocking(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            _ack_provider()
        self.assertIn("не блокирует", output.getvalue())

    def test_front_state_alone_does_not_trigger_local_exit_doctor(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = Layout(root=Path(temp))
            (layout.state / "fronts/example.org").mkdir(parents=True)
            self.assertFalse(_managed_exit_present(layout))
            layout.handoff.write_text("{}", encoding="utf-8")
            self.assertTrue(_managed_exit_present(layout))

    def test_cloudflare_trace_requires_valid_ipv4(self):
        self.assertEqual(
            _parse_cloudflare_trace_ip("fl=1\nip=203.0.113.20\nts=1\n"),
            "203.0.113.20",
        )
        with self.assertRaises(VerificationError):
            _parse_cloudflare_trace_ip("fl=1\nts=1\n")


if __name__ == "__main__":
    unittest.main()
