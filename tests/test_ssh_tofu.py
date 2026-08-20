import hashlib
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.ssh_transport import (
    SFTPClient,
    SSHAuth,
    SSHClient,
    pin_host_key,
    tofu_known_hosts_path,
    trust_host_key_tofu,
)


_FINGERPRINT = "SHA256:" + "A" * 43
_OTHER_FINGERPRINT = "SHA256:" + "B" * 43
_RSA = "UlNBT05F"
_ECDSA = "RUNEU0E="
_ED25519 = "AAAAZWQyNTUxOQ=="


def _completed(argv, stdout="", stderr="", returncode=0):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


class SSHTofuTests(unittest.TestCase):
    def _runner(self, scan_lines):
        def fake_run(argv, **kwargs):
            if argv[0] == "ssh-keyscan":
                return _completed(argv, "\n".join(scan_lines) + "\n")
            if argv[0] == "ssh-keygen":
                return _completed(argv, f"256 {_FINGERPRINT} endpoint (ED25519)\n")
            self.fail(f"unexpected command: {argv!r}")

        return fake_run

    def test_path_is_endpoint_scoped_and_uses_normalized_host(self):
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            first = tofu_known_hosts_path(
                trust_dir=trust_dir, host="EXAMPLE.org.", port=22
            )
            second = tofu_known_hosts_path(
                trust_dir=trust_dir, host="example.org", port="22"
            )
            other_port = tofu_known_hosts_path(
                trust_dir=trust_dir, host="example.org", port=2222
            )

        digest = hashlib.sha256(b"example.org\x0022").hexdigest()
        self.assertEqual(first, trust_dir / f"{digest}.known_hosts")
        self.assertEqual(first, second)
        self.assertNotEqual(first, other_port)

    def test_first_use_prefers_ed25519_and_creates_private_files(self):
        scan = [
            f"example.org ssh-rsa {_RSA}",
            f"example.org ecdsa-sha2-nistp256 {_ECDSA}",
            f"example.org ssh-ed25519 {_ED25519}",
        ]
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            with mock.patch(
                "xhttp_setup.ssh_transport.run", side_effect=self._runner(scan)
            ):
                known_hosts, fingerprint = trust_host_key_tofu(
                    host="EXAMPLE.org.", port=22, trust_dir=trust_dir
                )

            self.assertEqual(fingerprint, _FINGERPRINT)
            self.assertEqual(
                known_hosts.read_text("utf-8"),
                f"example.org ssh-ed25519 {_ED25519}\n",
            )
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(trust_dir.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(known_hosts.stat().st_mode), 0o600)

    def test_empty_keyscan_is_retried_but_success_is_still_pinned_once(self):
        scan_calls = 0

        def flaky_run(argv, **_kwargs):
            nonlocal scan_calls
            if argv[0] == "ssh-keyscan":
                scan_calls += 1
                if scan_calls < 3:
                    return _completed(argv, stderr="temporary timeout\n", returncode=1)
                return _completed(argv, f"example.org ssh-ed25519 {_ED25519}\n")
            if argv[0] == "ssh-keygen":
                return _completed(
                    argv,
                    f"256 {_FINGERPRINT} endpoint (ED25519)\n",
                )
            self.fail(f"unexpected command: {argv!r}")

        with tempfile.TemporaryDirectory() as temp:
            with (
                mock.patch("xhttp_setup.ssh_transport.run", side_effect=flaky_run),
                mock.patch("xhttp_setup.ssh_transport.time.sleep") as sleep,
            ):
                known_hosts, fingerprint = trust_host_key_tofu(
                    host="example.org",
                    port=22,
                    trust_dir=Path(temp) / "ssh",
                )
                content = known_hosts.read_text("utf-8")

        self.assertEqual(scan_calls, 3)
        self.assertEqual(sleep.call_count, 2)
        self.assertEqual(fingerprint, _FINGERPRINT)
        self.assertIn("ssh-ed25519", content)

    def test_empty_keyscan_fails_after_bounded_attempts(self):
        calls = 0

        def empty_run(argv, **_kwargs):
            nonlocal calls
            calls += 1
            return _completed(argv, stderr="timeout\n", returncode=1)

        with tempfile.TemporaryDirectory() as temp:
            with (
                mock.patch("xhttp_setup.ssh_transport.run", side_effect=empty_run),
                mock.patch("xhttp_setup.ssh_transport.time.sleep") as sleep,
                self.assertRaisesRegex(VerificationError, "после 3 попыток"),
            ):
                trust_host_key_tofu(
                    host="example.org",
                    port=22,
                    trust_dir=Path(temp) / "ssh",
                )

        self.assertEqual(calls, 3)
        self.assertEqual(sleep.call_count, 2)

    def test_existing_trust_is_reused_without_another_keyscan(self):
        scan = [f"example.org ssh-ed25519 {_ED25519}"]
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            runner = self._runner(scan)
            with mock.patch("xhttp_setup.ssh_transport.run", side_effect=runner) as run_mock:
                known_hosts, first = trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )
                original = known_hosts.read_bytes()
                reused, second = trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )

            self.assertEqual(reused, known_hosts)
            self.assertEqual(first, second)
            self.assertEqual(known_hosts.read_bytes(), original)
            scans = [call for call in run_mock.call_args_list if call.args[0][0] == "ssh-keyscan"]
            self.assertEqual(len(scans), 1)

    def test_existing_key_survives_addition_of_a_more_preferred_key(self):
        initial = [f"example.org ecdsa-sha2-nistp256 {_ECDSA}"]
        expanded = [
            f"example.org ssh-ed25519 {_ED25519}",
            f"example.org ecdsa-sha2-nistp256 {_ECDSA}",
        ]
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            with mock.patch(
                "xhttp_setup.ssh_transport.run", side_effect=self._runner(initial)
            ):
                known_hosts, first = trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )
            original = known_hosts.read_bytes()
            with mock.patch(
                "xhttp_setup.ssh_transport.run", side_effect=self._runner(expanded)
            ):
                reused, second = trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )

            self.assertEqual(reused, known_hosts)
            self.assertEqual(first, second)
            self.assertEqual(known_hosts.read_bytes(), original)

    def test_cached_trust_is_not_replaced_by_a_later_unauthenticated_scan(self):
        initial = [f"example.org ssh-ed25519 {_ED25519}"]
        changed = ["example.org ssh-ed25519 AAAAY2hhbmdlZA=="]
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            with mock.patch(
                "xhttp_setup.ssh_transport.run", side_effect=self._runner(initial)
            ):
                known_hosts, _ = trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )
            original = known_hosts.read_bytes()

            with mock.patch(
                "xhttp_setup.ssh_transport.run", side_effect=self._runner(changed)
            ) as run_mock:
                reused, fingerprint = trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )

            self.assertEqual(reused, known_hosts)
            self.assertEqual(fingerprint, _FINGERPRINT)
            self.assertFalse(
                any(call.args[0][0] == "ssh-keyscan" for call in run_mock.call_args_list)
            )
            self.assertEqual(known_hosts.read_bytes(), original)

    def test_pin_seeds_from_exact_private_trust_without_keyscan(self):
        line = f"example.org ssh-ed25519 {_ED25519}\n"

        def runner(argv, **_kwargs):
            if argv[0] == "ssh-keygen":
                return _completed(argv, f"256 {_FINGERPRINT} endpoint (ED25519)\n")
            self.fail(f"unexpected network command: {argv!r}")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.known_hosts"
            target = root / "managed" / "known_hosts"
            source.write_bytes(line.encode("utf-8"))
            os.chmod(source, 0o600)
            with mock.patch("xhttp_setup.ssh_transport.run", side_effect=runner):
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=target,
                    trusted_known_hosts=source,
                )

            self.assertEqual(target.read_text("utf-8"), line)
            if os.name == "posix":
                self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)

    def test_pin_first_use_still_scans_and_pins_expected_key(self):
        scan = [f"example.org ssh-ed25519 {_ED25519}"]
        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "managed" / "known_hosts"
            with mock.patch(
                "xhttp_setup.ssh_transport.run", side_effect=self._runner(scan)
            ) as run_mock:
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=target,
                )

            self.assertEqual(
                target.read_bytes(),
                f"example.org ssh-ed25519 {_ED25519}\n".encode("utf-8"),
            )
            self.assertEqual(
                sum(
                    call.args[0][0] == "ssh-keyscan"
                    for call in run_mock.call_args_list
                ),
                1,
            )

    def test_pin_reuses_matching_target_without_keyscan(self):
        line = f"example.org ssh-ed25519 {_ED25519}\n"

        def runner(argv, **_kwargs):
            if argv[0] == "ssh-keygen":
                return _completed(argv, f"256 {_FINGERPRINT} endpoint (ED25519)\n")
            self.fail(f"unexpected network command: {argv!r}")

        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "known_hosts"
            target.write_bytes(line.encode("utf-8"))
            os.chmod(target, 0o600)
            original = target.read_bytes()
            with mock.patch("xhttp_setup.ssh_transport.run", side_effect=runner):
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=target,
                )

            self.assertEqual(target.read_bytes(), original)

    def test_pin_rejects_wrong_trusted_fingerprint_without_creating_target(self):
        line = f"example.org ssh-ed25519 {_ED25519}\n"

        def runner(argv, **_kwargs):
            if argv[0] == "ssh-keygen":
                return _completed(argv, f"256 {_OTHER_FINGERPRINT} endpoint (ED25519)\n")
            self.fail(f"unexpected network command: {argv!r}")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.known_hosts"
            target = root / "managed" / "known_hosts"
            source.write_bytes(line.encode("utf-8"))
            os.chmod(source, 0o600)
            with (
                mock.patch("xhttp_setup.ssh_transport.run", side_effect=runner),
                self.assertRaisesRegex(VerificationError, "не совпал"),
            ):
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=target,
                    trusted_known_hosts=source,
                )

            self.assertFalse(target.exists())

    def test_pin_rejects_existing_target_fingerprint_mismatch_without_scan(self):
        line = f"example.org ssh-ed25519 {_ED25519}\n"

        def runner(argv, **_kwargs):
            if argv[0] == "ssh-keygen":
                return _completed(argv, f"256 {_OTHER_FINGERPRINT} endpoint\n")
            self.fail(f"unexpected network command: {argv!r}")

        with tempfile.TemporaryDirectory() as temp:
            target = Path(temp) / "known_hosts"
            target.write_bytes(line.encode("utf-8"))
            os.chmod(target, 0o600)
            original = target.read_bytes()
            with (
                mock.patch("xhttp_setup.ssh_transport.run", side_effect=runner),
                self.assertRaisesRegex(VerificationError, "не совпал"),
            ):
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=target,
                )

            self.assertEqual(target.read_bytes(), original)

    def test_pin_rejects_trusted_file_for_another_endpoint(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.known_hosts"
            target = root / "managed" / "known_hosts"
            source.write_bytes(
                f"other.example.org ssh-ed25519 {_ED25519}\n".encode("utf-8")
            )
            os.chmod(source, 0o600)
            with (
                mock.patch("xhttp_setup.ssh_transport.run") as runner,
                self.assertRaisesRegex(VerificationError, "другому endpoint"),
            ):
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=target,
                    trusted_known_hosts=source,
                )

            runner.assert_not_called()
            self.assertFalse(target.exists())

    def test_pin_seed_race_never_overwrites_concurrent_target(self):
        line = f"example.org ssh-ed25519 {_ED25519}\n"
        concurrent = b"concurrent owner data\n"

        def runner(argv, **_kwargs):
            if argv[0] == "ssh-keygen":
                return _completed(argv, f"256 {_FINGERPRINT} endpoint\n")
            self.fail(f"unexpected network command: {argv!r}")

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "source.known_hosts"
            target = root / "managed" / "known_hosts"
            source.write_bytes(line.encode("utf-8"))
            os.chmod(source, 0o600)

            def race(_temporary, destination):
                Path(destination).write_bytes(concurrent)
                raise FileExistsError(destination)

            with (
                mock.patch("xhttp_setup.ssh_transport.run", side_effect=runner),
                mock.patch("xhttp_setup.ssh_transport.os.link", side_effect=race),
                self.assertRaisesRegex(VerificationError, "появился параллельно"),
            ):
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=target,
                    trusted_known_hosts=source,
                )

            self.assertEqual(target.read_bytes(), concurrent)

    def test_pin_rejects_missing_trusted_file_without_falling_back_to_scan(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with (
                mock.patch("xhttp_setup.ssh_transport.run") as runner,
                self.assertRaisesRegex(VerificationError, "отсутствует"),
            ):
                pin_host_key(
                    host="example.org",
                    port=22,
                    expected_sha256=_FINGERPRINT,
                    known_hosts=root / "managed" / "known_hosts",
                    trusted_known_hosts=root / "missing.known_hosts",
                )

            runner.assert_not_called()

    def test_ambiguous_scan_fails_without_creating_trust(self):
        scan = [
            f"example.org ssh-ed25519 {_ED25519}",
            "example.org ssh-ed25519 AAAAYW5vdGhlcg==",
        ]
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            known_hosts = tofu_known_hosts_path(
                trust_dir=trust_dir, host="example.org", port=22
            )
            with (
                mock.patch(
                    "xhttp_setup.ssh_transport.run", side_effect=self._runner(scan)
                ),
                self.assertRaises(VerificationError),
            ):
                trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )

            self.assertFalse(known_hosts.exists())

    def test_corrupt_existing_trust_fails_before_network_and_is_unchanged(self):
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            trust_dir.mkdir(mode=0o700)
            os.chmod(trust_dir, 0o700)
            known_hosts = tofu_known_hosts_path(
                trust_dir=trust_dir, host="example.org", port=22
            )
            known_hosts.write_text("not a known-hosts line\n", encoding="utf-8")
            os.chmod(known_hosts, 0o600)
            original = known_hosts.read_bytes()

            with (
                mock.patch("xhttp_setup.ssh_transport.run") as runner,
                self.assertRaises(VerificationError),
            ):
                trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )

            runner.assert_not_called()
            self.assertEqual(known_hosts.read_bytes(), original)

    def test_symlink_trust_file_is_rejected_without_touching_target(self):
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            trust_dir.mkdir(mode=0o700)
            os.chmod(trust_dir, 0o700)
            target = Path(temp) / "target"
            target.write_text("keep me\n", encoding="utf-8")
            known_hosts = tofu_known_hosts_path(
                trust_dir=trust_dir, host="example.org", port=22
            )
            try:
                known_hosts.symlink_to(target)
            except OSError as exc:
                self.skipTest(f"symlink creation is unavailable: {exc}")

            with (
                mock.patch("xhttp_setup.ssh_transport.run") as runner,
                self.assertRaises(InstallerError),
            ):
                trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )

            runner.assert_not_called()
            self.assertEqual(target.read_text("utf-8"), "keep me\n")

    @unittest.skipUnless(os.name == "posix", "POSIX permission semantics required")
    def test_existing_trust_with_broad_permissions_is_rejected(self):
        with tempfile.TemporaryDirectory() as temp:
            trust_dir = Path(temp) / "ssh"
            trust_dir.mkdir(mode=0o700)
            known_hosts = tofu_known_hosts_path(
                trust_dir=trust_dir, host="example.org", port=22
            )
            known_hosts.write_text(
                f"example.org ssh-ed25519 {_ED25519}\n", encoding="utf-8"
            )
            os.chmod(known_hosts, 0o644)

            with (
                mock.patch("xhttp_setup.ssh_transport.run") as runner,
                self.assertRaises(InstallerError),
            ):
                trust_host_key_tofu(
                    host="example.org", port=22, trust_dir=trust_dir
                )

            runner.assert_not_called()

    def test_clients_disable_openssh_host_key_updates(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            key = root / "id_ed25519"
            key.write_text("test", encoding="utf-8")
            auth = SSHAuth("key", private_key=str(key))
            kwargs = {
                "host": "example.org",
                "port": 22,
                "user": "root",
                "known_hosts": root / "known_hosts",
                "auth": auth,
            }

            ssh_argv = SSHClient(**kwargs)._argv()
            sftp = SFTPClient(**kwargs)

            self.assertIn("UpdateHostKeys=no", ssh_argv)
            self.assertIn("UpdateHostKeys=no", sftp._argv())
            self.assertIn("UpdateHostKeys=no", sftp._master_argv(root / "control"))


if __name__ == "__main__":
    unittest.main()
