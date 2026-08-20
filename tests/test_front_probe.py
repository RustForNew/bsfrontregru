import contextlib
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.front_probe import run_with_temporary_front_route
from xhttp_setup.models import FrontDesired
from xhttp_setup.ssh_transport import SSHAuth


_HOST_FINGERPRINT = "SHA256:" + "A" * 43


def _desired() -> FrontDesired:
    return FrontDesired(
        domain="front.example.org",
        client_connect_ip="192.0.2.10",
        dns_ipv4="192.0.2.10",
        sftp_host="sftp.example.org",
        sftp_port=22,
        sftp_user="site-user",
        document_root="/var/www/site",
        ssh_host_key_sha256=_HOST_FINGERPRINT,
        exit_address="203.0.113.20",
        exit_port=25432,
        xhttp_path="/api/temporary-probe",
    )


class TemporaryFrontRouteTests(unittest.TestCase):
    def _run(
        self,
        root: Path,
        *,
        operation,
        rollback_side_effect=None,
        upload_side_effect=None,
    ):
        events: list[str] = []
        captured: dict[str, object] = {}
        self.last_events = events
        self.last_captured = captured
        client = object()

        def download(_client, remote_dir, name, local):
            self.assertIs(_client, client)
            self.assertEqual(remote_dir, "/var/www/site")
            self.assertEqual(name, ".htaccess")
            local.write_text("RewriteEngine On\n# owner rule\n", encoding="utf-8")
            return True

        def upload(_client, **kwargs):
            self.assertIs(_client, client)
            self.assertEqual(kwargs["remote_dir"], "/var/www/site")
            self.assertEqual(kwargs["target"], ".htaccess")
            self.assertRegex(
                kwargs["backup_name"], r"^\.xhttp-backup-htaccess-probe-"
            )
            captured["temporary"] = kwargs["local"].read_text("utf-8")
            kwargs["journal"].append("temporary-htaccess-mutation")
            events.append("upload")
            if upload_side_effect is not None:
                raise upload_side_effect

        def rollback(_client, **kwargs):
            self.assertIs(_client, client)
            self.assertEqual(kwargs["remote_dir"], "/var/www/site")
            self.assertEqual(kwargs["journal"], ["temporary-htaccess-mutation"])
            captured["rollback_original"] = kwargs["original"]
            events.append("rollback")
            if rollback_side_effect is not None:
                raise rollback_side_effect

        def wrapped_operation():
            events.append("operation")
            return operation()

        def atomic_write(path, text, _mode):
            path.write_text(text, encoding="utf-8")

        secret = "front-sftp-password-never-log"
        auth = SSHAuth("password", password=secret)
        with (
            mock.patch("xhttp_setup.front_probe.check_front_dns"),
            mock.patch("xhttp_setup.front_probe.check_public_tls"),
            mock.patch("xhttp_setup.front_probe.pin_host_key"),
            mock.patch("xhttp_setup.front_probe.SFTPClient", return_value=client) as sftp,
            mock.patch(
                "xhttp_setup.front_probe.exclusive_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch(
                "xhttp_setup.front_probe.atomic_write_text",
                side_effect=atomic_write,
            ),
            mock.patch(
                "xhttp_setup.front_probe._download_optional", side_effect=download
            ),
            mock.patch("xhttp_setup.front_probe._upload_verified", side_effect=upload),
            mock.patch(
                "xhttp_setup.front_probe._rollback_journal", side_effect=rollback
            ),
        ):
            try:
                result = run_with_temporary_front_route(
                    _desired(),
                    auth=auth,
                    state_dir=root / "probe-state",
                    operation=wrapped_operation,
                )
            finally:
                captured["sftp_calls"] = sftp.call_args_list

        self.assertNotIn(secret, repr(captured))
        return result, events, captured

    def test_success_uploads_temporary_htaccess_then_rolls_it_back(self):
        with tempfile.TemporaryDirectory() as temp:
            result, events, captured = self._run(
                Path(temp), operation=lambda: "measurement complete"
            )

        self.assertEqual(result, "measurement complete")
        self.assertEqual(events, ["upload", "operation", "rollback"])
        temporary = captured["temporary"]
        self.assertIn("# owner rule", temporary)
        self.assertIn("203.0.113.20:25432", temporary)
        self.assertIn("/api/temporary-probe", temporary)
        self.assertIsInstance(captured["rollback_original"], InstallerError)

    def test_operation_error_is_reraised_only_after_rollback(self):
        original = VerificationError("frontend request failed")

        def fail():
            raise original

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(VerificationError) as raised:
                self._run(Path(temp), operation=fail)

        self.assertIs(raised.exception, original)
        self.assertEqual(self.last_events, ["upload", "operation", "rollback"])
        self.assertIs(self.last_captured["rollback_original"], original)
        self.assertNotIn("front-sftp-password-never-log", repr(self.last_captured))

    def test_keyboard_interrupt_is_reraised_only_after_rollback(self):
        original = KeyboardInterrupt()

        def interrupt():
            raise original

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(KeyboardInterrupt) as raised:
                self._run(Path(temp), operation=interrupt)

        self.assertIs(raised.exception, original)
        self.assertEqual(self.last_events, ["upload", "operation", "rollback"])
        self.assertIs(self.last_captured["rollback_original"], original)
        self.assertNotIn("front-sftp-password-never-log", repr(self.last_captured))

    def test_partial_upload_error_still_rolls_back_registered_mutation(self):
        original = InstallerError("upload connection lost")
        operation = mock.Mock(return_value=None)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InstallerError) as raised:
                self._run(
                    Path(temp),
                    operation=operation,
                    upload_side_effect=original,
                )

        self.assertIs(raised.exception, original)
        self.assertEqual(self.last_events, ["upload", "rollback"])
        self.assertIs(self.last_captured["rollback_original"], original)
        self.assertNotIn("front-sftp-password-never-log", repr(self.last_captured))
        operation.assert_not_called()

    def test_rollback_failure_is_propagated_after_success(self):
        rollback_error = InstallerError("rollback cleanup incomplete")
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InstallerError) as raised:
                self._run(
                    Path(temp),
                    operation=lambda: "unused",
                    rollback_side_effect=rollback_error,
                )

        self.assertIs(raised.exception, rollback_error)

    def test_rollback_failure_supersedes_operation_error(self):
        original = VerificationError("request failed")
        rollback_error = InstallerError("rollback cleanup incomplete")

        def fail():
            raise original

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InstallerError) as raised:
                self._run(
                    Path(temp),
                    operation=fail,
                    rollback_side_effect=rollback_error,
                )

        self.assertIs(raised.exception, rollback_error)


if __name__ == "__main__":
    unittest.main()
