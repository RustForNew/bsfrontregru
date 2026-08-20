import contextlib
import io
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xhttp_setup.cli import _apply_front_and_issue, wizard_full
from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.exit_installer import Layout
from xhttp_setup.front import FrontResult, _apply_front_locked, apply_front
from xhttp_setup.models import ExitDesired, FrontDesired, Handoff
from xhttp_setup.ssh_transport import SSHAuth


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef0123456789abcdef"
ENCRYPTION = (
    "mlkem768x25519plus.native.0rtt.yFAUa9gUf_hlvbaqG6nYRyTqpfo2kE-BYoFqCqq6vQ4"
)
FINGERPRINT = "SHA256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"


def desired_front(*, placeholder: str = "neutral") -> FrontDesired:
    return FrontDesired(
        domain="front.example.org",
        client_connect_ip="198.51.100.20",
        dns_ipv4="192.0.2.30",
        sftp_host="sftp.example.org",
        sftp_port=22,
        sftp_user="site_user",
        document_root="/var/www/site",
        ssh_host_key_sha256=FINGERPRINT,
        exit_address="203.0.113.10",
        exit_port=8083,
        xhttp_path=PATH,
        placeholder_mode=placeholder,
    ).validate()


def handoff() -> Handoff:
    return Handoff(
        "203.0.113.10",
        8083,
        UUID,
        PATH,
        ENCRYPTION,
        "Test",
    ).validate()


def write_text_for_test(path: Path, text: str, mode: int) -> None:
    path.write_text(text, encoding="utf-8")
    if os.name == "posix":
        os.chmod(path, mode)


class MemorySFTP:
    def __init__(self, files=None, after_command=None):
        self.files = dict(files or {})
        self.after_command = after_command
        self.commands = []
        self.session_events = []

    @contextlib.contextmanager
    def session(self):
        self.session_events.append("open")
        try:
            yield self
        finally:
            self.session_events.append("close")

    def batch(self, commands, check=True):
        self.commands.extend(commands)
        for raw in commands:
            ignored = raw.startswith("-")
            parts = shlex.split(raw[1:] if ignored else raw)
            try:
                if parts[0] == "cd":
                    continue
                if parts[0] == "ls":
                    if parts[-1] not in self.files:
                        raise FileNotFoundError(parts[-1])
                elif parts[0] == "get":
                    Path(parts[2]).write_bytes(self.files[parts[1]])
                elif parts[0] == "put":
                    self.files[parts[2]] = Path(parts[1]).read_bytes()
                elif parts[0] == "rename":
                    self.files[parts[2]] = self.files.pop(parts[1])
                elif parts[0] == "rm":
                    del self.files[parts[1]]
                elif parts[0] == "chmod":
                    if parts[2] not in self.files:
                        raise FileNotFoundError(parts[2])
                else:
                    raise AssertionError(f"unexpected SFTP command: {raw}")
                if self.after_command is not None:
                    self.after_command(self, parts)
            except (FileNotFoundError, KeyError):
                if ignored:
                    continue
                result = subprocess.CompletedProcess(commands, 1, "", "No such file")
                if check:
                    raise InstallerError("simulated missing remote file")
                return result
        return subprocess.CompletedProcess(commands, 0, "", "")


class FrontPostApplyTests(unittest.TestCase):
    def test_full_routes_firewall_ack_through_pre_apply_transaction(self):
        exit_desired = ExitDesired(
            public_address="203.0.113.10",
            listen_port=8083,
            front_egress_ip="198.51.100.20",
            xhttp_path=PATH,
            client_id=UUID,
        ).validate()
        result = FrontResult(200, 404, Path("backups"), None, None)
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.cli._collect_exit", return_value=exit_desired),
                patch("xhttp_setup.cli._collect_front", return_value=desired_front()),
                patch("xhttp_setup.cli._show_plan"),
                patch("xhttp_setup.cli.check_front_dns"),
                patch("xhttp_setup.cli.check_public_tls"),
                patch("xhttp_setup.cli._ack_provider"),
                patch("xhttp_setup.cli._confirm_apply"),
                patch(
                    "xhttp_setup.cli._collect_auth",
                    return_value=SSHAuth("password", password="not-logged"),
                ),
                patch("xhttp_setup.cli.apply_exit", return_value=handoff()),
                patch("xhttp_setup.cli._default_state", return_value=state_dir),
                patch(
                    "xhttp_setup.cli._apply_front_and_issue", return_value=result
                ) as apply_and_issue,
                patch("xhttp_setup.cli._print_front_result"),
                patch("xhttp_setup.cli._ack_firewall") as direct_ack,
            ):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(wizard_full(), 0)

        direct_ack.assert_not_called()
        kwargs = apply_and_issue.call_args.kwargs
        self.assertEqual(kwargs["firewall_plan_path"], Layout().firewall_plan)
        self.assertIs(kwargs["firewall_supplied"], False)

    def test_failure_cleanup_runs_before_apply_lock_is_released(self):
        events = []

        @contextlib.contextmanager
        def fake_lock(_):
            events.append("lock entered")
            try:
                yield
            finally:
                events.append("lock released")

        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            (state_dir / ".xhttp-setup-state").write_text(
                "xhttp-setup front state v1\n", encoding="utf-8"
            )
            with (
                patch("xhttp_setup.front.exclusive_lock", side_effect=fake_lock),
                patch(
                    "xhttp_setup.front._apply_front_locked",
                    side_effect=VerificationError("precheck failed"),
                ),
            ):
                with self.assertRaises(VerificationError):
                    apply_front(
                        desired_front(),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        pre_apply=lambda: events.append("link withheld"),
                        on_failure=lambda _: events.append("failure recorded"),
                    )

        self.assertEqual(
            events,
            [
                "lock entered",
                "link withheld",
                "failure recorded",
                "lock released",
            ],
        )

    def test_lock_failure_before_callback_does_not_mutate_managed_state(self):
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            (state_dir / ".xhttp-setup-state").write_text(
                "xhttp-setup front state v1\n", encoding="utf-8"
            )
            link = state_dir / "client.vless"
            link.write_text("old profile", encoding="utf-8")
            failure = InstallerError("Другой экземпляр установщика уже работает")

            with patch("xhttp_setup.cli.apply_front", side_effect=failure):
                with self.assertRaises(InstallerError):
                    _apply_front_and_issue(
                        desired=desired_front(),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        handoff=handoff(),
                        layout=Layout(root=state_dir / "runtime"),
                    )

            self.assertEqual(link.read_text("utf-8"), "old profile")
            self.assertFalse((state_dir / "last-failure.log").exists())

    def test_apply_failure_after_pre_callback_withholds_managed_stale_link(self):
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            (state_dir / ".xhttp-setup-state").write_text(
                "xhttp-setup front state v1\n", encoding="utf-8"
            )
            link = state_dir / "client.vless"
            link.write_text("old profile", encoding="utf-8")
            failure = VerificationError(f"TLS precheck failed for {PATH}")

            def fake_apply(*args, pre_apply, on_failure, **kwargs):
                try:
                    pre_apply()
                    raise failure
                except BaseException as error:
                    on_failure(error)
                    raise

            with patch("xhttp_setup.cli.apply_front", side_effect=fake_apply):
                with self.assertRaises(VerificationError):
                    _apply_front_and_issue(
                        desired=desired_front(),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        handoff=handoff(),
                        layout=Layout(root=state_dir / "runtime"),
                    )

            self.assertFalse(link.exists())
            failure_log = (state_dir / "last-failure.log").read_text("utf-8")
            self.assertIn("stage=frontend apply", failure_log)
            self.assertIn("client_link=absent", failure_log)
            self.assertNotIn(PATH, failure_log)

    def test_post_apply_failure_removes_files_that_did_not_exist_before(self):
        client = MemorySFTP()
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key") as pin,
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaisesRegex(VerificationError, "profile failed"):
                    _apply_front_locked(
                        desired_front(),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        trusted_known_hosts=state_dir / "persistent-sftp.known_hosts",
                        post_apply=lambda _: (_ for _ in ()).throw(
                            VerificationError("profile failed")
                        ),
                    )

        self.assertEqual(client.files, {})
        self.assertEqual(client.session_events, ["open", "close"])
        self.assertEqual(
            pin.call_args.kwargs["trusted_known_hosts"],
            Path(temp) / "persistent-sftp.known_hosts",
        )

    def test_post_apply_failure_restores_exact_index_and_htaccess(self):
        original = {
            "index.html": b"original index\n",
            ".htaccess": b"RewriteEngine On\n# original rule\n",
        }
        client = MemorySFTP(original)
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key"),
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaisesRegex(VerificationError, "E2E failed"):
                    _apply_front_locked(
                        desired_front(),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        post_apply=lambda _: (_ for _ in ()).throw(
                            VerificationError("E2E failed")
                        ),
                    )

        self.assertEqual(client.files, original)
        chmod_commands = [
            command for command in client.commands if command.startswith("chmod 644 ")
        ]
        self.assertEqual(len(chmod_commands), 2)

    def test_post_apply_concurrent_remote_edit_is_never_overwritten(self):
        original = b"original htaccess\n"
        concurrent = b"site owner edit after switch\n"
        client = MemorySFTP({".htaccess": original})

        def edit_then_fail(_):
            client.files[".htaccess"] = concurrent
            raise VerificationError("E2E failed after concurrent edit")

        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key"),
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaisesRegex(
                    InstallerError, "rollback неполон"
                ) as raised:
                    _apply_front_locked(
                        desired_front(placeholder="keep"),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        post_apply=edit_then_fail,
                    )

        self.assertEqual(client.files[".htaccess"], concurrent)
        backups = {
            name: content
            for name, content in client.files.items()
            if name.startswith(".xhttp-backup-htaccess-")
        }
        self.assertEqual(list(backups.values()), [original])
        self.assertIsInstance(raised.exception.__cause__, VerificationError)
        self.assertIn("отказался перезаписывать", str(raised.exception))

    def test_edit_between_precondition_and_switch_survives_failed_e2e(self):
        original = b"original htaccess\n"
        owner_edit = b"owner edit between precondition and switch\n"
        injected = False

        def inject_after_precondition_get(client, parts):
            nonlocal injected
            if (
                not injected
                and parts[0] == "get"
                and "precondition-htaccess-" in parts[2]
            ):
                client.files[".htaccess"] = owner_edit
                injected = True

        client = MemorySFTP(
            {".htaccess": original}, after_command=inject_after_precondition_get
        )
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key"),
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaisesRegex(
                    InstallerError, "rollback неполон"
                ) as raised:
                    _apply_front_locked(
                        desired_front(placeholder="keep"),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        post_apply=lambda _: (_ for _ in ()).throw(
                            VerificationError("E2E failed")
                        ),
                    )

        self.assertTrue(injected)
        self.assertIn(owner_edit, client.files.values())
        owner_locations = [
            name for name, content in client.files.items() if content == owner_edit
        ]
        self.assertEqual(len(owner_locations), 1)
        self.assertTrue(owner_locations[0].startswith(".xhttp-backup-htaccess-"))
        self.assertIn(f"/var/www/site/{owner_locations[0]}", str(raised.exception))

    def test_absent_original_owner_edit_at_rollback_boundary_is_quarantined(self):
        owner_edit = b"owner edit before rollback removal\n"
        armed = False
        injected = False

        def inject_after_rollback_target_get(client, parts):
            nonlocal injected
            if (
                armed
                and not injected
                and parts[0] == "get"
                and parts[1] == ".htaccess"
                and "rollback-htaccess-" in parts[2]
            ):
                client.files[".htaccess"] = owner_edit
                injected = True

        client = MemorySFTP(after_command=inject_after_rollback_target_get)

        def arm_and_fail(_):
            nonlocal armed
            armed = True
            raise VerificationError("E2E failed")

        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key"),
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaisesRegex(
                    InstallerError, "rollback неполон"
                ) as raised:
                    _apply_front_locked(
                        desired_front(placeholder="keep"),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        post_apply=arm_and_fail,
                    )

        self.assertTrue(injected)
        owner_locations = [
            name for name, content in client.files.items() if content == owner_edit
        ]
        self.assertEqual(len(owner_locations), 1)
        self.assertIn("xhttp-current-", owner_locations[0])
        self.assertIn(f"/var/www/site/{owner_locations[0]}", str(raised.exception))

    def test_target_created_before_backup_promotion_is_quarantined(self):
        original = b"original htaccess\n"
        owner_edit = b"owner target created before backup promotion\n"
        installed_quarantined = False
        injected = False

        def inject_before_promotion(client, parts):
            nonlocal installed_quarantined, injected
            if (
                parts[0] == "rename"
                and parts[1] == ".htaccess"
                and "xhttp-current-" in parts[2]
            ):
                installed_quarantined = True
            elif (
                installed_quarantined
                and not injected
                and parts[0] == "get"
                and parts[1].startswith(".xhttp-backup-htaccess-")
            ):
                client.files[".htaccess"] = owner_edit
                injected = True

        client = MemorySFTP(
            {".htaccess": original}, after_command=inject_before_promotion
        )
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key"),
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaisesRegex(
                    InstallerError, "rollback неполон"
                ) as raised:
                    _apply_front_locked(
                        desired_front(placeholder="keep"),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        post_apply=lambda _: (_ for _ in ()).throw(
                            VerificationError("E2E failed")
                        ),
                    )

        self.assertTrue(installed_quarantined)
        self.assertTrue(injected)
        owner_locations = [
            name for name, content in client.files.items() if content == owner_edit
        ]
        self.assertEqual(len(owner_locations), 1)
        self.assertIn("xhttp-late-", owner_locations[0])
        self.assertIn(f"/var/www/site/{owner_locations[0]}", str(raised.exception))
        self.assertEqual(client.files[".htaccess"], original)

    def test_changed_remote_temp_after_quarantine_is_preserved(self):
        original = b"original htaccess\n"
        owner_edit = b"owner bytes in transaction temp name\n"
        remote_temp = None
        injected = False

        def replace_temp_after_quarantine(client, parts):
            nonlocal remote_temp, injected
            if (
                parts[0] == "rename"
                and "xhttp-new-" in parts[1]
                and parts[2] == ".htaccess"
            ):
                remote_temp = parts[1]
            elif (
                remote_temp is not None
                and not injected
                and parts[0] == "rename"
                and parts[1] == ".htaccess"
                and "xhttp-current-" in parts[2]
            ):
                client.files[remote_temp] = owner_edit
                injected = True

        client = MemorySFTP(
            {".htaccess": original}, after_command=replace_temp_after_quarantine
        )
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key"),
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaisesRegex(
                    InstallerError, "rollback неполон"
                ) as raised:
                    _apply_front_locked(
                        desired_front(placeholder="keep"),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        post_apply=lambda _: (_ for _ in ()).throw(
                            VerificationError("E2E failed")
                        ),
                    )

        self.assertTrue(injected)
        self.assertIsNotNone(remote_temp)
        self.assertEqual(client.files[remote_temp], owner_edit)
        self.assertIn(f"/var/www/site/{remote_temp}", str(raised.exception))

    def test_keyboard_interrupt_during_post_apply_also_rolls_back(self):
        original = {".htaccess": b"original\n"}
        client = MemorySFTP(original)
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            with (
                patch("xhttp_setup.front.check_front_dns"),
                patch("xhttp_setup.front.check_public_tls"),
                patch("xhttp_setup.front.pin_host_key"),
                patch("xhttp_setup.front.https_status", side_effect=(200, 200, 404)),
                patch("xhttp_setup.front.SFTPClient", return_value=client),
                patch(
                    "xhttp_setup.front.atomic_write_text",
                    side_effect=write_text_for_test,
                ),
            ):
                with self.assertRaises(KeyboardInterrupt):
                    _apply_front_locked(
                        desired_front(placeholder="keep"),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        post_apply=lambda _: (_ for _ in ()).throw(KeyboardInterrupt()),
                    )

        self.assertEqual(client.files, original)

    def test_firewall_failure_withholds_stale_link_and_writes_redacted_log(self):
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            (state_dir / ".xhttp-setup-state").write_text(
                "xhttp-setup front state v1\n", encoding="utf-8"
            )
            link = state_dir / "client.vless"
            link.write_text("old profile", encoding="utf-8")
            result = FrontResult(200, 404, state_dir / "backups", None, None)
            remote_mutated = False

            def fake_apply(*args, pre_apply, post_apply, on_failure, **kwargs):
                nonlocal remote_mutated
                try:
                    pre_apply()
                    remote_mutated = True
                    post_apply(result)
                    return result
                except BaseException as error:
                    on_failure(error)
                    raise

            secret_error = InstallerError(
                f"firewall rejected {UUID} {ENCRYPTION} {PATH}"
            )
            with (
                patch("xhttp_setup.cli.apply_front", side_effect=fake_apply),
                patch("xhttp_setup.cli._ack_firewall", side_effect=secret_error),
            ):
                with self.assertRaises(InstallerError):
                    _apply_front_and_issue(
                        desired=desired_front(),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        handoff=handoff(),
                        layout=Layout(root=state_dir / "runtime"),
                        firewall_supplied=False,
                    )

            self.assertFalse(link.exists())
            self.assertFalse(remote_mutated)
            failure = (state_dir / "last-failure.log").read_text("utf-8")
            self.assertIn("stage=firewall acknowledgement", failure)
            self.assertIn("frontend_rollback=completed", failure)
            self.assertIn("client_link=absent", failure)
            self.assertNotIn(UUID, failure)
            self.assertNotIn(ENCRYPTION, failure)
            self.assertNotIn(PATH, failure)
            if os.name == "posix":
                self.assertEqual(
                    (state_dir / "last-failure.log").stat().st_mode & 0o777, 0o600
                )

    def test_profile_failure_removes_partially_issued_link(self):
        with tempfile.TemporaryDirectory() as temp:
            state_dir = Path(temp)
            (state_dir / ".xhttp-setup-state").write_text(
                "xhttp-setup front state v1\n", encoding="utf-8"
            )
            result = FrontResult(200, 404, state_dir / "backups", None, None)

            def fake_apply(*args, pre_apply, post_apply, on_failure, **kwargs):
                try:
                    pre_apply()
                    post_apply(result)
                    return result
                except BaseException as error:
                    on_failure(error)
                    raise

            def partial_issue(**kwargs):
                (state_dir / "client.vless").write_text(
                    "unverified profile", encoding="utf-8"
                )
                raise VerificationError("profile write interrupted")

            with (
                patch("xhttp_setup.cli.apply_front", side_effect=fake_apply),
                patch(
                    "xhttp_setup.cli._run_probe_and_issue", side_effect=partial_issue
                ),
            ):
                with self.assertRaises(VerificationError):
                    _apply_front_and_issue(
                        desired=desired_front(),
                        auth=SSHAuth("password", password="not-logged"),
                        state_dir=state_dir,
                        handoff=handoff(),
                        layout=Layout(root=state_dir / "runtime"),
                    )

            self.assertFalse((state_dir / "client.vless").exists())


if __name__ == "__main__":
    unittest.main()
