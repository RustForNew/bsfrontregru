import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.front import (
    FrontRollbackError,
    _RemoteMutation,
    _download_optional,
    _rollback_journal,
    _rollback_mutation,
    _upload_verified,
)


class FakeSFTP:
    def __init__(self, probe_returncode=0, probe_error=""):
        self.probe_returncode = probe_returncode
        self.probe_error = probe_error
        self.calls = 0

    def batch(self, commands, check=True):
        self.calls += 1
        if self.calls == 1:
            return subprocess.CompletedProcess(
                commands, self.probe_returncode, "", self.probe_error
            )
        destination = commands[-1].split('"')[-2]
        Path(destination).write_text("remote", encoding="utf-8")
        return subprocess.CompletedProcess(commands, 0, "", "")


class MemorySFTP:
    def __init__(self, files=None, fail_after=None, after_command=None):
        self.files = dict(files or {})
        self.fail_after = fail_after
        self.after_command = after_command
        self.failed = False

    def batch(self, commands, check=True):
        for raw in commands:
            ignored = raw.startswith("-")
            command = raw[1:] if ignored else raw
            parts = shlex.split(command)
            verb = parts[0]
            try:
                if verb == "cd":
                    pass
                elif verb == "ls":
                    if parts[-1] not in self.files:
                        raise FileNotFoundError(parts[-1])
                elif verb == "get":
                    Path(parts[2]).write_bytes(self.files[parts[1]])
                elif verb == "put":
                    self.files[parts[2]] = Path(parts[1]).read_bytes()
                elif verb == "rename":
                    self.files[parts[2]] = self.files.pop(parts[1])
                elif verb == "rm":
                    del self.files[parts[1]]
                elif verb == "chmod":
                    if parts[2] not in self.files:
                        raise FileNotFoundError(parts[2])
                else:
                    raise AssertionError(f"unexpected SFTP command: {raw}")
            except (FileNotFoundError, KeyError):
                if ignored:
                    continue
                result = subprocess.CompletedProcess(commands, 1, "", "No such file")
                if check:
                    raise InstallerError("simulated missing remote file")
                return result
            if (
                self.fail_after is not None
                and not self.failed
                and self.fail_after(parts)
            ):
                self.failed = True
                raise InstallerError("simulated connection loss")
            if self.after_command is not None:
                self.after_command(self, parts)
        return subprocess.CompletedProcess(commands, 0, "", "")


class FrontTransactionTests(unittest.TestCase):
    def test_missing_remote_file_is_optional(self):
        with tempfile.TemporaryDirectory() as temp:
            local = Path(temp) / "copy"
            client = FakeSFTP(1, "No such file")
            self.assertFalse(_download_optional(client, "/remote", ".htaccess", local))
            self.assertEqual(client.calls, 1)

    def test_permission_or_auth_failure_is_not_treated_as_missing(self):
        with tempfile.TemporaryDirectory() as temp:
            local = Path(temp) / "copy"
            client = FakeSFTP(255, "Permission denied")
            with self.assertRaises(InstallerError):
                _download_optional(client, "/remote", ".htaccess", local)
            self.assertEqual(client.calls, 1)

    def test_existing_remote_file_must_be_downloaded(self):
        with tempfile.TemporaryDirectory() as temp:
            local = Path(temp) / "copy"
            client = FakeSFTP()
            self.assertTrue(_download_optional(client, "/remote", ".htaccess", local))
            self.assertEqual(local.read_text("utf-8"), "remote")

    def test_existing_file_is_restored_after_first_rename_disconnect(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            local = work_dir / "new-index"
            local.write_bytes(b"new")
            backup = ".xhttp-backup-index-test"
            client = MemorySFTP(
                {"index.html": b"old"},
                fail_after=lambda parts: (
                    parts[0] == "rename"
                    and parts[1] == "index.html"
                    and parts[2] == backup
                ),
            )
            journal = []

            with self.assertRaisesRegex(InstallerError, "connection loss"):
                _upload_verified(
                    client,
                    remote_dir="/remote",
                    local=local,
                    target="index.html",
                    backup_name=backup,
                    work_dir=work_dir,
                    journal=journal,
                )

            self.assertEqual(len(journal), 1)
            _rollback_mutation(client, remote_dir="/remote", mutation=journal[0])
            self.assertEqual(client.files, {"index.html": b"old"})

    def test_new_file_is_removed_after_target_rename_disconnect(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            local = work_dir / "new-htaccess"
            local.write_bytes(b"new")
            backup = ".xhttp-backup-htaccess-test"
            client = MemorySFTP(
                fail_after=lambda parts: (
                    parts[0] == "rename" and parts[2] == ".htaccess"
                )
            )
            journal = []

            with self.assertRaisesRegex(InstallerError, "connection loss"):
                _upload_verified(
                    client,
                    remote_dir="/remote",
                    local=local,
                    target=".htaccess",
                    backup_name=backup,
                    work_dir=work_dir,
                    journal=journal,
                )

            self.assertEqual(len(journal), 1)
            _rollback_mutation(client, remote_dir="/remote", mutation=journal[0])
            self.assertEqual(client.files, {})

    def test_existing_file_is_restored_after_chmod_disconnect(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            local = work_dir / "new-index"
            local.write_bytes(b"new")
            client = MemorySFTP(
                {"index.html": b"old"},
                fail_after=lambda parts: (
                    parts[0] == "chmod" and parts[2] == "index.html"
                ),
            )
            journal = []

            with self.assertRaisesRegex(InstallerError, "connection loss"):
                _upload_verified(
                    client,
                    remote_dir="/remote",
                    local=local,
                    target="index.html",
                    backup_name=".xhttp-backup-index-test",
                    work_dir=work_dir,
                    journal=journal,
                )

            _rollback_mutation(client, remote_dir="/remote", mutation=journal[0])
            self.assertEqual(client.files, {"index.html": b"old"})

    def test_concurrent_edit_aborts_before_switch_and_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            local = work_dir / "new-index"
            local.write_bytes(b"new")
            mutated = False

            def edit_after_temp_verification(client, parts):
                nonlocal mutated
                if not mutated and parts[0] == "get" and ".xhttp-new-" in parts[1]:
                    client.files["index.html"] = b"concurrent-edit"
                    mutated = True

            client = MemorySFTP(
                {"index.html": b"old"},
                after_command=edit_after_temp_verification,
            )
            journal = []

            with self.assertRaisesRegex(InstallerError, "изменён параллельно"):
                try:
                    _upload_verified(
                        client,
                        remote_dir="/remote",
                        local=local,
                        target="index.html",
                        backup_name=".xhttp-backup-index-test",
                        work_dir=work_dir,
                        journal=journal,
                    )
                except Exception as exc:
                    _rollback_journal(
                        client,
                        remote_dir="/remote",
                        journal=journal,
                        original=exc,
                    )
                    raise

            self.assertTrue(mutated)
            self.assertEqual(client.files, {"index.html": b"concurrent-edit"})

    def test_unswitched_changed_remote_temp_is_preserved(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            local = work_dir / "new-index"
            local.write_bytes(b"new")
            remote_temp = None
            mutated = False

            def replace_temp_after_verification(client, parts):
                nonlocal remote_temp, mutated
                if parts[0] == "put" and "xhttp-new-" in parts[2]:
                    remote_temp = parts[2]
                elif (
                    not mutated
                    and remote_temp is not None
                    and parts[0] == "get"
                    and parts[1] == remote_temp
                ):
                    client.files["index.html"] = b"concurrent-edit"
                    client.files[remote_temp] = b"owner-temp-bytes"
                    mutated = True

            client = MemorySFTP(
                {"index.html": b"old"},
                after_command=replace_temp_after_verification,
            )
            journal = []

            try:
                _upload_verified(
                    client,
                    remote_dir="/remote",
                    local=local,
                    target="index.html",
                    backup_name=".xhttp-backup-index-test",
                    work_dir=work_dir,
                    journal=journal,
                )
            except InstallerError as original:
                with self.assertRaisesRegex(
                    InstallerError, "rollback неполон"
                ) as raised:
                    _rollback_journal(
                        client,
                        remote_dir="/remote",
                        journal=journal,
                        original=original,
                    )
            else:
                self.fail("expected precondition mismatch")

            self.assertTrue(mutated)
            self.assertIsNotNone(remote_temp)
            self.assertEqual(client.files["index.html"], b"concurrent-edit")
            self.assertEqual(client.files[remote_temp], b"owner-temp-bytes")
            self.assertIn(f"/remote/{remote_temp}", str(raised.exception))

    def test_journal_restores_both_files(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            index = work_dir / "new-index"
            htaccess = work_dir / "new-htaccess"
            index.write_bytes(b"new-index")
            htaccess.write_bytes(b"new-htaccess")
            client = MemorySFTP({"index.html": b"old-index"})
            journal = []

            for local, target in (
                (index, "index.html"),
                (htaccess, ".htaccess"),
            ):
                _upload_verified(
                    client,
                    remote_dir="/remote",
                    local=local,
                    target=target,
                    backup_name=f".xhttp-backup-{target}-test",
                    work_dir=work_dir,
                    journal=journal,
                )

            original = VerificationError("post-apply check failed")
            _rollback_journal(
                client,
                remote_dir="/remote",
                journal=journal,
                original=original,
            )
            self.assertEqual(client.files, {"index.html": b"old-index"})
            self.assertEqual(str(original), "post-apply check failed")

    def test_rollback_aggregates_all_failures_on_original_exception(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            mutations = [
                _RemoteMutation(
                    target=target,
                    backup_name=f"backup-{target}",
                    remote_temp=f"temp-{target}",
                    original_local=work_dir / f"original-{index}",
                    original_existed=False,
                    original_sha256=None,
                    work_dir=work_dir,
                    installed_sha256="00" * 32,
                )
                for index, target in enumerate(("index.html", ".htaccess"))
            ]
            original = VerificationError("primary verification failed")
            with patch(
                "xhttp_setup.front._rollback_mutation",
                side_effect=(InstallerError("first"), InstallerError("second")),
            ):
                with self.assertRaises(InstallerError) as raised:
                    _rollback_journal(
                        object(),
                        remote_dir="/remote",
                        journal=mutations,
                        original=original,
                    )

            detail = str(raised.exception)
            self.assertIs(raised.exception.__cause__, original)
            self.assertIn("rollback неполон", detail)
            self.assertIn("index.html", detail)
            self.assertIn(".htaccess", detail)
            self.assertIn("first", detail)
            self.assertIn("second", detail)

    def test_interrupt_during_rollback_is_typed_as_incomplete(self):
        with tempfile.TemporaryDirectory() as temp:
            work_dir = Path(temp)
            mutation = _RemoteMutation(
                target=".htaccess",
                backup_name="backup-htaccess",
                remote_temp="temp-htaccess",
                original_local=work_dir / "original",
                original_existed=False,
                original_sha256=None,
                work_dir=work_dir,
                installed_sha256="00" * 32,
            )
            original = VerificationError("frontend verification failed")
            with patch(
                "xhttp_setup.front._rollback_mutation",
                side_effect=KeyboardInterrupt(),
            ):
                with self.assertRaisesRegex(
                    FrontRollbackError, "rollback неполон.*KeyboardInterrupt"
                ) as raised:
                    _rollback_journal(
                        object(),
                        remote_dir="/remote",
                        journal=[mutation],
                        original=original,
                    )

        self.assertIs(raised.exception.__cause__, original)


if __name__ == "__main__":
    unittest.main()
