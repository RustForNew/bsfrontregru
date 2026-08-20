import hashlib
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from xhttp_setup import exit_installer
from xhttp_setup.doctor import doctor_exit
from xhttp_setup.errors import InstallerError
from xhttp_setup.exit_installer import (
    Layout,
    _FileSnapshot,
    _assert_directory_group_transition,
    _assert_directory_metadata,
    _assert_regular_file_metadata,
    _ensure_service_user,
    _normalize_managed_file,
    _record_rollback_command,
    _requires_atomic_rewrite,
    _restore_optional,
    _snapshot_optional,
    _verify_service_namespace,
    install_xray_binary,
)


def completed(stdout: str = "", returncode: int = 0):
    return subprocess.CompletedProcess(
        ["systemctl"], returncode, stdout=stdout, stderr=""
    )


class ExitHardeningTests(unittest.TestCase):
    def test_custom_layout_existing_xray_stays_unprivileged(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = Layout(root=Path(temp))
            layout.binary_dir.mkdir(parents=True)
            hashes: dict[str, str] = {}
            for name in ("xray", "geoip.dat", "geosite.dat"):
                payload = name.encode("ascii")
                (layout.binary_dir / name).write_bytes(payload)
                hashes[name] = hashlib.sha256(payload).hexdigest()
            (layout.binary_dir / "manifest.json").write_text(
                json.dumps(
                    {
                        "version": exit_installer.XRAY_VERSION,
                        "architecture": "x86_64",
                        "archive": "Xray-linux-64.zip",
                        "archive_sha256": exit_installer.XRAY_ASSETS["x86_64"][1],
                        "files": hashes,
                    }
                ),
                encoding="utf-8",
            )
            with mock.patch.object(
                exit_installer.platform, "machine", return_value="x86_64"
            ):
                install_xray_binary(layout)

    def test_atomic_rewrite_decision_covers_content_and_metadata(self):
        safe = _FileSnapshot(b"expected", 0o600, 0, 0)
        self.assertFalse(
            _requires_atomic_rewrite(safe, b"expected", mode=0o600, uid=0, gid=0)
        )
        for unsafe in (
            None,
            _FileSnapshot(b"changed", 0o600, 0, 0),
            _FileSnapshot(b"expected", 0o666, 0, 0),
            _FileSnapshot(b"expected", 0o600, 1000, 0),
            _FileSnapshot(b"expected", 0o600, 0, 1000),
        ):
            with self.subTest(snapshot=unsafe):
                self.assertTrue(
                    _requires_atomic_rewrite(
                        unsafe, b"expected", mode=0o600, uid=0, gid=0
                    )
                )

    def test_namespace_accepts_only_absent_or_our_fragment(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = Layout(root=Path(temp))
            absent = "LoadState=not-found\nFragmentPath=\n"
            with mock.patch.object(
                exit_installer, "run", return_value=completed(absent)
            ):
                _verify_service_namespace(layout, has_managed_unit=False)

            loaded = f"LoadState=loaded\nFragmentPath={layout.unit}\n"
            with mock.patch.object(
                exit_installer, "run", return_value=completed(loaded)
            ):
                _verify_service_namespace(layout, has_managed_unit=True)

    def test_namespace_rejects_foreign_fragment_and_inconsistent_disk_state(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = Layout(root=Path(temp))
            foreign = "LoadState=loaded\nFragmentPath=/usr/lib/systemd/system/xhttp-setup-xray.service\n"
            with mock.patch.object(
                exit_installer, "run", return_value=completed(foreign)
            ):
                with self.assertRaises(InstallerError):
                    _verify_service_namespace(layout, has_managed_unit=True)

            absent = "LoadState=not-found\nFragmentPath=\n"
            with mock.patch.object(
                exit_installer, "run", return_value=completed(absent)
            ):
                with self.assertRaises(InstallerError):
                    _verify_service_namespace(layout, has_managed_unit=True)

    def test_doctor_malformed_manifest_shapes_fail_without_crashing(self):
        for payload in ([], {"files": []}, {"files": {}}):
            with self.subTest(payload=payload), tempfile.TemporaryDirectory() as temp:
                layout = Layout(root=Path(temp))
                layout.binary_dir.mkdir(parents=True)
                layout.binary.write_bytes(b"binary")
                (layout.binary_dir / "manifest.json").write_text(
                    json.dumps(payload), encoding="utf-8"
                )
                with mock.patch("platform.machine", return_value="x86_64"):
                    checks = doctor_exit(layout)
                self.assertEqual(checks[0].name, "Xray supply chain")
                self.assertFalse(checks[0].ok)

    def test_rollback_command_records_exception_and_next_command_runs(self):
        errors: list[str] = []
        with mock.patch.object(
            exit_installer,
            "run",
            side_effect=[InstallerError("systemctl unavailable"), completed()],
        ) as run_mock:
            _record_rollback_command(["systemctl", "stop", "service"], errors)
            _record_rollback_command(["systemctl", "daemon-reload"], errors)
        self.assertEqual(run_mock.call_count, 2)
        self.assertEqual(len(errors), 1)
        self.assertIn("systemctl stop service", errors[0])

    def test_existing_service_account_requires_matching_safe_group(self):
        safe_account = SimpleNamespace(
            pw_name="xhttp-setup",
            pw_uid=998,
            pw_gid=998,
            pw_dir="/var/lib/xhttp-setup",
            pw_shell="/usr/sbin/nologin",
        )
        safe_group = SimpleNamespace(gr_gid=998)
        pwd_stub = SimpleNamespace(getpwnam=mock.Mock(return_value=safe_account))
        grp_stub = SimpleNamespace(getgrnam=mock.Mock(return_value=safe_group))
        with (
            mock.patch.object(exit_installer, "pwd", pwd_stub),
            mock.patch.object(exit_installer, "grp", grp_stub),
            mock.patch.object(
                exit_installer.os,
                "getgrouplist",
                return_value=[998],
                create=True,
            ),
        ):
            self.assertEqual(_ensure_service_user(), (998, 998))

        bad_group = SimpleNamespace(gr_gid=997)
        grp_stub = SimpleNamespace(getgrnam=mock.Mock(return_value=bad_group))
        with (
            mock.patch.object(exit_installer, "pwd", pwd_stub),
            mock.patch.object(exit_installer, "grp", grp_stub),
        ):
            with self.assertRaises(InstallerError):
                _ensure_service_user()

    def test_existing_service_account_requires_nologin(self):
        account = SimpleNamespace(
            pw_name="xhttp-setup",
            pw_uid=998,
            pw_gid=998,
            pw_dir="/var/lib/xhttp-setup",
            pw_shell="/bin/bash",
        )
        group = SimpleNamespace(gr_gid=998)
        with (
            mock.patch.object(
                exit_installer,
                "pwd",
                SimpleNamespace(getpwnam=mock.Mock(return_value=account)),
            ),
            mock.patch.object(
                exit_installer,
                "grp",
                SimpleNamespace(getgrnam=mock.Mock(return_value=group)),
            ),
        ):
            with self.assertRaises(InstallerError):
                _ensure_service_user()

    def test_existing_service_account_rejects_supplementary_groups(self):
        account = SimpleNamespace(
            pw_name="xhttp-setup",
            pw_uid=998,
            pw_gid=998,
            pw_dir="/var/lib/xhttp-setup",
            pw_shell="/usr/sbin/nologin",
        )
        group = SimpleNamespace(gr_gid=998)
        with (
            mock.patch.object(
                exit_installer,
                "pwd",
                SimpleNamespace(getpwnam=mock.Mock(return_value=account)),
            ),
            mock.patch.object(
                exit_installer,
                "grp",
                SimpleNamespace(getgrnam=mock.Mock(return_value=group)),
            ),
            mock.patch.object(
                exit_installer.os,
                "getgrouplist",
                return_value=[998, 27],
                create=True,
            ),
        ):
            with self.assertRaises(InstallerError):
                _ensure_service_user()

    def test_preexisting_group_without_account_is_rejected(self):
        pwd_stub = SimpleNamespace(getpwnam=mock.Mock(side_effect=KeyError))
        grp_stub = SimpleNamespace(
            getgrnam=mock.Mock(return_value=SimpleNamespace(gr_gid=998))
        )
        with (
            mock.patch.object(exit_installer, "pwd", pwd_stub),
            mock.patch.object(exit_installer, "grp", grp_stub),
            mock.patch.object(exit_installer, "run") as run_mock,
        ):
            with self.assertRaises(InstallerError):
                _ensure_service_user()
        run_mock.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "POSIX owner/mode semantics")
    def test_posix_metadata_helpers_fail_closed(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            directory = root / "managed-dir"
            directory.mkdir(mode=0o750)
            os.chmod(directory, 0o750)
            _assert_directory_metadata(
                directory, mode=0o750, uid=os.getuid(), gid=os.getgid()
            )
            _assert_directory_group_transition(
                directory,
                mode=0o750,
                uid=os.getuid(),
                allowed_gids={os.getgid()},
            )
            with self.assertRaises(InstallerError):
                _assert_directory_metadata(
                    directory, mode=0o750, uid=os.getuid() + 1, gid=os.getgid()
                )

            managed_file = root / "managed-file"
            managed_file.write_bytes(b"data")
            os.chmod(managed_file, 0o640)
            _assert_regular_file_metadata(
                managed_file, mode=0o640, uid=os.getuid(), gid=os.getgid()
            )
            os.chmod(managed_file, 0o666)
            with self.assertRaises(InstallerError):
                _assert_regular_file_metadata(
                    managed_file, mode=0o640, uid=os.getuid(), gid=os.getgid()
                )

    @unittest.skipUnless(os.name == "posix", "POSIX owner/mode semantics")
    def test_normalize_and_restore_preserve_exact_metadata(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "managed"
            path.write_bytes(b"before")
            os.chmod(path, 0o640)
            snapshot = _snapshot_optional(path)
            self.assertIsNotNone(snapshot)

            path.write_bytes(b"after")
            os.chmod(path, 0o666)
            _normalize_managed_file(
                path,
                mode=0o600,
                uid=os.getuid(),
                gid=os.getgid(),
            )
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

            _restore_optional(path, snapshot)
            self.assertEqual(path.read_bytes(), b"before")
            self.assertEqual(path.stat().st_mode & 0o777, 0o640)


if __name__ == "__main__":
    unittest.main()
