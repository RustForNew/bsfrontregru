from __future__ import annotations

import hashlib
import importlib.util
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _load_builder():
    script = ROOT / "scripts/build_windows_bundle.py"
    spec = importlib.util.spec_from_file_location("build_windows_bundle", script)
    if spec is None or spec.loader is None:
        raise RuntimeError("Could not load Windows bundle builder")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WindowsBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.builder = _load_builder()

    def _fake_root(self, parent: Path, *, checksum: str | None = None) -> Path:
        fake_root = parent / "source"
        (fake_root / "xhttp_setup").mkdir(parents=True)
        (fake_root / "xhttp_setup/__init__.py").write_text(
            '__version__ = "9.8.7"\n', encoding="utf-8"
        )
        shutil.copytree(ROOT / "windows", fake_root / "windows")
        (fake_root / "dist").mkdir()
        payload = b"deterministic fake pyz\n"
        (fake_root / "dist/xhttp-setup-9.8.7.pyz").write_bytes(payload)
        digest = checksum or hashlib.sha256(payload).hexdigest()
        (fake_root / "dist/xhttp-setup-9.8.7.pyz.sha256").write_text(
            digest + "\n", encoding="ascii"
        )
        return fake_root

    def test_bundle_is_deterministic_and_contains_only_expected_files(self) -> None:
        release = "9.8.7"
        pyz_name = f"xhttp-setup-{release}.pyz"
        expected_names = [
            "INSTRUCTION.txt",
            "START-WINDOWS.cmd",
            "_internal/run-wsl.sh",
            f"_internal/{pyz_name}",
            "_internal/xhttp-setup.ps1",
        ]
        with tempfile.TemporaryDirectory() as temp:
            temp_path = Path(temp)
            fake_root = self._fake_root(temp_path)
            first_dir = temp_path / "first"
            second_dir = temp_path / "second"
            first = self.builder.build(root=fake_root, output_dir=first_dir)
            second = self.builder.build(root=fake_root, output_dir=second_dir)
            first_payload = first.read_bytes()
            self.assertEqual(first_payload, second.read_bytes())
            self.assertEqual(
                (first_dir / "INSTRUCTION.txt").read_bytes(),
                (second_dir / "INSTRUCTION.txt").read_bytes(),
            )
            self.assertEqual(
                (first_dir / f"{first.name}.sha256").read_text("ascii"),
                hashlib.sha256(first_payload).hexdigest() + "\n",
            )

            with zipfile.ZipFile(first) as archive:
                self.assertEqual(archive.namelist(), expected_names)
                self.assertTrue(
                    all(
                        info.date_time == (1980, 1, 1, 0, 0, 0)
                        for info in archive.infolist()
                    )
                )
                pyz_payload = archive.read(f"_internal/{pyz_name}")
                pyz_sha256 = hashlib.sha256(pyz_payload).hexdigest()
                command_file = archive.read("START-WINDOWS.cmd")
                instruction = archive.read("INSTRUCTION.txt")
                powershell_payload = archive.read("_internal/xhttp-setup.ps1")
                runner_payload = archive.read("_internal/run-wsl.sh")
                powershell = powershell_payload.decode("utf-8")
                runner = runner_payload.decode("utf-8")
                command_text = command_file.decode("utf-8")
                runner_sha256 = hashlib.sha256(runner_payload).hexdigest()
                self.assertNotIn(b"\n", command_file.replace(b"\r\n", b""))
                self.assertNotIn(b"\n", instruction.replace(b"\r\n", b""))
                self.assertNotIn(b"\n", powershell_payload.replace(b"\r\n", b""))
                self.assertNotIn(b"\r", runner_payload)
                self.assertIn(pyz_name, powershell)
                self.assertIn(pyz_sha256, powershell)
                self.assertIn(runner_sha256, powershell)
                self.assertIn("Get-XhttpFileSha256", powershell)
                self.assertNotIn("Get-FileHash", powershell)
                self.assertGreaterEqual(
                    powershell.count("--distribution $DistroName"), 2
                )
                self.assertIn("System32\\wsl.exe", powershell)
                self.assertIn(pyz_sha256, runner)
                for executable in (
                    "python3",
                    "ssh",
                    "sftp",
                    "ssh-keyscan",
                    "ssh-keygen",
                    "curl",
                ):
                    self.assertIn(executable, runner)
                self.assertIn("[ -t 0 ] && [ -t 1 ]", runner)
                self.assertIn('exec python3 -I "$installer" pc', runner)
                self.assertIn(
                    "%SystemRoot%\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                    command_text,
                )
                self.assertIn("_internal\\xhttp-setup.ps1", command_text)
                self.assertNotIn("%*", command_text)
                self.assertNotIn("@@", powershell + runner)
                instruction_text = instruction.decode("utf-8")
                self.assertEqual(
                    instruction,
                    (first_dir / "INSTRUCTION.txt").read_bytes(),
                )
                self.assertIn("START-WINDOWS.cmd", instruction_text)
                self.assertIn("Извлечь все", instruction_text)
                self.assertIn("wsl --install -d Ubuntu", instruction_text)
                self.assertIn(f"python3 xhttp-setup-{release}.pyz pc", instruction_text)
                self.assertIn("sha256sum -c -", instruction_text)
                self.assertNotIn(
                    f"sha256sum -c xhttp-setup-{release}.pyz.sha256",
                    instruction_text,
                )
                for user_field in (
                    "IPv4 выходного сервера",
                    "SSH port выхода",
                    "SSH login выхода",
                    "SSH password выхода",
                    "HTTPS-адрес панели REG.RU",
                    "основной логин REG.RU",
                    "пароль панели REG.RU",
                    "IPv4 подключения REG.RU",
                    "домен frontend",
                ):
                    self.assertIn(user_field, instruction_text)
                for automatic_invariant in (
                    "TOFU",
                    "client.vless",
                    "E2E",
                    "мастер сайт не создаёт",
                    "не трогает index.html",
                ):
                    self.assertIn(automatic_invariant, instruction_text)
                for obsolete_manual_token in (
                    "xhttp-setup-egress-probe",
                    "EXIT_EGRESS_IP",
                    "FRONT_EGRESS_IP",
                    "Для применения введите APPLY PC",
                    "Проверенный SSH host-key fingerprint выхода SHA256",
                    "отдельной строкой ГОТОВО",
                ):
                    self.assertNotIn(obsolete_manual_token, instruction_text)
                self.assertNotIn("@@", instruction_text)
                self.assertEqual(
                    [name for name in archive.namelist() if name.endswith(".txt")],
                    ["INSTRUCTION.txt"],
                )
                self.assertNotIn(f"{pyz_name}.sha256", archive.namelist())

    def test_builder_rejects_mismatched_pyz_checksum(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            fake_root = self._fake_root(Path(temp), checksum="0" * 64)
            with self.assertRaisesRegex(SystemExit, "checksum mismatch"):
                self.builder.build(root=fake_root)


if __name__ == "__main__":
    unittest.main()
