from __future__ import annotations

import base64
import hashlib
import os
import shutil
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "windows" / "xhttp-setup.ps1"


def _windows_powershell() -> str | None:
    if os.name != "nt":
        return None
    system_root = os.environ.get("SystemRoot")
    if system_root:
        executable = Path(system_root) / "System32/WindowsPowerShell/v1.0/powershell.exe"
        if executable.is_file():
            return str(executable)
    return shutil.which("powershell.exe")


@unittest.skipUnless(_windows_powershell(), "Windows PowerShell is not available")
class WindowsLauncherRuntimeTests(unittest.TestCase):
    def _run_windows_powershell(self, script: str) -> subprocess.CompletedProcess[str]:
        # -EncodedCommand is UTF-16LE in Windows PowerShell and avoids cmd/quote
        # differences while still exercising the real 5.1 parser and runtime.
        encoded = base64.b64encode(script.encode("utf-16le")).decode("ascii")
        return subprocess.run(
            [
                _windows_powershell() or "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )

    def test_script_parses_in_windows_powershell(self) -> None:
        path = str(LAUNCHER).replace("'", "''")
        result = self._run_windows_powershell(
            "$ErrorActionPreference = 'Stop'\n"
            f"$null = [scriptblock]::Create([IO.File]::ReadAllText('{path}'))\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_wsl2_list_parser_removes_nuls_without_replace_overload_error(self) -> None:
        path = str(LAUNCHER).replace("'", "''")
        result = self._run_windows_powershell(
            "$ErrorActionPreference = 'Stop'\n"
            f"$source = [IO.File]::ReadAllText('{path}')\n"
            "$tokens = $null\n"
            "$errors = $null\n"
            "$ast = [Management.Automation.Language.Parser]::ParseInput("
            "$source, [ref]$tokens, [ref]$errors)\n"
            "if ($errors.Count -ne 0) { throw $errors[0] }\n"
            "$functionAst = $ast.Find({ param($node) "
            "$node -is [Management.Automation.Language.FunctionDefinitionAst] -and "
            "$node.Name -eq 'Get-XhttpWsl2Distribution' }, $true)\n"
            "if ($null -eq $functionAst) { throw 'Parser function was not found.' }\n"
            "Invoke-Expression $functionAst.Extent.Text\n"
            "function fake-wsl {\n"
            "  $script:LASTEXITCODE = 0\n"
            "  $nul = [char]0\n"
            "  '*' + $nul + ' Ubuntu' + $nul + '    Running         2' + $nul\n"
            "}\n"
            "$script:LASTEXITCODE = 0\n"
            "$distro = Get-XhttpWsl2Distribution -WslExe 'fake-wsl'\n"
            "if ($distro -cne 'Ubuntu') { throw \"Unexpected distro: $distro\" }\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)

    def test_sha256_helper_does_not_require_get_file_hash_module(self) -> None:
        path = str(LAUNCHER).replace("'", "''")
        expected = hashlib.sha256(LAUNCHER.read_bytes()).hexdigest()
        result = self._run_windows_powershell(
            "$ErrorActionPreference = 'Stop'\n"
            f"$source = [IO.File]::ReadAllText('{path}')\n"
            "$tokens = $null\n"
            "$errors = $null\n"
            "$ast = [Management.Automation.Language.Parser]::ParseInput("
            "$source, [ref]$tokens, [ref]$errors)\n"
            "if ($errors.Count -ne 0) { throw $errors[0] }\n"
            "$functionAst = $ast.Find({ param($node) "
            "$node -is [Management.Automation.Language.FunctionDefinitionAst] -and "
            "$node.Name -eq 'Get-XhttpFileSha256' }, $true)\n"
            "if ($null -eq $functionAst) { throw 'SHA-256 function was not found.' }\n"
            "Invoke-Expression $functionAst.Extent.Text\n"
            f"$actual = Get-XhttpFileSha256 -LiteralPath '{path}'\n"
            f"if ($actual -cne '{expected}') {{ throw \"Unexpected SHA-256: $actual\" }}\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertNotIn("Get-FileHash", LAUNCHER.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
