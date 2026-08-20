from __future__ import annotations

import base64
import hashlib
import os
import re
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


def _has_usable_wsl2_distribution() -> bool:
    executable = shutil.which("wsl.exe")
    if not executable:
        return False
    try:
        result = subprocess.run(
            [executable, "--list", "--verbose"],
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    if result.returncode != 0:
        return False
    # Windows PowerShell exposes wsl.exe's UTF-16 output with NULs.  Only the
    # ASCII version column matters for deciding whether this integration test
    # can run on the current machine.
    normalized = result.stdout.replace(b"\x00", b"").decode("ascii", "ignore")
    for line in normalized.splitlines():
        match = re.match(r"^\s*\*?\s*(?P<name>.+?)\s{2,}.+?\s{2,}2\s*$", line)
        if match and match.group("name").lower().startswith(("ubuntu", "debian")):
            return True
    return False


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

    @unittest.skipUnless(
        _has_usable_wsl2_distribution(),
        "an installed WSL2 distribution is not available",
    )
    def test_root_script_is_transmitted_intact_to_real_wsl(self) -> None:
        path = str(LAUNCHER).replace("'", "''")
        result = self._run_windows_powershell(
            "$ErrorActionPreference = 'Stop'\n"
            f"$source = [IO.File]::ReadAllText('{path}')\n"
            "$tokens = $null\n"
            "$errors = $null\n"
            "$ast = [Management.Automation.Language.Parser]::ParseInput("
            "$source, [ref]$tokens, [ref]$errors)\n"
            "if ($errors.Count -ne 0) { throw $errors[0] }\n"
            "foreach ($name in @('Get-XhttpWsl2Distribution', "
            "'Invoke-XhttpWslRootScript')) {\n"
            "  $functionAst = $ast.Find({ param($node) "
            "$node -is [Management.Automation.Language.FunctionDefinitionAst] -and "
            "$node.Name -eq $name }, $true)\n"
            "  if ($null -eq $functionAst) { throw \"Function not found: $name\" }\n"
            "  Invoke-Expression $functionAst.Extent.Text\n"
            "}\n"
            "$wsl = Join-Path $env:SystemRoot 'System32\\wsl.exe'\n"
            "$distro = Get-XhttpWsl2Distribution -WslExe $wsl\n"
            "$scriptText = \"set -eu`r`ntest `\"`$(id -u)`\" = 0`r`n\" + "
            "\"case `\"`$-`\" in *e*) ;; *) exit 91;; esac`r`n\" + "
            "\"case `\"`$-`\" in *u*) ;; *) exit 92;; esac`r`n\" + "
            "\"for tool in sh python3; do command -v `\"`$tool`\" >/dev/null; done\"\n"
            "$output = @(Invoke-XhttpWslRootScript -WslExe $wsl "
            "-Distribution $distro -ScriptText $scriptText)\n"
            "if ($script:XhttpWslLastExitCode -ne 0) { "
            "throw \"WSL script failed: $script:XhttpWslLastExitCode / $output\" }\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr or result.stdout)
        self.assertNotIn("not found", result.stderr)


if __name__ == "__main__":
    unittest.main()
