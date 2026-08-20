Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallerName = "@@PYZ_NAME@@"
$ExpectedSha256 = "@@PYZ_SHA256@@"
$RunnerName = "run-wsl.sh"
$ExpectedRunnerSha256 = "@@RUNNER_SHA256@@"

function Stop-XhttpSetup {
    param([string]$Message)
    [Console]::Error.WriteLine("ERROR: " + $Message)
    exit 1
}

function Get-XhttpFileSha256 {
    param([string]$LiteralPath)

    $Stream = [System.IO.File]::OpenRead($LiteralPath)
    try {
        $Sha256 = [System.Security.Cryptography.SHA256]::Create()
        try {
            $Digest = $Sha256.ComputeHash($Stream)
        }
        finally {
            $Sha256.Dispose()
        }
    }
    finally {
        $Stream.Dispose()
    }
    return ([System.BitConverter]::ToString($Digest)).Replace("-", "").ToLowerInvariant()
}

function Invoke-XhttpWslRootScript {
    param(
        [string]$WslExe,
        [string]$Distribution,
        [string]$ScriptText
    )

    # Windows PowerShell 5.1 neither preserves a multiline `sh -c` argument
    # nor reliably emits BOM-free stdin to a native pipeline.  The script has
    # no credentials, so write it as an explicitly BOM-free private-user temp
    # file, translate that path through WSL, execute it, and always remove it.
    $Normalized = $ScriptText -replace "`r`n?", "`n"
    $Normalized = $Normalized.TrimStart([char]0xfeff)
    $Payload = $Normalized + "`n# xhttp-setup eof"
    $TempScript = [System.IO.Path]::Combine(
        [System.IO.Path]::GetTempPath(),
        "xhttp-setup-" + [System.Guid]::NewGuid().ToString("N") + ".sh"
    )
    try {
        $Utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($TempScript, $Payload, $Utf8NoBom)
        $WslPathOutput = @(
            & $WslExe --distribution $Distribution --user root --exec wslpath -a -u $TempScript
        )
        if ($LASTEXITCODE -ne 0 -or $WslPathOutput.Count -ne 1) {
            throw "WSL could not translate the temporary dependency script path."
        }
        $WslScript = ([string]$WslPathOutput[0]).Trim()
        if ([string]::IsNullOrWhiteSpace($WslScript) -or -not $WslScript.StartsWith("/")) {
            throw "WSL returned an invalid temporary dependency script path."
        }
        & $WslExe --distribution $Distribution --user root --exec sh $WslScript
        $script:XhttpWslLastExitCode = $LASTEXITCODE
    }
    finally {
        [System.IO.File]::Delete($TempScript)
    }
}

function Get-XhttpWsl2Distribution {
    param([string]$WslExe)

    $ListOutput = @(& $WslExe --list --verbose)
    if ($LASTEXITCODE -ne 0) {
        Stop-XhttpSetup "Could not list WSL distributions. Configure WSL2 manually, then retry."
    }

    $Candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($RawLine in $ListOutput) {
        $Line = ([string]$RawLine).Replace(([char]0).ToString(), [string]::Empty).Trim()
        if ($Line.StartsWith("*")) {
            $Line = $Line.Substring(1).TrimStart()
        }
        $Match = [regex]::Match($Line, '^(?<name>.+?)\s{2,}.+?\s{2,}2\s*$')
        if (-not $Match.Success) {
            continue
        }
        $Name = $Match.Groups["name"].Value.Trim()
        if (
            $Name.Length -lt 1 -or
            $Name.Length -gt 128 -or
            $Name.StartsWith("-") -or
            $Name -match '[\x00-\x1f\x7f]'
        ) {
            continue
        }
        if (-not $Candidates.Contains($Name)) {
            $Candidates.Add($Name)
        }
    }
    if ($Candidates.Count -eq 0) {
        Stop-XhttpSetup "No installed WSL2 distribution was found. Configure one manually, then retry."
    }

    foreach ($Prefix in @("Ubuntu", "Debian")) {
        foreach ($Name in $Candidates) {
            if ($Name -match ("^" + [regex]::Escape($Prefix) + "(?:$|[-_. ])")) {
                return $Name
            }
        }
    }
    return $Candidates[0]
}

try {
    $InstallerPath = Join-Path -Path $PSScriptRoot -ChildPath $InstallerName
    $RunnerPath = Join-Path -Path $PSScriptRoot -ChildPath $RunnerName

    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        Stop-XhttpSetup "Release bundle is incomplete. Use File Explorer 'Extract All', then retry."
    }
    if (-not (Test-Path -LiteralPath $RunnerPath -PathType Leaf)) {
        Stop-XhttpSetup "Release bundle is incomplete. Use File Explorer 'Extract All', then retry."
    }

    $ActualSha256 = Get-XhttpFileSha256 -LiteralPath $InstallerPath
    if ($ActualSha256 -cne $ExpectedSha256) {
        Stop-XhttpSetup "Installer SHA-256 mismatch. Extract a fresh release ZIP."
    }

    $ActualRunnerSha256 = Get-XhttpFileSha256 -LiteralPath $RunnerPath
    if ($ActualRunnerSha256 -cne $ExpectedRunnerSha256) {
        Stop-XhttpSetup "WSL runner SHA-256 mismatch. Extract a fresh release ZIP."
    }

    $WslExe = Join-Path -Path $env:SystemRoot -ChildPath "System32\wsl.exe"
    if (-not (Test-Path -LiteralPath $WslExe -PathType Leaf)) {
        Stop-XhttpSetup "WSL2 is not available. Configure it manually, then retry."
    }
    $DistroName = Get-XhttpWsl2Distribution -WslExe $WslExe
    Write-Host "Using WSL2 distribution: $DistroName"

    $DependencyCheck = @'
set -eu
test "$(id -u)" = 0
. /etc/os-release
case "${ID:-}" in ubuntu|debian) ;; *) exit 1 ;; esac
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'
for tool in curl sha256sum ssh sftp ssh-keyscan ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1
done
'@
    Invoke-XhttpWslRootScript -WslExe $WslExe -Distribution $DistroName -ScriptText $DependencyCheck
    if ($script:XhttpWslLastExitCode -ne 0) {
        Write-Host "Installing required packages inside WSL2..."
        $DependencyInstall = @'
set -eu
test "$(id -u)" = 0
. /etc/os-release
case "${ID:-}" in ubuntu|debian) ;; *)
    echo 'Only Ubuntu or Debian WSL2 distributions are supported.' >&2
    exit 1
;; esac
export DEBIAN_FRONTEND=noninteractive
apt-get -o DPkg::Lock::Timeout=180 update
apt-get -o DPkg::Lock::Timeout=180 install -y --no-install-recommends python3 ca-certificates curl coreutils openssh-client
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'
'@
        Invoke-XhttpWslRootScript -WslExe $WslExe -Distribution $DistroName -ScriptText $DependencyInstall
        if ($script:XhttpWslLastExitCode -ne 0) {
            Stop-XhttpSetup "Could not prepare Ubuntu/Debian WSL2 with Python 3.10+."
        }
    }

    $WslBundlePathOutput = @(
        & $WslExe --distribution $DistroName --exec wslpath -a -u $PSScriptRoot
    )
    if ($LASTEXITCODE -ne 0 -or $WslBundlePathOutput.Count -eq 0) {
        Stop-XhttpSetup "The selected WSL2 distribution could not access the extracted folder."
    }
    $WslBundlePath = ([string]$WslBundlePathOutput[0]).Trim()
    if ([string]::IsNullOrWhiteSpace($WslBundlePath) -or -not $WslBundlePath.StartsWith("/")) {
        Stop-XhttpSetup "WSL could not translate the release directory path."
    }

    $WslRunnerPath = $WslBundlePath + "/run-wsl.sh"
    $WslInstallerPath = $WslBundlePath + "/" + $InstallerName
    & $WslExe --distribution $DistroName --exec sh $WslRunnerPath $WslInstallerPath
    exit $LASTEXITCODE
}
catch {
    Stop-XhttpSetup $_.Exception.Message
}
