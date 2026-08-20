Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$InstallerName = "@@PYZ_NAME@@"
$ChecksumName = "@@PYZ_SHA_NAME@@"
$ExpectedSha256 = "@@PYZ_SHA256@@"
$RunnerName = "run-wsl.sh"
$ExpectedRunnerSha256 = "@@RUNNER_SHA256@@"

function Stop-XhttpSetup {
    param([string]$Message)
    [Console]::Error.WriteLine("ERROR: " + $Message)
    exit 1
}

function Get-XhttpWsl2Distribution {
    param([string]$WslExe)

    $ListOutput = @(& $WslExe --list --verbose)
    if ($LASTEXITCODE -ne 0) {
        Stop-XhttpSetup "Could not list WSL distributions. Configure WSL2 manually, then retry."
    }

    $Candidates = [System.Collections.Generic.List[string]]::new()
    foreach ($RawLine in $ListOutput) {
        $Line = ([string]$RawLine).Replace([char]0, "").Trim()
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
    $ChecksumPath = Join-Path -Path $PSScriptRoot -ChildPath $ChecksumName
    $RunnerPath = Join-Path -Path $PSScriptRoot -ChildPath $RunnerName

    if (-not (Test-Path -LiteralPath $InstallerPath -PathType Leaf)) {
        Stop-XhttpSetup "Release bundle is incomplete. Use File Explorer 'Extract All', then retry."
    }
    if (-not (Test-Path -LiteralPath $ChecksumPath -PathType Leaf)) {
        Stop-XhttpSetup "Release bundle is incomplete. Use File Explorer 'Extract All', then retry."
    }
    if (-not (Test-Path -LiteralPath $RunnerPath -PathType Leaf)) {
        Stop-XhttpSetup "Release bundle is incomplete. Use File Explorer 'Extract All', then retry."
    }

    $ManifestSha256 = (Get-Content -LiteralPath $ChecksumPath -Raw -Encoding ASCII).Trim()
    if ($ManifestSha256 -notmatch '\A[0-9a-fA-F]{64}\z') {
        Stop-XhttpSetup "Invalid installer checksum file. Extract the ZIP again."
    }
    if ($ManifestSha256.ToLowerInvariant() -cne $ExpectedSha256) {
        Stop-XhttpSetup "Installer checksum manifest does not match this launcher."
    }

    $ActualSha256 = (Get-FileHash -LiteralPath $InstallerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualSha256 -cne $ExpectedSha256) {
        Stop-XhttpSetup "Installer SHA-256 mismatch. Extract a fresh release ZIP."
    }

    $ActualRunnerSha256 = (Get-FileHash -LiteralPath $RunnerPath -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($ActualRunnerSha256 -cne $ExpectedRunnerSha256) {
        Stop-XhttpSetup "WSL runner SHA-256 mismatch. Extract a fresh release ZIP."
    }

    $WslExe = Join-Path -Path $env:SystemRoot -ChildPath "System32\wsl.exe"
    if (-not (Test-Path -LiteralPath $WslExe -PathType Leaf)) {
        Stop-XhttpSetup "WSL2 is not available. Configure it manually, then retry."
    }
    $DistroName = Get-XhttpWsl2Distribution -WslExe $WslExe
    Write-Host "Using WSL2 distribution: $DistroName"

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
