#!/bin/sh
set -eu

fail() {
    printf 'ERROR: %s\n' "$1" >&2
    exit 1
}

[ "$#" -eq 1 ] || fail "Internal launcher argument error."
installer=$1

[ -t 0 ] && [ -t 1 ] \
    || fail "An interactive terminal is required. Run START-WINDOWS.cmd directly."

kernel_release=$(uname -r 2>/dev/null || true)
case "$kernel_release" in
    *microsoft-standard*|*Microsoft-standard*) ;;
    *) fail "WSL2 is required. Convert the default distribution with: wsl --set-version <Distro> 2" ;;
esac

command -v python3 >/dev/null 2>&1 || fail "Python 3 is missing in WSL. Install package: python3"
python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' \
    || fail "Python 3.10 or newer is required in WSL."

for tool in ssh sftp ssh-keyscan ssh-keygen; do
    command -v "$tool" >/dev/null 2>&1 \
        || fail "OpenSSH client is incomplete in WSL. Install package: openssh-client"
done
command -v curl >/dev/null 2>&1 || fail "curl is missing in WSL. Install package: curl"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is missing in WSL."

[ -f "$installer" ] || fail "Installer .pyz is missing. Extract the ZIP again."
[ ! -L "$installer" ] || fail "Installer .pyz must not be a symbolic link."

actual_sha256=$(sha256sum -- "$installer") || fail "Could not hash installer .pyz."
actual_sha256=${actual_sha256%% *}
[ "$actual_sha256" = "@@PYZ_SHA256@@" ] \
    || fail "Installer SHA-256 mismatch. Extract a fresh release ZIP."

exec python3 -I "$installer" pc
