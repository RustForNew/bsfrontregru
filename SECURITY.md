# Security model

- All remote targets are fixed input fields; `.htaccess` never derives an
  upstream from request headers or query parameters.
- Public TLS uses the operating-system trust store and hostname verification by
  default. Explicit pin mode disables CA/hostname verification only inside the
  TLS handshake and replaces it with an exact, constant-time comparison of the
  presented leaf certificate's SHA-256. CA, SAN/hostname, validity dates and
  revocation are not checked in this mode; it is not equivalent to public PKI.
  SNI and HTTP Host are still preserved, and an unrelated leaf is rejected.
- A leaf certificate pin is public but operationally short-lived. Certificate
  renewal requires re-verification and reissuing the client URI. Root and
  intermediate CA hashes must not be used as the pin, and the client must
  actually support Xray's `pinnedPeerCertSha256` / URI `pcs` parameter. Pins are
  never refreshed automatically.
- Pin verification authenticates a certificate, not an Apache virtual-host
  mapping. Enable the site's SSL/443 vhost and verify that SNI/Host reaches that
  site before capturing a pin; never pin a provider's unrelated default vhost.
- Capture the leaf with the frontend domain sent as SNI. Never copy the hash
  from `xray tls ping`'s `Pinging without SNI` section: the same IP can select a
  different default certificate when SNI is absent.
- SFTP uses `StrictHostKeyChecking=yes` with a dedicated known_hosts file.
- Passwords are read with `getpass` and exposed once to OpenSSH askpass through
  a kernel-backed FIFO inside a private temporary directory. Password-auth SFTP
  first authenticates a short-lived foreground ControlMaster, then preserves
  fail-on-command semantics by running `sftp -b` only through its private
  control socket. Passwords are not placed in argv, regular files, config files,
  or environment values.
- The PC wizard pins exit and optional bridge host keys before password
  authentication. Root passwords use the same private FIFO transport.
- In bridge mode the SFTP password is sent as one bounded stdin line inside an
  already host-key-pinned SSH command. It is not placed in argv, environment,
  regular files, or relayed command output.
- The optional bridge is a trusted operator host, not an anonymous proxy. Its
  root can observe the handoff, frontend credentials and managed client
  material; compromise of bridge root defeats these protections.
- Remote firewall automation is fail-closed and restricted to already-active
  UFW on clean Debian/Ubuntu. It never changes UFW state, defaults, SSH access,
  or cloud firewall.
- The Windows bundle does not implement a second SSH stack. Its PowerShell
  launcher verifies the bundled Linux zipapp SHA-256 and starts that same
  controller inside WSL2. Native Windows execution without WSL is rejected.
- UUID, VLESS Encryption material, handoff, backups and client URI are secrets.
- Xray runs as a dedicated unprivileged user and does not replace another Xray
  service.
- Managed state/lock paths reject symlinks and unexpected ownership or modes.
- Release and Xray versions are pinned. Checksums, regular-file type, ownership
  and modes are verified by installer install/re-apply. Subsequent systemd
  restarts rely on the root-owned managed directory; they do not re-hash the
  binary before every ExecStart.
- A previous `client.vless` is withheld before a new attempt. Firewall
  acknowledgement runs under the apply lock but before any SFTP mutation.
  Failure or interruption during E2E or profile issuance rolls back only a
  target that still exactly matches the digest installed by this transaction.
  A later third-party edit is preserved and reported as an incomplete rollback;
  the error names any hidden backup/quarantine needed for recovery, and no
  unverified client URI is left behind. SFTP offers neither compare-and-swap nor
  `renameat2`: quarantine-first checks protect observable command boundaries,
  but absolute atomicity against an external writer between remote commands is
  not guaranteed. Detected canonical-target conflicts fail closed. Random
  `.xhttp-*` names are an installer-owned transaction namespace; an external
  writer deliberately changing those cleanup artifacts between verification
  and the next SFTP command is outside the rollback guarantee.
- Failed probes retain only a bounded, redacted Xray log tail. UUID, VLESS
  Encryption material, XHTTP path, encoded forms and complete `vless://` URIs
  are removed from the full input before the tail is bounded and written with
  mode `0600`.

Threats not solved by this project:

- a compromised operator host or GitHub account;
- metadata visible to shared hosting (IP addresses, XHTTP path, timing, sizes);
- hosting-provider policy enforcement or traffic limits;
- an SSH key fingerprint accepted without independent verification;
- a backend firewall incorrectly confirmed by the operator;
- an incorrect or later-changed frontend egress IPv4 supplied by the operator;
- compromise of the optional trusted bridge;
- traffic analysis by network operators;
- client applications that silently discard the VLESS Encryption parameter.
- client applications that discard `pcs` (causing failure for an otherwise
  invalid certificate, or a silent fallback to public PKI when the certificate
  is otherwise valid), and unnoticed certificate renewal that makes an
  intentionally pinned client unavailable.

Do not include real credentials, handoff files, VLESS URIs, server dumps, or
`.env` files in bug reports.
