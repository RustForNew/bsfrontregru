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
  actually support Xray's `pinnedPeerCertSha256` / URI `pcs` parameter. A
  different explicitly pinned leaf is never accepted automatically. Migration to a
  public-CA certificate is allowed only after normal CA and hostname
  verification succeeds.
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
- The PC wizard discovers exit, optional bridge and SFTP host keys before
  password authentication, accepts the first supported key for each endpoint
  as TOFU, and persists it in an endpoint-scoped private store. Later
  disappearance or change of that exact key is rejected; adding another key
  type does not silently replace it. This removes manual fingerprints but does
  not independently authenticate the first network contact. Root passwords use
  the same private FIFO transport.
- Ready-made credential blocks remain available only in advanced modes. They
  are read from the controlling Linux/WSL terminal with echo disabled for the
  whole bounded paste. The minimal PC wizard instead asks for each credential
  separately with hidden password input. PC mode disables core dumps before
  reading credentials. The program cannot clear the host clipboard or its
  history.
- REG.RU endpoints are restricted to ISPmanager login URLs on
  `vip<digits>.hosting.reg.ru:1500` with a known path before the panel secret is
  requested or sent. The endpoint uses the system CA store, rejects redirects
  and has no userinfo, query or fragment. The PC flow performs only login and a
  read-only exact site lookup; it never creates or edits a site.
- The panel password is tried once as the primary-account SFTP password. A
  separate hidden SFTP password is requested, up to three total authentication
  attempts, only after
  a structured OpenSSH authentication failure. Network, TLS and document-root
  errors never trigger credential guessing. Reflected remote errors are
  redacted without a secret-bearing exception chain.
- The optional PC bridge is a trusted, setup-only SSH control-plane host. PC
  mode uses fixed bridge TCP/22, hidden password input and one TOFU-pinned
  ControlMaster, then requires `id -u` to return `0`. The bridge password is
  consumed by the same FIFO-backed askpass mechanism and is not stored in argv,
  environment values, regular files or recovery state.
- When selected, loopback-only forwards carry ISPmanager HTTPS, SFTP/keyscan,
  frontend TLS, temporary-probe HTTPS and final E2E frontend TCP. ISPmanager and
  frontend TLS retain their logical hostname/SNI checks, while SFTP remains a
  nested host-key-checked SSH connection. Exit SSH is always direct from the
  controller and DNS resolution remains local. The bridge session is closed at
  success or failure; no Xray is installed there, and the bridge is absent from
  `client.vless`, the VLESS URI and the post-setup datapath.
- A bridge is nevertheless a privileged network position and must be trusted.
  Its root can observe endpoint metadata, disrupt or redirect forwarded
  connections, and can attack a first-use SFTP TOFU decision. Public PKI or an
  already-pinned endpoint still fails closed on a mismatched identity, but the
  bridge is not a substitute for independent first-contact verification.
- The separate legacy/advanced remote-front workflow is not the optional PC
  bridge. That older mode uploads bounded staging material and relays one SFTP
  password line over an already pinned SSH command; its wider bridge exposure
  does not describe the current PC forwarding design.
- Remote firewall automation is fail-closed and restricted to clean supported
  Debian/Ubuntu hosts. An already-active compatible UFW is preserved. For a
  pristine inactive UFW, the PC flow installs only allowlisted prerequisites,
  adds the actual SSH-port allow before enabling UFW, arms a bounded systemd
  rollback guard, and verifies a fresh SSH connection both before and after
  quiescing its timer and service. A later run detects and reconciles an owned
  stale guard or the single exact pre-guard SSH rule; unexpected/additional
  rules remain fail-closed.
  It never edits provider cloud firewalls, merges custom nftables/iptables, or
  disables a standalone firewall service.
- The Windows bundle does not implement a second SSH stack. Its PowerShell
  launcher verifies the bundled runner and Linux zipapp SHA-256, prepares the
  allowlisted Ubuntu/Debian dependencies when needed, and starts that same
  controller inside one selected WSL2 distribution. Enabling WSL itself may
  still require Windows administrator rights and a reboot.
- UUID, VLESS Encryption material, handoff, backups and client URI are secrets.
- Xray runs as a dedicated unprivileged user and does not replace another Xray
  service.
- Managed state/lock paths reject symlinks and unexpected ownership or modes.
  The complete PC flow holds one nonblocking private lock. Phase and write-once
  pending markers bind interrupted work to the exact endpoint, UUID, XHTTP path
  and egress values without storing passwords or VLESS Encryption material.
  Incomplete frontend rollback phases refuse automatic continuation.
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
- a first-use SSH/SFTP key or explicitly pinned leaf accepted without independent
  verification;
- a missing or incorrectly configured provider cloud firewall;
- a later change of frontend egress IPv4 (automatic `/32` migration is refused);
- compromise of the optional trusted bridge;
- traffic analysis by network operators;
- client applications that silently discard the VLESS Encryption parameter.
- client applications that discard `pcs` (causing failure for an otherwise
  invalid certificate, or a silent fallback to public PKI when the certificate
  is otherwise valid), and unnoticed certificate renewal that makes an
  intentionally pinned client unavailable.

Do not include real credentials, handoff files, VLESS URIs, server dumps, or
`.env` files in bug reports.
