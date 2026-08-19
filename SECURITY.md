# Security model

- All remote targets are fixed input fields; `.htaccess` never derives an
  upstream from request headers or query parameters.
- Public TLS uses the operating-system trust store and hostname verification.
- SFTP uses `StrictHostKeyChecking=yes` with a dedicated known_hosts file.
- Passwords are read with `getpass` and sent to OpenSSH askpass over an inherited
  one-use pipe. They are not placed in argv, config files, or environment values.
- UUID, VLESS Encryption material, handoff, backups and client URI are secrets.
- Xray runs as a dedicated unprivileged user and does not replace another Xray
  service.
- Managed state/lock paths reject symlinks and unexpected ownership or modes.
- Release and Xray versions are pinned. Checksums, regular-file type, ownership
  and modes are verified by installer install/re-apply. Subsequent systemd
  restarts rely on the root-owned managed directory; they do not re-hash the
  binary before every ExecStart.
- A failed end-to-end probe must not create or print a client URI.

Threats not solved by this project:

- a compromised operator host or GitHub account;
- metadata visible to shared hosting (IP addresses, XHTTP path, timing, sizes);
- hosting-provider policy enforcement or traffic limits;
- an SSH key fingerprint accepted without independent verification;
- a backend firewall incorrectly confirmed by the operator;
- traffic analysis by network operators;
- client applications that silently discard the VLESS Encryption parameter.

Do not include real credentials, handoff files, VLESS URIs, server dumps, or
`.env` files in bug reports.
