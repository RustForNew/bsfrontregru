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
  authenticates one short-lived foreground ControlMaster per bounded logical
  transaction, then runs every isolated `sftp -b` batch in that transaction only
  through the private control socket. A slave has `ProxyCommand=/bin/false` and
  all authentication methods disabled, so a missing master cannot reconnect or
  fall back to a direct path. Passwords are not placed in argv, regular files,
  config files, or environment values.
- The PC wizard discovers exit, optional bridge and SFTP host keys before
  password authentication, accepts the first supported key for each endpoint
  as TOFU, and atomically persists it in an endpoint-scoped private store.
  Subsequent runs validate and seed from that exact local record without another
  unauthenticated `ssh-keyscan`, then immediately make a real OpenSSH connection
  with `StrictHostKeyChecking=yes`, `GlobalKnownHostsFile=/dev/null`, and
  `UpdateHostKeys=no`. That handshake rejects disappearance or change of the
  pinned key before authentication or remote mutation; adding another key type
  does not silently replace it. This removes manual fingerprints but does not
  independently authenticate the first network contact. Root passwords use the
  same private FIFO transport.
- Ready-made credential blocks remain available only in advanced modes. They
  are read from the controlling Linux/WSL terminal with echo disabled for the
  whole bounded paste. The minimal PC wizard instead asks for each credential
  separately with hidden password input. PC mode disables core dumps before
  reading credentials. The program cannot clear the host clipboard or its
  history.
- REG.RU endpoints are restricted to ISPmanager login URLs on the known
  `vip<digits>.hosting.reg.ru:1500` or
  `server<digits>.hosting.reg.ru:1500` node families with a known path before
  the panel secret is requested or sent. The endpoint uses the system CA store,
  rejects redirects and has no userinfo, query or fragment. The PC flow performs
  only login and a read-only exact site lookup; it never creates or edits a site.
- The panel password is tried once as the primary-account SFTP password. A
  separate hidden SFTP password is requested, up to three total authentication
  attempts, only after
  a structured OpenSSH authentication failure. Network, TLS and document-root
  errors never trigger credential guessing. Reflected remote errors are
  redacted without a secret-bearing exception chain.
- PC mode uses one SFTP authentication for document-root discovery, one for
  each of the independently rolled-back `302` and local `[P]` controls, one for
  each of three independently rolled-back `[P]` frontend egress samples, and one
  for the final frontend transaction through post-apply E2E and any rollback. It
  never opens
  a new authenticated SSH master for every individual file command. Long remote
  exit/front apply phases close the upload session and open a separate bounded
  download session afterwards instead of keeping one idle for up to 900 seconds.
  If an authenticated master dies after a possibly completed mutation, that
  mutation is never replayed. Only a transport-only rollback failure may open
  one fresh pinned session to reconcile the existing journal. A state conflict,
  a mixed failure, or unsuccessful reconciliation remains an incomplete
  rollback and blocks automatic continuation.
- ISPmanager document roots are resolved with at most two read-only,
  non-guessing interpretations. The exact validated API path is tried first.
  Only one allowlisted OpenSSH `No such file` diagnostic permits a second path
  formed from the authenticated SFTP start directory plus the same API path.
  Every successful probe must return an unambiguous absolute `pwd`; a
  user-rooted result (including a canonicalized in-tree symlink) must remain
  below that start directory. Permission/mixed diagnostics, malformed output,
  escape, and post-authentication transport changes fail closed and never
  trigger another password prompt.
- The optional PC bridge is a trusted, setup-only SSH control-plane host. PC
  mode uses fixed bridge TCP/22, hidden password input and one TOFU-pinned
  ControlMaster, then requires `id -u` to return `0`. The bridge password is
  consumed by the same FIFO-backed askpass mechanism and is not stored in argv,
  environment values, regular files or recovery state.
- When selected, loopback-only forwards carry ISPmanager HTTPS, SFTP and its
  first-use keyscan, frontend TLS, both local canary requests, all three
  TCP/8083 probe waves and final E2E frontend TCP. ISPmanager and
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
- Direct exit commands are grouped into explicitly scoped, pinned OpenSSH
  ControlMaster sessions instead of authenticating once per probe or package
  check. Multiplexed children have `ProxyCommand=/bin/false`, `BatchMode=yes`
  and every authentication/agent method disabled, so a missing control socket
  cannot reconnect or fall back. Firewall transitions deliberately require a
  separate fresh pinned root connection while the prior master remains alive
  for an authorized rollback. Transport loss never causes an automatic command
  replay; only an explicitly idempotent cleanup or already-authorized rollback
  may open a separate recovery session. OpenSSH transport diagnostics are
  bounded, allowlisted and secret-redacted before they become user-facing.
- Remote firewall automation is fail-closed and restricted to clean supported
  Debian/Ubuntu hosts. Fresh preparation accepts only the exact current-port SSH
  guard created by this flow. A proven resume may contain that guard plus the
  complete exact managed allow/deny pair bound to the saved profile. The whole
  numbered/user-rule inventory is checked; empty, foreign, uncommented,
  duplicate, partial and wrong-port states are rejected. For a pristine inactive
  UFW, the PC flow installs only allowlisted prerequisites, adds the actual
  SSH-port allow before enabling UFW, arms a bounded systemd rollback guard, and
  verifies a fresh SSH connection both before and after quiescing its timer and
  service. The timer must report active before the first firewall mutation. It
  only disables UFW and never deletes the sole SSH allow after a failed disable.
  UFW 0.36.x's official `(None)` marker is treated as an empty persistent rule
  inventory; the marker mixed with commands, unknown payload lines and stderr
  diagnostics still fail closed. A no-END `user.rules`/`user6.rules` package
  seed is accepted only when its complete text matches the local template
  previously checked by `dpkg --verify`. A rewritten file is accepted only
  when the complete file matches an upstream-generated empty UFW 0.36.x layout
  for one of the five logging levels and either rate-limit-chain capability.
  Extra, missing, reordered or foreign content anywhere in either form fails
  closed; an empty delimited RULES body alone is not sufficient.
  After a failed first enable, a package seed may legitimately become a complete
  approved empty rewrite and leave an inert dual-stack UFW scaffold. Recovery is
  accepted only after guard quiescence and a fresh-SSH proof of inactive UFW, no
  saved user commands, approved persistent files, ACCEPT base policies, no
  executable UFW-chain rules and no custom firewall state. Failure reporting
  separately probes whether the rollback guard is armed, inactive or of unknown
  state.
  A later run detects and reconciles an owned stale guard or exact dormant SSH
  rule. It never edits provider cloud firewalls, merges custom nftables/iptables,
  or disables a standalone firewall service.
- The firewall proof assumes a clean supported host and no concurrent privileged
  actor. Local locking prevents a second wizard in the same state directory, but
  it is not a distributed lock against another controller or a root operator.
  Persistent UFW user rules are checked strictly; distribution-owned `ufw-*`
  chain names are not cryptographic ownership evidence for pre-edited raw
  `before/after` files or injected internal-chain contents. Such hosts are
  outside the automatic merge contract and require manual audit or replacement.
- Fixed human-oriented command labels and headers are compared as normalized
  word sequences, ignoring only presentation case, whitespace and punctuation.
  Extra or missing words remain semantic changes. Machine fields, paths, unit
  state tokens, rule bodies, keys, identifiers and comments retain their strict
  owning-module validation; unknown payload and stderr diagnostics fail closed.
  The sole bounded stderr exception is nft's iptables-nft ownership notice: stdout
  is validated first, every notice must semantically identify an `ip` or `ip6`
  `filter` table managed by `iptables-nft`, the notice set must exactly match the
  validated stdout table set, and duplicates are rejected. Only presentation
  case, whitespace and punctuation may vary; mixed or unknown diagnostics fail.
- Before any new mutation of a fresh exit, PC mode exercises one secret URL in
  two separate `.htaccess` CAS transactions. The exact `[R=302,L]` route must
  return HTTP 302; after its byte-exact rollback, a literal `[P,L]` route to
  `http://127.0.0.1:9/<nonce>` is observed. HTTP 502, 503 or 504 is a strong
  positive; another bounded HTTP or post-send outcome remains unconfirmed and
  proceeds to the authoritative three-wave TCP/8083 capture. The second result
  is classified only after its own byte-exact rollback. TLS/pre-send failure or
  incomplete rollback stops before fresh exit/UFW preparation.
  The upstream authority and path are generated literals: no
  request data, backreference, query or user input can select a proxy target.
  This paired gate checks bounded local Apache/mod_rewrite/`[P]` handling; it
  neither enables PHP/FastCGI, `mod_proxy` or `mod_proxy_http`, nor proves
  external egress or a complete live E2E.
- Frontend egress discovery uses three separate, deadline-complete captures on
  the actual final backend TCP/8083. Every HTTPS wave has a fresh CSPRNG suffix,
  every capture must contain at least three independent SYN source endpoints,
  and all three waves must identify the same public IPv4. A fresh or unverified
  pending installation also proves TCP/8083 free before and after every wave;
  an occupied listener is accepted only after the existing managed Xray PID,
  receipt, config and service were verified during exact resume.
  Each capture starts only after its temporary `.htaccess` route is installed;
  a packet-cap exit, a wrong destination port, too few endpoints, no public
  source, multiple sources in one sample, or different sources across samples
  fails closed. After agreement, the wizard prints the measured `/32` and blocks
  at an interactive checkpoint before exit apply/E2E. When a provider firewall
  exists, the operator must restrict TCP/8083 to that `/32` before continuing;
  no-firewall installations simply acknowledge the same checkpoint.
  TCP/8083 is predictable, so this remains bounded probabilistic attribution,
  not cryptographic proof against a targeted continuous scanner, SYN spoofing or
  an on-path attacker. The final authenticated Xray E2E remains mandatory and no
  client profile is issued from the SYN measurement alone.
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
  `exact_recovery=failed`, an unfinished exact reconciliation, or an incomplete
  rollback is a manual-audit STOP condition; it is never treated as a generic
  transport retry. Only a completed exact recovery or a proven pre-mutation
  failure permits the bounded retry described by the operator documentation.
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
