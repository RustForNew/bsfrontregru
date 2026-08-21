import subprocess
import unittest
from dataclasses import dataclass

import xhttp_setup.remote_network as subject
from xhttp_setup.errors import InstallerError, ValidationError, VerificationError
from xhttp_setup.exit_network import ExitNetworkProfile
from xhttp_setup.remote_network import (
    RemoteExitNetworkError,
    RemoteExitNetworkRecovery,
    apply_remote_exit_network,
    preflight_remote_exit_network,
    reconcile_remote_exit_network,
    rollback_remote_exit_network,
)
from xhttp_setup.ssh_transport import SSHTransportError


@dataclass
class FakeUfwRule:
    port: int
    action: str
    source: str
    comment: str
    ipv6: bool = False

    def render(self, index: int) -> str:
        family = " (v6)" if self.ipv6 else ""
        comment = f" # {self.comment}" if self.comment else ""
        return (
            f"[{index:2d}] {self.port}/tcp{family} {self.action} IN "
            f"{self.source}{family}{comment}"
        )


def completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout=stdout,
        stderr=stderr,
    )


def active_nft_ruleset() -> str:
    tables = []
    for family, prefix in (("ip", "ufw-"), ("ip6", "ufw6-")):
        tables.append(
            f"""table {family} filter {{
 chain {prefix}before-input {{
  ct state related,established accept
 }}
 chain {prefix}before-output {{
 }}
 chain {prefix}before-forward {{
 }}
 chain INPUT {{
  type filter hook input priority filter; policy drop;
  counter packets 0 bytes 0 jump {prefix}before-input
 }}
 chain OUTPUT {{
  type filter hook output priority filter; policy accept;
  counter packets 0 bytes 0 jump {prefix}before-output
 }}
 chain FORWARD {{
  type filter hook forward priority filter; policy drop;
  counter packets 0 bytes 0 jump {prefix}before-forward
 }}
}}
"""
        )
    return "".join(tables)


def active_iptables_ruleset(prefix: str) -> str:
    return f"""*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:{prefix}before-input - [0:0]
:{prefix}before-output - [0:0]
:{prefix}before-forward - [0:0]
-A INPUT -j {prefix}before-input
-A OUTPUT -j {prefix}before-output
-A FORWARD -j {prefix}before-forward
-A {prefix}before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
"""


class FakeSSH:
    def __init__(self):
        self.uid = 0
        self.os_id = "debian"
        self.docker_units = ""
        self.docker_units_returncode = 1
        self.docker_units_stderr = ""
        self.nft_active = (3, "inactive\n")
        self.nft_enabled = (1, "disabled\n")
        self.nft_active_stderr = ""
        self.nft_enabled_stderr = ""
        self.nft_ruleset = active_nft_ruleset()
        self.nft_stderr = ""
        self.iptables_ruleset = active_iptables_ruleset("ufw-")
        self.ip6tables_ruleset = active_iptables_ruleset("ufw6-")
        self.iptables_stderr = ""
        self.ip6tables_stderr = ""
        self.ufw_active = True
        self.ufw_status_stderr = ""
        self.ufw_status_extra = ""
        self.rules = [
            FakeUfwRule(
                22,
                "ALLOW",
                "Anywhere",
                "xhttp-setup-ssh-guard-22",
            )
        ]
        self.show_added_commands: list[str] | None = None
        self.calls: list[tuple[tuple[str, ...], int]] = []
        self.fail_deny = False
        self.transport_after_allow = False
        self.transport_after_deny = False
        self.interrupt_after_allow = False
        self.fail_post_mutation_id = False
        self.fresh_transport_failure = False
        self.fail_delete_comments: set[str] = set()
        self.id_calls = 0
        self.fresh_calls = 0

    def _ufw_output(self) -> str:
        if not self.ufw_active:
            return "Status: inactive\n"
        lines = ["Status: active"]
        lines.extend(rule.render(index) for index, rule in enumerate(self.rules, 1))
        return "\n".join(lines) + "\n" + self.ufw_status_extra

    def _show_added(self) -> str:
        header = "Added user rules (see 'ufw status' for running firewall):"
        if self.show_added_commands is not None:
            return "\n".join([header, *self.show_added_commands]) + "\n"
        commands: list[str] = []
        seen: set[str] = set()
        for rule in self.rules:
            if rule.comment in seen:
                continue
            seen.add(rule.comment)
            if rule.comment == f"xhttp-setup-ssh-guard-{rule.port}":
                command = f"ufw allow {rule.port}/tcp comment {rule.comment}"
            elif rule.comment.startswith("xhttp-setup-allow-"):
                command = (
                    f"ufw allow from {rule.source}/32 to any port {rule.port} "
                    f"proto tcp comment {rule.comment}"
                )
            elif rule.comment.startswith("xhttp-setup-deny-"):
                command = (
                    f"ufw deny to any port {rule.port} proto tcp comment {rule.comment}"
                )
            elif rule.comment:
                command = f"ufw allow {rule.port}/tcp comment {rule.comment}"
            else:
                command = f"ufw allow {rule.port}/tcp"
            commands.append(command)
        return "\n".join([header, *commands]) + "\n"

    def _ufw(self, argv, inner):
        if inner == ["status", "numbered"]:
            return completed(
                argv,
                stdout=self._ufw_output(),
                stderr=self.ufw_status_stderr,
            )
        if inner == ["show", "added"]:
            return completed(argv, stdout=self._show_added())
        if inner[:3] == ["insert", "1", "allow"]:
            source = inner[inner.index("from") + 1].removesuffix("/32")
            port = int(inner[inner.index("port") + 1])
            comment = inner[inner.index("comment") + 1]
            self.rules.insert(0, FakeUfwRule(port, "ALLOW", source, comment))
            if self.interrupt_after_allow:
                raise KeyboardInterrupt()
            if self.transport_after_allow:
                raise SSHTransportError("simulated transport loss after allow")
            return completed(argv, stdout="Rule inserted\n")
        if len(inner) >= 3 and inner[0] == "insert" and inner[2] == "deny":
            if self.fail_deny:
                return completed(argv, returncode=1, stderr="simulated failure")
            index = int(inner[1])
            port = int(inner[inner.index("port") + 1])
            comment = inner[inner.index("comment") + 1]
            self.rules.insert(
                index - 1,
                FakeUfwRule(port, "DENY", "Anywhere", comment),
            )
            if self.transport_after_deny:
                raise SSHTransportError("simulated transport loss after deny")
            return completed(argv, stdout="Rule inserted\n")
        if inner[:2] == ["--force", "delete"]:
            action = inner[2].upper()
            port = int(inner[inner.index("port") + 1])
            comment = inner[inner.index("comment") + 1]
            source = (
                inner[inner.index("from") + 1].removesuffix("/32")
                if "from" in inner
                else "Anywhere"
            )
            if comment in self.fail_delete_comments:
                return completed(argv, returncode=1, stderr="simulated delete failure")
            self.rules = [
                rule
                for rule in self.rules
                if not (
                    rule.port == port
                    and rule.action == action
                    and rule.source == source
                    and rule.comment == comment
                )
            ]
            return completed(argv, stdout="Rule deleted\n")
        raise AssertionError(f"unexpected UFW command: {inner!r}")

    def command(self, argv, *, check=True, timeout=300):
        del check
        command = list(argv)
        self.calls.append((tuple(command), timeout))
        if command == ["id", "-u"]:
            self.id_calls += 1
            if self.fail_post_mutation_id and self.id_calls > 1:
                return completed(command, returncode=255, stderr="connection lost")
            return completed(command, stdout=f"{self.uid}\n")
        if command == ["cat", "/etc/os-release"]:
            return completed(command, stdout=f"ID={self.os_id}\n")
        if command[:2] == ["systemctl", "list-unit-files"]:
            return completed(
                command,
                returncode=self.docker_units_returncode,
                stdout=self.docker_units,
                stderr=self.docker_units_stderr,
            )
        if command == [
            "env",
            "LC_ALL=C",
            "LANG=C",
            "systemctl",
            "is-active",
            "nftables.service",
        ]:
            code, output = self.nft_active
            return completed(
                command,
                returncode=code,
                stdout=output,
                stderr=self.nft_active_stderr,
            )
        if command == [
            "env",
            "LC_ALL=C",
            "LANG=C",
            "systemctl",
            "is-enabled",
            "nftables.service",
        ]:
            code, output = self.nft_enabled
            return completed(
                command,
                returncode=code,
                stdout=output,
                stderr=self.nft_enabled_stderr,
            )
        if command == ["nft", "list", "ruleset"]:
            return completed(command, stdout=self.nft_ruleset, stderr=self.nft_stderr)
        if command == ["iptables-save"]:
            return completed(
                command,
                stdout=self.iptables_ruleset,
                stderr=self.iptables_stderr,
            )
        if command == ["ip6tables-save"]:
            return completed(
                command,
                stdout=self.ip6tables_ruleset,
                stderr=self.ip6tables_stderr,
            )
        if command[:4] == ["env", "LC_ALL=C", "LANG=C", "ufw"]:
            return self._ufw(command, command[4:])
        raise AssertionError(f"unexpected SSH command: {command!r}")

    def fresh_command(self, argv, *, check=True, timeout=300):
        self.fresh_calls += 1
        if self.fresh_transport_failure:
            raise SSHTransportError("simulated independent fresh proof failure")
        return self.command(argv, check=check, timeout=timeout)


class RemoteNetworkTests(unittest.TestCase):
    def setUp(self):
        self.profile = ExitNetworkProfile("198.51.100.20", 8083)

    def test_numbered_status_accepts_presentation_variants(self):
        output = (
            " STATUS, ACTIVE!\n"
            "To   Action   From\n"
            "--- -------- -----\n"
            "[ 1] 22/tcp ALLOW IN Anywhere # xhttp-setup-ssh-guard-22\n"
        )

        self.assertEqual(
            subject._numbered_rules(output),
            [(1, "22/tcp ALLOW IN Anywhere", "xhttp-setup-ssh-guard-22")],
        )

    def test_numbered_status_rejects_semantic_extra_text(self):
        with self.assertRaisesRegex(VerificationError, "Некорректный вывод"):
            subject._numbered_rules("Status: active, degraded\n")

    @staticmethod
    def _commands(ssh: FakeSSH) -> list[tuple[str, ...]]:
        return [command for command, _timeout in ssh.calls]

    @staticmethod
    def _managed(ssh: FakeSSH) -> list[FakeUfwRule]:
        return [
            rule
            for rule in ssh.rules
            if rule.comment.startswith(("xhttp-setup-allow-", "xhttp-setup-deny-"))
        ]

    def test_preflight_requires_direct_root_without_mutation(self):
        ssh = FakeSSH()
        ssh.uid = 1000

        with self.assertRaisesRegex(InstallerError, "root"):
            preflight_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(self._commands(ssh), [("id", "-u")])
        self.assertEqual(self._managed(ssh), [])

    def test_preflight_rejects_docker_and_custom_nftables(self):
        cases = []
        docker = FakeSSH()
        docker.docker_units = "docker.service enabled enabled\n"
        docker.docker_units_returncode = 0
        cases.append((docker, "Docker"))
        custom_nft = FakeSSH()
        custom_nft.nft_ruleset = "table inet custom {\n}\n"
        cases.append((custom_nft, "custom nftables"))

        for ssh, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(InstallerError, message):
                    preflight_remote_exit_network(ssh, self.profile, ssh_port=22)
                self.assertEqual(self._managed(ssh), [])
                self.assertFalse(
                    any("insert" in command for command in self._commands(ssh))
                )

    def test_absent_docker_unit_patterns_returncode_one_is_clean(self):
        ssh = FakeSSH()
        ssh.docker_units_returncode = 1

        state = preflight_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(state.os_id, "debian")
        self.assertIn(
            (
                "systemctl",
                "list-unit-files",
                "--no-legend",
                "--no-pager",
                "docker.service",
                "docker.socket",
                "containerd.service",
            ),
            self._commands(ssh),
        )

    def test_docker_unit_query_error_fails_closed(self):
        ssh = FakeSSH()
        ssh.docker_units_returncode = 2
        ssh.docker_units_stderr = "systemctl failed\n"

        with self.assertRaisesRegex(InstallerError, "код 2"):
            subject._reject_docker_units(ssh)

    def test_docker_unit_response_matrix_rejects_every_nonclean_shape(self):
        cases = (
            (0, "", "", "неоднозначный список"),
            (
                0,
                "docker.service enabled enabled\n",
                "warning\n",
                "неоднозначную диагностику",
            ),
            (0, "podman.service enabled enabled\n", "", "неоднозначный список"),
            (
                0,
                "docker.service enabled enabled\npodman.service enabled enabled\n",
                "",
                "неоднозначный список",
            ),
            (1, "docker.service enabled enabled\n", "", "код 1"),
            (1, "", "warning\n", "код 1"),
        )
        for code, stdout, stderr, message in cases:
            with self.subTest(code=code, stdout=stdout, stderr=stderr):
                ssh = FakeSSH()
                ssh.docker_units_returncode = code
                ssh.docker_units = stdout
                ssh.docker_units_stderr = stderr
                with self.assertRaisesRegex(InstallerError, message):
                    subject._reject_docker_units(ssh)

    def test_missing_nftables_unit_diagnostic_is_clean(self):
        ssh = FakeSSH()
        ssh.nft_active = (3, "inactive\n")
        ssh.nft_enabled = (1, "")
        ssh.nft_enabled_stderr = (
            "Failed to get unit file state for nftables.service: "
            "No such file or directory\n"
        )

        subject._reject_nftables_service(ssh)

    def test_unknown_nftables_unit_diagnostic_fails_closed(self):
        ssh = FakeSSH()
        ssh.nft_enabled = (1, "")
        ssh.nft_enabled_stderr = "unexpected systemctl error\n"

        with self.assertRaisesRegex(InstallerError, "enablement"):
            subject._reject_nftables_service(ssh)

    def test_preflight_allows_only_ufw_shaped_nft_rules(self):
        ssh = FakeSSH()
        ssh.nft_ruleset = "# managed through iptables-nft\n" + active_nft_ruleset()

        state = preflight_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(state.os_id, "debian")

    def test_missing_nftables_unit_diagnostic_ignores_presentation(self):
        ssh = FakeSSH()
        ssh.nft_enabled = (1, "")
        ssh.nft_enabled_stderr = (
            "FAILED to get unit-file state for nftables.service!  "
            "No such file or directory.\n"
        )

        state = preflight_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(state.os_id, "debian")
        self.assertEqual(state.ufw_allow_indices, ())

    def test_dual_stack_family_and_all_inspector_outputs_are_fail_closed(self):
        clean = FakeSSH()
        state = preflight_remote_exit_network(clean, self.profile, ssh_port=22)
        self.assertEqual(state.os_id, "debian")

        cross_family = FakeSSH()
        cross_family.nft_ruleset = cross_family.nft_ruleset.replace(
            "ufw6-before-input",
            "ufw-before-input",
        )
        with self.assertRaisesRegex(InstallerError, "custom nftables chain"):
            preflight_remote_exit_network(cross_family, self.profile, ssh_port=22)

        ipv6_foreign = FakeSSH()
        ipv6_foreign.ip6tables_ruleset = ipv6_foreign.ip6tables_ruleset.replace(
            "-A INPUT -j ufw6-before-input",
            "-A INPUT -p tcp --dport 9999 -j ACCEPT\n-A INPUT -j ufw6-before-input",
        )
        with self.assertRaisesRegex(InstallerError, "custom iptables base-chain"):
            preflight_remote_exit_network(ipv6_foreign, self.profile, ssh_port=22)

        warning = FakeSSH()
        warning.iptables_stderr = "legacy tables present\n"
        with self.assertRaisesRegex(InstallerError, "предупреждение"):
            preflight_remote_exit_network(warning, self.profile, ssh_port=22)

    def test_inactive_ufw_fails_without_enabling_or_changing_defaults(self):
        ssh = FakeSSH()
        ssh.ufw_active = False

        with self.assertRaisesRegex(InstallerError, "inactive/unknown"):
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        ufw_calls = [
            command[4:]
            for command in self._commands(ssh)
            if command[:4]
            == (
                "env",
                "LC_ALL=C",
                "LANG=C",
                "ufw",
            )
        ]
        self.assertEqual(ufw_calls, [("status", "numbered")])
        self.assertEqual(self._managed(ssh), [])

    def test_preflight_rejects_empty_foreign_uncommented_and_duplicate_rules(self):
        empty = FakeSSH()
        empty.rules = []
        foreign = FakeSSH()
        foreign.rules.append(FakeUfwRule(443, "ALLOW", "Anywhere", "foreign"))
        uncommented = FakeSSH()
        uncommented.rules.append(FakeUfwRule(443, "ALLOW", "Anywhere", ""))
        duplicate_guard = FakeSSH()
        duplicate_guard.rules.append(
            FakeUfwRule(22, "ALLOW", "Anywhere", "xhttp-setup-ssh-guard-22")
        )
        cases = (
            (empty, "SSH guard"),
            (foreign, "foreign"),
            (uncommented, "без managed comment"),
            (duplicate_guard, "SSH guard"),
        )

        for ssh, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(InstallerError, message):
                    preflight_remote_exit_network(ssh, self.profile, ssh_port=22)
                self.assertFalse(
                    any("insert" in command for command in self._commands(ssh))
                )

    def test_preflight_requires_current_port_and_exact_guard_command(self):
        wrong_port = FakeSSH()
        with self.assertRaisesRegex(InstallerError, "foreign"):
            preflight_remote_exit_network(
                wrong_port,
                self.profile,
                ssh_port=2222,
            )

        wrong_semantics = FakeSSH()
        wrong_semantics.rules = [
            FakeUfwRule(
                2222,
                "ALLOW",
                "Anywhere",
                "xhttp-setup-ssh-guard-22",
            )
        ]
        wrong_semantics.show_added_commands = [
            "ufw allow 22/tcp comment xhttp-setup-ssh-guard-22"
        ]
        with self.assertRaisesRegex(InstallerError, "exact managed SSH guard"):
            preflight_remote_exit_network(
                wrong_semantics,
                self.profile,
                ssh_port=22,
            )

        wrong_command = FakeSSH()
        wrong_command.show_added_commands = [
            "ufw allow 2222/tcp comment xhttp-setup-ssh-guard-22"
        ]
        with self.assertRaisesRegex(InstallerError, "exact managed rule"):
            preflight_remote_exit_network(
                wrong_command,
                self.profile,
                ssh_port=22,
            )

        duplicate_command = FakeSSH()
        duplicate_command.show_added_commands = [
            "ufw allow 22/tcp comment xhttp-setup-ssh-guard-22",
            "ufw allow 22/tcp comment xhttp-setup-ssh-guard-22",
        ]
        with self.assertRaisesRegex(InstallerError, "show added"):
            preflight_remote_exit_network(
                duplicate_command,
                self.profile,
                ssh_port=22,
            )

    def test_ufw_status_warning_or_unknown_stdout_fails_closed(self):
        warning = FakeSSH()
        warning.ufw_status_stderr = "legacy backend warning\n"
        with self.assertRaisesRegex(VerificationError, "предупреждение"):
            preflight_remote_exit_network(warning, self.profile, ssh_port=22)

        unknown = FakeSSH()
        unknown.ufw_status_extra = "unexpected status diagnostic\n"
        with self.assertRaisesRegex(VerificationError, "Некорректный вывод"):
            preflight_remote_exit_network(unknown, self.profile, ssh_port=22)

    def test_ipv4_guard_is_required_and_ipv6_counterparts_are_optional(self):
        dual_guard = FakeSSH()
        dual_guard.rules.append(
            FakeUfwRule(
                22,
                "ALLOW",
                "Anywhere",
                "xhttp-setup-ssh-guard-22",
                ipv6=True,
            )
        )
        state = preflight_remote_exit_network(
            dual_guard,
            self.profile,
            ssh_port=22,
        )
        self.assertEqual(state.ufw_allow_indices, ())
        self.assertEqual(state.ufw_deny_indices, ())

        v6_only = FakeSSH()
        v6_only.rules = [
            FakeUfwRule(
                22,
                "ALLOW",
                "Anywhere",
                "xhttp-setup-ssh-guard-22",
                ipv6=True,
            )
        ]
        with self.assertRaisesRegex(InstallerError, "SSH guard"):
            preflight_remote_exit_network(v6_only, self.profile, ssh_port=22)

    def test_complete_pair_accepts_optional_ipv6_deny_as_one_logical_rule(self):
        ssh = FakeSSH()
        ssh.rules = [
            FakeUfwRule(
                8083,
                "ALLOW",
                "198.51.100.20",
                "xhttp-setup-allow-8083-198.51.100.20",
            ),
            FakeUfwRule(
                8083,
                "DENY",
                "Anywhere",
                "xhttp-setup-deny-8083",
            ),
            FakeUfwRule(
                22,
                "ALLOW",
                "Anywhere",
                "xhttp-setup-ssh-guard-22",
            ),
            FakeUfwRule(
                8083,
                "DENY",
                "Anywhere",
                "xhttp-setup-deny-8083",
                ipv6=True,
            ),
        ]

        result = apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(result.ssh_port, 22)
        self.assertFalse(result.ufw_allow_added)
        self.assertFalse(result.ufw_deny_added)
        self.assertEqual(len(self._managed(ssh)), 3)

    def test_nondefault_ssh_port_is_validated_and_persisted(self):
        ssh = FakeSSH()
        ssh.rules = [
            FakeUfwRule(
                2222,
                "ALLOW",
                "Anywhere",
                "xhttp-setup-ssh-guard-2222",
            )
        ]

        result = apply_remote_exit_network(ssh, self.profile, ssh_port=2222)

        self.assertEqual(result.ssh_port, 2222)
        self.assertEqual(
            [rule.comment for rule in ssh.rules][-1],
            "xhttp-setup-ssh-guard-2222",
        )

    def test_backend_port_equal_to_ssh_port_is_rejected_before_commands(self):
        ssh = FakeSSH()

        with self.assertRaisesRegex(ValidationError, "SSH-портом"):
            apply_remote_exit_network(ssh, self.profile, ssh_port=8083)

        self.assertEqual(ssh.calls, [])

    def test_apply_inserts_exact_pair_in_order_and_rechecks_ssh(self):
        ssh = FakeSSH()

        result = apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertTrue(result.ufw_allow_added)
        self.assertTrue(result.ufw_deny_added)
        self.assertEqual(ssh.rules[0].source, "198.51.100.20")
        self.assertEqual(ssh.rules[0].action, "ALLOW")
        self.assertEqual(ssh.rules[1].action, "DENY")
        self.assertEqual(ssh.rules[2].comment, "xhttp-setup-ssh-guard-22")
        self.assertEqual(ssh.fresh_calls, 1)
        commands = self._commands(ssh)
        allow = (
            "env",
            "LC_ALL=C",
            "LANG=C",
            "ufw",
            "insert",
            "1",
            "allow",
            "from",
            "198.51.100.20/32",
            "to",
            "any",
            "port",
            "8083",
            "proto",
            "tcp",
            "comment",
            result.allow_comment,
        )
        deny = (
            "env",
            "LC_ALL=C",
            "LANG=C",
            "ufw",
            "insert",
            "2",
            "deny",
            "to",
            "any",
            "port",
            "8083",
            "proto",
            "tcp",
            "comment",
            result.deny_comment,
        )
        self.assertLess(commands.index(allow), commands.index(deny))
        self.assertGreater(commands.index(("id", "-u"), 1), commands.index(deny))
        self.assertEqual(ssh.id_calls, 2)
        self.assertTrue(all(0 < timeout <= 30 for _command, timeout in ssh.calls))
        for command in commands:
            if command[:4] == ("env", "LC_ALL=C", "LANG=C", "ufw"):
                self.assertNotIn(command[4], {"enable", "disable", "default", "reset"})

    def test_second_apply_and_its_rollback_do_not_touch_preexisting_rules(self):
        ssh = FakeSSH()
        first = apply_remote_exit_network(ssh, self.profile, ssh_port=22)
        second = apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertFalse(second.ufw_allow_added)
        self.assertFalse(second.ufw_deny_added)
        no_op = rollback_remote_exit_network(ssh, second)
        self.assertFalse(no_op.ufw_allow_removed)
        self.assertFalse(no_op.ufw_deny_removed)
        self.assertEqual(len(self._managed(ssh)), 2)

        removed = rollback_remote_exit_network(ssh, first)
        self.assertTrue(removed.ufw_allow_removed)
        self.assertTrue(removed.ufw_deny_removed)
        self.assertEqual(self._managed(ssh), [])
        self.assertEqual(
            [rule.comment for rule in ssh.rules],
            ["xhttp-setup-ssh-guard-22"],
        )
        self.assertEqual(ssh.fresh_calls, 2)

    def test_preexisting_pair_read_transport_loss_needs_no_recovery(self):
        ssh = FakeSSH()
        apply_remote_exit_network(ssh, self.profile, ssh_port=22)
        before = list(ssh.rules)
        ssh.calls.clear()

        original_command = ssh.command
        status_reads = 0
        transport_broken = False

        def fail_after_preflight(argv, *, check=True, timeout=300):
            nonlocal status_reads, transport_broken
            if transport_broken:
                raise SSHTransportError("simulated broken scoped session")
            if list(argv)[-3:] == ["ufw", "status", "numbered"]:
                status_reads += 1
                if status_reads == 2:
                    transport_broken = True
                    raise SSHTransportError("simulated read transport loss")
            return original_command(argv, check=check, timeout=timeout)

        ssh.command = fail_after_preflight
        with self.assertRaises(SSHTransportError) as raised:
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertNotIsInstance(raised.exception, RemoteExitNetworkError)
        self.assertEqual(ssh.rules, before)
        self.assertFalse(
            any(
                command[4] in {"insert", "--force"}
                for command in self._commands(ssh)
                if len(command) > 4
                and command[:4] == ("env", "LC_ALL=C", "LANG=C", "ufw")
            )
        )

    def test_foreign_rule_blocks_rollback_without_deleting_owned_or_foreign(self):
        ssh = FakeSSH()
        result = apply_remote_exit_network(ssh, self.profile, ssh_port=22)
        foreign = FakeUfwRule(
            8083,
            "ALLOW",
            "198.51.100.20",
            "foreign-same-semantics",
        )
        ssh.rules.append(foreign)

        with self.assertRaisesRegex(InstallerError, "rollback неполон"):
            rollback_remote_exit_network(ssh, result)

        self.assertEqual(len(self._managed(ssh)), 2)
        self.assertIn(foreign, ssh.rules)

    def test_deny_failure_rolls_back_only_allow_added_by_this_call(self):
        ssh = FakeSSH()
        ssh.fail_deny = True

        with self.assertRaisesRegex(InstallerError, "backend deny"):
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(self._managed(ssh), [])
        self.assertEqual(
            [rule.comment for rule in ssh.rules],
            ["xhttp-setup-ssh-guard-22"],
        )

    def test_transport_loss_after_mutation_exposes_exact_recovery_journal(self):
        ssh = FakeSSH()
        ssh.transport_after_allow = True

        with self.assertRaises(RemoteExitNetworkError) as raised:
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        error = raised.exception
        self.assertFalse(error.recovery_completed)
        self.assertEqual(error.recovery.ssh_port, 22)
        self.assertEqual(
            error.recovery.attempted_comments,
            (("UFW frontend allow", "xhttp-setup-allow-8083-198.51.100.20"),),
        )
        self.assertEqual(len(self._managed(ssh)), 1)
        self.assertEqual(
            sum(
                command[4:7] == ("insert", "1", "allow")
                for command in self._commands(ssh)
                if len(command) >= 7
            ),
            1,
        )

        recovery_ssh = FakeSSH()
        recovery_ssh.rules = list(ssh.rules)
        reconciled = reconcile_remote_exit_network(recovery_ssh, error.recovery)

        self.assertTrue(reconciled.ufw_allow_removed)
        self.assertFalse(reconciled.ufw_deny_removed)
        self.assertEqual(self._managed(recovery_ssh), [])
        self.assertEqual(
            [rule.comment for rule in recovery_ssh.rules],
            ["xhttp-setup-ssh-guard-22"],
        )
        self.assertFalse(
            any("insert" in command for command in self._commands(recovery_ssh))
        )

    def test_keyboard_interrupt_after_allow_rolls_back_before_reraise(self):
        ssh = FakeSSH()
        ssh.interrupt_after_allow = True

        with self.assertRaises(KeyboardInterrupt):
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(
            [rule.comment for rule in ssh.rules],
            ["xhttp-setup-ssh-guard-22"],
        )

    def test_keyboard_interrupt_preserved_when_rollback_is_incomplete(self):
        ssh = FakeSSH()
        ssh.interrupt_after_allow = True
        ssh.fail_delete_comments.add("xhttp-setup-allow-8083-198.51.100.20")

        with self.assertRaises(KeyboardInterrupt) as raised:
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertTrue(any("rollback" in note for note in raised.exception.__notes__))
        self.assertEqual(len(self._managed(ssh)), 1)

    def test_recovery_rejects_foreign_or_duplicate_journal_before_commands(self):
        valid = (
            "UFW frontend allow",
            "xhttp-setup-allow-8083-198.51.100.20",
        )
        journals = (
            (("UFW frontend allow", "foreign-comment"),),
            (valid, valid),
        )
        for comments in journals:
            with self.subTest(comments=comments):
                ssh = FakeSSH()
                with self.assertRaises(ValidationError):
                    reconcile_remote_exit_network(
                        ssh,
                        RemoteExitNetworkRecovery(self.profile, 22, comments),
                    )
                self.assertEqual(ssh.calls, [])

    def test_recovery_rejects_forged_or_mismatched_ssh_port(self):
        comment = "xhttp-setup-allow-8083-198.51.100.20"
        invalid = FakeSSH()
        with self.assertRaisesRegex(ValidationError, "SSH-портом"):
            reconcile_remote_exit_network(
                invalid,
                RemoteExitNetworkRecovery(
                    self.profile,
                    8083,
                    (("UFW frontend allow", comment),),
                ),
            )
        self.assertEqual(invalid.calls, [])

        mismatched = FakeSSH()
        attempted = FakeUfwRule(
            8083,
            "ALLOW",
            "198.51.100.20",
            comment,
        )
        mismatched.rules.insert(0, attempted)
        before = list(mismatched.rules)
        with self.assertRaisesRegex(InstallerError, "rollback неполон"):
            reconcile_remote_exit_network(
                mismatched,
                RemoteExitNetworkRecovery(
                    self.profile,
                    2222,
                    (("UFW frontend allow", comment),),
                ),
            )
        self.assertEqual(mismatched.rules, before)
        self.assertFalse(
            any(
                command[4:6] == ("--force", "delete")
                for command in self._commands(mismatched)
                if len(command) >= 6
            )
        )

    def test_transport_loss_after_deny_journals_and_reconciles_both_rules(self):
        ssh = FakeSSH()
        ssh.transport_after_deny = True

        with self.assertRaises(RemoteExitNetworkError) as raised:
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(
            raised.exception.recovery.attempted_comments,
            (
                (
                    "UFW frontend allow",
                    "xhttp-setup-allow-8083-198.51.100.20",
                ),
                ("UFW backend deny", "xhttp-setup-deny-8083"),
            ),
        )
        recovery_ssh = FakeSSH()
        recovery_ssh.rules = list(ssh.rules)
        reconcile_remote_exit_network(recovery_ssh, raised.exception.recovery)

        self.assertEqual(self._managed(recovery_ssh), [])
        self.assertEqual(
            [rule.comment for rule in recovery_ssh.rules],
            ["xhttp-setup-ssh-guard-22"],
        )
        delete_calls = [
            command
            for command in self._commands(recovery_ssh)
            if command[4:6] == ("--force", "delete")
        ]
        self.assertEqual(len(delete_calls), 2)
        self.assertEqual(recovery_ssh.fresh_calls, 0)

    def test_stable_partial_pair_is_rejected_without_mutation(self):
        ssh = FakeSSH()
        ssh.rules.insert(
            0,
            FakeUfwRule(
                8083,
                "ALLOW",
                "198.51.100.20",
                "xhttp-setup-allow-8083-198.51.100.20",
            ),
        )
        with self.assertRaisesRegex(InstallerError, "неполную managed"):
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(len(self._managed(ssh)), 1)
        self.assertEqual(self._managed(ssh)[0].action, "ALLOW")
        self.assertFalse(any("insert" in command for command in self._commands(ssh)))

    def test_post_mutation_ssh_failure_rolls_back_both_rules(self):
        ssh = FakeSSH()
        ssh.fail_post_mutation_id = True

        with self.assertRaisesRegex(InstallerError, "UID"):
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(self._managed(ssh), [])
        self.assertEqual(
            [rule.comment for rule in ssh.rules],
            ["xhttp-setup-ssh-guard-22"],
        )

    def test_fresh_proof_transport_failure_rolls_back_on_healthy_main_mux(self):
        ssh = FakeSSH()
        ssh.fresh_transport_failure = True

        with self.assertRaises(SSHTransportError):
            apply_remote_exit_network(ssh, self.profile, ssh_port=22)

        self.assertEqual(self._managed(ssh), [])
        self.assertEqual(
            [rule.comment for rule in ssh.rules],
            ["xhttp-setup-ssh-guard-22"],
        )
        self.assertEqual(ssh.fresh_calls, 1)
        delete_calls = [
            command
            for command in self._commands(ssh)
            if command[4:7] == ("--force", "delete", "deny")
            or command[4:7] == ("--force", "delete", "allow")
        ]
        self.assertEqual(len(delete_calls), 2)

    def test_explicit_rollback_reports_partial_failure_without_foreign_delete(self):
        ssh = FakeSSH()
        result = apply_remote_exit_network(ssh, self.profile, ssh_port=22)
        ssh.fail_delete_comments.add(result.allow_comment)

        with self.assertRaisesRegex(InstallerError, "rollback неполон"):
            rollback_remote_exit_network(ssh, result)

        self.assertEqual(
            [rule.comment for rule in ssh.rules][-1],
            "xhttp-setup-ssh-guard-22",
        )
        # Deletion failed before the post-rollback fresh proof.
        self.assertEqual(ssh.fresh_calls, 1)
        managed = self._managed(ssh)
        self.assertEqual([rule.comment for rule in managed], [result.allow_comment])


if __name__ == "__main__":
    unittest.main()
