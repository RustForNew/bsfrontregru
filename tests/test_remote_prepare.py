import shlex
import subprocess
import unittest
from unittest.mock import patch

import xhttp_setup.remote_prepare as subject
from xhttp_setup.errors import InstallerError, VerificationError


def completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout=stdout,
        stderr=stderr,
    )


class FakeGuard:
    def __init__(self, *, armed=False, disarm_effect=None, arm_effective=True):
        self.calls = []
        self.armed = armed
        self.disarm_effect = disarm_effect
        self.arm_effective = arm_effective

    def is_armed(self, ssh, *, ssh_port):
        del ssh, ssh_port
        return self.armed

    def arm(self, ssh, *, ssh_port):
        self.calls.append(("arm", ssh_port))
        self.armed = self.arm_effective
        ssh.events.append(("guard", "arm", ssh_port))

    def disarm(self, ssh, *, ssh_port):
        self.calls.append(("disarm", ssh_port))
        if self.disarm_effect is not None:
            effect = self.disarm_effect
            self.disarm_effect = None
            effect(ssh)
        self.armed = False
        ssh.events.append(("guard", "disarm", ssh_port))


class FakeSSH:
    def __init__(self):
        self.uid = 0
        self.pid_one = "systemd"
        self.systemd_state = (0, "running\n")
        self.systemd_states = []
        self.os_release = 'ID=debian\nVERSION_ID="12"\n'
        self.docker_units = ""
        self.docker_units_returncode = 1
        self.docker_units_stderr = ""
        # systemd 259 returns rc=1 for an inactive or absent unit.
        self.nft_active = (1, "inactive\n")
        self.nft_enabled = (1, "disabled\n")
        self.nft_active_stderr = ""
        self.nft_enabled_stderr = ""
        self.tools = {"iptables-save", "ip6tables-save", "nft", "ufw"}
        self.nft_ruleset_override = None
        self.iptables_override = None
        self.ip6tables_override = None
        self.nft_stderr = ""
        self.iptables_stderr = ""
        self.ip6tables_stderr = ""
        self.inactive_ufw_scaffold = False
        self.proc_tables = {"ipv4": "", "ipv6": ""}
        self.ufw_active = False
        self.ufw_rules = []
        self.ufw_show_added_override = None
        self.ufw_show_added_stderr = ""
        self.ufw_defaults = """DEFAULT_INPUT_POLICY=\"DROP\"
DEFAULT_OUTPUT_POLICY=\"ACCEPT\"
DEFAULT_FORWARD_POLICY=\"DROP\"
DEFAULT_APPLICATION_POLICY=\"SKIP\"
MANAGE_BUILTINS=no
IPV6=yes
"""
        self.packages = set(subject._PACKAGES)
        self.package_results = {}
        self.python_version = "3.11\n"
        self.calls = []
        self.events = []
        self.id_calls = 0
        self.fail_fresh_id_once = False
        self.trace_payloads = []
        self.systemd_unit_states = {}
        self.guard_stop_lag_queries = 0
        self.guard_stopping_units = set()
        self.package_verify = (0, "", "")
        self.user_rules = "*filter\n### RULES ###\n\n### END RULES ###\nCOMMIT\n"
        self.user6_rules = "*filter\n### RULES ###\n\n### END RULES ###\nCOMMIT\n"
        self.fail_allow_after_side_effect = False
        self.foreign_rule_after_allow = None
        self.foreign_nft_after_disable = None
        self.fresh_calls = 0

    def _nft_ruleset(self):
        if self.nft_ruleset_override is not None:
            return self.nft_ruleset_override
        if not self.ufw_active and not self.inactive_ufw_scaffold:
            return ""
        policy = "drop" if self.ufw_active else "accept"
        body = "  ct state related,established accept\n" if self.ufw_active else ""
        tables = []
        for family, prefix in (("ip", "ufw-"), ("ip6", "ufw6-")):
            tables.append(
                f"""table {family} filter {{
 chain {prefix}before-input {{
{body} }}
 chain {prefix}before-output {{
 }}
 chain {prefix}before-forward {{
 }}
 chain INPUT {{
  type filter hook input priority filter; policy {policy};
  counter packets 5 bytes 10 jump {prefix}before-input
 }}
 chain OUTPUT {{
  type filter hook output priority filter; policy accept;
  counter packets 6 bytes 20 jump {prefix}before-output
 }}
 chain FORWARD {{
  type filter hook forward priority filter; policy {policy};
  counter packets 0 bytes 0 jump {prefix}before-forward
 }}
}}
"""
            )
        return "".join(tables)

    def _iptables_save(self, *, ipv6=False):
        override = self.ip6tables_override if ipv6 else self.iptables_override
        if override is not None:
            return override
        prefix = "ufw6-" if ipv6 else "ufw-"
        if self.ufw_active or self.inactive_ufw_scaffold:
            input_policy = "DROP" if self.ufw_active else "ACCEPT"
            body = (
                f"-A {prefix}before-input -m conntrack "
                "--ctstate RELATED,ESTABLISHED -j ACCEPT\n"
                if self.ufw_active
                else ""
            )
            return f"""*filter
:INPUT {input_policy} [0:0]
:FORWARD {input_policy} [0:0]
:OUTPUT ACCEPT [0:0]
:{prefix}before-input - [0:0]
:{prefix}before-output - [0:0]
:{prefix}before-forward - [0:0]
-A INPUT -j {prefix}before-input
-A OUTPUT -j {prefix}before-output
-A FORWARD -j {prefix}before-forward
{body}COMMIT
"""
        return """*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
COMMIT
"""

    def _ufw_output(self):
        if not self.ufw_active:
            return "Status: inactive\n"
        return "Status: active\n"

    def _show_added(self):
        if self.ufw_show_added_override is not None:
            return self.ufw_show_added_override
        header = "Added user rules (see 'ufw status' for running firewall):\n"
        if not self.ufw_rules:
            return header + "(None)\n"
        return header + "".join(shlex.join(rule) + "\n" for rule in self.ufw_rules)

    def _ufw(self, command, inner):
        if inner == ["status", "numbered"]:
            return completed(command, stdout=self._ufw_output())
        if inner == ["show", "added"]:
            return completed(
                command,
                stdout=self._show_added(),
                stderr=self.ufw_show_added_stderr,
            )
        if inner[:1] == ["allow"]:
            port = inner[1]
            comment = inner[3]
            self.ufw_rules.append(["ufw", "allow", port, "comment", comment])
            self.events.append(("ufw", "allow"))
            if self.foreign_rule_after_allow is not None:
                self.ufw_rules.append(self.foreign_rule_after_allow)
            if self.fail_allow_after_side_effect:
                return completed(command, returncode=255, stderr="connection lost")
            return completed(command, stdout="Rule added\n")
        if inner == ["--force", "enable"]:
            self.ufw_active = True
            self.events.append(("ufw", "enable"))
            return completed(command, stdout="Firewall is active\n")
        if inner == ["--force", "disable"]:
            self.ufw_active = False
            if self.foreign_nft_after_disable is not None:
                self.nft_ruleset_override = self.foreign_nft_after_disable
            self.events.append(("ufw", "disable"))
            return completed(command, stdout="Firewall stopped\n")
        if inner[:3] == ["--force", "delete", "allow"] and len(inner) == 6:
            port = inner[3]
            comment = inner[5]
            self.ufw_rules = [
                rule
                for rule in self.ufw_rules
                if not (rule[2] == port and rule[4] == comment)
            ]
            self.events.append(("ufw", "delete"))
            return completed(command, stdout="Rule deleted\n")
        raise AssertionError(f"unexpected UFW command: {inner!r}")

    def command(self, argv, *, check=True, timeout=300):
        del check, timeout
        command = list(argv)
        self.calls.append(tuple(command))
        if command == ["id", "-u"]:
            self.id_calls += 1
            if self.fail_fresh_id_once and self.ufw_active:
                self.fail_fresh_id_once = False
                return completed(command, returncode=255, stderr="lost")
            return completed(command, stdout=f"{self.uid}\n")
        if command == ["cat", "/proc/1/comm"]:
            return completed(command, stdout=f"{self.pid_one}\n")
        if command == ["systemctl", "is-system-running"]:
            code, output = (
                self.systemd_states.pop(0)
                if self.systemd_states
                else self.systemd_state
            )
            return completed(command, returncode=code, stdout=output)
        if command == ["cat", "/etc/os-release"]:
            return completed(command, stdout=self.os_release)
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
        if command[:2] == ["command", "-v"]:
            name = command[2]
            if name in self.tools:
                return completed(command, stdout=f"/usr/sbin/{name}\n")
            return completed(command, returncode=1)
        if command == ["nft", "list", "ruleset"]:
            return completed(
                command, stdout=self._nft_ruleset(), stderr=self.nft_stderr
            )
        if command == ["iptables-save"]:
            return completed(
                command,
                stdout=self._iptables_save(ipv6=False),
                stderr=self.iptables_stderr,
            )
        if command == ["ip6tables-save"]:
            return completed(
                command,
                stdout=self._iptables_save(ipv6=True),
                stderr=self.ip6tables_stderr,
            )
        if command == ["cat", "/proc/net/ip_tables_names"]:
            return completed(command, stdout=self.proc_tables["ipv4"])
        if command == ["cat", "/proc/net/ip6_tables_names"]:
            return completed(command, stdout=self.proc_tables["ipv6"])
        if command[:4] == ["env", "LC_ALL=C", "LANG=C", "ufw"]:
            return self._ufw(command, command[4:])
        if command == ["cat", "/etc/default/ufw"]:
            return completed(command, stdout=self.ufw_defaults)
        if command == ["cat", "/etc/ufw/user.rules"]:
            return completed(command, stdout=self.user_rules)
        if command == ["cat", "/etc/ufw/user6.rules"]:
            return completed(command, stdout=self.user6_rules)
        if command == ["env", "LC_ALL=C", "LANG=C", "dpkg", "--verify", "ufw"]:
            code, stdout, stderr = self.package_verify
            return completed(command, returncode=code, stdout=stdout, stderr=stderr)
        if command[:6] == [
            "env",
            "LC_ALL=C",
            "LANG=C",
            "dpkg-query",
            "--show",
            "--showformat=${db:Status-Abbrev}",
        ]:
            package = command[6]
            if package in self.package_results:
                code, stdout, stderr = self.package_results[package]
                return completed(
                    command, returncode=code, stdout=stdout, stderr=stderr
                )
            if package in self.packages:
                return completed(command, stdout="ii ")
            return completed(command, stdout="un ")
        if "apt-get" in command:
            apt_index = command.index("apt-get")
            operation = command[apt_index + 3]
            if command[apt_index + 1 : apt_index + 3] != [
                "-o",
                f"DPkg::Lock::Timeout={subject._APT_LOCK_SECONDS}",
            ]:
                raise AssertionError("apt lock timeout missing")
            self.events.append(("apt", operation))
            if operation == "install":
                separator = command.index("--")
                self.packages.update(command[separator + 1 :])
            return completed(command)
        if command[:2] == ["python3", "-c"]:
            return completed(command, stdout=self.python_version)
        if "curl" in command and command[-1] == subject._EGRESS_URL:
            if not self.trace_payloads:
                raise AssertionError("no trace payload")
            return completed(command, stdout=self.trace_payloads.pop(0))
        if command and command[0] == "systemd-run":
            unit_arg = next(part for part in command if part.startswith("--unit="))
            unit = unit_arg.partition("=")[2]
            self.systemd_unit_states[f"{unit}.timer"] = (0, "active\n")
            self.systemd_unit_states[f"{unit}.service"] = (1, "inactive\n")
            return completed(command)
        if command[0:2] == ["systemctl", "stop"]:
            for unit in command[2:]:
                self.systemd_unit_states[unit] = (1, "inactive\n")
            if self.guard_stop_lag_queries:
                self.guard_stopping_units = set(command[2:])
            return completed(command)
        if command[0:2] == ["systemctl", "is-active"]:
            if (
                command[2] in self.guard_stopping_units
                and self.guard_stop_lag_queries > 0
            ):
                self.guard_stop_lag_queries -= 1
                return completed(command, stdout="active\n")
            if command[2] in self.systemd_unit_states:
                code, output = self.systemd_unit_states[command[2]]
                return completed(command, returncode=code, stdout=output)
            return completed(command, returncode=1, stdout="inactive\n")
        raise AssertionError(f"unexpected SSH command: {command!r}")

    def fresh_command(self, argv, *, check=True, timeout=300):
        self.fresh_calls += 1
        self.events.append(("ssh", "fresh"))
        return self.command(argv, check=check, timeout=timeout)


class RemotePrepareTests(unittest.TestCase):
    @staticmethod
    def _index(events, value):
        return events.index(value)

    def test_inactive_pristine_ufw_is_enabled_in_safe_order(self):
        ssh = FakeSSH()
        guard = FakeGuard()

        result = subject.prepare_remote_exit(
            ssh,
            ssh_port=22,
            rollback_guard=guard,
        )

        self.assertTrue(result.ufw_enabled)
        self.assertTrue(result.ssh_rule_added)
        self.assertFalse(result.ufw_was_active)
        self.assertEqual(result.newly_installed_packages, ())
        self.assertTrue(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [subject._expected_ssh_rule(22)])
        self.assertLess(
            self._index(ssh.events, ("guard", "arm", 22)),
            self._index(ssh.events, ("ufw", "allow")),
        )
        self.assertLess(
            self._index(ssh.events, ("ufw", "allow")),
            self._index(ssh.events, ("ufw", "enable")),
        )
        self.assertLess(
            self._index(ssh.events, ("ufw", "enable")),
            self._index(ssh.events, ("guard", "disarm", 22)),
        )
        self.assertEqual(ssh.id_calls, 3)
        self.assertEqual(ssh.fresh_calls, 2)
        flat = " ".join(" ".join(call) for call in ssh.calls)
        self.assertNotIn("ufw reset", flat)
        self.assertNotIn("ufw default", flat)

    def test_waits_for_booting_systemd_but_rejects_timeout_or_bad_state(self):
        booting = FakeSSH()
        booting.ufw_active = True
        booting.ufw_rules = [subject._expected_ssh_rule(22)]
        booting.systemd_states = [(1, "starting\n"), (0, "running\n")]
        with patch("xhttp_setup.remote_prepare.time.sleep") as sleep:
            subject.prepare_remote_exit(booting, ssh_port=22)
        sleep.assert_called_once_with(subject._SYSTEMD_POLL_SECONDS)
        self.assertEqual(booting.fresh_calls, 0)

        timed_out = FakeSSH()
        timed_out.systemd_state = (1, "starting\n")
        with (
            patch(
                "xhttp_setup.remote_prepare.time.monotonic",
                side_effect=(0, subject._SYSTEMD_READY_SECONDS + 1),
            ),
            self.assertRaisesRegex(InstallerError, "120 секунд"),
        ):
            subject.prepare_remote_exit(timed_out, ssh_port=22)

        maintenance = FakeSSH()
        maintenance.systemd_state = (1, "maintenance\n")
        with self.assertRaisesRegex(InstallerError, "рабочем состоянии"):
            subject.prepare_remote_exit(maintenance, ssh_port=22)

    def test_dirty_inactive_ufw_and_custom_iptables_rejected_before_mutation(self):
        dirty_ufw = FakeSSH()
        dirty_ufw.packages.remove("tcpdump")
        dirty_ufw.ufw_rules = [["ufw", "allow", "80/tcp"]]

        custom_iptables = FakeSSH()
        custom_iptables.packages.remove("tcpdump")
        custom_iptables.iptables_override = """*filter
:INPUT ACCEPT [0:0]
:FORWARD ACCEPT [0:0]
:OUTPUT ACCEPT [0:0]
-A INPUT -p tcp --dport 80 -j ACCEPT
COMMIT
"""

        for ssh, message in (
            (dirty_ufw, "foreign rules"),
            (custom_iptables, "custom iptables"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(InstallerError, message):
                    subject.prepare_remote_exit(
                        ssh,
                        ssh_port=22,
                        rollback_guard=FakeGuard(),
                    )
                self.assertFalse(ssh.events)

    def test_disable_only_guard_success_leaves_dormant_rule_for_next_prepare(self):
        ssh = FakeSSH()
        # A successful disable-only timer makes UFW inactive but deliberately
        # leaves its exact SSH rule as the durable recovery state.
        ssh.ufw_active = True
        ssh.ufw_rules = [subject._expected_ssh_rule(22)]
        ssh.ufw_active = False
        guard = FakeGuard()

        result = subject.prepare_remote_exit(
            ssh,
            ssh_port=22,
            rollback_guard=guard,
        )

        self.assertTrue(result.ufw_enabled)
        self.assertTrue(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [subject._expected_ssh_rule(22)])
        self.assertEqual(guard.calls, [("arm", 22), ("disarm", 22)])
        self.assertLess(
            self._index(ssh.events, ("ufw", "delete")),
            self._index(ssh.events, ("ufw", "allow")),
        )

    def test_orphan_recovery_never_removes_an_additional_rule(self):
        ssh = FakeSSH()
        ssh.ufw_rules = [
            subject._expected_ssh_rule(22),
            ["ufw", "allow", "80/tcp", "comment", "foreign"],
        ]

        with self.assertRaisesRegex(InstallerError, "foreign rules"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=FakeGuard(),
            )

        self.assertEqual(
            ssh.ufw_rules,
            [
                subject._expected_ssh_rule(22),
                ["ufw", "allow", "80/tcp", "comment", "foreign"],
            ],
        )
        self.assertFalse(ssh.events)

    def test_container_and_old_os_are_rejected(self):
        docker = FakeSSH()
        docker.docker_units = "docker.service enabled enabled\n"
        docker.docker_units_returncode = 0
        old_ubuntu = FakeSSH()
        old_ubuntu.os_release = 'ID=ubuntu\nVERSION_ID="20.04"\n'

        for ssh, message in ((docker, "Docker"), (old_ubuntu, "Ubuntu 22.04")):
            with self.subTest(message=message):
                with self.assertRaisesRegex(InstallerError, message):
                    subject.prepare_remote_exit(
                        ssh,
                        ssh_port=22,
                        rollback_guard=FakeGuard(),
                    )
                self.assertFalse(ssh.events)

    def test_absent_container_unit_patterns_returncode_one_is_clean(self):
        ssh = FakeSSH()
        ssh.docker_units_returncode = 1

        subject._reject_container_runtime(ssh)
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
            ssh.calls,
        )

    def test_container_unit_query_errors_or_ambiguous_output_fail_closed(self):
        failed = FakeSSH()
        failed.docker_units_returncode = 2
        failed.docker_units_stderr = "systemctl failed\n"
        with self.assertRaisesRegex(InstallerError, "код 2"):
            subject._reject_container_runtime(failed)

        ambiguous = FakeSSH()
        ambiguous.docker_units_returncode = 1
        ambiguous.docker_units_stderr = "unexpected warning\n"
        with self.assertRaisesRegex(InstallerError, "код 1"):
            subject._reject_container_runtime(ambiguous)

    def test_container_unit_response_matrix_rejects_every_nonclean_shape(self):
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
                    subject._reject_container_runtime(ssh)

    def test_missing_nftables_unit_diagnostic_is_clean(self):
        ssh = FakeSSH()
        ssh.nft_active = (3, "inactive\n")
        ssh.nft_enabled = (1, "")
        ssh.nft_enabled_stderr = (
            "Failed to get unit file state for nftables.service: "
            "No such file or directory\n"
        )

        subject._reject_standalone_nftables_service(ssh)

    def test_unknown_nftables_unit_diagnostic_fails_closed(self):
        ssh = FakeSSH()
        ssh.nft_enabled = (1, "")
        ssh.nft_enabled_stderr = "unexpected systemctl error\n"

        with self.assertRaisesRegex(InstallerError, "enablement"):
            subject._reject_standalone_nftables_service(ssh)

    def test_active_exact_owned_ssh_guard_is_an_idempotent_no_op(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        ssh.ufw_rules = [subject._expected_ssh_rule(22)]
        guard = FakeGuard()

        first = subject.prepare_remote_exit(
            ssh,
            ssh_port=22,
            rollback_guard=guard,
        )
        second = subject.prepare_remote_exit(
            ssh,
            ssh_port=22,
            rollback_guard=guard,
        )

        self.assertFalse(first.ufw_enabled)
        self.assertFalse(first.ssh_rule_added)
        self.assertFalse(second.ufw_enabled)
        self.assertEqual(guard.calls, [])
        self.assertFalse(any(event[0] in {"apt", "ufw"} for event in ssh.events))
        self.assertEqual(ssh.ufw_rules, [subject._expected_ssh_rule(22)])

    def test_active_ufw_rejects_non_owned_or_ambiguous_saved_rules(self):
        expected = subject._expected_ssh_rule(22)
        cases = {
            "empty": [],
            "foreign": [["ufw", "allow", "22/tcp", "comment", "foreign-ssh"]],
            "additional": [
                expected,
                ["ufw", "allow", "80/tcp", "comment", "foreign-http"],
            ],
            "different-port": [subject._expected_ssh_rule(2222)],
        }
        for name, rules in cases.items():
            with self.subTest(name=name):
                ssh = FakeSSH()
                ssh.ufw_active = True
                ssh.ufw_rules = rules
                ssh.packages.remove("tcpdump")

                with self.assertRaisesRegex(InstallerError, "exact managed SSH rule"):
                    subject.prepare_remote_exit(
                        ssh,
                        ssh_port=22,
                        rollback_guard=FakeGuard(),
                    )

                self.assertFalse(ssh.events)

    def test_ufw_show_added_diagnostics_and_unknown_lines_fail_closed(self):
        cases = ("stderr", "garbage")
        for name in cases:
            with self.subTest(name=name):
                ssh = FakeSSH()
                ssh.ufw_active = True
                ssh.ufw_rules = [subject._expected_ssh_rule(22)]
                ssh.packages.remove("tcpdump")
                if name == "stderr":
                    ssh.ufw_show_added_stderr = "unexpected warning\n"
                else:
                    ssh.ufw_show_added_override = (
                        subject._UFW_SHOW_ADDED_HEADER + "\nunknown state\n"
                    )

                with self.assertRaisesRegex(
                    VerificationError, "диагностику|неизвестную строку"
                ):
                    subject.prepare_remote_exit(
                        ssh,
                        ssh_port=22,
                        rollback_guard=FakeGuard(),
                    )

                self.assertFalse(ssh.events)

    def test_ufw_show_added_accepts_official_empty_marker(self):
        ssh = FakeSSH()
        ssh.ufw_show_added_override = subject._UFW_SHOW_ADDED_HEADER + "\n(None)\n"

        self.assertEqual(subject._ufw_added_commands(ssh), [])

    def test_ufw_show_added_empty_marker_must_be_the_only_payload(self):
        expected = shlex.join(subject._expected_ssh_rule(22))
        cases = (
            f"{subject._UFW_SHOW_ADDED_HEADER}\n(None)\n{expected}\n",
            f"{subject._UFW_SHOW_ADDED_HEADER}\n(None)\n(None)\n",
        )
        for output in cases:
            with self.subTest(output=output):
                ssh = FakeSSH()
                ssh.ufw_show_added_override = output

                with self.assertRaisesRegex(VerificationError, "неизвестную строку"):
                    subject._ufw_added_commands(ssh)

    def test_stale_guard_is_quiesced_before_active_ufw_is_accepted(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        ssh.ufw_rules = [subject._expected_ssh_rule(22)]
        guard = FakeGuard(armed=True)

        result = subject.prepare_remote_exit(
            ssh,
            ssh_port=22,
            rollback_guard=guard,
        )

        self.assertFalse(guard.armed)
        self.assertEqual(guard.calls, [("disarm", 22)])
        self.assertTrue(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [subject._expected_ssh_rule(22)])
        self.assertFalse(result.ufw_enabled)
        self.assertGreaterEqual(ssh.id_calls, 3)

    def test_real_systemd_stale_timer_and_service_are_both_stopped(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        ssh.ufw_rules = [subject._expected_ssh_rule(2222)]
        unit = "xhttp-setup-ufw-rollback-2222"
        ssh.systemd_unit_states[f"{unit}.timer"] = (0, "active\n")
        ssh.systemd_unit_states[f"{unit}.service"] = (0, "active\n")

        result = subject.prepare_remote_exit(ssh, ssh_port=2222)

        self.assertFalse(result.ufw_enabled)
        self.assertTrue(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [subject._expected_ssh_rule(2222)])
        stop = next(call for call in ssh.calls if call[:2] == ("systemctl", "stop"))
        self.assertEqual(
            stop[2:],
            (f"{unit}.timer", f"{unit}.service"),
        )
        self.assertEqual(
            ssh.systemd_unit_states,
            {
                f"{unit}.timer": (1, "inactive\n"),
                f"{unit}.service": (1, "inactive\n"),
            },
        )

    def test_stale_guard_with_unexpected_rules_is_left_armed(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        ssh.ufw_rules = [
            subject._expected_ssh_rule(22),
            ["ufw", "allow", "80/tcp", "comment", "foreign"],
        ]
        guard = FakeGuard(armed=True)

        with self.assertRaisesRegex(InstallerError, "неожиданными rules"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=guard,
            )

        self.assertTrue(guard.armed)
        self.assertEqual(guard.calls, [])

    def test_guard_service_race_is_quiesced_and_pristine_ufw_reenabled(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        ssh.ufw_rules = [subject._expected_ssh_rule(22)]

        def finish_rollback(target):
            target.ufw_active = False
            target.ufw_rules = []
            target.events.append(("guard", "service-finished"))

        guard = FakeGuard(armed=True, disarm_effect=finish_rollback)

        result = subject.prepare_remote_exit(
            ssh,
            ssh_port=22,
            rollback_guard=guard,
        )

        self.assertTrue(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [subject._expected_ssh_rule(22)])
        self.assertTrue(result.ufw_enabled)
        self.assertFalse(guard.armed)
        self.assertEqual(guard.calls, [("disarm", 22), ("arm", 22), ("disarm", 22)])

    def test_apt_installs_only_missing_allowlisted_packages(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        ssh.ufw_rules = [subject._expected_ssh_rule(2222)]
        ssh.packages.difference_update({"curl", "tcpdump"})

        result = subject.prepare_remote_exit(
            ssh,
            ssh_port=2222,
            rollback_guard=FakeGuard(),
        )

        self.assertEqual(result.newly_installed_packages, ("curl", "tcpdump"))
        install = next(call for call in ssh.calls if "install" in call)
        apt_index = install.index("apt-get")
        self.assertEqual(
            install[apt_index + 1 : apt_index + 3],
            ("-o", "DPkg::Lock::Timeout=180"),
        )
        self.assertEqual(install[install.index("--") + 1 :], ("curl", "tcpdump"))
        self.assertEqual(
            [event for event in ssh.events if event[0] == "apt"],
            [("apt", "update"), ("apt", "install")],
        )

    def test_package_query_accepts_only_exact_clean_missing_states(self):
        known_missing = FakeSSH()
        known_missing.packages.remove("ufw")
        self.assertIn("ufw", subject._missing_packages(known_missing))

        unknown_missing = FakeSSH()
        unknown_missing.package_results["ufw"] = (
            1,
            "",
            "dpkg-query: no packages found matching ufw\n",
        )
        self.assertIn("ufw", subject._missing_packages(unknown_missing))

        bad_shapes = (
            (0, "rc ", ""),
            (0, "un ", "warning\n"),
            (1, "", "unexpected error\n"),
            (2, "", "dpkg database error\n"),
        )
        for code, stdout, stderr in bad_shapes:
            with self.subTest(code=code, stdout=stdout, stderr=stderr):
                broken = FakeSSH()
                broken.package_results["ufw"] = (code, stdout, stderr)
                with self.assertRaisesRegex(InstallerError, "пакет ufw"):
                    subject._missing_packages(broken)

    def test_failed_fresh_ssh_verification_restores_inactive_ufw(self):
        ssh = FakeSSH()
        ssh.fail_fresh_id_once = True
        guard = FakeGuard()

        with self.assertRaisesRegex(InstallerError, "inactive-состояние восстановлено"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=guard,
            )

        self.assertFalse(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [])
        self.assertEqual(guard.calls, [("arm", 22), ("disarm", 22)])
        self.assertLess(
            self._index(ssh.events, ("ufw", "disable")),
            self._index(ssh.events, ("ufw", "delete")),
        )

    def test_unarmed_guard_aborts_before_first_ufw_mutation(self):
        ssh = FakeSSH()
        guard = FakeGuard(arm_effective=False)

        with self.assertRaisesRegex(InstallerError, "guard-verify"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=guard,
            )

        self.assertFalse(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [])
        self.assertEqual(guard.calls, [("arm", 22), ("disarm", 22)])
        self.assertFalse(any(event[0] == "ufw" for event in ssh.events))

    def test_inactive_dual_stack_ufw_scaffold_is_a_safe_baseline(self):
        ssh = FakeSSH()
        ssh.inactive_ufw_scaffold = True

        result = subject.prepare_remote_exit(
            ssh,
            ssh_port=22,
            rollback_guard=FakeGuard(),
        )

        self.assertTrue(result.ufw_enabled)
        self.assertTrue(ssh.ufw_active)
        subject._validate_nft_ruleset(ssh._nft_ruleset(), allow_ufw=True)
        subject._validate_iptables_save(
            ssh._iptables_save(ipv6=True),
            allow_ufw=True,
            ufw_prefix="ufw6-",
        )

    def test_allow_error_after_side_effect_is_rolled_back_under_guard(self):
        ssh = FakeSSH()
        ssh.fail_allow_after_side_effect = True
        guard = FakeGuard()

        with self.assertRaisesRegex(InstallerError, "inactive-состояние восстановлено"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=guard,
            )

        self.assertEqual(ssh.ufw_rules, [])
        self.assertFalse(guard.armed)
        self.assertLess(
            self._index(ssh.events, ("guard", "arm", 22)),
            self._index(ssh.events, ("ufw", "allow")),
        )
        self.assertIn(("ufw", "delete"), ssh.events)

    def test_rollback_never_deletes_concurrent_same_port_foreign_comment(self):
        ssh = FakeSSH()
        foreign = ["ufw", "allow", "22/tcp", "comment", "foreign-same-port"]
        ssh.foreign_rule_after_allow = foreign
        ssh.fail_allow_after_side_effect = True
        guard = FakeGuard()

        with self.assertRaisesRegex(InstallerError, "guard оставлен активным"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=guard,
            )

        self.assertEqual(ssh.ufw_rules, [foreign])
        self.assertTrue(guard.armed)

    def test_kernel_baseline_mismatch_cannot_be_reported_as_rollback_success(self):
        ssh = FakeSSH()
        ssh.fail_fresh_id_once = True
        ssh.foreign_nft_after_disable = "table inet foreign {\n}\n"
        guard = FakeGuard()

        with self.assertRaisesRegex(InstallerError, "guard оставлен активным"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=guard,
            )

        self.assertTrue(guard.armed)

    def test_modified_package_or_dormant_user_rules_fail_before_mutation(self):
        modified = FakeSSH()
        modified.package_verify = (
            0,
            "??5?????? c /etc/ufw/before.rules\n",
            "",
        )
        dormant = FakeSSH()
        dormant.user_rules = (
            "*filter\n### RULES ###\n-A ufw-user-input -p tcp --dport 80 "
            "-j ACCEPT\n### END RULES ###\nCOMMIT\n"
        )

        for ssh, message in (
            (modified, "configuration изменена"),
            (dormant, "dormant user rules"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(InstallerError, message):
                    subject.prepare_remote_exit(
                        ssh,
                        ssh_port=22,
                        rollback_guard=FakeGuard(),
                    )
                self.assertFalse(ssh.events)

    def test_minimal_image_missing_only_ufw_docs_is_accepted(self):
        ssh = FakeSSH()
        ssh.package_verify = (
            0,
            "missing     /usr/share/doc/ufw/README.gz\n"
            "missing     /usr/share/man/man8/ufw.8.gz\n",
            "",
        )

        subject._verify_ufw_package_integrity(ssh)

    def test_cross_family_ufw_and_inspector_warnings_fail_closed(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        cross_family = ssh._nft_ruleset().replace(
            "ufw6-before-input",
            "ufw-before-input",
        )
        with self.assertRaisesRegex(InstallerError, "custom nftables chain"):
            subject._validate_nft_ruleset(cross_family, allow_ufw=True)

        warning = FakeSSH()
        warning.nft_stderr = "warning: incomplete ruleset\n"
        with self.assertRaisesRegex(VerificationError, "диагностику"):
            subject._inspect_firewall(warning, ufw_active=False)

        warning = FakeSSH()
        warning.ip6tables_stderr = "legacy tables present\n"
        with self.assertRaisesRegex(VerificationError, "предупреждение"):
            subject._inspect_firewall(warning, ufw_active=False)

    def test_firewall_snapshot_ignores_only_runtime_counters_and_comments(self):
        nft_a = "# first\ncounter packets 1 bytes 2 jump ufw-before-input\n"
        nft_b = "# second\ncounter packets 99 bytes 200 jump ufw-before-input\n"
        self.assertEqual(subject._canonical_nft(nft_a), subject._canonical_nft(nft_b))
        ipt_a = ":INPUT ACCEPT [1:2]\n# generated now\n"
        ipt_b = ":INPUT ACCEPT [99:200]\n# generated later\n"
        self.assertEqual(
            subject._canonical_iptables(ipt_a),
            subject._canonical_iptables(ipt_b),
        )

    def test_guard_service_race_at_normal_disarm_cannot_report_success(self):
        ssh = FakeSSH()

        def finish_rollback(target):
            target.ufw_active = False
            target.ufw_rules = []
            target.events.append(("guard", "service-finished"))

        guard = FakeGuard(disarm_effect=finish_rollback)

        with self.assertRaisesRegex(InstallerError, "inactive-состояние восстановлено"):
            subject.prepare_remote_exit(
                ssh,
                ssh_port=22,
                rollback_guard=guard,
            )

        self.assertFalse(ssh.ufw_active)
        self.assertEqual(ssh.ufw_rules, [])
        self.assertFalse(guard.armed)
        self.assertEqual(guard.calls, [("arm", 22), ("disarm", 22)])
        self.assertIn(("guard", "service-finished"), ssh.events)

    def test_systemd_guard_schedules_exact_bounded_rollback(self):
        ssh = FakeSSH()
        guard = subject._SystemdUfwRollbackGuard()

        guard.arm(ssh, ssh_port=2222)
        guard.disarm(ssh, ssh_port=2222)

        arm = next(call for call in ssh.calls if call[0] == "systemd-run")
        self.assertIn("--on-active=120s", arm)
        self.assertIn("--unit=xhttp-setup-ufw-rollback-2222", arm)
        self.assertNotIn("sh", arm)
        script = arm[arm.index("-c") + 1]
        self.assertIn("/usr/sbin/ufw", script)
        self.assertIn("'--force','disable'", script)
        self.assertNotIn("delete", script)
        self.assertIs(arm[-1], script)
        stop = next(call for call in ssh.calls if call[:2] == ("systemctl", "stop"))
        self.assertEqual(
            stop[2:],
            (
                "xhttp-setup-ufw-rollback-2222.timer",
                "xhttp-setup-ufw-rollback-2222.service",
            ),
        )

    def test_systemd_guard_propagates_disable_failure_without_delete(self):
        for returncode in (0, 17):
            with self.subTest(returncode=returncode):
                result = completed(["ufw", "disable"], returncode=returncode)
                with patch("subprocess.run", return_value=result) as run:
                    with self.assertRaises(SystemExit) as raised:
                        exec(subject._SystemdUfwRollbackGuard._SCRIPT, {})

                self.assertEqual(raised.exception.code, returncode)
                run.assert_called_once_with(
                    ["/usr/sbin/ufw", "--force", "disable"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    check=False,
                )

    def test_systemd_guard_accepts_real_rc1_inactive_but_rejects_ambiguity(self):
        ssh = FakeSSH()
        guard = subject._SystemdUfwRollbackGuard()

        self.assertFalse(guard.is_armed(ssh, ssh_port=22))

        unit = "xhttp-setup-ufw-rollback-22"
        ssh.systemd_unit_states[f"{unit}.timer"] = (0, "inactive\n")
        with self.assertRaisesRegex(VerificationError, "неоднозначно"):
            guard.is_armed(ssh, ssh_port=22)

    def test_systemd_guard_disarm_waits_for_transient_active_state(self):
        ssh = FakeSSH()
        guard = subject._SystemdUfwRollbackGuard()
        unit = "xhttp-setup-ufw-rollback-22"
        ssh.systemd_unit_states[f"{unit}.timer"] = (0, "active\n")
        ssh.systemd_unit_states[f"{unit}.service"] = (1, "inactive\n")
        ssh.guard_stop_lag_queries = 1

        with patch("xhttp_setup.remote_prepare.time.sleep") as sleep:
            guard.disarm(ssh, ssh_port=22)

        sleep.assert_called_once_with(subject._GUARD_STOP_POLL_SECONDS)
        self.assertFalse(guard.is_armed(ssh, ssh_port=22))

    def test_stable_direct_global_ipv4_is_returned(self):
        ssh = FakeSSH()
        ssh.trace_payloads = ["fl=1\nip=1.1.1.1\nts=1\n"] * 3

        observed = subject.measure_remote_exit_egress(ssh)

        self.assertEqual(observed, "1.1.1.1")
        curl_calls = [call for call in ssh.calls if "curl" in call]
        self.assertEqual(len(curl_calls), 3)
        for command in curl_calls:
            self.assertIn("--noproxy", command)
            self.assertIn("--proxy", command)
            self.assertIn("--ipv4", command)
            for variable in ("http_proxy", "HTTPS_PROXY", "ALL_PROXY"):
                self.assertIn(variable, command)

    def test_unstable_or_private_egress_is_rejected(self):
        unstable = FakeSSH()
        unstable.trace_payloads = [
            "ip=1.1.1.1\n",
            "ip=8.8.8.8\n",
            "ip=1.1.1.1\n",
        ]
        private = FakeSSH()
        private.trace_payloads = ["ip=10.0.0.1\n"] * 3

        with self.assertRaisesRegex(VerificationError, "меняется"):
            subject.measure_remote_exit_egress(unstable)
        with self.assertRaisesRegex(VerificationError, "не глобальный"):
            subject.measure_remote_exit_egress(private)


if __name__ == "__main__":
    unittest.main()
