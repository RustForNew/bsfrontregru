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
    def __init__(self, *, armed=False, disarm_effect=None):
        self.calls = []
        self.armed = armed
        self.disarm_effect = disarm_effect

    def is_armed(self, ssh, *, ssh_port):
        del ssh, ssh_port
        return self.armed

    def arm(self, ssh, *, ssh_port):
        self.calls.append(("arm", ssh_port))
        self.armed = True
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
        # systemd 259 returns rc=1 for an inactive or absent unit.
        self.nft_active = (1, "inactive\n")
        self.nft_enabled = (1, "disabled\n")
        self.tools = {"iptables-save", "nft", "ufw"}
        self.nft_ruleset_override = None
        self.iptables_override = None
        self.proc_tables = {"ipv4": "", "ipv6": ""}
        self.ufw_active = False
        self.ufw_rules = []
        self.ufw_defaults = """DEFAULT_INPUT_POLICY=\"DROP\"
DEFAULT_OUTPUT_POLICY=\"ACCEPT\"
DEFAULT_FORWARD_POLICY=\"DROP\"
DEFAULT_APPLICATION_POLICY=\"SKIP\"
MANAGE_BUILTINS=no
IPV6=yes
"""
        self.packages = set(subject._PACKAGES)
        self.python_version = "3.11\n"
        self.calls = []
        self.events = []
        self.id_calls = 0
        self.fail_fresh_id_once = False
        self.trace_payloads = []
        self.systemd_unit_states = {}

    def _nft_ruleset(self):
        if self.nft_ruleset_override is not None:
            return self.nft_ruleset_override
        if not self.ufw_active:
            return ""
        return """table ip filter {
 chain INPUT {
  type filter hook input priority filter; policy drop;
  jump ufw-before-input
 }
 chain ufw-before-input {
  ct state related,established accept
 }
}
"""

    def _iptables_save(self):
        if self.iptables_override is not None:
            return self.iptables_override
        if self.ufw_active:
            return """*filter
:INPUT DROP [0:0]
:FORWARD DROP [0:0]
:OUTPUT ACCEPT [0:0]
:ufw-before-input - [0:0]
-A INPUT -j ufw-before-input
-A ufw-before-input -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
COMMIT
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
        header = "Added user rules (see 'ufw status' for running firewall):\n"
        return header + "".join(shlex.join(rule) + "\n" for rule in self.ufw_rules)

    def _ufw(self, command, inner):
        if inner == ["status", "numbered"]:
            return completed(command, stdout=self._ufw_output())
        if inner == ["show", "added"]:
            return completed(command, stdout=self._show_added())
        if inner[:1] == ["allow"]:
            port = inner[1]
            comment = inner[3]
            self.ufw_rules.append(["ufw", "allow", port, "comment", comment])
            self.events.append(("ufw", "allow"))
            return completed(command, stdout="Rule added\n")
        if inner == ["--force", "enable"]:
            self.ufw_active = True
            self.events.append(("ufw", "enable"))
            return completed(command, stdout="Firewall is active\n")
        if inner == ["--force", "disable"]:
            self.ufw_active = False
            self.events.append(("ufw", "disable"))
            return completed(command, stdout="Firewall stopped\n")
        if inner[:4] == ["--force", "delete", "allow", inner[-1]]:
            port = inner[-1]
            self.ufw_rules = [rule for rule in self.ufw_rules if rule[2] != port]
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
            return completed(command, stdout=self.docker_units)
        if command == ["systemctl", "is-active", "nftables.service"]:
            code, output = self.nft_active
            return completed(command, returncode=code, stdout=output)
        if command == ["systemctl", "is-enabled", "nftables.service"]:
            code, output = self.nft_enabled
            return completed(command, returncode=code, stdout=output)
        if command[:2] == ["command", "-v"]:
            name = command[2]
            if name in self.tools:
                return completed(command, stdout=f"/usr/sbin/{name}\n")
            return completed(command, returncode=1)
        if command == ["nft", "list", "ruleset"]:
            return completed(command, stdout=self._nft_ruleset())
        if command == ["iptables-save"]:
            return completed(command, stdout=self._iptables_save())
        if command == ["cat", "/proc/net/ip_tables_names"]:
            return completed(command, stdout=self.proc_tables["ipv4"])
        if command == ["cat", "/proc/net/ip6_tables_names"]:
            return completed(command, stdout=self.proc_tables["ipv6"])
        if command[:4] == ["env", "LC_ALL=C", "LANG=C", "ufw"]:
            return self._ufw(command, command[4:])
        if command == ["cat", "/etc/default/ufw"]:
            return completed(command, stdout=self.ufw_defaults)
        if command[:3] == ["dpkg-query", "--show", "--showformat=${db:Status-Abbrev}"]:
            package = command[3]
            if package in self.packages:
                return completed(command, stdout="ii ")
            return completed(command, returncode=1)
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
            return completed(command)
        if command[0:2] == ["systemctl", "is-active"]:
            if command[2] in self.systemd_unit_states:
                code, output = self.systemd_unit_states[command[2]]
                return completed(command, returncode=code, stdout=output)
            return completed(command, returncode=1, stdout="inactive\n")
        raise AssertionError(f"unexpected SSH command: {command!r}")


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
            self._index(ssh.events, ("ufw", "allow")),
            self._index(ssh.events, ("guard", "arm", 22)),
        )
        self.assertLess(
            self._index(ssh.events, ("guard", "arm", 22)),
            self._index(ssh.events, ("ufw", "enable")),
        )
        self.assertLess(
            self._index(ssh.events, ("ufw", "enable")),
            self._index(ssh.events, ("guard", "disarm", 22)),
        )
        self.assertEqual(ssh.id_calls, 3)
        flat = " ".join(" ".join(call) for call in ssh.calls)
        self.assertNotIn("ufw reset", flat)
        self.assertNotIn("ufw default", flat)

    def test_waits_for_booting_systemd_but_rejects_timeout_or_bad_state(self):
        booting = FakeSSH()
        booting.ufw_active = True
        booting.systemd_states = [(1, "starting\n"), (0, "running\n")]
        with patch("xhttp_setup.remote_prepare.time.sleep") as sleep:
            subject.prepare_remote_exit(booting, ssh_port=22)
        sleep.assert_called_once_with(subject._SYSTEMD_POLL_SECONDS)

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

    def test_exact_orphaned_ssh_rule_from_kill_before_guard_is_reconciled(self):
        ssh = FakeSSH()
        ssh.ufw_rules = [subject._expected_ssh_rule(22)]
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

    def test_active_ufw_is_an_idempotent_no_op(self):
        ssh = FakeSSH()
        ssh.ufw_active = True
        ssh.ufw_rules = [["ufw", "allow", "22/tcp", "comment", "foreign-ssh"]]
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
        self.assertEqual(
            ssh.ufw_rules,
            [["ufw", "allow", "22/tcp", "comment", "foreign-ssh"]],
        )

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
        self.assertIn("/usr/sbin/ufw", arm[arm.index("-c") + 1])
        self.assertEqual(arm[-1], "2222")
        stop = next(call for call in ssh.calls if call[:2] == ("systemctl", "stop"))
        self.assertEqual(
            stop[2:],
            (
                "xhttp-setup-ufw-rollback-2222.timer",
                "xhttp-setup-ufw-rollback-2222.service",
            ),
        )

    def test_systemd_guard_accepts_real_rc1_inactive_but_rejects_ambiguity(self):
        ssh = FakeSSH()
        guard = subject._SystemdUfwRollbackGuard()

        self.assertFalse(guard.is_armed(ssh, ssh_port=22))

        unit = "xhttp-setup-ufw-rollback-22"
        ssh.systemd_unit_states[f"{unit}.timer"] = (0, "inactive\n")
        with self.assertRaisesRegex(VerificationError, "неоднозначно"):
            guard.is_armed(ssh, ssh_port=22)

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
