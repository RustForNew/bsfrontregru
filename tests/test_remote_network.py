import subprocess
import unittest
from dataclasses import dataclass

from xhttp_setup.errors import InstallerError
from xhttp_setup.exit_network import ExitNetworkProfile
from xhttp_setup.remote_network import (
    apply_remote_exit_network,
    preflight_remote_exit_network,
    rollback_remote_exit_network,
)


@dataclass
class FakeUfwRule:
    port: int
    action: str
    source: str
    comment: str

    def render(self, index: int) -> str:
        return (
            f"[{index:2d}] {self.port}/tcp {self.action} IN {self.source} "
            f"# {self.comment}"
        )


def completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(
        argv,
        returncode,
        stdout=stdout,
        stderr=stderr,
    )


class FakeSSH:
    def __init__(self):
        self.uid = 0
        self.os_id = "debian"
        self.docker_units = ""
        self.nft_active = (3, "inactive\n")
        self.nft_enabled = (1, "disabled\n")
        self.nft_ruleset = ""
        self.ufw_active = True
        self.rules = [FakeUfwRule(22, "ALLOW", "Anywhere", "foreign-ssh")]
        self.calls: list[tuple[tuple[str, ...], int]] = []
        self.fail_deny = False
        self.fail_post_mutation_id = False
        self.fail_delete_comments: set[str] = set()
        self.id_calls = 0

    def _ufw_output(self) -> str:
        if not self.ufw_active:
            return "Status: inactive\n"
        lines = ["Status: active"]
        lines.extend(rule.render(index) for index, rule in enumerate(self.rules, 1))
        return "\n".join(lines) + "\n"

    def _ufw(self, argv, inner):
        if inner == ["status", "numbered"]:
            return completed(argv, stdout=self._ufw_output())
        if inner[:3] == ["insert", "1", "allow"]:
            source = inner[inner.index("from") + 1].removesuffix("/32")
            port = int(inner[inner.index("port") + 1])
            comment = inner[inner.index("comment") + 1]
            self.rules.insert(0, FakeUfwRule(port, "ALLOW", source, comment))
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
            return completed(argv, stdout="Rule inserted\n")
        if inner[:2] == ["--force", "delete"]:
            index = int(inner[2])
            rule = self.rules[index - 1]
            if rule.comment in self.fail_delete_comments:
                return completed(argv, returncode=1, stderr="simulated delete failure")
            del self.rules[index - 1]
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
            return completed(command, stdout=self.docker_units)
        if command == ["systemctl", "is-active", "nftables.service"]:
            code, output = self.nft_active
            return completed(command, returncode=code, stdout=output)
        if command == ["systemctl", "is-enabled", "nftables.service"]:
            code, output = self.nft_enabled
            return completed(command, returncode=code, stdout=output)
        if command == ["nft", "list", "ruleset"]:
            return completed(command, stdout=self.nft_ruleset)
        if command[:4] == ["env", "LC_ALL=C", "LANG=C", "ufw"]:
            return self._ufw(command, command[4:])
        raise AssertionError(f"unexpected SSH command: {command!r}")


class RemoteNetworkTests(unittest.TestCase):
    def setUp(self):
        self.profile = ExitNetworkProfile("198.51.100.20", 8083)

    @staticmethod
    def _commands(ssh: FakeSSH) -> list[tuple[str, ...]]:
        return [command for command, _timeout in ssh.calls]

    @staticmethod
    def _managed(ssh: FakeSSH) -> list[FakeUfwRule]:
        return [rule for rule in ssh.rules if rule.comment.startswith("xhttp-setup-")]

    def test_preflight_requires_direct_root_without_mutation(self):
        ssh = FakeSSH()
        ssh.uid = 1000

        with self.assertRaisesRegex(InstallerError, "root"):
            preflight_remote_exit_network(ssh, self.profile)

        self.assertEqual(self._commands(ssh), [("id", "-u")])
        self.assertEqual(self._managed(ssh), [])

    def test_preflight_rejects_docker_and_custom_nftables(self):
        cases = []
        docker = FakeSSH()
        docker.docker_units = "docker.service enabled enabled\n"
        cases.append((docker, "Docker"))
        custom_nft = FakeSSH()
        custom_nft.nft_ruleset = "table inet custom {\n}\n"
        cases.append((custom_nft, "custom nftables"))

        for ssh, message in cases:
            with self.subTest(message=message):
                with self.assertRaisesRegex(InstallerError, message):
                    preflight_remote_exit_network(ssh, self.profile)
                self.assertEqual(self._managed(ssh), [])
                self.assertFalse(
                    any("insert" in command for command in self._commands(ssh))
                )

    def test_preflight_allows_only_ufw_shaped_nft_rules(self):
        ssh = FakeSSH()
        ssh.nft_ruleset = """# Warning: managed through iptables-nft
table ip filter {
    chain INPUT {
        type filter hook input priority filter; policy drop;
        counter packets 0 bytes 0 jump ufw-before-input
    }
    chain ufw-before-input {
        ct state related,established counter accept
    }
}
"""

        state = preflight_remote_exit_network(ssh, self.profile)

        self.assertEqual(state.os_id, "debian")
        self.assertEqual(state.ufw_allow_indices, ())

    def test_inactive_ufw_fails_without_enabling_or_changing_defaults(self):
        ssh = FakeSSH()
        ssh.ufw_active = False

        with self.assertRaisesRegex(InstallerError, "inactive/unknown"):
            apply_remote_exit_network(ssh, self.profile)

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

    def test_apply_inserts_exact_pair_in_order_and_rechecks_ssh(self):
        ssh = FakeSSH()

        result = apply_remote_exit_network(ssh, self.profile)

        self.assertTrue(result.ufw_allow_added)
        self.assertTrue(result.ufw_deny_added)
        self.assertEqual(ssh.rules[0].source, "198.51.100.20")
        self.assertEqual(ssh.rules[0].action, "ALLOW")
        self.assertEqual(ssh.rules[1].action, "DENY")
        self.assertEqual(ssh.rules[2].comment, "foreign-ssh")
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
        first = apply_remote_exit_network(ssh, self.profile)
        second = apply_remote_exit_network(ssh, self.profile)

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
        self.assertEqual([rule.comment for rule in ssh.rules], ["foreign-ssh"])

    def test_deny_failure_rolls_back_only_allow_added_by_this_call(self):
        ssh = FakeSSH()
        ssh.fail_deny = True

        with self.assertRaisesRegex(InstallerError, "backend deny"):
            apply_remote_exit_network(ssh, self.profile)

        self.assertEqual(self._managed(ssh), [])
        self.assertEqual([rule.comment for rule in ssh.rules], ["foreign-ssh"])

    def test_preexisting_allow_survives_failed_deny(self):
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
        ssh.fail_deny = True

        with self.assertRaisesRegex(InstallerError, "backend deny"):
            apply_remote_exit_network(ssh, self.profile)

        self.assertEqual(len(self._managed(ssh)), 1)
        self.assertEqual(self._managed(ssh)[0].action, "ALLOW")

    def test_post_mutation_ssh_failure_rolls_back_both_rules(self):
        ssh = FakeSSH()
        ssh.fail_post_mutation_id = True

        with self.assertRaisesRegex(InstallerError, "UID"):
            apply_remote_exit_network(ssh, self.profile)

        self.assertEqual(self._managed(ssh), [])
        self.assertEqual([rule.comment for rule in ssh.rules], ["foreign-ssh"])

    def test_explicit_rollback_reports_partial_failure_without_foreign_delete(self):
        ssh = FakeSSH()
        result = apply_remote_exit_network(ssh, self.profile)
        ssh.fail_delete_comments.add(result.allow_comment)

        with self.assertRaisesRegex(InstallerError, "rollback неполон"):
            rollback_remote_exit_network(ssh, result)

        self.assertEqual([rule.comment for rule in ssh.rules][-1], "foreign-ssh")
        managed = self._managed(ssh)
        self.assertEqual([rule.comment for rule in managed], [result.allow_comment])


if __name__ == "__main__":
    unittest.main()
