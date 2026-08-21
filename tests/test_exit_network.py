import subprocess
import tempfile
import unittest
import os
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError, ValidationError
from xhttp_setup.exit_network import (
    SYSCTL_MARKER,
    SYSCTL_VALUES,
    ExitNetworkLayout,
    ExitNetworkProfile,
    apply_exit_network,
    doctor_exit_network,
    plan_exit_network,
)


def completed(argv, stdout="", returncode=0, stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


def portable_atomic_write(path: Path, data: bytes, mode: int):
    path.parent.mkdir(parents=True, exist_ok=True)
    candidate = path.with_name(f".{path.name}.test-tmp")
    candidate.write_bytes(data)
    candidate.chmod(mode)
    candidate.replace(path)


class FakeNetworkSystem:
    def __init__(self, sysctl_file: Path):
        self.sysctl_file = sysctl_file
        self.active = True
        self.allow = False
        self.deny = False
        self.interface = "eth0"
        self.runtime = {
            "net.core.default_qdisc": "pfifo_fast",
            "net.ipv4.tcp_congestion_control": "cubic",
            "net.ipv4.tcp_mtu_probing": "0",
            "net.ipv4.tcp_slow_start_after_idle": "1",
            "net.core.somaxconn": "4096",
        }
        self.output_rule = False
        self.postrouting_rule = False
        self.calls: list[tuple[str, ...]] = []
        self.fail_add_postrouting = False
        self.fail_rollback_chains: set[str] = set()
        self.fail_sysctl_restore = False
        self.malformed_allow = False
        self.leading_rule = False

    @staticmethod
    def _allow_comment() -> str:
        return "xhttp-setup-allow-8083-198.51.100.20"

    @staticmethod
    def _deny_comment() -> str:
        return "xhttp-setup-deny-8083"

    def _ufw_output(self) -> str:
        if not self.active:
            return "Status: inactive\n"
        lines = ["Status: active"]
        index = 1
        if self.leading_rule:
            lines.append("[ 1] 22/tcp ALLOW IN Anywhere # foreign-ssh")
            index = 2
        if self.allow:
            source = "203.0.113.99" if self.malformed_allow else "198.51.100.20"
            lines.append(
                f"[ {index}] 8083/tcp ALLOW IN {source} # {self._allow_comment()}"
            )
            index += 1
        if self.deny:
            lines.append(
                f"[ {index}] 8083/tcp DENY IN Anywhere # {self._deny_comment()}"
            )
        return "\n".join(lines) + "\n"

    def _iptables_save(self) -> str:
        lines = ["*mangle"]
        if self.output_rule:
            lines.append(
                '-A OUTPUT -p tcp -m comment --comment "xhttp-setup-mss-1280-output" '
                "-j TCPMSS --set-mss 1280"
            )
        if self.postrouting_rule:
            lines.append(
                "-A POSTROUTING -o eth0 -p tcp -m comment --comment "
                '"xhttp-setup-mss-1280-postrouting-eth0" -j TCPMSS --set-mss 1280'
            )
        lines.append("COMMIT")
        return "\n".join(lines) + "\n"

    def __call__(self, argv, **_kwargs):
        args = tuple(argv)
        self.calls.append(args)
        if args[:5] == ("ip", "-4", "route", "get", "1.1.1.1"):
            return completed(
                argv, f"1.1.1.1 via 192.0.2.1 dev {self.interface} src 192.0.2.2\n"
            )
        if args == ("ufw", "status", "numbered"):
            return completed(argv, self._ufw_output())
        if args[:3] == ("ufw", "insert", "1") and "allow" in args:
            self.allow = True
            return completed(argv, "Rule inserted\n")
        if args[:2] == ("ufw", "insert") and "deny" in args:
            self.deny = True
            return completed(argv, "Rule inserted\n")
        if args[:3] == ("ufw", "--force", "delete"):
            index = int(args[3])
            if self.allow and index == 1:
                self.allow = False
            elif self.deny:
                self.deny = False
            return completed(argv, "Rule deleted\n")
        if args == (
            "sysctl",
            "-n",
            "net.ipv4.tcp_available_congestion_control",
        ):
            return completed(argv, "reno cubic bbr\n")
        if args[:2] == ("sysctl", "-n"):
            return completed(argv, self.runtime[args[2]] + "\n")
        if args[:2] == ("sysctl", "-w"):
            key, value = args[2].split("=", 1)
            if self.fail_sysctl_restore and value != SYSCTL_VALUES.get(key):
                return completed(argv, returncode=1, stderr="restore failed")
            self.runtime[key] = value
            return completed(argv, f"{key} = {value}\n")
        if args == ("iptables-save", "-w", "5", "-t", "mangle"):
            return completed(argv, self._iptables_save())
        if args[0] == "iptables":
            action = args[5]
            chain = args[6]
            selected = "output_rule" if chain == "OUTPUT" else "postrouting_rule"
            if action == "-C":
                return completed(argv, returncode=0 if getattr(self, selected) else 1)
            if action == "-A":
                if chain == "POSTROUTING" and self.fail_add_postrouting:
                    return completed(argv, returncode=2, stderr="append failed")
                setattr(self, selected, True)
                return completed(argv)
            if action == "-D":
                if chain in self.fail_rollback_chains:
                    return completed(argv, returncode=2, stderr="delete failed")
                setattr(self, selected, False)
                return completed(argv)
        return completed(argv, returncode=127, stderr="unexpected command")


class ExitNetworkTests(unittest.TestCase):
    def setUp(self):
        self.profile = ExitNetworkProfile("198.51.100.20", 8083)

    def test_ufw_status_presentation_variant_is_not_treated_as_inactive(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            original = fake._ufw_output
            fake._ufw_output = lambda: original().replace(
                "Status: active", " STATUS, ACTIVE!"
            )

            apply_exit_network(self.profile, layout=layout, runner=fake)

        self.assertTrue(fake.allow)
        self.assertTrue(fake.deny)
        patcher = mock.patch(
            "xhttp_setup.exit_network.atomic_write",
            side_effect=portable_atomic_write,
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_profile_validates_ipv4_and_port(self):
        self.assertEqual(self.profile.validate(), self.profile)
        with self.assertRaises(ValidationError):
            ExitNetworkProfile("not-an-ip", 8083).validate()
        with self.assertRaises(ValidationError):
            ExitNetworkProfile("198.51.100.20", 70000).validate()
        with self.assertRaises(ValidationError):
            ExitNetworkProfile("198.51.100.20", 22).validate()

    def test_plan_is_strictly_read_only(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            plan = plan_exit_network(self.profile, layout=layout, runner=fake)

        self.assertEqual(plan.interface, "eth0")
        rendered_calls = [" ".join(call) for call in fake.calls]
        forbidden = (" ufw insert ", " -A ", "sysctl --system", " -D ")
        for command in rendered_calls:
            self.assertFalse(any(token in f" {command} " for token in forbidden))
        self.assertTrue(any("UFW frontend /32 allow" == c.name for c in plan.checks))
        self.assertTrue(any("rules.v4" in step for step in plan.steps))
        self.assertTrue(any("runtime-only" in step for step in plan.steps))
        self.assertTrue(any("198.51.100.20/32" in step for step in plan.steps))

    def test_apply_fails_closed_when_ufw_is_inactive(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            fake.active = False
            with self.assertRaisesRegex(InstallerError, "inactive/unknown"):
                apply_exit_network(self.profile, layout=layout, runner=fake)
        self.assertFalse(fake.allow)
        self.assertFalse(fake.output_rule)
        self.assertFalse(layout.sysctl_file.exists())

    def test_apply_installs_exact_profile_and_second_apply_is_idempotent(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            result = apply_exit_network(self.profile, layout=layout, runner=fake)
            self.assertTrue(result.ufw_allow_added)
            self.assertTrue(result.ufw_deny_added)
            self.assertTrue(result.sysctl_file_changed)
            self.assertTrue(result.sysctl_applied)
            self.assertTrue(result.mss_output_added)
            self.assertTrue(result.mss_postrouting_added)
            self.assertTrue(result.mss_runtime_only)
            self.assertTrue(fake.allow)
            self.assertTrue(fake.deny)
            self.assertEqual(fake.runtime, SYSCTL_VALUES)
            self.assertTrue(fake.output_rule)
            self.assertTrue(fake.postrouting_rule)
            sysctl_text = layout.sysctl_file.read_text(encoding="utf-8")
            self.assertTrue(sysctl_text.startswith(SYSCTL_MARKER + "\n"))
            if os.name == "posix":
                self.assertEqual(layout.sysctl_file.stat().st_mode & 0o777, 0o644)

            call_count = len(fake.calls)
            again = apply_exit_network(self.profile, layout=layout, runner=fake)
            repeated = fake.calls[call_count:]

        self.assertFalse(again.ufw_allow_added)
        self.assertFalse(again.ufw_deny_added)
        self.assertFalse(again.sysctl_file_changed)
        self.assertFalse(again.sysctl_applied)
        self.assertFalse(again.mss_output_added)
        self.assertFalse(again.mss_postrouting_added)
        self.assertFalse(any("insert" in call for call in repeated))
        self.assertFalse(any("-A" in call for call in repeated))
        self.assertNotIn(("sysctl", "--system"), repeated)

    def test_failure_rolls_back_only_changes_from_this_apply(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            before_runtime = dict(fake.runtime)
            fake.fail_add_postrouting = True
            with self.assertRaisesRegex(InstallerError, "POSTROUTING"):
                apply_exit_network(self.profile, layout=layout, runner=fake)

            self.assertFalse(fake.allow)
            self.assertFalse(fake.deny)
            self.assertFalse(fake.output_rule)
            self.assertFalse(fake.postrouting_rule)
            self.assertEqual(fake.runtime, before_runtime)
            self.assertFalse(layout.sysctl_file.exists())
            self.assertTrue(
                any("-D" in call and "OUTPUT" in call for call in fake.calls)
            )
            self.assertFalse(any("nft" in call for call in fake.calls))
            self.assertFalse(any("rules.v4" in call for call in fake.calls))
            self.assertFalse(any(call == ("sysctl", "--system") for call in fake.calls))

    def test_rollback_reports_all_independent_failures(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            fake.fail_add_postrouting = True
            fake.fail_rollback_chains.add("OUTPUT")
            fake.fail_sysctl_restore = True
            with self.assertRaisesRegex(InstallerError, "rollback неполон") as raised:
                apply_exit_network(self.profile, layout=layout, runner=fake)
        message = str(raised.exception)
        self.assertIn("TCPMSS OUTPUT", message)
        self.assertIn("sysctl file/runtime", message)
        self.assertFalse(fake.allow)
        self.assertFalse(fake.deny)

    def test_foreign_managed_comment_is_rejected_before_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            fake.allow = True
            fake.malformed_allow = True
            with self.assertRaisesRegex(InstallerError, "comment занят"):
                apply_exit_network(self.profile, layout=layout, runner=fake)
        self.assertFalse(any("insert" in call for call in fake.calls))
        self.assertFalse(any("-A" in call for call in fake.calls))

    def test_preexisting_managed_rules_must_be_the_effective_first_rules(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            fake.allow = True
            fake.deny = True
            fake.leading_rule = True
            with self.assertRaisesRegex(InstallerError, "не стоит первой"):
                apply_exit_network(self.profile, layout=layout, runner=fake)
        self.assertFalse(any("insert" in call for call in fake.calls))
        self.assertFalse(any("-A" in call for call in fake.calls))

    def test_doctor_reports_complete_profile(self):
        with tempfile.TemporaryDirectory() as temp:
            layout = ExitNetworkLayout(Path(temp))
            fake = FakeNetworkSystem(layout.sysctl_file)
            apply_exit_network(self.profile, layout=layout, runner=fake)
            checks = doctor_exit_network(self.profile, layout=layout, runner=fake)
        self.assertGreaterEqual(len(checks), 10)
        self.assertTrue(all(check.ok for check in checks), checks)


if __name__ == "__main__":
    unittest.main()
