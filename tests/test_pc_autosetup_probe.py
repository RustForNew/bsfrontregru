import concurrent.futures
import hashlib
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.models import FrontDesired
from xhttp_setup.pc_autosetup import (
    PcUserInputs,
    _select_front_probe_port,
    measure_front_egress,
    parse_front_egress_capture,
)
from xhttp_setup.ssh_transport import SSHAuth


_HOST_FINGERPRINT = "SHA256:" + "A" * 43


def _desired() -> FrontDesired:
    return FrontDesired(
        domain="front.example.org",
        client_connect_ip="192.0.2.10",
        dns_ipv4="192.0.2.10",
        sftp_host="sftp.example.org",
        sftp_port=22,
        sftp_user="site-user",
        document_root="/var/www/site",
        ssh_host_key_sha256=_HOST_FINGERPRINT,
        exit_address="203.0.113.20",
        exit_port=25432,
        xhttp_path="/api/temporary-probe",
    )


def _capture(*endpoints: tuple[str, int]) -> str:
    return "\n".join(
        "12:34:56.123456 IP "
        f"{address}.{port} > 203.0.113.20.25432: Flags [S], seq 1, length 0"
        for address, port in endpoints
    )


class FakeExitSSH:
    def __init__(self, capture: str, *, remove_returncode: int = 0):
        self.capture = capture
        self.remove_returncode = remove_returncode
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self._lock = threading.Lock()

    def command(self, remote_argv, **kwargs):
        argv = list(remote_argv)
        with self._lock:
            self.calls.append((argv, dict(kwargs)))
        if argv[0] == "ss":
            return subprocess.CompletedProcess(argv, 0, "", "")
        if argv[:3] == ["command", "-v", "tcpdump"]:
            return subprocess.CompletedProcess(argv, 0, "/usr/bin/tcpdump\n", "")
        if argv[0] == "sh":
            return subprocess.CompletedProcess(argv, 124, self.capture, "")
        if argv[:3] == ["rm", "-f", "--"]:
            return subprocess.CompletedProcess(
                argv, self.remove_returncode, "", "simulated cleanup failure"
            )
        raise AssertionError(f"unexpected SSH command: {argv!r}")


class FrontEgressCaptureTests(unittest.TestCase):
    def test_one_public_ip_with_three_independent_endpoints_is_accepted(self):
        output = _capture(
            ("8.8.8.8", 41001),
            ("8.8.8.8", 41002),
            ("8.8.8.8", 41003),
            ("8.8.8.8", 41003),
        )
        self.assertEqual(parse_front_egress_capture(output), "8.8.8.8")

    def test_multiple_source_addresses_are_rejected(self):
        output = _capture(
            ("8.8.8.8", 41001),
            ("8.8.8.8", 41002),
            ("1.1.1.1", 41003),
        )
        with self.assertRaisesRegex(VerificationError, "несколько исходящих IPv4"):
            parse_front_egress_capture(output)

    def test_private_source_address_is_rejected(self):
        output = _capture(
            ("10.0.0.5", 41001),
            ("10.0.0.5", 41002),
            ("10.0.0.5", 41003),
        )
        with self.assertRaisesRegex(VerificationError, "не является публичным"):
            parse_front_egress_capture(output)

    def test_fewer_than_three_unique_endpoints_are_rejected(self):
        output = _capture(
            ("8.8.8.8", 41001),
            ("8.8.8.8", 41002),
            ("8.8.8.8", 41002),
        )
        with self.assertRaisesRegex(VerificationError, "независимых соединений"):
            parse_front_egress_capture(output)

    def test_stable_probe_port_retries_collision_and_never_uses_backend(self):
        class PortSSH:
            def __init__(self, occupied: set[int]):
                self.checked = []
                self.occupied = occupied

            def command(self, argv, *, check=True, timeout=300):
                del check, timeout
                port = int(argv[-1].removeprefix("sport = :"))
                self.checked.append(port)
                stdout = "LISTEN\n" if port in self.occupied else ""
                return subprocess.CompletedProcess(argv, 0, stdout, "")

        seed = "front.example.org|8.8.8.8|22"
        first = 20000 + (
            int.from_bytes(hashlib.sha256(seed.encode()).digest()[:8], "big")
            % 40000
        )
        ssh = PortSSH({first})
        selected = _select_front_probe_port(
            ssh,
            backend_port=8083,
            ssh_port=22,
            seed=seed,
        )

        expected = 20000 + ((first - 20000 + 1) % 40000)
        self.assertEqual(selected, expected)
        self.assertEqual(ssh.checked, [first, expected])
        self.assertNotIn(8083, ssh.checked)


class FrontEgressMeasureTests(unittest.TestCase):
    def _measure(self, root: Path, *, remove_returncode: int = 0):
        capture = _capture(
            ("8.8.8.8", 41001),
            ("8.8.8.8", 41002),
            ("8.8.8.8", 41003),
        )
        ssh = FakeExitSSH(capture, remove_returncode=remove_returncode)
        secret = "sftp-secret-never-in-command"
        front_auth = SSHAuth("password", password=secret)

        def temporary_route(_desired_value, **kwargs):
            self.assertIs(kwargs["auth"], front_auth)
            return kwargs["operation"]()

        with (
            mock.patch("xhttp_setup.pc_autosetup.secrets.token_hex", return_value="abc123"),
            mock.patch("xhttp_setup.pc_autosetup._wait_capture_ready"),
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route",
                side_effect=temporary_route,
            ) as route,
            mock.patch("xhttp_setup.pc_autosetup._trigger_front_requests") as trigger,
        ):
            try:
                result = measure_front_egress(
                    ssh=ssh,
                    temporary_front=_desired(),
                    front_auth=front_auth,
                    state_dir=root / "front-probe",
                )
            finally:
                self.last_ssh = ssh
                self.last_route_calls = route.call_args_list
                self.last_trigger_calls = trigger.call_args_list

        combined = repr(
            (self.last_ssh.calls, self.last_route_calls, self.last_trigger_calls)
        )
        self.assertNotIn(secret, combined)
        return result

    def test_measure_runs_temporary_route_cleans_marker_and_parses_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._measure(Path(temp))

        self.assertEqual(result, "8.8.8.8")
        self.assertEqual(len(self.last_route_calls), 1)
        self.assertEqual(len(self.last_trigger_calls), 1)
        cleanup = [call for call in self.last_ssh.calls if call[0][0] == "rm"]
        self.assertEqual(
            cleanup[0][0],
            ["rm", "-f", "--", "/tmp/xhttp-front-probe.abc123.ready"],
        )

    def test_marker_cleanup_failure_is_propagated(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(InstallerError, "удалить marker"):
                self._measure(Path(temp), remove_returncode=1)

        self.assertEqual(len(self.last_route_calls), 1)
        self.assertNotIn(
            "sftp-secret-never-in-command",
            repr((self.last_ssh.calls, self.last_route_calls)),
        )

    def test_capture_timeout_is_wrapped_and_marker_is_still_removed(self):
        future = mock.Mock()
        future.done.return_value = False
        future.result.side_effect = concurrent.futures.TimeoutError
        capture = _capture(
            ("8.8.8.8", 41001),
            ("8.8.8.8", 41002),
            ("8.8.8.8", 41003),
        )
        ssh = FakeExitSSH(capture)
        with (
            mock.patch(
                "xhttp_setup.pc_autosetup.concurrent.futures.ThreadPoolExecutor.submit",
                return_value=future,
            ),
            mock.patch("xhttp_setup.pc_autosetup._wait_capture_ready"),
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route",
                side_effect=lambda _desired, **kwargs: kwargs["operation"](),
            ),
            mock.patch("xhttp_setup.pc_autosetup._trigger_front_requests"),
            self.assertRaisesRegex(InstallerError, "отведённое время"),
        ):
            measure_front_egress(
                ssh=ssh,
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
            )

        cleanup = [call for call in ssh.calls if call[0][0] == "rm"]
        self.assertEqual(len(cleanup), 1)

    def test_all_user_passwords_are_absent_from_repr(self):
        secrets = ("exit-secret", "panel-secret")
        inputs = PcUserInputs(
            exit_host="8.8.8.8",
            exit_port=22,
            exit_user="root",
            exit_password=secrets[0],
            panel_url="https://vip999.hosting.reg.ru:1500/ispmgr",
            panel_user="site-user",
            panel_password=secrets[1],
            front_connect_ip="192.0.2.10",
            domain="front.example.org",
        ).validate()

        rendered = repr(inputs)
        for secret in secrets:
            self.assertNotIn(secret, rendered)


if __name__ == "__main__":
    unittest.main()
