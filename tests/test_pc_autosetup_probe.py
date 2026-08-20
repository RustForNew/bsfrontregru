import concurrent.futures
import json
import os
import stat
import subprocess
import tempfile
import threading
import traceback
import unittest
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import (
    HTTPSResponseError,
    InstallerError,
    TLSVerificationError,
    VerificationError,
)
from xhttp_setup.models import FrontDesired
from xhttp_setup.pc_autosetup import (
    PcUserInputs,
    _consume_front_probe_ports,
    _load_or_create_front_probe_ports,
    _select_front_probe_ports,
    _trigger_front_requests,
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


def _capture(*endpoints: tuple[str, int], destination_port: int = 25432) -> str:
    return "\n".join(
        "12:34:56.123456 IP "
        f"{address}.{port} > 203.0.113.20.{destination_port}: "
        "Flags [S], seq 1, length 0"
        for address, port in endpoints
    )


class FakeExitSSH:
    def __init__(
        self,
        capture: str | None = None,
        *,
        remove_returncode: int = 0,
        capture_returncode: int = 124,
        source_by_port: dict[int, str] | None = None,
    ):
        self.capture = capture
        self.remove_returncode = remove_returncode
        self.capture_returncode = capture_returncode
        self.source_by_port = source_by_port or {}
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
            destination_port = int(argv[-1])
            capture = self.capture
            if capture is None:
                capture = _capture(
                    (self.source_by_port.get(destination_port, "8.8.8.8"), 41001),
                    destination_port=destination_port,
                )
            return subprocess.CompletedProcess(
                argv, self.capture_returncode, capture, ""
            )
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
        with self.assertRaisesRegex(
            VerificationError,
            r"независимых соединений \(получено 2, требуется минимум 3\)",
        ):
            parse_front_egress_capture(output)

    def test_one_endpoint_is_accepted_only_for_an_exact_sample_port(self):
        output = _capture(("8.8.8.8", 41001), destination_port=25432)
        self.assertEqual(
            parse_front_egress_capture(
                output,
                expected_destination_port=25432,
                minimum_endpoints=1,
            ),
            "8.8.8.8",
        )
        with self.assertRaisesRegex(VerificationError, "не на выбранный"):
            parse_front_egress_capture(
                output,
                expected_destination_port=25433,
                minimum_endpoints=1,
            )

    def test_request_wave_is_bounded_and_uses_unique_paths(self):
        desired = _desired()
        seen_urls: list[str] = []

        def status(url: str, **kwargs):
            seen_urls.append(url)
            self.assertEqual(kwargs["timeout"], 8)
            return 502

        with (
            mock.patch("xhttp_setup.pc_autosetup.https_status", side_effect=status),
        ):
            outcomes = _trigger_front_requests(desired)

        self.assertEqual(len(seen_urls), 8)
        self.assertEqual(outcomes, {502: 8})
        self.assertEqual(
            {url.rsplit("/probe-", 1)[1] for url in seen_urls},
            {f"25432-{number}" for number in range(8)},
        )

    def test_request_wave_propagates_tls_pin_failure(self):
        secret = "secret-path-token-must-not-leak"
        with (
            mock.patch(
                "xhttp_setup.pc_autosetup.https_status",
                side_effect=TLSVerificationError(
                    f"pin mismatch at https://front.example.org/{secret}"
                ),
            ),
            self.assertRaises(TLSVerificationError) as caught,
        ):
            _trigger_front_requests(_desired())
        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertIn("TLS/SNI/leaf", str(caught.exception))
        self.assertNotIn(secret, rendered)
        self.assertNotIn("https://", rendered)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_request_wave_swallows_only_expected_transport_failure(self):
        timeout = HTTPSResponseError(
            "backend timed out at https://front.example.org/secret-probe-token"
        )
        with mock.patch("xhttp_setup.pc_autosetup.https_status", side_effect=timeout):
            outcomes = _trigger_front_requests(_desired())
        self.assertEqual(outcomes, {None: 8})
        self.assertNotIn("secret-probe-token", repr(outcomes))

        secret = "pre-send-secret-token"
        with (
            mock.patch(
                "xhttp_setup.pc_autosetup.https_status",
                side_effect=VerificationError(
                    f"pre-send failure for https://front.example.org/{secret}"
                ),
            ),
            self.assertRaises(VerificationError) as caught,
        ):
            _trigger_front_requests(_desired())
        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertIn("безопасно отправить", str(caught.exception))
        self.assertNotIn(secret, rendered)
        self.assertNotIn("https://", rendered)
        self.assertIsNone(caught.exception.__cause__)
        self.assertIsNone(caught.exception.__context__)

    def test_request_wave_retains_mixed_safe_outcome_histogram(self):
        def status(url: str, **_kwargs):
            number = int(url.rsplit("-", 1)[1])
            if number in {0, 1, 2, 3}:
                return 404
            if number in {4, 5}:
                return 502
            raise HTTPSResponseError(
                "sent request containing https://front.example.org/secret-token"
            )

        with mock.patch(
            "xhttp_setup.pc_autosetup.https_status", side_effect=status
        ):
            outcomes = _trigger_front_requests(_desired())

        self.assertEqual(outcomes, {404: 4, 502: 2, None: 2})
        self.assertNotIn("secret-token", repr(outcomes))

    def test_probe_ports_are_random_distinct_free_and_never_use_backend(self):
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

        ssh = PortSSH({20100})
        with mock.patch(
            "xhttp_setup.pc_autosetup.secrets.randbelow",
            side_effect=(100, 101, 102, 103),
        ):
            selected = _select_front_probe_ports(
                ssh,
                backend_port=8083,
                ssh_port=22,
            )

        self.assertEqual(selected, (20101, 20102, 20103))
        self.assertEqual(ssh.checked, [20100, 20101, 20102, 20103])
        self.assertNotIn(8083, ssh.checked)

    def test_random_probe_ports_are_persisted_for_cloud_firewall_retry(self):
        ssh = FakeExitSSH()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch(
                "xhttp_setup.pc_autosetup.secrets.randbelow",
                side_effect=(100, 101, 102),
            ):
                first, reused = _load_or_create_front_probe_ports(
                    ssh,
                    state_dir=root,
                    exit_host="8.8.8.8",
                    backend_port=8083,
                    ssh_port=22,
                    domain="front.example.org",
                )
            with mock.patch(
                "xhttp_setup.pc_autosetup._select_front_probe_ports",
                side_effect=AssertionError("must reuse persisted ports"),
            ):
                second, reused_second = _load_or_create_front_probe_ports(
                    ssh,
                    state_dir=root,
                    exit_host="8.8.8.8",
                    backend_port=8083,
                    ssh_port=22,
                    domain="front.example.org",
                )

            payload = json.loads((root / "front-probe-ports.json").read_text("utf-8"))
            if os.name == "posix":
                self.assertEqual(
                    stat.S_IMODE((root / "front-probe-ports.json").stat().st_mode),
                    0o600,
                )
            _consume_front_probe_ports(
                state_dir=root,
                ports=second,
                exit_host="8.8.8.8",
                backend_port=8083,
                ssh_port=22,
                domain="front.example.org",
            )
            self.assertFalse((root / "front-probe-ports.json").exists())

        self.assertEqual(first, (20100, 20101, 20102))
        self.assertFalse(reused)
        self.assertEqual(second, first)
        self.assertTrue(reused_second)
        self.assertEqual(payload["ports"], list(first))

    def test_persisted_probe_ports_are_bound_to_exact_endpoint(self):
        ssh = FakeExitSSH()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with mock.patch(
                "xhttp_setup.pc_autosetup.secrets.randbelow",
                side_effect=(100, 101, 102),
            ):
                _load_or_create_front_probe_ports(
                    ssh,
                    state_dir=root,
                    exit_host="8.8.8.8",
                    backend_port=8083,
                    ssh_port=22,
                    domain="front.example.org",
                )
            with self.assertRaisesRegex(InstallerError, "другому endpoint"):
                _load_or_create_front_probe_ports(
                    ssh,
                    state_dir=root,
                    exit_host="1.1.1.1",
                    backend_port=8083,
                    ssh_port=22,
                    domain="front.example.org",
                )


class FrontEgressMeasureTests(unittest.TestCase):
    def setUp(self):
        control_patcher = mock.patch(
            "xhttp_setup.pc_autosetup.verify_front_rewrite_control"
        )
        self.rewrite_control = control_patcher.start()
        self.addCleanup(control_patcher.stop)

    def _measure(self, root: Path, *, remove_returncode: int = 0):
        ssh = FakeExitSSH(remove_returncode=remove_returncode)
        secret = "sftp-secret-never-in-command"
        front_auth = SSHAuth("password", password=secret)
        events: list[str] = []

        self.rewrite_control.side_effect = lambda *_args, **_kwargs: events.append(
            "rewrite-control"
        )

        def temporary_route(_desired_value, **kwargs):
            events.append(f"proxy:{_desired_value.exit_port}")
            self.assertIs(kwargs["auth"], front_auth)
            before = sum(call[0][0] == "sh" for call in ssh.calls)
            result = kwargs["operation"]()
            after = sum(call[0][0] == "sh" for call in ssh.calls)
            self.assertEqual(after, before + 1)
            return result

        with (
            mock.patch(
                "xhttp_setup.pc_autosetup.secrets.token_hex", return_value="abc123"
            ),
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
                    probe_ports=(25432, 25433, 25434),
                    trusted_known_hosts=root / "persistent-sftp.known_hosts",
                )
            finally:
                self.last_ssh = ssh
                self.last_route_calls = route.call_args_list
                self.last_trigger_calls = trigger.call_args_list
                self.last_measure_events = events

        combined = repr(
            (self.last_ssh.calls, self.last_route_calls, self.last_trigger_calls)
        )
        self.assertNotIn(secret, combined)
        return result

    def test_measure_runs_temporary_route_cleans_marker_and_parses_capture(self):
        with tempfile.TemporaryDirectory() as temp:
            result = self._measure(Path(temp))

        self.assertEqual(result, "8.8.8.8")
        self.assertEqual(
            self.last_measure_events,
            [
                "rewrite-control",
                "proxy:25432",
                "proxy:25433",
                "proxy:25434",
            ],
        )
        self.rewrite_control.assert_called_once()
        control_kwargs = self.rewrite_control.call_args.kwargs
        self.assertEqual(control_kwargs["state_dir"], Path(temp) / "front-probe")
        self.assertEqual(
            control_kwargs["trusted_known_hosts"],
            Path(temp) / "persistent-sftp.known_hosts",
        )
        self.assertEqual(len(self.last_route_calls), 3)
        self.assertEqual(len(self.last_trigger_calls), 3)
        for call in self.last_route_calls:
            self.assertEqual(
                call.kwargs["trusted_known_hosts"],
                Path(temp) / "persistent-sftp.known_hosts",
            )
        cleanup = [call for call in self.last_ssh.calls if call[0][0] == "rm"]
        self.assertEqual(len(cleanup), 3)
        self.assertEqual(
            cleanup[0][0],
            ["rm", "-f", "--", "/tmp/xhttp-front-probe.abc123.ready"],
        )

    def test_three_samples_must_report_the_same_public_ip(self):
        ssh = FakeExitSSH(
            source_by_port={25432: "8.8.8.8", 25433: "1.1.1.1", 25434: "8.8.8.8"}
        )
        with (
            mock.patch("xhttp_setup.pc_autosetup._wait_capture_ready"),
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route",
                side_effect=lambda _desired, **kwargs: kwargs["operation"](),
            ),
            mock.patch("xhttp_setup.pc_autosetup._trigger_front_requests"),
            self.assertRaisesRegex(VerificationError, "разные исходящие IPv4"),
        ):
            measure_front_egress(
                ssh=ssh,
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
                probe_ports=(25432, 25433, 25434),
            )
        sampled_ports = [
            int(argv[-1]) for argv, _kwargs in ssh.calls if argv[0] == "sh"
        ]
        self.assertEqual(sampled_ports, [25432, 25433])

    def test_rewrite_control_failure_stops_before_any_proxy_probe(self):
        ssh = FakeExitSSH()
        self.rewrite_control.side_effect = VerificationError(
            "контрольный HTTP-статус не совпал"
        )
        with (
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route"
            ) as route,
            mock.patch("xhttp_setup.pc_autosetup._trigger_front_requests") as trigger,
            self.assertRaisesRegex(VerificationError, "контрольный HTTP-статус"),
        ):
            measure_front_egress(
                ssh=ssh,
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
                probe_ports=(25432, 25433, 25434),
            )

        route.assert_not_called()
        trigger.assert_not_called()
        self.assertFalse(any(argv[0] == "sh" for argv, _kwargs in ssh.calls))

    def test_zero_syn_with_all_404_reports_safe_route_diagnosis(self):
        ssh = FakeExitSSH(capture="")
        secret_path = _desired().xhttp_path
        with (
            mock.patch("xhttp_setup.pc_autosetup._wait_capture_ready"),
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route",
                side_effect=lambda _desired, **kwargs: kwargs["operation"](),
            ),
            mock.patch(
                "xhttp_setup.pc_autosetup._trigger_front_requests",
                return_value={404: 8},
            ),
            self.assertRaises(VerificationError) as caught,
        ):
            measure_front_egress(
                ssh=ssh,
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
                probe_ports=(25432, 25433, 25434),
            )

        message = str(caught.exception)
        self.assertIn("получено 0", message)
        self.assertIn("HTTP 404 = 8", message)
        self.assertIn("не является свидетельством блокировки cloud firewall", message)
        self.assertIn("[P]/mod_proxy_http не подтверждён", message)
        self.assertNotIn(secret_path, message)
        self.assertNotIn("https://", message)

    def test_parse_failure_reports_mixed_histogram_without_exception_details(self):
        ssh = FakeExitSSH(
            capture=_capture(("8.8.8.8", 41001), destination_port=25433)
        )
        with (
            mock.patch("xhttp_setup.pc_autosetup._wait_capture_ready"),
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route",
                side_effect=lambda _desired, **kwargs: kwargs["operation"](),
            ),
            mock.patch(
                "xhttp_setup.pc_autosetup._trigger_front_requests",
                return_value={404: 3, 502: 2, None: 3},
            ),
            self.assertRaises(VerificationError) as caught,
        ):
            measure_front_egress(
                ssh=ssh,
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
                probe_ports=(25432, 25433, 25434),
            )

        message = str(caught.exception)
        self.assertIn("HTTP 404 = 3", message)
        self.assertIn("HTTP 502 = 2", message)
        self.assertIn("без корректного HTTP-статуса = 3", message)
        self.assertIn(
            "не классифицированы автоматически как блокировка cloud firewall",
            message,
        )
        self.assertNotIn(_desired().xhttp_path, message)

    def test_saturated_capture_is_rejected_and_route_operation_rolls_back(self):
        ssh = FakeExitSSH(capture_returncode=0)
        events = []

        def temporary_route(_desired, **kwargs):
            events.append(f"installed:{_desired.exit_port}")
            try:
                return kwargs["operation"]()
            finally:
                events.append(f"rollback:{_desired.exit_port}")

        with (
            mock.patch("xhttp_setup.pc_autosetup._wait_capture_ready"),
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route",
                side_effect=temporary_route,
            ),
            mock.patch("xhttp_setup.pc_autosetup._trigger_front_requests"),
            self.assertRaisesRegex(VerificationError, "переполнен и был обрезан"),
        ):
            measure_front_egress(
                ssh=ssh,
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
                probe_ports=(25432, 25433, 25434),
            )
        self.assertEqual(events, ["installed:25432", "rollback:25432"])

    def test_tls_failure_inside_capture_rolls_back_temporary_route(self):
        ssh = FakeExitSSH()
        events = []

        def temporary_route(_desired, **kwargs):
            events.append("installed")
            try:
                return kwargs["operation"]()
            finally:
                events.append("rollback")

        with (
            mock.patch("xhttp_setup.pc_autosetup._wait_capture_ready"),
            mock.patch(
                "xhttp_setup.pc_autosetup.run_with_temporary_front_route",
                side_effect=temporary_route,
            ),
            mock.patch(
                "xhttp_setup.pc_autosetup._trigger_front_requests",
                side_effect=TLSVerificationError("pin mismatch"),
            ),
            self.assertRaisesRegex(TLSVerificationError, "pin mismatch"),
        ):
            measure_front_egress(
                ssh=ssh,
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
                probe_ports=(25432, 25433, 25434),
            )
        self.assertEqual(events, ["installed", "rollback"])

    def test_probe_requires_exactly_three_distinct_ports(self):
        with self.assertRaisesRegex(InstallerError, "три разных"):
            measure_front_egress(
                ssh=FakeExitSSH(),
                temporary_front=_desired(),
                front_auth=SSHAuth("password", password="secret"),
                state_dir=Path("/tmp/front-probe"),
                probe_ports=(25432, 25432, 25434),
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
                probe_ports=(25432, 25433, 25434),
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
