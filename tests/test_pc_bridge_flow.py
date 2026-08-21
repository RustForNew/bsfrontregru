from __future__ import annotations

import subprocess
import tempfile
import unittest
from contextlib import (
    ExitStack,
    contextmanager,
    nullcontext,
    redirect_stderr,
    redirect_stdout,
)
from io import StringIO
from pathlib import Path
from unittest import mock

from xhttp_setup.cli import _run_pc_install, _run_probe_and_issue
from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.exit_installer import Layout
from xhttp_setup.front_discovery import FrontTLSDiscovery
from xhttp_setup.ispmanager import SiteInfo
from xhttp_setup.models import ExitDesired, FrontDesired, Handoff, TLS_MODE_PUBLIC
from xhttp_setup.pc_autosetup import (
    PcBridgeAccess,
    PcBridgeInputs,
    PcPreparedInstall,
    PcUserInputs,
    open_pc_bridge,
    prepare_pc_install,
)
from xhttp_setup.remote_exit import RemoteExitTarget
from xhttp_setup.ssh_transport import (
    SSHAuth,
    SSHAuthenticationError,
    SSHRoute,
    TCPRoute,
)


DOMAIN = "front.example.org"
EXIT_PASSWORD = "exit-password-only-for-test-12"
PANEL_PASSWORD = "panel-password-only-for-test-47"
SFTP_PASSWORD = "sftp-password-only-for-test-58"
BRIDGE_PASSWORD = "bridge-password-only-for-test-93"
FINGERPRINT = "SHA256:" + ("C" * 43)
CLIENT_ID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
XHTTP_PATH = "/api/0123456789abcdef0123456789abcdef"
ENCRYPTION = (
    "mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)


def completed(argv, *, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout, stderr)


def bridge_access() -> PcBridgeAccess:
    return PcBridgeAccess(
        panel_route=TCPRoute("127.0.0.1", 44101).validate(),
        sftp_route=SSHRoute(
            scan=TCPRoute("127.0.0.1", 44102),
            proxy_command=(
                "ssh -F /dev/null -S /tmp/bridge-control -W %h:%p "
                "root@bridge.example.org"
            ),
        ).validate(),
        front_route=TCPRoute("127.0.0.1", 44103).validate(),
    )


def user_inputs(*, bridge: bool) -> PcUserInputs:
    return PcUserInputs(
        exit_host="8.8.8.8",
        exit_port=22,
        exit_user="root",
        exit_password=EXIT_PASSWORD,
        panel_url="https://vip999.hosting.reg.ru:1500/",
        panel_user="u1234567",
        panel_password=PANEL_PASSWORD,
        front_connect_ip="192.0.2.30",
        domain=DOMAIN,
        bridge=(
            PcBridgeInputs(
                host="1.1.1.1",
                user="root",
                password=BRIDGE_PASSWORD,
            )
            if bridge
            else None
        ),
    ).validate()


def handoff() -> Handoff:
    return Handoff(
        exit_address="8.8.8.8",
        exit_port=8083,
        client_id=CLIENT_ID,
        xhttp_path=XHTTP_PATH,
        encryption=ENCRYPTION,
        expected_egress_ip="8.8.8.8",
    ).validate()


def prepared_install(*, existing=True) -> PcPreparedInstall:
    desired_exit = ExitDesired(
        public_address="8.8.8.8",
        listen_port=8083,
        front_egress_ip="9.9.9.9",
        xhttp_path=XHTTP_PATH,
        client_id=CLIENT_ID,
        expected_egress_ip="8.8.8.8",
    ).validate()
    desired_front = FrontDesired(
        domain=DOMAIN,
        client_connect_ip="192.0.2.30",
        dns_ipv4="192.0.2.31",
        sftp_host="vip999.hosting.reg.ru",
        sftp_port=22,
        sftp_user="u1234567",
        document_root=f"/var/www/u/data/www/{DOMAIN}",
        ssh_host_key_sha256=FINGERPRINT,
        exit_address=desired_exit.public_address,
        exit_port=desired_exit.listen_port,
        xhttp_path=desired_exit.xhttp_path,
    ).validate()
    return PcPreparedInstall(
        exit_target=RemoteExitTarget(
            host="8.8.8.8",
            port=22,
            user="root",
            host_key_sha256=FINGERPRINT,
        ).validate(),
        exit_auth=SSHAuth("password", password=EXIT_PASSWORD).validate(),
        desired_exit=desired_exit,
        desired_front=desired_front,
        front_auth=SSHAuth("password", password=SFTP_PASSWORD).validate(),
        exit_known_hosts=Path("/private/exit.known_hosts"),
        sftp_known_hosts=Path("/private/sftp.known_hosts"),
        existing_handoff=(handoff() if existing else None),
    )


class FakeBridgeSession:
    def __init__(self, events, *, close_error=None):
        self.events = events
        self.close_calls = 0
        self.close_error = close_error

    def close(self):
        self.close_calls += 1
        self.events.append("close")
        if self.close_error is not None:
            raise self.close_error

    def __repr__(self):
        return "FakeBridgeSession(open=True)"


class PcBridgeOpenTests(unittest.TestCase):
    def test_wrong_bridge_password_reprompts_only_that_secret(self):
        inputs = user_inputs(bridge=True)
        passwords = []
        sessions = []
        replacement = "replacement-bridge-password-18"

        class Session:
            def __init__(self, **kwargs):
                self.number = len(sessions)
                self.auth = kwargs["auth"]
                passwords.append(self.auth.password)
                sessions.append(self)

            def open(self):
                if self.number == 0:
                    raise SSHAuthenticationError("Permission denied")
                return self

            def tcp_route(self, name):
                return (
                    bridge_access().panel_route
                    if name == "panel"
                    else bridge_access().front_route
                )

            def ssh_route(self, name):
                self.assert_sftp_name = name
                return bridge_access().sftp_route

            def close(self):
                return None

        prompt = mock.Mock(return_value=replacement)
        progress = []
        with (
            mock.patch(
                "xhttp_setup.ssh_transport.trust_host_key_tofu",
                return_value=(Path("/private/bridge.known_hosts"), FINGERPRINT),
            ),
            mock.patch("xhttp_setup.pc_autosetup.SSHBridgeSession", Session),
        ):
            session, access = open_pc_bridge(
                inputs,
                progress=progress.append,
                password_prompt=prompt,
            )

        self.assertIs(session, sessions[1])
        self.assertEqual(passwords, [BRIDGE_PASSWORD, replacement])
        prompt.assert_called_once_with()
        self.assertEqual(access.front_route, bridge_access().front_route)
        rendered = repr((session, access, progress))
        self.assertNotIn(BRIDGE_PASSWORD, rendered)
        self.assertNotIn(replacement, rendered)

    def test_access_failure_remains_primary_when_bridge_close_fails(self):
        inputs = user_inputs(bridge=True)
        body_error = InstallerError("primary bridge access failure")
        cleanup_secret = "bridge-close-secret-must-not-leak"
        sessions = []

        class Session:
            def __init__(self, **_kwargs):
                self.close_calls = 0
                sessions.append(self)

            def open(self):
                return self

            def tcp_route(self, _name):
                raise body_error

            def close(self):
                self.close_calls += 1
                raise InstallerError(cleanup_secret)

        with (
            mock.patch(
                "xhttp_setup.ssh_transport.trust_host_key_tofu",
                return_value=(Path("/private/bridge.known_hosts"), FINGERPRINT),
            ),
            mock.patch("xhttp_setup.pc_autosetup.SSHBridgeSession", Session),
            self.assertRaises(InstallerError) as raised,
        ):
            open_pc_bridge(inputs)

        self.assertIs(raised.exception, body_error)
        self.assertEqual(sessions[0].close_calls, 1)
        self.assertIn("teardown SSH-моста", repr(body_error.__notes__))
        self.assertNotIn(cleanup_secret, repr(body_error.__notes__))


class PcBridgeOrchestrationTests(unittest.TestCase):
    def _common_stack(self, stack: ExitStack):
        stack.enter_context(
            mock.patch("xhttp_setup.cli._read_pc_phase", return_value=None)
        )
        stack.enter_context(mock.patch("xhttp_setup.cli._write_pc_phase"))
        stack.enter_context(mock.patch("xhttp_setup.cli.clear_pending_pc_exit"))
        stack.enter_context(mock.patch("xhttp_setup.cli.write_pending_pc_exit"))
        stack.enter_context(mock.patch("xhttp_setup.cli._confirm_pc_provider_firewall"))
        return stack.enter_context(mock.patch("xhttp_setup.cli.apply_pc_exit"))

    def test_bridge_opens_before_prepare_routes_final_apply_and_closes_on_success(self):
        inputs = user_inputs(bridge=True)
        prepared = prepared_install()
        access = bridge_access()
        events = []
        session = FakeBridgeSession(events)
        stdout = StringIO()
        stderr = StringIO()

        def open_bridge(actual, **kwargs):
            events.append("open")
            self.assertIs(actual, inputs)
            self.assertTrue(callable(kwargs["progress"]))
            self.assertTrue(callable(kwargs["password_prompt"]))
            return session, access

        def prepare(actual, **kwargs):
            events.append("prepare")
            self.assertIs(actual, inputs)
            self.assertIs(kwargs["bridge_access"], access)
            return prepared

        def final_apply(**kwargs):
            events.append("final")
            self.assertIs(kwargs["bridge_access"], access)
            self.assertEqual(kwargs["trusted_known_hosts"], prepared.sftp_known_hosts)

        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            apply_exit = self._common_stack(stack)
            stack.enter_context(
                mock.patch("xhttp_setup.cli.open_pc_bridge", side_effect=open_bridge)
            )
            stack.enter_context(
                mock.patch("xhttp_setup.cli.prepare_pc_install", side_effect=prepare)
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.cli._apply_front_and_issue", side_effect=final_apply
                )
            )
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            result = _run_pc_install(
                inputs=inputs,
                output_dir=Path(temp) / "pc-output",
                installer_pyz=Path(temp) / "installer.pyz",
            )

        self.assertEqual(result, 0)
        self.assertEqual(events, ["open", "prepare", "final", "close"])
        self.assertEqual(session.close_calls, 1)
        apply_exit.assert_not_called()
        rendered = stdout.getvalue() + stderr.getvalue()
        for value in (repr(inputs), repr(access), repr(session), rendered):
            self.assertNotIn(BRIDGE_PASSWORD, value)

    def test_direct_mode_neither_opens_bridge_nor_passes_bridge_kwargs(self):
        inputs = user_inputs(bridge=False)
        prepared = prepared_install()
        events = []

        def prepare(actual, **kwargs):
            events.append("prepare")
            self.assertIs(actual, inputs)
            self.assertNotIn("bridge_access", kwargs)
            return prepared

        def final_apply(**kwargs):
            events.append("final")
            self.assertNotIn("bridge_access", kwargs)
            self.assertEqual(kwargs["trusted_known_hosts"], prepared.sftp_known_hosts)

        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            apply_exit = self._common_stack(stack)
            open_bridge = stack.enter_context(
                mock.patch("xhttp_setup.cli.open_pc_bridge")
            )
            stack.enter_context(
                mock.patch("xhttp_setup.cli.prepare_pc_install", side_effect=prepare)
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.cli._apply_front_and_issue", side_effect=final_apply
                )
            )
            stack.enter_context(redirect_stdout(StringIO()))
            self.assertEqual(
                _run_pc_install(
                    inputs=inputs,
                    output_dir=Path(temp) / "pc-output",
                    installer_pyz=Path(temp) / "installer.pyz",
                ),
                0,
            )

        self.assertEqual(events, ["prepare", "final"])
        open_bridge.assert_not_called()
        apply_exit.assert_not_called()

    def test_bridge_closes_after_prepare_or_final_exception(self):
        for failure_stage in ("prepare", "final"):
            with self.subTest(stage=failure_stage):
                inputs = user_inputs(bridge=True)
                prepared = prepared_install()
                access = bridge_access()
                events = []
                session = FakeBridgeSession(events)
                stdout = StringIO()
                stderr = StringIO()

                def open_bridge(*_args, **_kwargs):
                    events.append("open")
                    return session, access

                def prepare(actual, **kwargs):
                    events.append("prepare")
                    self.assertIs(kwargs["bridge_access"], access)
                    if failure_stage == "prepare":
                        raise InstallerError(f"prepare failed for {actual!r}")
                    return prepared

                def final_apply(**kwargs):
                    events.append("final")
                    self.assertIs(kwargs["bridge_access"], access)
                    self.assertEqual(
                        kwargs["trusted_known_hosts"],
                        prepared.sftp_known_hosts,
                    )
                    raise InstallerError(
                        f"final failed for {kwargs['bridge_access']!r}"
                    )

                with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
                    apply_exit = self._common_stack(stack)
                    stack.enter_context(
                        mock.patch(
                            "xhttp_setup.cli.open_pc_bridge",
                            side_effect=open_bridge,
                        )
                    )
                    stack.enter_context(
                        mock.patch(
                            "xhttp_setup.cli.prepare_pc_install",
                            side_effect=prepare,
                        )
                    )
                    final = stack.enter_context(
                        mock.patch(
                            "xhttp_setup.cli._apply_front_and_issue",
                            side_effect=final_apply,
                        )
                    )
                    stack.enter_context(redirect_stdout(stdout))
                    stack.enter_context(redirect_stderr(stderr))
                    with self.assertRaises(InstallerError) as raised:
                        _run_pc_install(
                            inputs=inputs,
                            output_dir=Path(temp) / "pc-output",
                            installer_pyz=Path(temp) / "installer.pyz",
                        )

                expected = (
                    ["open", "prepare", "close"]
                    if failure_stage == "prepare"
                    else ["open", "prepare", "final", "close"]
                )
                self.assertEqual(events, expected)
                self.assertEqual(session.close_calls, 1)
                apply_exit.assert_not_called()
                if failure_stage == "prepare":
                    final.assert_not_called()
                for value in (
                    str(raised.exception),
                    stdout.getvalue(),
                    stderr.getvalue(),
                    repr(inputs),
                    repr(access),
                ):
                    self.assertNotIn(BRIDGE_PASSWORD, value)

    def test_bridge_close_does_not_mask_pc_body_error(self):
        inputs = user_inputs(bridge=True)
        access = bridge_access()
        events = []
        body_error = KeyboardInterrupt("primary PC interruption")
        cleanup_secret = "pc-bridge-close-secret-must-not-leak"
        session = FakeBridgeSession(
            events,
            close_error=InstallerError(cleanup_secret),
        )

        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            self._common_stack(stack)
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.cli.open_pc_bridge",
                    return_value=(session, access),
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.cli.prepare_pc_install",
                    side_effect=body_error,
                )
            )
            stack.enter_context(redirect_stdout(StringIO()))
            stack.enter_context(redirect_stderr(StringIO()))
            with self.assertRaises(KeyboardInterrupt) as raised:
                _run_pc_install(
                    inputs=inputs,
                    output_dir=Path(temp) / "pc-output",
                    installer_pyz=Path(temp) / "installer.pyz",
                )

        self.assertIs(raised.exception, body_error)
        self.assertEqual(session.close_calls, 1)
        self.assertIn("teardown SSH-моста", repr(body_error.__notes__))
        self.assertNotIn(cleanup_secret, repr(body_error.__notes__))

    def test_bridge_close_only_failure_is_propagated(self):
        inputs = user_inputs(bridge=True)
        prepared = prepared_install()
        access = bridge_access()
        events = []
        close_error = InstallerError("bridge teardown failed")
        session = FakeBridgeSession(events, close_error=close_error)

        with tempfile.TemporaryDirectory() as temp, ExitStack() as stack:
            apply_exit = self._common_stack(stack)
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.cli.open_pc_bridge",
                    return_value=(session, access),
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.cli.prepare_pc_install",
                    return_value=prepared,
                )
            )
            stack.enter_context(mock.patch("xhttp_setup.cli._apply_front_and_issue"))
            stack.enter_context(redirect_stdout(StringIO()))
            stack.enter_context(redirect_stderr(StringIO()))
            with self.assertRaises(InstallerError) as raised:
                _run_pc_install(
                    inputs=inputs,
                    output_dir=Path(temp) / "pc-output",
                    installer_pyz=Path(temp) / "installer.pyz",
                )

        self.assertIs(raised.exception, close_error)
        self.assertEqual(session.close_calls, 1)
        apply_exit.assert_not_called()

    def test_e2e_uses_bridge_forward_but_issued_profile_keeps_real_frontend(self):
        access = bridge_access()
        with (
            tempfile.TemporaryDirectory() as temp,
            mock.patch("xhttp_setup.cli.e2e_probe", return_value="ok\n") as probe,
            mock.patch("xhttp_setup.cli._save_verified_link") as save,
            redirect_stdout(StringIO()),
        ):
            _run_probe_and_issue(
                handoff=handoff(),
                domain=DOMAIN,
                client_connect_ip="192.0.2.30",
                state_dir=Path(temp) / "front",
                layout=Layout(root=Path(temp) / "runtime"),
                bridge_access=access,
            )

        self.assertEqual(probe.call_args.kwargs["front_address"], "127.0.0.1")
        self.assertEqual(probe.call_args.kwargs["front_port"], 44103)
        self.assertEqual(save.call_args.kwargs["client_connect_ip"], "192.0.2.30")


class FakeExitSession:
    def __init__(self, client):
        self.client = client

    def command(self, argv, *, check=True, timeout=300, input_text=None):
        return self.client.command(
            argv, check=check, timeout=timeout, input_text=input_text
        )

    def fresh_command(self, argv, *, check=True, timeout=300, input_text=None):
        return self.client.command(
            argv, check=check, timeout=timeout, input_text=input_text
        )


class FakeExitSSH:
    def __init__(self):
        self.calls = []
        self.sessions = []
        self.session_events = []

    @contextmanager
    def session(self):
        session = FakeExitSession(self)
        self.sessions.append(session)
        self.session_events.append("open")
        try:
            yield session
        finally:
            self.session_events.append("close")

    def command(self, argv, *, check=True, timeout=300, input_text=None):
        self.calls.append((argv, check, timeout, input_text))
        if argv == ["id", "-u"]:
            return completed(argv, stdout="0\n")
        raise AssertionError(f"unexpected direct exit command: {argv!r}")


class PcBridgePreparationTests(unittest.TestCase):
    def _run_prepare(self, root: Path, *, tls_error=None):
        inputs = user_inputs(bridge=True)
        access = bridge_access()
        exit_ssh = FakeExitSSH()
        events = []
        trust_calls = []
        ssh_constructor_calls = []
        sftp_constructor_calls = []
        panel_calls = []
        tls_calls = []
        probe_calls = []

        def trust(**kwargs):
            trust_calls.append(kwargs)
            if kwargs["host"] == inputs.exit_host:
                events.append("exit-tofu")
                return root / "exit.known_hosts", FINGERPRINT
            events.append("sftp-tofu")
            return root / "sftp.known_hosts", FINGERPRINT

        def ssh_factory(**kwargs):
            ssh_constructor_calls.append(kwargs)
            return exit_ssh

        def inspect(**kwargs):
            events.append("panel")
            panel_calls.append(kwargs)
            return SiteInfo(
                name=DOMAIN,
                docroot=f"/var/www/u/data/www/{DOMAIN}",
                ipaddr=None,
            )

        class SuccessfulSFTP:
            def __init__(self, **kwargs):
                sftp_constructor_calls.append(kwargs)

            def session(self):
                return nullcontext(self)

            def batch(self, commands, *, check=True):
                del check
                events.append("sftp")
                return completed(
                    commands,
                    stdout=(
                        "Remote working directory: /home/u1234567\n"
                        f"Remote working directory: /var/www/u/data/www/{DOMAIN}\n"
                    ),
                )

        def tls(*args, **kwargs):
            events.append("tls")
            tls_calls.append((args, kwargs))
            if tls_error is not None:
                raise tls_error
            return FrontTLSDiscovery(TLS_MODE_PUBLIC, None)

        def prepare_exit(*_args, **_kwargs):
            events.append("prepare-exit")

        def front_probe(**kwargs):
            events.append("front-probe")
            probe_calls.append(kwargs)
            return "9.9.9.9"

        capability_calls = []

        def front_capability(_desired, **kwargs):
            events.append("front-capability")
            capability_calls.append(kwargs)
            return True

        stdout = StringIO()
        stderr = StringIO()
        prepare_exit_mock = mock.Mock(side_effect=prepare_exit)
        measure_exit = mock.Mock(return_value="8.8.8.8")
        front_probe_mock = mock.Mock(side_effect=front_probe)
        with ExitStack() as stack:
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.ssh_transport.trust_host_key_tofu",
                    side_effect=trust,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.pc_autosetup.SSHClient", side_effect=ssh_factory
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.pc_autosetup.SFTPClient",
                    side_effect=SuccessfulSFTP,
                )
            )
            stack.enter_context(
                mock.patch("xhttp_setup.pc_autosetup.inspect_site", side_effect=inspect)
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.front_discovery.resolve_front_dns",
                    return_value="192.0.2.31",
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.front_discovery.discover_front_tls_policy",
                    side_effect=tls,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.pc_autosetup._load_pending_pc_exit",
                    return_value=None,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.pc_autosetup.inspect_existing_pc_exit",
                    return_value=None,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.pc_autosetup._remote_port_is_free",
                    return_value=True,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.remote_prepare.prepare_remote_exit",
                    prepare_exit_mock,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.remote_prepare.measure_remote_exit_egress",
                    measure_exit,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.pc_autosetup.measure_front_egress",
                    front_probe_mock,
                )
            )
            stack.enter_context(
                mock.patch(
                    "xhttp_setup.pc_autosetup.verify_front_proxy_capability",
                    side_effect=front_capability,
                )
            )
            stack.enter_context(redirect_stdout(stdout))
            stack.enter_context(redirect_stderr(stderr))
            try:
                result = prepare_pc_install(
                    inputs,
                    output_dir=root / "state",
                    bridge_access=access,
                    progress=lambda message: print(f"step: {message}"),
                )
            except BaseException as error:
                result = error

        return {
            "inputs": inputs,
            "access": access,
            "result": result,
            "exit_ssh": exit_ssh,
            "events": events,
            "trust_calls": trust_calls,
            "ssh_constructor_calls": ssh_constructor_calls,
            "sftp_constructor_calls": sftp_constructor_calls,
            "panel_calls": panel_calls,
            "tls_calls": tls_calls,
            "probe_calls": probe_calls,
            "capability_calls": capability_calls,
            "prepare_exit": prepare_exit_mock,
            "measure_exit": measure_exit,
            "front_probe": front_probe_mock,
            "output": stdout.getvalue() + stderr.getvalue(),
        }

    def test_prepare_routes_every_frontend_endpoint_but_exit_ssh_stays_direct(self):
        with tempfile.TemporaryDirectory() as temp:
            state = self._run_prepare(Path(temp))

        result = state["result"]
        self.assertIsInstance(result, PcPreparedInstall)
        access = state["access"]
        self.assertEqual(len(state["ssh_constructor_calls"]), 1)
        exit_kwargs = state["ssh_constructor_calls"][0]
        self.assertEqual(exit_kwargs["host"], "8.8.8.8")
        self.assertNotIn("route", exit_kwargs)
        self.assertEqual(state["exit_ssh"].calls[0][0], ["id", "-u"])
        self.assertEqual(
            state["exit_ssh"].session_events,
            ["open", "close", "open", "close"],
        )

        self.assertEqual(len(state["trust_calls"]), 2)
        exit_trust, sftp_trust = state["trust_calls"]
        self.assertEqual(exit_trust["host"], "8.8.8.8")
        self.assertNotIn("route", exit_trust)
        self.assertIs(sftp_trust["route"], access.sftp_route)
        self.assertIs(state["panel_calls"][0]["route"], access.panel_route)
        self.assertIs(state["sftp_constructor_calls"][0]["route"], access.sftp_route)
        self.assertIs(state["tls_calls"][0][1]["route"], access.front_route)
        self.assertIs(state["capability_calls"][0]["sftp_route"], access.sftp_route)
        self.assertIs(state["capability_calls"][0]["https_route"], access.front_route)
        self.assertIs(state["probe_calls"][0]["sftp_route"], access.sftp_route)
        self.assertIs(state["probe_calls"][0]["https_route"], access.front_route)
        self.assertIs(state["probe_calls"][0]["local_proxy_confirmed"], True)
        self.assertEqual(
            state["probe_calls"][0]["trusted_known_hosts"],
            result.sftp_known_hosts,
        )
        self.assertEqual(result.exit_known_hosts, Path(temp) / "exit.known_hosts")
        self.assertEqual(result.sftp_known_hosts, Path(temp) / "sftp.known_hosts")
        main_session = state["exit_ssh"].sessions[1]
        self.assertIs(state["probe_calls"][0]["ssh"], main_session)
        self.assertEqual(state["probe_calls"][0]["temporary_front"].exit_port, 8083)
        self.assertTrue(state["probe_calls"][0]["require_free_port"])
        self.assertNotIn("probe_ports", state["probe_calls"][0])
        self.assertIs(state["prepare_exit"].call_args.args[0], main_session)
        self.assertIs(state["measure_exit"].call_args.args[0], main_session)
        self.assertLess(
            state["events"].index("tls"), state["events"].index("prepare-exit")
        )
        self.assertLess(
            state["events"].index("front-capability"),
            state["events"].index("prepare-exit"),
        )
        self.assertLess(
            state["events"].index("prepare-exit"),
            state["events"].index("front-probe"),
        )
        for value in (
            state["output"],
            repr(state["inputs"]),
            repr(state["access"]),
            repr(result),
        ):
            self.assertNotIn(BRIDGE_PASSWORD, value)

    def test_frontend_preflight_failure_stops_before_exit_prepare_or_apply(self):
        failure = VerificationError("TLS frontend preflight failed")
        with tempfile.TemporaryDirectory() as temp:
            state = self._run_prepare(Path(temp), tls_error=failure)

        self.assertIs(state["result"], failure)
        self.assertIs(state["panel_calls"][0]["route"], state["access"].panel_route)
        self.assertIs(
            state["sftp_constructor_calls"][0]["route"],
            state["access"].sftp_route,
        )
        self.assertIs(state["tls_calls"][0][1]["route"], state["access"].front_route)
        state["prepare_exit"].assert_not_called()
        state["measure_exit"].assert_not_called()
        state["front_probe"].assert_not_called()
        self.assertNotIn("prepare-exit", state["events"])
        self.assertNotIn("front-probe", state["events"])
        for value in (
            state["output"],
            str(state["result"]),
            repr(state["inputs"]),
            repr(state["access"]),
        ):
            self.assertNotIn(BRIDGE_PASSWORD, value)


if __name__ == "__main__":
    unittest.main()
