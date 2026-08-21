from __future__ import annotations

import json
import os
import tempfile
import unittest
from contextlib import ExitStack, nullcontext, redirect_stderr, redirect_stdout
from dataclasses import replace
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from xhttp_setup.cli import (
    _confirm_pc_provider_firewall,
    _collect_pc_minimal_inputs,
    _read_pc_phase,
    _write_pc_phase,
    _yes_no,
    wizard_pc,
)
from xhttp_setup.errors import InstallerError
from xhttp_setup.front import FrontResult, FrontRollbackError
from xhttp_setup.models import ExitDesired, FrontDesired, Handoff
from xhttp_setup.osutil import exclusive_lock
from xhttp_setup.pc_autosetup import PcBridgeInputs, PcPreparedInstall, PcUserInputs
from xhttp_setup.remote_exit import RemoteExitTarget
from xhttp_setup.ssh_transport import SSHAuth


DOMAIN = "front.example.org"
EXIT_PASSWORD = "ExitPassword-only-for-test-73"
PANEL_PASSWORD = "PanelPassword-only-for-test-42"
SFTP_PASSWORD = "SftpPassword-only-for-test-91"
BRIDGE_PASSWORD = "BridgePassword-only-for-test-64"
FINGERPRINT = "SHA256:" + ("A" * 43)
CLIENT_ID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
XHTTP_PATH = "/api/0123456789abcdef0123456789abcdef"
ENCRYPTION = (
    "mlkem768x25519plus.native.0rtt."
    "clientmaterialxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
)


def _inputs() -> PcUserInputs:
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
    ).validate()


def _prepared() -> PcPreparedInstall:
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
        dns_ipv4="192.0.2.30",
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
    )


def _handoff() -> Handoff:
    return Handoff(
        exit_address="8.8.8.8",
        exit_port=8083,
        client_id=CLIENT_ID,
        xhttp_path=XHTTP_PATH,
        encryption=ENCRYPTION,
        expected_egress_ip="8.8.8.8",
    ).validate()


def _assert_no_manual_technical_inputs(test: unittest.TestCase, transcript: str) -> None:
    lowered = transcript.lower()
    for forbidden in ("sha", "fingerprint", "egress", "docroot", "path", "key"):
        test.assertNotIn(forbidden, lowered)
    # These were old confirmation/input tokens. A human-readable success
    # message "Готово" remains allowed.
    test.assertNotIn("ГОТОВО", transcript)
    test.assertNotIn("APPLY", transcript)
    test.assertNotIn("Для завершения", transcript)
    test.assertNotIn("Для применения введите", transcript)


class PcMinimalInputTests(unittest.TestCase):
    def test_yes_no_accepts_ascii_y(self):
        with patch("builtins.input", return_value="y"):
            self.assertTrue(_yes_no("Использовать мост для входа?"))

    def test_yes_no_accepts_cyrillic_u_and_reprompts_unknown_answers(self):
        answers = iter(("unexpected", "у"))
        error = StringIO()

        with (
            patch("builtins.input", side_effect=lambda _prompt: next(answers)),
            redirect_stderr(error),
        ):
            self.assertTrue(_yes_no("Использовать мост для входа?"))

        self.assertEqual(
            error.getvalue(),
            "Ошибка: ответьте y/yes/да или n/no/нет.\n",
        )

    def test_yes_no_accepts_explicit_negative_answers(self):
        with patch("builtins.input", return_value="нет"):
            self.assertFalse(_yes_no("Использовать мост для входа?", default=True))

    def test_direct_collects_eight_visible_fields_and_two_hidden_passwords(self):
        visible_answers = iter(
            (
                "8.8.8.8",
                "",  # SSH port=22
                "",  # SSH login=root
                "",  # bridge=no
                "https://vip999.hosting.reg.ru:1500/",
                "u1234567",
                "192.0.2.30",
                DOMAIN,
            )
        )
        hidden_answers = iter((EXIT_PASSWORD, PANEL_PASSWORD))
        prompts: list[str] = []

        def visible(prompt: str) -> str:
            prompts.append(prompt)
            print(prompt, end="")
            return next(visible_answers)

        def hidden(prompt: str) -> str:
            prompts.append(prompt)
            print(prompt, end="")
            return next(hidden_answers)

        output = StringIO()
        with (
            patch("builtins.input", side_effect=visible),
            patch("xhttp_setup.cli.getpass.getpass", side_effect=hidden),
            redirect_stdout(output),
        ):
            inputs = _collect_pc_minimal_inputs()

        self.assertEqual(
            prompts,
            [
                "IPv4 выходного сервера: ",
                "SSH port выхода [22]: ",
                "SSH login выхода [root]: ",
                "SSH password выхода: ",
                "Использовать мост для входа? [y/N]: ",
                "HTTPS-адрес панели REG.RU "
                "(например https://vip123.hosting.reg.ru:1500/ или "
                "https://server205.hosting.reg.ru:1500/): ",
                "Логин REG.RU: ",
                "Пароль панели REG.RU: ",
                "IPv4 подключения REG.RU (поле «IP-адрес сервера»): ",
                "Домен frontend: ",
            ],
        )
        self.assertEqual(inputs, _inputs())
        transcript = output.getvalue()
        _assert_no_manual_technical_inputs(self, transcript)
        for secret in (EXIT_PASSWORD, PANEL_PASSWORD):
            self.assertNotIn(secret, transcript)
            self.assertNotIn(secret, repr(inputs))

    def test_bridge_collects_only_ipv4_login_and_hidden_password(self):
        visible_answers = iter(
            (
                "8.8.8.8",
                "",
                "",
                "у",
                "9.9.9.9",
                "",
                "https://vip999.hosting.reg.ru:1500/",
                "u1234567",
                "192.0.2.30",
                DOMAIN,
            )
        )
        hidden_answers = iter((EXIT_PASSWORD, BRIDGE_PASSWORD, PANEL_PASSWORD))
        prompts: list[str] = []

        def visible(prompt: str) -> str:
            prompts.append(prompt)
            return next(visible_answers)

        def hidden(prompt: str) -> str:
            prompts.append(prompt)
            return next(hidden_answers)

        output = StringIO()
        with (
            patch("builtins.input", side_effect=visible),
            patch("xhttp_setup.cli.getpass.getpass", side_effect=hidden),
            redirect_stdout(output),
        ):
            inputs = _collect_pc_minimal_inputs()

        self.assertEqual(
            prompts,
            [
                "IPv4 выходного сервера: ",
                "SSH port выхода [22]: ",
                "SSH login выхода [root]: ",
                "SSH password выхода: ",
                "Использовать мост для входа? [y/N]: ",
                "IPv4 моста: ",
                "SSH login моста [root]: ",
                "SSH password моста: ",
                "HTTPS-адрес панели REG.RU "
                "(например https://vip123.hosting.reg.ru:1500/ или "
                "https://server205.hosting.reg.ru:1500/): ",
                "Логин REG.RU: ",
                "Пароль панели REG.RU: ",
                "IPv4 подключения REG.RU (поле «IP-адрес сервера»): ",
                "Домен frontend: ",
            ],
        )
        self.assertEqual(
            inputs.bridge,
            PcBridgeInputs(
                host="9.9.9.9",
                user="root",
                password=BRIDGE_PASSWORD,
            ).validate(),
        )
        self.assertEqual(inputs.bridge.port, 22)
        transcript = output.getvalue()
        _assert_no_manual_technical_inputs(self, transcript)
        self.assertNotIn("port моста", transcript)
        for secret in (EXIT_PASSWORD, BRIDGE_PASSWORD, PANEL_PASSWORD):
            self.assertNotIn(secret, transcript)
            self.assertNotIn(secret, repr(inputs))

    def test_invalid_secret_reprompts_only_that_hidden_field(self):
        visible_answers = iter(
            (
                "8.8.8.8",
                "",
                "",
                "",
                "https://vip999.hosting.reg.ru:1500/",
                "u1234567",
                "192.0.2.30",
                DOMAIN,
            )
        )
        hidden_answers = iter(("", EXIT_PASSWORD, PANEL_PASSWORD))
        visible_prompts = []
        hidden_prompts = []

        def visible(prompt):
            visible_prompts.append(prompt)
            return next(visible_answers)

        def hidden(prompt):
            hidden_prompts.append(prompt)
            return next(hidden_answers)

        with (
            patch("builtins.input", side_effect=visible),
            patch("xhttp_setup.cli.getpass.getpass", side_effect=hidden),
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
        ):
            result = _collect_pc_minimal_inputs()

        self.assertEqual(result, _inputs())
        self.assertEqual(len(visible_prompts), 8)
        self.assertEqual(
            hidden_prompts,
            [
                "SSH password выхода: ",
                "SSH password выхода: ",
                "Пароль панели REG.RU: ",
            ],
        )

    def test_non_regru_panel_url_is_rejected_before_panel_password_prompt(self):
        events = []
        visible_answers = iter(
            (
                "8.8.8.8",
                "",
                "",
                "",
                "https://evil.example/ispmgr",
                "https://vip999.hosting.reg.ru:1500/",
                "u1234567",
                "192.0.2.30",
                DOMAIN,
            )
        )
        hidden_answers = iter((EXIT_PASSWORD, PANEL_PASSWORD))

        def visible(prompt):
            value = next(visible_answers)
            events.append(("visible", prompt, value))
            return value

        def hidden(prompt):
            events.append(("hidden", prompt, "[REDACTED]"))
            return next(hidden_answers)

        with (
            patch("builtins.input", side_effect=visible),
            patch("xhttp_setup.cli.getpass.getpass", side_effect=hidden),
            redirect_stdout(StringIO()),
            redirect_stderr(StringIO()),
        ):
            result = _collect_pc_minimal_inputs()

        self.assertEqual(result, _inputs())
        invalid_url = next(
            index
            for index, event in enumerate(events)
            if event[0] == "visible" and event[2] == "https://evil.example/ispmgr"
        )
        valid_url = next(
            index
            for index, event in enumerate(events)
            if event[0] == "visible"
            and event[2] == "https://vip999.hosting.reg.ru:1500/"
        )
        panel_password = next(
            index
            for index, event in enumerate(events)
            if event[0] == "hidden" and event[1] == "Пароль панели REG.RU: "
        )
        self.assertLess(invalid_url, valid_url)
        self.assertLess(valid_url, panel_password)


class PcMinimalWizardOrchestrationTests(unittest.TestCase):
    def setUp(self) -> None:
        patcher = patch(
            "xhttp_setup.cli.exclusive_lock",
            side_effect=lambda _path: nullcontext(),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        firewall_patcher = patch("xhttp_setup.cli._confirm_pc_provider_firewall")
        self.confirm_provider_firewall = firewall_patcher.start()
        self.addCleanup(firewall_patcher.stop)

    def test_runs_prepare_then_existing_exit_front_and_e2e_without_firewall_ack(self):
        inputs = _inputs()
        prepared = _prepared()
        events: list[str] = []
        recovery_order: list[str] = []
        self.confirm_provider_firewall.side_effect = (
            lambda _desired: events.append("provider-firewall")
        )

        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "pc-output"
            handoff_path = Path(temp) / "handoff.json"
            handoff_path.write_text(
                json.dumps(_handoff().to_dict()), encoding="utf-8"
            )
            firewall_plan = Path(temp) / "firewall-plan.txt"

            def prepare(
                actual,
                *,
                output_dir: Path,
                progress,
                phase_callback,
                exit_password_prompt,
                panel_password_prompt,
                sftp_password_prompt,
                require_exit_recovery,
            ):
                events.append("prepare")
                self.assertIs(actual, inputs)
                self.assertEqual(output_dir, Path(temp) / "pc-output")
                self.assertTrue(callable(progress))
                self.assertTrue(callable(phase_callback))
                self.assertTrue(callable(exit_password_prompt))
                self.assertTrue(callable(panel_password_prompt))
                self.assertTrue(callable(sftp_password_prompt))
                self.assertFalse(require_exit_recovery)
                progress("Автоматическая подготовка завершена")
                return prepared

            def apply_exit(**kwargs):
                events.append("exit")
                self.assertIs(kwargs["desired"], prepared.desired_exit)
                self.assertIs(kwargs["target"], prepared.exit_target)
                self.assertIs(kwargs["auth"], prepared.exit_auth)
                self.assertEqual(kwargs["output_dir"], output_dir)
                self.assertEqual(
                    kwargs["trusted_known_hosts"], prepared.exit_known_hosts
                )
                return SimpleNamespace(
                    remote=SimpleNamespace(
                        handoff_path=handoff_path,
                        firewall_plan_path=firewall_plan,
                    )
                )

            front_result = FrontResult(
                root_status=200,
                path_status=404,
                backup_dir=Path(temp) / "backup",
                remote_htaccess_backup=None,
                remote_index_backup=None,
            )

            def apply_front(desired, **kwargs):
                events.append("front")
                self.assertEqual(desired.domain, DOMAIN)
                self.assertIs(kwargs["auth"], prepared.front_auth)
                self.assertEqual(
                    kwargs["trusted_known_hosts"], prepared.sftp_known_hosts
                )
                kwargs["pre_apply"]()
                kwargs["post_apply"](front_result)
                return front_result

            def e2e(**kwargs):
                events.append("e2e")
                self.assertEqual(kwargs["domain"], DOMAIN)
                self.assertEqual(kwargs["front_address"], "192.0.2.30")
                return "HTTP/1.1 200 OK"

            def issue(**kwargs):
                events.append("issue")
                return kwargs["state_dir"] / "client.vless"

            stdout = StringIO()
            stderr = StringIO()
            with ExitStack() as stack:
                stack.enter_context(patch("xhttp_setup.cli._require_linux_apply"))
                stack.enter_context(patch("xhttp_setup.cli._disable_pc_core_dumps"))
                stack.enter_context(
                    patch(
                        "xhttp_setup.cli._installer_pyz_from_runtime",
                        return_value=Path(temp) / "installer.pyz",
                    )
                )
                stack.enter_context(
                    patch(
                        "xhttp_setup.cli._collect_pc_minimal_inputs",
                        return_value=inputs,
                    )
                )
                stack.enter_context(
                    patch("xhttp_setup.cli._pc_output_dir", return_value=output_dir)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli.prepare_pc_install", side_effect=prepare)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli.apply_pc_exit", side_effect=apply_exit)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli.apply_front", side_effect=apply_front)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli.e2e_probe", side_effect=e2e)
                )
                stack.enter_context(
                    patch("xhttp_setup.cli._save_verified_link", side_effect=issue)
                )
                firewall_ack = stack.enter_context(
                    patch("xhttp_setup.cli._ack_firewall")
                )
                phase = stack.enter_context(patch("xhttp_setup.cli._write_pc_phase"))
                phase.side_effect = (
                    lambda _root, value: recovery_order.append(f"phase:{value}")
                )
                pending = stack.enter_context(
                    patch("xhttp_setup.cli.write_pending_pc_exit")
                )
                clear_pending = stack.enter_context(
                    patch("xhttp_setup.cli.clear_pending_pc_exit")
                )
                clear_pending.side_effect = (
                    lambda _root: recovery_order.append("clear_pending")
                )
                stack.enter_context(redirect_stdout(stdout))
                stack.enter_context(redirect_stderr(stderr))
                self.assertEqual(wizard_pc(), 0)

        self.assertEqual(
            events,
            ["prepare", "provider-firewall", "exit", "front", "e2e", "issue"],
        )
        self.confirm_provider_firewall.assert_called_once_with(
            prepared.desired_exit
        )
        self.assertEqual(
            [call.args[1] for call in phase.call_args_list],
            ["exit_applying", "exit_ready", "front_in_progress", "complete"],
        )
        self.assertEqual(
            recovery_order,
            [
                "phase:exit_applying",
                "phase:exit_ready",
                "clear_pending",
                "phase:front_in_progress",
                "phase:complete",
            ],
        )
        pending.assert_called_once()
        clear_pending.assert_called_once_with(output_dir)
        firewall_ack.assert_not_called()
        transcript = stdout.getvalue() + stderr.getvalue()
        _assert_no_manual_technical_inputs(self, transcript)
        for secret in (EXIT_PASSWORD, PANEL_PASSWORD, SFTP_PASSWORD):
            self.assertNotIn(secret, transcript)
            self.assertNotIn(secret, repr(inputs))
            self.assertNotIn(secret, repr(prepared))

    def test_verified_resume_skips_exit_apply_and_runs_same_front_e2e_path(self):
        prepared = replace(_prepared(), existing_handoff=_handoff())
        front_result = FrontResult(
            root_status=200,
            path_status=404,
            backup_dir=Path("/tmp/test-backup"),
            remote_htaccess_backup=None,
            remote_index_backup=None,
        )
        with tempfile.TemporaryDirectory() as temp:
            output = StringIO()
            with (
                patch("xhttp_setup.cli._require_linux_apply"),
                patch("xhttp_setup.cli._disable_pc_core_dumps"),
                patch(
                    "xhttp_setup.cli._installer_pyz_from_runtime",
                    return_value=Path(temp) / "installer.pyz",
                ),
                patch(
                    "xhttp_setup.cli._collect_pc_minimal_inputs",
                    return_value=_inputs(),
                ),
                patch(
                    "xhttp_setup.cli._pc_output_dir",
                    return_value=Path(temp) / "pc-output",
                ),
                patch(
                    "xhttp_setup.cli.prepare_pc_install", return_value=prepared
                ),
                patch("xhttp_setup.cli.apply_pc_exit") as apply_exit,
                patch("xhttp_setup.cli.write_pending_pc_exit") as pending,
                patch("xhttp_setup.cli.clear_pending_pc_exit") as clear_pending,
                patch(
                    "xhttp_setup.cli._apply_front_and_issue",
                    return_value=front_result,
                ) as apply_front,
                patch("xhttp_setup.cli._write_pc_phase") as phase,
                redirect_stdout(output),
            ):
                self.assertEqual(wizard_pc(), 0)

        apply_exit.assert_not_called()
        pending.assert_not_called()
        clear_pending.assert_called_once()
        apply_front.assert_called_once()
        self.assertEqual(
            [call.args[1] for call in phase.call_args_list],
            ["exit_ready", "front_in_progress", "complete"],
        )
        self.assertEqual(
            apply_front.call_args.kwargs["handoff"], prepared.existing_handoff
        )
        self.assertIn("ранее подтверждённый защищённый выход", output.getvalue())

    def test_exit_applying_phase_reuses_pending_desired_for_idempotent_apply(self):
        prepared = replace(_prepared(), pending_exit_recovery=True)
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "pc-output"
            handoff_path = Path(temp) / "handoff.json"
            handoff_path.write_text(
                json.dumps(_handoff().to_dict()), encoding="utf-8"
            )
            exit_result = SimpleNamespace(
                remote=SimpleNamespace(handoff_path=handoff_path)
            )

            def prepare(*args, **kwargs):
                self.assertEqual(args, (_inputs(),))
                self.assertTrue(kwargs["require_exit_recovery"])
                return prepared

            with (
                patch("xhttp_setup.cli._require_linux_apply"),
                patch("xhttp_setup.cli._disable_pc_core_dumps"),
                patch(
                    "xhttp_setup.cli._installer_pyz_from_runtime",
                    return_value=Path(temp) / "installer.pyz",
                ),
                patch(
                    "xhttp_setup.cli._collect_pc_minimal_inputs",
                    return_value=_inputs(),
                ),
                patch("xhttp_setup.cli._pc_output_dir", return_value=output_dir),
                patch(
                    "xhttp_setup.cli._read_pc_phase",
                    return_value="exit_applying",
                ),
                patch("xhttp_setup.cli.prepare_pc_install", side_effect=prepare),
                patch(
                    "xhttp_setup.cli.apply_pc_exit", return_value=exit_result
                ) as apply_exit,
                patch("xhttp_setup.cli.write_pending_pc_exit") as pending,
                patch("xhttp_setup.cli.clear_pending_pc_exit") as clear_pending,
                patch("xhttp_setup.cli._apply_front_and_issue"),
                patch("xhttp_setup.cli._write_pc_phase") as phase,
                redirect_stdout(StringIO()),
            ):
                self.assertEqual(wizard_pc(), 0)

        pending.assert_called_once()
        self.assertIs(pending.call_args.kwargs["prepared"], prepared)
        self.assertIs(apply_exit.call_args.kwargs["desired"], prepared.desired_exit)
        clear_pending.assert_called_once_with(output_dir)
        self.assertEqual(
            [call.args[1] for call in phase.call_args_list],
            ["exit_applying", "exit_ready", "front_in_progress", "complete"],
        )

    def test_in_progress_phase_refuses_resume_before_prepare(self):
        for interrupted_phase in (
            "front_probe_in_progress",
            "front_in_progress",
        ):
            with self.subTest(phase=interrupted_phase):
                with (
                    patch("xhttp_setup.cli._require_linux_apply"),
                    patch("xhttp_setup.cli._disable_pc_core_dumps"),
                    patch("xhttp_setup.cli._installer_pyz_from_runtime"),
                    patch(
                        "xhttp_setup.cli._collect_pc_minimal_inputs",
                        return_value=_inputs(),
                    ),
                    patch(
                        "xhttp_setup.cli._pc_output_dir",
                        return_value=Path("/tmp/pc"),
                    ),
                    patch(
                        "xhttp_setup.cli._read_pc_phase",
                        return_value=interrupted_phase,
                    ),
                    patch("xhttp_setup.cli.prepare_pc_install") as prepare,
                    self.assertRaisesRegex(InstallerError, "жёстко прерван"),
                    redirect_stdout(StringIO()),
                ):
                    wizard_pc()
                prepare.assert_not_called()

    def test_incomplete_front_rollback_leaves_in_progress_marker(self):
        prepared = _prepared()
        phases = []
        with tempfile.TemporaryDirectory() as temp:
            handoff_path = Path(temp) / "handoff.json"
            handoff_path.write_text(json.dumps(_handoff().to_dict()), encoding="utf-8")
            exit_result = SimpleNamespace(
                remote=SimpleNamespace(handoff_path=handoff_path)
            )
            with (
                patch("xhttp_setup.cli._require_linux_apply"),
                patch("xhttp_setup.cli._disable_pc_core_dumps"),
                patch(
                    "xhttp_setup.cli._installer_pyz_from_runtime",
                    return_value=Path(temp) / "installer.pyz",
                ),
                patch(
                    "xhttp_setup.cli._collect_pc_minimal_inputs",
                    return_value=_inputs(),
                ),
                patch(
                    "xhttp_setup.cli._pc_output_dir",
                    return_value=Path(temp) / "pc-output",
                ),
                patch("xhttp_setup.cli.prepare_pc_install", return_value=prepared),
                patch("xhttp_setup.cli.apply_pc_exit", return_value=exit_result),
                patch("xhttp_setup.cli.write_pending_pc_exit"),
                patch("xhttp_setup.cli.clear_pending_pc_exit"),
                patch(
                    "xhttp_setup.cli._apply_front_and_issue",
                    side_effect=FrontRollbackError("rollback неполон"),
                ),
                patch(
                    "xhttp_setup.cli._write_pc_phase",
                    side_effect=lambda _root, value: phases.append(value),
                ),
                redirect_stdout(StringIO()),
                redirect_stderr(StringIO()),
                self.assertRaises(FrontRollbackError),
            ):
                wizard_pc()
        self.assertEqual(
            phases, ["exit_applying", "exit_ready", "front_in_progress"]
        )

    @unittest.skipUnless(os.name == "posix", "POSIX phase file semantics")
    def test_phase_marker_round_trip_is_private_and_strict(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            os.chmod(root, 0o700)
            _write_pc_phase(root, "exit_ready")
            marker = root / "pc-phase.json"
            self.assertEqual(_read_pc_phase(root), "exit_ready")
            self.assertEqual(marker.stat().st_mode & 0o777, 0o600)


class PcProviderFirewallCheckpointTests(unittest.TestCase):
    def test_prints_exact_rule_and_waits_once_before_apply(self):
        desired = _prepared().desired_exit
        output = StringIO()
        with patch("builtins.input", return_value="") as prompt, redirect_stdout(
            output
        ):
            _confirm_pc_provider_firewall(desired)

        rendered = output.getvalue()
        self.assertIn(f"TCP/{desired.listen_port}", rendered)
        self.assertIn(f"{desired.front_egress_ip}/32", rendered)
        self.assertIn("ограничьте", rendered)
        self.assertNotIn("probe-порт", rendered)
        self.assertIn("если такой панели нет", rendered.lower())
        prompt.assert_called_once()


@unittest.skipUnless(os.name == "posix", "POSIX wizard lock semantics")
class PcWizardLockTests(unittest.TestCase):
    def test_second_wizard_stops_before_prepare_while_first_holds_lock(self):
        with tempfile.TemporaryDirectory() as temp:
            output_dir = Path(temp) / "pc-output"
            output_dir.mkdir(mode=0o700)
            with (
                exclusive_lock(output_dir / "wizard.lock"),
                patch("xhttp_setup.cli._require_linux_apply"),
                patch("xhttp_setup.cli._disable_pc_core_dumps"),
                patch(
                    "xhttp_setup.cli._installer_pyz_from_runtime",
                    return_value=Path(temp) / "installer.pyz",
                ),
                patch(
                    "xhttp_setup.cli._collect_pc_minimal_inputs",
                    return_value=_inputs(),
                ),
                patch("xhttp_setup.cli._pc_output_dir", return_value=output_dir),
                patch("xhttp_setup.cli.prepare_pc_install") as prepare,
                redirect_stdout(StringIO()),
                self.assertRaisesRegex(InstallerError, "уже работает"),
            ):
                wizard_pc()
            prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
