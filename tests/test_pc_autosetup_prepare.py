from __future__ import annotations

import contextlib
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.front_discovery import FrontTLSDiscovery
from xhttp_setup.ispmanager import ISPmanagerAuthenticationError, SiteInfo
from xhttp_setup.models import ExitDesired, Handoff, TLS_MODE_PUBLIC
from xhttp_setup.pc_autosetup import PcExitResume, PcUserInputs, prepare_pc_install
from xhttp_setup.ssh_transport import SFTPTransportError, SSHAuthenticationError


EXIT_PASSWORD = "exit-secret-for-test"
PANEL_PASSWORD = "panel-secret-for-test"
SFTP_PASSWORD = "separate-sftp-secret-for-test"
FINGERPRINT = "SHA256:" + ("A" * 43)


def completed(argv, returncode=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(argv, returncode, stdout=stdout, stderr=stderr)


def successful_docroot_probe(commands, *, start="/home/u1234567"):
    if len(commands) != 3 or commands[0] != "pwd" or commands[2] != "pwd":
        raise AssertionError(commands)
    operation, target = shlex.split(commands[1])
    if operation != "cd":
        raise AssertionError(commands)
    return completed(
        commands,
        stdout=(
            f"Remote working directory: {start}\nRemote working directory: {target}\n"
        ),
    )


def inputs() -> PcUserInputs:
    return PcUserInputs(
        exit_host="8.8.8.8",
        exit_port=22,
        exit_user="root",
        exit_password=EXIT_PASSWORD,
        panel_url="https://vip999.hosting.reg.ru:1500/",
        panel_user="u1234567",
        panel_password=PANEL_PASSWORD,
        front_connect_ip="192.0.2.30",
        domain="front.example.org",
    ).validate()


class FakeExitSSH:
    def __init__(self, events=None):
        self.events = events

    @contextlib.contextmanager
    def session(self):
        if self.events is not None:
            self.events.append("exit-session-open")
        try:
            yield self
        finally:
            if self.events is not None:
                self.events.append("exit-session-close")

    def command(self, argv, *, check=True, timeout=300):
        del check, timeout
        if argv == ["id", "-u"]:
            return completed(argv, stdout="0\n")
        if argv[:3] == ["ss", "-H", "-lnt"]:
            return completed(argv)
        raise AssertionError(argv)


class SuccessfulSFTP:
    def __init__(self, *, auth, events, **_kwargs):
        self.auth = auth
        self.events = events

    def batch(self, commands, *, check=True):
        del check
        self.events.append("sftp")
        return successful_docroot_probe(commands)


class PcPrepareTests(unittest.TestCase):
    def _run(
        self,
        root: Path,
        *,
        sftp_factory=None,
        password_prompt=None,
        inspect_side_effect=None,
        resume=None,
        exit_password_prompt=None,
        panel_password_prompt=None,
        exit_ssh_factory=None,
        inspect_sequence=None,
        phase_callback=None,
        front_egress_error=None,
        pending_desired=None,
    ):
        events: list[str] = []
        inspect_values = list(inspect_sequence or ())
        sftp_factory = sftp_factory or (
            lambda **kwargs: SuccessfulSFTP(events=events, **kwargs)
        )

        def scoped_sftp_factory(**kwargs):
            client = sftp_factory(**kwargs)
            if not hasattr(client, "session"):
                client.session = lambda: contextlib.nullcontext(client)
            return client

        exit_ssh_factory = exit_ssh_factory or (
            lambda **_kwargs: FakeExitSSH(events=events)
        )

        def inspect(**_kwargs):
            events.append("site")
            if inspect_values:
                value = inspect_values.pop(0)
                if isinstance(value, BaseException):
                    raise value
                return value
            if inspect_side_effect is not None:
                raise inspect_side_effect
            return SiteInfo(
                name="front.example.org",
                docroot="/var/www/site/data/www/front.example.org",
                ipaddr=None,
            )

        def dns(_domain):
            events.append("dns")
            return "192.0.2.31"

        def tls(*_args, **_kwargs):
            events.append("tls")
            return FrontTLSDiscovery(TLS_MODE_PUBLIC, None)

        def prepare(*_args, **_kwargs):
            events.append("prepare-exit")

        def exit_egress(*_args, **_kwargs):
            events.append("exit-egress")
            return "8.8.8.8"

        def front_egress(**_kwargs):
            events.append("front-egress")
            self.assertGreaterEqual(_kwargs["temporary_front"].exit_port, 20000)
            self.assertLess(_kwargs["temporary_front"].exit_port, 60000)
            self.assertNotEqual(_kwargs["temporary_front"].exit_port, 8083)
            if front_egress_error is not None:
                raise front_egress_error
            return "9.9.9.9"

        with (
            patch(
                "xhttp_setup.ssh_transport.trust_host_key_tofu",
                side_effect=(
                    (root / "exit.known_hosts", FINGERPRINT),
                    (root / "front.known_hosts", FINGERPRINT),
                ),
            ),
            patch("xhttp_setup.pc_autosetup.SSHClient", side_effect=exit_ssh_factory),
            patch(
                "xhttp_setup.pc_autosetup.SFTPClient",
                side_effect=scoped_sftp_factory,
            ),
            patch("xhttp_setup.pc_autosetup.inspect_site", side_effect=inspect),
            patch("xhttp_setup.front_discovery.resolve_front_dns", side_effect=dns),
            patch(
                "xhttp_setup.front_discovery.discover_front_tls_policy",
                side_effect=tls,
            ),
            patch(
                "xhttp_setup.pc_autosetup.inspect_existing_pc_exit",
                return_value=resume,
            ),
            patch(
                "xhttp_setup.pc_autosetup._load_pending_pc_exit",
                return_value=pending_desired,
            ),
            patch(
                "xhttp_setup.remote_prepare.prepare_remote_exit",
                side_effect=prepare,
            ) as prepare_exit,
            patch(
                "xhttp_setup.remote_prepare.measure_remote_exit_egress",
                side_effect=exit_egress,
            ),
            patch(
                "xhttp_setup.pc_autosetup.measure_front_egress",
                side_effect=front_egress,
            ),
        ):
            result = prepare_pc_install(
                inputs(),
                output_dir=root / "state",
                phase_callback=phase_callback,
                exit_password_prompt=exit_password_prompt,
                panel_password_prompt=panel_password_prompt,
                sftp_password_prompt=password_prompt,
            )
        return result, events, prepare_exit

    def test_all_frontend_preflights_finish_before_exit_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            result, events, _ = self._run(Path(temp))

        self.assertEqual(
            [event for event in events if event.startswith("exit-session-")],
            [
                "exit-session-open",
                "exit-session-close",
                "exit-session-open",
                "exit-session-close",
            ],
        )
        first_close = events.index("exit-session-close")
        second_open = events.index("exit-session-open", first_close + 1)
        for frontend_preflight in ("site", "dns", "sftp", "tls"):
            self.assertGreater(events.index(frontend_preflight), first_close)
            self.assertLess(events.index(frontend_preflight), second_open)
        mutation = events.index("prepare-exit")
        for read_only in ("site", "dns", "sftp", "tls"):
            self.assertLess(events.index(read_only), mutation)
        self.assertEqual(result.desired_exit.front_egress_ip, "9.9.9.9")
        self.assertEqual(result.desired_front.placeholder_mode, "keep")
        self.assertEqual(result.desired_front.client_connect_ip, "192.0.2.30")
        self.assertEqual(result.desired_front.dns_ipv4, "192.0.2.31")
        self.assertEqual(result.front_auth.password, PANEL_PASSWORD)

    def test_missing_site_aborts_before_any_exit_mutation(self):
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(VerificationError, "site missing"):
                self._run(
                    Path(temp),
                    inspect_side_effect=VerificationError("site missing"),
                )

        # The helper cannot return its mock on failure, so prove the ordering by
        # supplying a separately visible remote mutation mock.
        prepare = Mock()
        with (
            tempfile.TemporaryDirectory() as temp,
            patch(
                "xhttp_setup.ssh_transport.trust_host_key_tofu",
                return_value=(Path(temp) / "known_hosts", FINGERPRINT),
            ),
            patch("xhttp_setup.pc_autosetup.SSHClient", return_value=FakeExitSSH()),
            patch(
                "xhttp_setup.pc_autosetup.inspect_site",
                side_effect=VerificationError("site missing"),
            ),
            patch("xhttp_setup.remote_prepare.prepare_remote_exit", prepare),
        ):
            with self.assertRaisesRegex(VerificationError, "site missing"):
                prepare_pc_install(inputs(), output_dir=Path(temp) / "state")
        prepare.assert_not_called()

    def test_separate_sftp_password_is_requested_only_after_exact_auth_failure(self):
        auths = []

        class ConditionalSFTP:
            def __init__(self, *, auth, **_kwargs):
                self.auth = auth
                auths.append(auth)

            @contextlib.contextmanager
            def session(self):
                if self.auth.password == PANEL_PASSWORD:
                    raise SSHAuthenticationError(
                        "operator@sftp.example: Permission denied (password)."
                    )
                yield self

            def batch(self, commands, *, check=True):
                del check
                return successful_docroot_probe(commands)

        prompt = Mock(return_value=SFTP_PASSWORD)
        with tempfile.TemporaryDirectory() as temp:
            result, _, _ = self._run(
                Path(temp),
                sftp_factory=ConditionalSFTP,
                password_prompt=prompt,
            )

        prompt.assert_called_once_with()
        self.assertEqual(len(auths), 2)
        self.assertEqual(auths[0].password, PANEL_PASSWORD)
        self.assertEqual(auths[1].password, SFTP_PASSWORD)
        self.assertEqual(result.front_auth.password, SFTP_PASSWORD)
        for secret in (EXIT_PASSWORD, PANEL_PASSWORD, SFTP_PASSWORD):
            self.assertNotIn(secret, repr(result))

    def test_docroot_failure_never_prompts_for_another_password(self):
        class DeniedDirectorySFTP:
            def __init__(self, **_kwargs):
                pass

            def batch(self, commands, *, check=True):
                del check
                return completed(commands, returncode=1, stderr="Permission denied")

        prompt = Mock(return_value=SFTP_PASSWORD)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(InstallerError, "doc(?:ument )?root"):
                self._run(
                    Path(temp),
                    sftp_factory=DeniedDirectorySFTP,
                    password_prompt=prompt,
                )
        prompt.assert_not_called()

    def test_user_rooted_ispmanager_docroot_resolves_against_sftp_start_dir(self):
        calls = []
        session_events = []
        api_docroot = "/front.example.org"
        sftp_home = "/var/www/u1234567/data"
        resolved_docroot = f"{sftp_home}{api_docroot}"

        class UserRootedSFTP:
            def __init__(self, **_kwargs):
                pass

            @contextlib.contextmanager
            def session(self):
                session_events.append("open")
                try:
                    yield self
                finally:
                    session_events.append("close")

            def batch(self, commands, *, check=True):
                del check
                calls.append(commands)
                if commands == ["pwd", f'cd "{api_docroot}"', "pwd"]:
                    return completed(
                        commands,
                        returncode=1,
                        stdout=f"Remote working directory: {sftp_home}\n",
                        stderr="stat remote: No such file or directory\n",
                    )
                if commands == [f'cd "{resolved_docroot}"', "pwd"]:
                    return completed(
                        commands,
                        stdout=f"Remote working directory: {resolved_docroot}\n",
                    )
                raise AssertionError(commands)

        site = SiteInfo(name="front.example.org", docroot=api_docroot, ipaddr=None)
        with tempfile.TemporaryDirectory() as temp:
            result, _, _ = self._run(
                Path(temp),
                sftp_factory=UserRootedSFTP,
                inspect_sequence=(site,),
            )

        self.assertEqual(result.desired_front.document_root, resolved_docroot)
        self.assertEqual(session_events, ["open", "close"])
        self.assertEqual(
            calls,
            [
                ["pwd", f'cd "{api_docroot}"', "pwd"],
                [f'cd "{resolved_docroot}"', "pwd"],
            ],
        )

    def test_exact_docroot_uses_canonical_pwd_returned_by_sftp(self):
        api_docroot = "/var/www/sites/front.example.org-link"
        canonical_docroot = "/srv/hosting/front.example.org"

        class CanonicalSFTP:
            def __init__(self, **_kwargs):
                pass

            def batch(self, commands, *, check=True):
                del check
                return completed(
                    commands,
                    stdout=(
                        "Remote working directory: /home/u1234567\n"
                        f"Remote working directory: {canonical_docroot}\n"
                    ),
                )

        site = SiteInfo(name="front.example.org", docroot=api_docroot, ipaddr=None)
        with tempfile.TemporaryDirectory() as temp:
            result, _, _ = self._run(
                Path(temp),
                sftp_factory=CanonicalSFTP,
                inspect_sequence=(site,),
            )

        self.assertEqual(result.desired_front.document_root, canonical_docroot)

    def test_user_rooted_docroot_requires_one_safe_sftp_pwd(self):
        class AmbiguousPwdSFTP:
            def __init__(self, **_kwargs):
                pass

            def batch(self, commands, *, check=True):
                del check
                return completed(
                    commands,
                    returncode=1,
                    stdout=(
                        "Remote working directory: /var/www/one\n"
                        "Remote working directory: /var/www/two\n"
                    ),
                    stderr="stat remote: No such file or directory\n",
                )

        site = SiteInfo(
            name="front.example.org",
            docroot="/sites/front.example.org",
            ipaddr=None,
        )
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(VerificationError, "однознач"):
                self._run(
                    Path(temp),
                    sftp_factory=AmbiguousPwdSFTP,
                    inspect_sequence=(site,),
                )

    def test_user_rooted_docroot_rejects_target_outside_sftp_start_dir(self):
        calls = 0

        class EscapingSFTP:
            def __init__(self, **_kwargs):
                pass

            def batch(self, commands, *, check=True):
                nonlocal calls
                del check
                calls += 1
                if calls == 1:
                    return completed(
                        commands,
                        returncode=1,
                        stdout="Remote working directory: /var/www/u/data\n",
                        stderr="stat remote: No such file or directory\n",
                    )
                return completed(
                    commands,
                    stdout="Remote working directory: /srv/other-site\n",
                )

        site = SiteInfo("front.example.org", "/front.example.org", None)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(VerificationError, "вышел"):
                self._run(
                    Path(temp),
                    sftp_factory=EscapingSFTP,
                    inspect_sequence=(site,),
                )
        self.assertEqual(calls, 2)

    def test_chroot_root_pwd_is_valid_but_gives_no_second_interpretation(self):
        calls = 0

        class RootedSFTP:
            def __init__(self, **_kwargs):
                pass

            def batch(self, commands, *, check=True):
                nonlocal calls
                del check
                calls += 1
                return completed(
                    commands,
                    returncode=1,
                    stdout="Remote working directory: /\n",
                    stderr="stat remote: No such file or directory\n",
                )

        site = SiteInfo("front.example.org", "/front.example.org", None)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(VerificationError, "сопоставить"):
                self._run(
                    Path(temp),
                    sftp_factory=RootedSFTP,
                    inspect_sequence=(site,),
                )
        self.assertEqual(calls, 1)

    def test_mixed_missing_path_diagnostic_does_not_authorize_fallback(self):
        calls = []

        class MixedFailureSFTP:
            def __init__(self, **_kwargs):
                pass

            def batch(self, commands, *, check=True):
                del check
                calls.append(commands)
                return completed(
                    commands,
                    returncode=1,
                    stdout="Remote working directory: /var/www/u/data\n",
                    stderr=(
                        "stat remote: No such file or directory\nPermission denied\n"
                    ),
                )

        site = SiteInfo("front.example.org", "/front.example.org", None)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(VerificationError, "недоступен"):
                self._run(
                    Path(temp),
                    sftp_factory=MixedFailureSFTP,
                    inspect_sequence=(site,),
                )
        self.assertEqual(len(calls), 1)

    def test_post_auth_fallback_failure_never_reprompts_password(self):
        calls = 0

        class ChangedTransportSFTP:
            def __init__(self, **_kwargs):
                pass

            def batch(self, commands, *, check=True):
                nonlocal calls
                del check
                calls += 1
                if calls == 1:
                    return completed(
                        commands,
                        returncode=1,
                        stdout="Remote working directory: /var/www/u/data\n",
                        stderr="stat remote: No such file or directory\n",
                    )
                raise SFTPTransportError("accepted session transport changed")

        prompt = Mock(return_value=SFTP_PASSWORD)
        site = SiteInfo("front.example.org", "/front.example.org", None)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(
                SFTPTransportError, "accepted session transport changed"
            ):
                self._run(
                    Path(temp),
                    sftp_factory=ChangedTransportSFTP,
                    inspect_sequence=(site,),
                    password_prompt=prompt,
                )
        prompt.assert_not_called()
        self.assertEqual(calls, 2)

    def test_session_cleanup_failure_after_auth_never_reprompts_password(self):
        class CleanupFailureSFTP:
            def __init__(self, **_kwargs):
                pass

            @contextlib.contextmanager
            def session(self):
                yield self
                raise InstallerError("authenticated SFTP cleanup failed")

            def batch(self, commands, *, check=True):
                del check
                return successful_docroot_probe(commands)

        prompt = Mock(return_value=SFTP_PASSWORD)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(
                InstallerError, "authenticated SFTP cleanup failed"
            ):
                self._run(
                    Path(temp),
                    sftp_factory=CleanupFailureSFTP,
                    password_prompt=prompt,
                )

        prompt.assert_not_called()

    def test_mistyped_separate_sftp_password_gets_one_bounded_retry(self):
        auths = []

        class RetrySFTP:
            def __init__(self, *, auth, **_kwargs):
                self.auth = auth
                auths.append(auth)

            @contextlib.contextmanager
            def session(self):
                if self.auth.password != SFTP_PASSWORD:
                    raise SSHAuthenticationError(
                        "operator@sftp.example: Permission denied (password)."
                    )
                yield self

            def batch(self, commands, *, check=True):
                del check
                return successful_docroot_probe(commands)

        prompt = Mock(side_effect=("mistyped-sftp-password", SFTP_PASSWORD))
        with tempfile.TemporaryDirectory() as temp:
            result, _, _ = self._run(
                Path(temp),
                sftp_factory=RetrySFTP,
                password_prompt=prompt,
            )

        self.assertEqual(prompt.call_count, 2)
        self.assertEqual(
            [auth.password for auth in auths],
            [PANEL_PASSWORD, "mistyped-sftp-password", SFTP_PASSWORD],
        )
        self.assertEqual(result.front_auth.password, SFTP_PASSWORD)

    def test_verified_resume_skips_exit_prepare_port_probe_and_new_credentials(self):
        client_id = "d342d11e-d424-4583-b36e-524ab1f0afa4"
        xhttp_path = "/api/resume-path-0123456789"
        desired = ExitDesired(
            public_address="8.8.8.8",
            listen_port=8083,
            front_egress_ip="9.9.9.9",
            xhttp_path=xhttp_path,
            client_id=client_id,
            expected_egress_ip="8.8.8.8",
        ).validate()
        handoff = Handoff(
            exit_address="8.8.8.8",
            exit_port=8083,
            client_id=client_id,
            xhttp_path=xhttp_path,
            encryption="mlkem768x25519plus.native.0rtt.clientmaterialxxxxxxxx",
            expected_egress_ip="8.8.8.8",
        ).validate()
        with tempfile.TemporaryDirectory() as temp:
            result, events, prepare = self._run(
                Path(temp), resume=PcExitResume(desired=desired, handoff=handoff)
            )

        self.assertIs(result.existing_handoff, handoff)
        self.assertEqual(result.desired_exit.client_id, client_id)
        self.assertEqual(result.desired_front.xhttp_path, xhttp_path)
        self.assertNotIn("prepare-exit", events)
        self.assertNotIn("exit-egress", events)
        self.assertIn("front-egress", events)
        prepare.assert_not_called()

    def test_wrong_exit_password_reprompts_only_that_secret(self):
        auths = []

        class AuthAwareExitSSH(FakeExitSSH):
            def __init__(self, auth):
                super().__init__()
                self.auth = auth

            def command(self, argv, *, check=True, timeout=300):
                if argv == ["id", "-u"] and self.auth.password == EXIT_PASSWORD:
                    raise SSHAuthenticationError("Permission denied")
                return super().command(argv, check=check, timeout=timeout)

        def factory(*, auth, **_kwargs):
            auths.append(auth)
            return AuthAwareExitSSH(auth)

        prompt = Mock(return_value="corrected-exit-password")
        with tempfile.TemporaryDirectory() as temp:
            result, _, _ = self._run(
                Path(temp),
                exit_password_prompt=prompt,
                exit_ssh_factory=factory,
            )

        prompt.assert_called_once_with()
        self.assertEqual(
            [auth.password for auth in auths],
            [EXIT_PASSWORD, "corrected-exit-password"],
        )
        self.assertEqual(result.exit_auth.password, "corrected-exit-password")

    def test_main_session_auth_failure_never_reprompts_exit_password(self):
        class MainSessionAuthFailure(FakeExitSSH):
            def __init__(self):
                super().__init__()
                self.session_calls = 0

            @contextlib.contextmanager
            def session(self):
                self.session_calls += 1
                if self.session_calls == 2:
                    raise SSHAuthenticationError("main SSH transport unavailable")
                yield self

        prompt = Mock(return_value="unused-corrected-exit-password")
        exit_client = MainSessionAuthFailure()
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(
                SSHAuthenticationError, "main SSH transport unavailable"
            ):
                self._run(
                    Path(temp),
                    exit_password_prompt=prompt,
                    exit_ssh_factory=lambda **_kwargs: exit_client,
                )

        self.assertEqual(exit_client.session_calls, 2)
        prompt.assert_not_called()

    def test_wrong_panel_password_reprompts_without_repeating_other_fields(self):
        site = SiteInfo(
            name="front.example.org",
            docroot="/var/www/site/data/www/front.example.org",
            ipaddr=None,
        )
        seen_sftp_auth = []

        class CaptureSFTP:
            def __init__(self, *, auth, **_kwargs):
                seen_sftp_auth.append(auth)

            def batch(self, commands, *, check=True):
                del check
                return successful_docroot_probe(commands)

        prompt = Mock(return_value="corrected-panel-password")
        with tempfile.TemporaryDirectory() as temp:
            result, events, _ = self._run(
                Path(temp),
                sftp_factory=CaptureSFTP,
                panel_password_prompt=prompt,
                inspect_sequence=(
                    ISPmanagerAuthenticationError("invalid password"),
                    site,
                ),
            )

        prompt.assert_called_once_with()
        self.assertEqual(events.count("site"), 2)
        self.assertEqual(seen_sftp_auth[0].password, "corrected-panel-password")
        self.assertEqual(result.front_auth.password, "corrected-panel-password")

    def test_incomplete_temporary_front_rollback_leaves_probe_phase(self):
        from xhttp_setup.front import FrontRollbackError

        phases = []
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(FrontRollbackError):
                self._run(
                    Path(temp),
                    phase_callback=phases.append,
                    front_egress_error=FrontRollbackError("rollback неполон"),
                )
        self.assertEqual(phases, ["front_probe_in_progress"])

    def test_pending_exit_recovery_reuses_exact_desired_and_skips_prepare(self):
        desired = ExitDesired(
            public_address="8.8.8.8",
            listen_port=8083,
            front_egress_ip="9.9.9.9",
            xhttp_path="/api/pending-path-0123456789",
            client_id="d342d11e-d424-4583-b36e-524ab1f0afa4",
            expected_egress_ip="8.8.8.8",
        ).validate()
        with tempfile.TemporaryDirectory() as temp:
            result, events, prepare = self._run(Path(temp), pending_desired=desired)

        self.assertTrue(result.pending_exit_recovery)
        self.assertIsNone(result.existing_handoff)
        self.assertEqual(result.desired_exit, desired)
        self.assertIn("front-egress", events)
        self.assertNotIn("prepare-exit", events)
        prepare.assert_not_called()


if __name__ == "__main__":
    unittest.main()
