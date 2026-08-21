import contextlib
import tempfile
import traceback
import unittest
from dataclasses import replace
from pathlib import Path
from unittest import mock

from xhttp_setup.errors import (
    HTTPSResponseError,
    InstallerError,
    TLSVerificationError,
    VerificationError,
)
from xhttp_setup.front_probe import (
    run_with_temporary_front_route,
    verify_front_proxy_capability,
    verify_front_rewrite_control,
)
from xhttp_setup.models import FrontDesired
from xhttp_setup.ssh_transport import SSHAuth, SSHRoute, TCPRoute


_HOST_FINGERPRINT = "SHA256:" + "A" * 43


class _ScopedClient:
    def __init__(self):
        self.session_events = []

    @contextlib.contextmanager
    def session(self):
        self.session_events.append("open")
        try:
            yield self
        finally:
            self.session_events.append("close")


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


class TemporaryFrontRouteTests(unittest.TestCase):
    def _run(
        self,
        root: Path,
        *,
        operation,
        route_mode="proxy",
        rollback_side_effect=None,
        upload_side_effect=None,
    ):
        events: list[str] = []
        captured: dict[str, object] = {}
        self.last_events = events
        self.last_captured = captured
        client = _ScopedClient()

        def download(_client, remote_dir, name, local):
            self.assertIs(_client, client)
            self.assertEqual(remote_dir, "/var/www/site")
            self.assertEqual(name, ".htaccess")
            local.write_text("RewriteEngine On\n# owner rule\n", encoding="utf-8")
            return True

        def upload(_client, **kwargs):
            self.assertIs(_client, client)
            self.assertEqual(kwargs["remote_dir"], "/var/www/site")
            self.assertEqual(kwargs["target"], ".htaccess")
            self.assertRegex(kwargs["backup_name"], r"^\.xhttp-backup-htaccess-probe-")
            captured["temporary"] = kwargs["local"].read_text("utf-8")
            kwargs["journal"].append("temporary-htaccess-mutation")
            events.append("upload")
            if upload_side_effect is not None:
                raise upload_side_effect

        def rollback(_transport, _session, **kwargs):
            self.assertIs(_transport, client)
            self.assertIs(_session, client)
            self.assertEqual(kwargs["remote_dir"], "/var/www/site")
            self.assertEqual(kwargs["journal"], ["temporary-htaccess-mutation"])
            captured["rollback_original"] = kwargs["original"]
            events.append("rollback")
            if rollback_side_effect is not None:
                raise rollback_side_effect

        def wrapped_operation():
            events.append("operation")
            return operation()

        def atomic_write(path, text, _mode):
            path.write_text(text, encoding="utf-8")

        secret = "front-sftp-password-never-log"
        auth = SSHAuth("password", password=secret)
        with (
            mock.patch("xhttp_setup.front_probe.check_front_dns"),
            mock.patch("xhttp_setup.front_probe.check_public_tls"),
            mock.patch("xhttp_setup.front_probe.pin_host_key") as pin,
            mock.patch(
                "xhttp_setup.front_probe.SFTPClient", return_value=client
            ) as sftp,
            mock.patch(
                "xhttp_setup.front_probe.exclusive_lock",
                return_value=contextlib.nullcontext(),
            ),
            mock.patch(
                "xhttp_setup.front_probe.atomic_write_text",
                side_effect=atomic_write,
            ),
            mock.patch(
                "xhttp_setup.front_probe._download_optional", side_effect=download
            ),
            mock.patch("xhttp_setup.front_probe._upload_verified", side_effect=upload),
            mock.patch(
                "xhttp_setup.front_probe._rollback_journal_with_recovery",
                side_effect=rollback,
            ),
        ):
            try:
                result = run_with_temporary_front_route(
                    _desired(),
                    auth=auth,
                    state_dir=root / "probe-state",
                    operation=wrapped_operation,
                    route_mode=route_mode,
                    rewrite_control_nonce=(
                        "b" * 32
                        if route_mode in ("rewrite-control", "proxy-control")
                        else None
                    ),
                    trusted_known_hosts=root / "persistent-sftp.known_hosts",
                )
            finally:
                captured["sftp_calls"] = sftp.call_args_list
                captured["pin_calls"] = pin.call_args_list
                captured["session_events"] = client.session_events

        self.assertNotIn(secret, repr(captured))
        return result, events, captured

    def test_success_uploads_temporary_htaccess_then_rolls_it_back(self):
        with tempfile.TemporaryDirectory() as temp:
            result, events, captured = self._run(
                Path(temp), operation=lambda: "measurement complete"
            )

        self.assertEqual(result, "measurement complete")
        self.assertEqual(events, ["upload", "operation", "rollback"])
        self.assertEqual(captured["session_events"], ["open", "close"])
        temporary = captured["temporary"]
        self.assertIn("# owner rule", temporary)
        self.assertIn("203.0.113.20:25432", temporary)
        self.assertIn("/api/temporary-probe", temporary)
        self.assertIsInstance(captured["rollback_original"], InstallerError)
        self.assertEqual(
            captured["pin_calls"][0].kwargs["trusted_known_hosts"],
            Path(temp) / "persistent-sftp.known_hosts",
        )

    def test_rewrite_control_uses_only_exact_redirect_rule_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as temp:
            result, events, captured = self._run(
                Path(temp),
                operation=lambda: "control complete",
                route_mode="rewrite-control",
            )

        self.assertEqual(result, "control complete")
        self.assertEqual(events, ["upload", "operation", "rollback"])
        temporary = captured["temporary"]
        self.assertIn(
            "RewriteRule ^api/temporary-probe/xhttp-setup-control-"
            + "b" * 32
            + "$ / [R=302,L]",
            temporary,
        )
        self.assertNotIn("[P,", temporary)
        self.assertNotIn("203.0.113.20:25432", temporary)
        self.assertNotIn("ProxyRequests", temporary)
        self.assertNotIn("CGI", temporary)

    def test_proxy_control_uses_exact_literal_upstream_and_rolls_back(self):
        with tempfile.TemporaryDirectory() as temp:
            result, events, captured = self._run(
                Path(temp),
                operation=lambda: "proxy control complete",
                route_mode="proxy-control",
            )

        self.assertEqual(result, "proxy control complete")
        self.assertEqual(events, ["upload", "operation", "rollback"])
        temporary = captured["temporary"]
        expected = (
            "RewriteRule ^api/temporary-probe/xhttp-setup-control-"
            + "b" * 32
            + "$ http://127.0.0.1:9/"
            + "b" * 32
            + " [P,L]"
        )
        self.assertIn(expected, temporary)
        self.assertNotIn("$1", temporary)
        self.assertNotIn("?", temporary)
        self.assertNotIn("203.0.113.20:25432", temporary)
        self.assertNotIn("ProxyRequests", temporary)

    def test_rewrite_control_error_is_reraised_only_after_rollback(self):
        original = VerificationError("control response was not 302")

        def fail():
            raise original

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(VerificationError) as raised:
                self._run(
                    Path(temp),
                    operation=fail,
                    route_mode="rewrite-control",
                )

        self.assertIs(raised.exception, original)
        self.assertEqual(self.last_events, ["upload", "operation", "rollback"])
        self.assertIs(self.last_captured["rollback_original"], original)

    def test_operation_error_is_reraised_only_after_rollback(self):
        original = VerificationError("frontend request failed")

        def fail():
            raise original

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(VerificationError) as raised:
                self._run(Path(temp), operation=fail)

        self.assertIs(raised.exception, original)
        self.assertEqual(self.last_events, ["upload", "operation", "rollback"])
        self.assertIs(self.last_captured["rollback_original"], original)
        self.assertNotIn("front-sftp-password-never-log", repr(self.last_captured))

    def test_keyboard_interrupt_is_reraised_only_after_rollback(self):
        original = KeyboardInterrupt()

        def interrupt():
            raise original

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(KeyboardInterrupt) as raised:
                self._run(Path(temp), operation=interrupt)

        self.assertIs(raised.exception, original)
        self.assertEqual(self.last_events, ["upload", "operation", "rollback"])
        self.assertIs(self.last_captured["rollback_original"], original)
        self.assertNotIn("front-sftp-password-never-log", repr(self.last_captured))

    def test_partial_upload_error_still_rolls_back_registered_mutation(self):
        original = InstallerError("upload connection lost")
        operation = mock.Mock(return_value=None)
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InstallerError) as raised:
                self._run(
                    Path(temp),
                    operation=operation,
                    upload_side_effect=original,
                )

        self.assertIs(raised.exception, original)
        self.assertEqual(self.last_events, ["upload", "rollback"])
        self.assertIs(self.last_captured["rollback_original"], original)
        self.assertNotIn("front-sftp-password-never-log", repr(self.last_captured))
        operation.assert_not_called()

    def test_rollback_failure_is_propagated_after_success(self):
        rollback_error = InstallerError("rollback cleanup incomplete")
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InstallerError) as raised:
                self._run(
                    Path(temp),
                    operation=lambda: "unused",
                    rollback_side_effect=rollback_error,
                )

        self.assertIs(raised.exception, rollback_error)

    def test_rollback_failure_supersedes_operation_error(self):
        original = VerificationError("request failed")
        rollback_error = InstallerError("rollback cleanup incomplete")

        def fail():
            raise original

        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaises(InstallerError) as raised:
                self._run(
                    Path(temp),
                    operation=fail,
                    rollback_side_effect=rollback_error,
                )

        self.assertIs(raised.exception, rollback_error)


class RewriteControlVerificationTests(unittest.TestCase):
    def _verify(self, desired: FrontDesired, *, status_or_error):
        route = TCPRoute("127.0.0.1", 44321)
        auth = SSHAuth("password", password="secret-never-log")
        seen: dict[str, object] = {}

        def temporary_route(route_desired, **kwargs):
            seen["desired"] = route_desired
            seen["kwargs"] = kwargs
            return kwargs["operation"]()

        with (
            mock.patch(
                "xhttp_setup.front_probe.secrets.token_hex",
                return_value="a" * 32,
            ),
            mock.patch(
                "xhttp_setup.front_probe.run_with_temporary_front_route",
                side_effect=temporary_route,
            ) as temporary,
            mock.patch(
                "xhttp_setup.front_probe.https_status",
                side_effect=(
                    status_or_error
                    if isinstance(status_or_error, BaseException)
                    else None
                ),
                return_value=(
                    status_or_error
                    if not isinstance(status_or_error, BaseException)
                    else None
                ),
            ) as status,
        ):
            verify_front_rewrite_control(
                desired,
                auth=auth,
                state_dir=Path("/tmp/front-control"),
                https_route=route,
                trusted_known_hosts=Path("/tmp/persistent-sftp.known_hosts"),
            )

        seen["temporary_calls"] = temporary.call_args_list
        seen["status_calls"] = status.call_args_list
        self.assertNotIn("secret-never-log", repr(seen))
        return seen

    def test_exact_302_passes_on_unique_suffix_without_mutating_max_path(self):
        desired = replace(_desired(), xhttp_path="/" + "a" * 179).validate()
        seen = self._verify(desired, status_or_error=302)

        installed = seen["desired"]
        self.assertEqual(installed.xhttp_path, desired.xhttp_path)
        kwargs = seen["kwargs"]
        self.assertEqual(kwargs["route_mode"], "rewrite-control")
        self.assertEqual(kwargs["rewrite_control_nonce"], "a" * 32)
        self.assertEqual(kwargs["https_route"], TCPRoute("127.0.0.1", 44321))
        call = seen["status_calls"][0]
        self.assertEqual(
            call.args[0],
            f"https://front.example.org{desired.xhttp_path}"
            "/xhttp-setup-control-" + "a" * 32,
        )
        self.assertEqual(call.kwargs["connect_ip"], "192.0.2.10")
        self.assertEqual(call.kwargs["timeout"], 8)
        self.assertEqual(call.kwargs["route"], TCPRoute("127.0.0.1", 44321))

    def test_non_302_status_fails_distinctly_without_path_disclosure(self):
        desired = _desired()
        with self.assertRaises(VerificationError) as caught:
            self._verify(desired, status_or_error=404)

        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertIn("ожидался HTTP 302, получен HTTP 404", rendered)
        self.assertNotIn(desired.xhttp_path, rendered)
        self.assertNotIn("https://", rendered)

    def test_transport_and_tls_failures_are_distinct_and_sanitized(self):
        desired = _desired()
        cases = (
            (
                HTTPSResponseError(
                    f"response failed at https://front.example.org{desired.xhttp_path}"
                ),
                VerificationError,
                "отправлен, но корректный HTTP-ответ не получен",
            ),
            (
                VerificationError(
                    f"connect failed at https://front.example.org{desired.xhttp_path}"
                ),
                VerificationError,
                "не удалось безопасно отправить",
            ),
            (
                TLSVerificationError(
                    f"pin failed at https://front.example.org{desired.xhttp_path}"
                ),
                TLSVerificationError,
                "TLS/SNI/leaf-сертификат не прошёл",
            ),
        )
        for error, expected_type, message in cases:
            with (
                self.subTest(error=type(error).__name__),
                self.assertRaises(expected_type) as caught,
            ):
                self._verify(desired, status_or_error=error)
            rendered = "".join(traceback.format_exception(caught.exception))
            self.assertIn(message, rendered)
            self.assertNotIn(desired.xhttp_path, rendered)
            self.assertNotIn("https://", rendered)
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)


class ProxyCapabilityVerificationTests(unittest.TestCase):
    def _verify(
        self,
        desired: FrontDesired,
        *,
        responses,
        rollback_error=None,
        sftp_route=None,
        https_route=None,
    ):
        auth = SSHAuth("password", password="proxy-secret-never-log")
        events: list[str] = []
        self.last_proxy_events = events

        def temporary_route(_desired_value, **kwargs):
            mode = kwargs["route_mode"]
            events.append(f"install:{mode}")
            result = kwargs["operation"]()
            events.append(f"rollback:{mode}")
            if rollback_error is not None and mode == "proxy-control":
                raise rollback_error
            return result

        def status(url, **_kwargs):
            events.append(f"request:{url}")
            response = responses.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        with (
            mock.patch(
                "xhttp_setup.front_probe.secrets.token_hex",
                return_value="c" * 32,
            ),
            mock.patch(
                "xhttp_setup.front_probe.run_with_temporary_front_route",
                side_effect=temporary_route,
            ) as temporary,
            mock.patch(
                "xhttp_setup.front_probe.https_status", side_effect=status
            ) as https_status,
        ):
            result = verify_front_proxy_capability(
                desired,
                auth=auth,
                state_dir=Path("/tmp/front-control"),
                sftp_route=sftp_route,
                https_route=https_route,
                trusted_known_hosts=Path("/tmp/persistent-sftp.known_hosts"),
            )

        captured = (temporary.call_args_list, https_status.call_args_list, events)
        self.assertNotIn("proxy-secret-never-log", repr(captured))
        return result, captured

    def test_same_exact_url_and_nonce_are_used_for_both_routes(self):
        result, captured = self._verify(_desired(), responses=[302, 503])
        temporary_calls, status_calls, events = captured

        self.assertIs(result, True)
        self.assertEqual(
            [call.kwargs["route_mode"] for call in temporary_calls],
            ["rewrite-control", "proxy-control"],
        )
        self.assertEqual(
            [call.kwargs["rewrite_control_nonce"] for call in temporary_calls],
            ["c" * 32, "c" * 32],
        )
        expected_url = (
            "https://front.example.org/api/temporary-probe/"
            "xhttp-setup-control-" + "c" * 32
        )
        self.assertEqual([call.args[0] for call in status_calls], [expected_url] * 2)
        self.assertEqual(
            events,
            [
                "install:rewrite-control",
                f"request:{expected_url}",
                "rollback:rewrite-control",
                "install:proxy-control",
                f"request:{expected_url}",
                "rollback:proxy-control",
            ],
        )

    def test_both_transactions_and_requests_preserve_bridge_routes(self):
        https_route = TCPRoute("127.0.0.1", 44321)
        sftp_route = SSHRoute(
            scan=TCPRoute("127.0.0.1", 44322),
            proxy_command="ssh -W %h:%p bridge",
        )
        result, captured = self._verify(
            _desired(),
            responses=[302, 503],
            sftp_route=sftp_route,
            https_route=https_route,
        )
        temporary_calls, status_calls, _events = captured

        self.assertIs(result, True)
        self.assertEqual(len(temporary_calls), 2)
        self.assertTrue(
            all(call.kwargs["sftp_route"] is sftp_route for call in temporary_calls)
        )
        self.assertTrue(
            all(call.kwargs["https_route"] is https_route for call in temporary_calls)
        )
        self.assertEqual(len(status_calls), 2)
        self.assertTrue(
            all(call.kwargs["route"] is https_route for call in status_calls)
        )

    def test_only_502_503_and_504_confirm_local_proxy(self):
        for status in (502, 503, 504):
            with self.subTest(status=status):
                result, _captured = self._verify(_desired(), responses=[302, status])
                self.assertIs(result, True)

    def test_other_valid_status_is_unconfirmed_only_after_rollback(self):
        desired = _desired()
        events: list[str] = []

        def temporary_route(_desired_value, **kwargs):
            events.append(f"install:{kwargs['route_mode']}")
            result = kwargs["operation"]()
            events.append(f"rollback:{kwargs['route_mode']}")
            return result

        with (
            mock.patch(
                "xhttp_setup.front_probe.secrets.token_hex", return_value="d" * 32
            ),
            mock.patch(
                "xhttp_setup.front_probe.run_with_temporary_front_route",
                side_effect=temporary_route,
            ),
            mock.patch("xhttp_setup.front_probe.https_status", side_effect=(302, 500)),
        ):
            result = verify_front_proxy_capability(
                desired,
                auth=SSHAuth("password", password="secret-never-log"),
                state_dir=Path("/tmp/front-control"),
            )

        self.assertEqual(events[-1], "rollback:proxy-control")
        self.assertIs(result, False)
        self.assertNotIn(desired.xhttp_path, repr(result))
        self.assertNotIn("secret-never-log", repr(result))

    def test_404_and_500_are_unconfirmed_not_fatal(self):
        for status in (404, 500):
            with self.subTest(status=status):
                result, captured = self._verify(_desired(), responses=[302, status])
                self.assertIs(result, False)
                self.assertEqual(captured[2][-1], "rollback:proxy-control")

    def test_non_302_rewrite_control_is_fatal_after_rollback(self):
        desired = _desired()
        with self.assertRaises(VerificationError) as caught:
            self._verify(desired, responses=[404])

        self.assertEqual(len(self.last_proxy_events), 3)
        self.assertEqual(self.last_proxy_events[0], "install:rewrite-control")
        self.assertEqual(self.last_proxy_events[-1], "rollback:rewrite-control")
        self.assertFalse(
            any("proxy-control" in event for event in self.last_proxy_events)
        )
        rendered = "".join(traceback.format_exception(caught.exception))
        self.assertIn("ожидался HTTP 302, получен HTTP 404", rendered)
        self.assertNotIn(desired.xhttp_path, rendered)

    def test_rollback_failure_supersedes_failed_proxy_observation(self):
        rollback_error = InstallerError("confirmed rollback failed")
        with self.assertRaises(InstallerError) as caught:
            self._verify(
                _desired(),
                responses=[302, 404],
                rollback_error=rollback_error,
            )
        self.assertIs(caught.exception, rollback_error)

    def test_post_send_is_unconfirmed_and_returns_no_secret(self):
        desired = _desired()
        secret_url = f"https://front.example.org{desired.xhttp_path}/secret"
        result, captured = self._verify(
            desired,
            responses=[302, HTTPSResponseError(secret_url)],
        )

        self.assertIs(result, False)
        self.assertEqual(captured[2][-1], "rollback:proxy-control")
        self.assertNotIn(secret_url, repr(result))
        self.assertNotIn(desired.xhttp_path, repr(result))

    def test_proxy_tls_pre_send_and_invalid_status_remain_fatal_and_redacted(self):
        desired = _desired()
        secret_url = f"https://front.example.org{desired.xhttp_path}/secret"
        cases = (
            (TLSVerificationError(secret_url), TLSVerificationError, "TLS/SNI"),
            (VerificationError(secret_url), VerificationError, "не удалось"),
            (None, VerificationError, "некорректный HTTP-статус"),
        )
        for response, expected_type, expected_text in cases:
            with (
                self.subTest(response=type(response).__name__),
                self.assertRaises(expected_type) as caught,
            ):
                self._verify(desired, responses=[302, response])
            rendered = "".join(traceback.format_exception(caught.exception))
            self.assertEqual(self.last_proxy_events[-1], "rollback:proxy-control")
            self.assertIn(expected_text, rendered)
            self.assertNotIn(secret_url, rendered)
            self.assertNotIn(desired.xhttp_path, rendered)
            self.assertIsNone(caught.exception.__cause__)
            self.assertIsNone(caught.exception.__context__)


if __name__ == "__main__":
    unittest.main()
