import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.ispmanager import (
    ISPmanagerAuthenticationError,
    inspect_site,
    panel_login_url_to_endpoint,
    parse_site_list,
    validate_panel_endpoint,
)


class ISPmanagerTests(unittest.TestCase):
    def test_endpoint_requires_https_and_no_credentials(self):
        self.assertEqual(
            validate_panel_endpoint("https://panel.example.org:1500/ispmgr/"),
            "https://panel.example.org:1500/ispmgr",
        )
        for value in (
            "http://panel.example.org:1500/ispmgr",
            "https://user:pass@panel.example.org:1500/ispmgr",
            "https://panel.example.org:1500/other",
        ):
            with self.subTest(value=value), self.assertRaises(InstallerError):
                validate_panel_endpoint(value)

    def test_login_url_is_converted_to_api_endpoint(self):
        self.assertEqual(
            panel_login_url_to_endpoint("https://vip999.hosting.reg.ru:1500/"),
            "https://vip999.hosting.reg.ru:1500/ispmgr",
        )
        self.assertEqual(
            panel_login_url_to_endpoint(
                "https://vip999.hosting.reg.ru:1500/manager/ispmgr/"
            ),
            "https://vip999.hosting.reg.ru:1500/manager/ispmgr",
        )

    def test_login_url_rejects_unsafe_or_unexpected_parts(self):
        for value in (
            "http://vip999.hosting.reg.ru:1500/",
            "https://user:secret@vip999.hosting.reg.ru:1500/",
            "https://vip999.hosting.reg.ru:1500/?auth=secret",
            "https://vip999.hosting.reg.ru:1500/unexpected",
        ):
            with self.subTest(value=value), self.assertRaises(InstallerError) as caught:
                panel_login_url_to_endpoint(value)
            self.assertNotIn("secret", str(caught.exception))

    def test_parse_site_list_uses_returned_docroot(self):
        root = ET.fromstring(
            """<doc><elem><name>front.example.org</name>
            <docroot>/var/www/u/data/www/front.example.org</docroot>
            <ipaddr>198.51.100.20</ipaddr></elem></doc>"""
        )
        site = parse_site_list(root, "FRONT.EXAMPLE.ORG")
        self.assertEqual(site.docroot, "/var/www/u/data/www/front.example.org")
        self.assertEqual(site.ipaddr, "198.51.100.20")

    def test_missing_site_fails(self):
        with self.assertRaises(VerificationError):
            parse_site_list(ET.fromstring("<doc/>"), "front.example.org")

    def test_duplicate_exact_site_fails_closed(self):
        root = ET.fromstring(
            """<doc>
            <elem><name>front.example.org</name><docroot>/one</docroot></elem>
            <elem><name>FRONT.EXAMPLE.ORG.</name><docroot>/two</docroot></elem>
            </doc>"""
        )
        with self.assertRaisesRegex(VerificationError, "несколько сайтов"):
            parse_site_list(root, "front.example.org")

    def test_inspection_uses_only_auth_and_read_only_site_list(self):
        auth = ET.fromstring('<doc><auth id="session-123" /></doc>')
        sites = ET.fromstring(
            """<doc><elem><name>front.example.org</name>
            <docroot>/var/www/front.example.org</docroot></elem></doc>"""
        )
        calls = []

        def post(_endpoint, fields, **_kwargs):
            calls.append(dict(fields))
            return auth if len(calls) == 1 else sites

        with patch("xhttp_setup.ispmanager._xml_post", side_effect=post):
            inspect_site(
                endpoint="https://panel.example.org:1500/ispmgr",
                username="example",
                password="secret",
                domain="front.example.org",
            )

        self.assertEqual([call["func"] for call in calls], ["auth", "webdomain"])
        self.assertFalse(any("sok" in call for call in calls))

    def test_inspection_redacts_reflected_password_without_exception_chain(self):
        secret = "FakeReflectedPanelSecret"
        with (
            patch(
                "xhttp_setup.ispmanager._xml_post",
                side_effect=VerificationError(f"remote reflected {secret}"),
            ),
            self.assertRaises(VerificationError) as caught,
        ):
            inspect_site(
                endpoint="https://panel.example.org:1500/ispmgr",
                username="example",
                password=secret,
                domain="front.example.org",
            )

        self.assertNotIn(secret, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)

    def test_missing_auth_session_is_a_typed_password_failure(self):
        with (
            patch(
                "xhttp_setup.ispmanager._xml_post",
                return_value=ET.fromstring("<doc><ok /></doc>"),
            ),
            self.assertRaises(ISPmanagerAuthenticationError),
        ):
            inspect_site(
                endpoint="https://panel.example.org:1500/ispmgr",
                username="example",
                password="wrong-secret",
                domain="front.example.org",
            )

    def test_typed_auth_failure_stays_typed_and_redacts_password(self):
        secret = "FakePanelSecretForRetry"
        with (
            patch(
                "xhttp_setup.ispmanager._xml_post",
                side_effect=ISPmanagerAuthenticationError(
                    f"Invalid password: {secret}"
                ),
            ),
            self.assertRaises(ISPmanagerAuthenticationError) as caught,
        ):
            inspect_site(
                endpoint="https://panel.example.org:1500/ispmgr",
                username="example",
                password=secret,
                domain="front.example.org",
            )
        self.assertNotIn(secret, str(caught.exception))
        self.assertIsNone(caught.exception.__cause__)


if __name__ == "__main__":
    unittest.main()
