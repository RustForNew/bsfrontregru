import unittest
import xml.etree.ElementTree as ET
from unittest.mock import patch

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.ispmanager import (
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


if __name__ == "__main__":
    unittest.main()
