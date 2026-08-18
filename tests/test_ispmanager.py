import unittest
import xml.etree.ElementTree as ET

from xhttp_setup.errors import InstallerError, VerificationError
from xhttp_setup.ispmanager import parse_site_list, validate_panel_endpoint


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


if __name__ == "__main__":
    unittest.main()
