import json
import unittest
from urllib.parse import parse_qs, urlsplit

from xhttp_setup.models import Handoff
from xhttp_setup.render import (
    BEGIN_MARKER,
    END_MARKER,
    merge_managed_block,
    render_htaccess_block,
    render_vless_uri,
    render_xray_client_config,
    render_xray_server_config,
)


UUID = "d342d11e-d424-4583-b36e-524ab1f0afa4"
PATH = "/api/0123456789abcdef0123456789abcdef"
DECRYPTION = (
    "mlkem768x25519plus.native.600s.yG0oHVjWspYtXKNwHbdHMcZSWMHCyPeyOm9CNhSBCVU"
)
ENCRYPTION = (
    "mlkem768x25519plus.native.0rtt.yFAUa9gUf_hlvbaqG6nYRyTqpfo2kE-BYoFqCqq6vQ4"
)


def handoff():
    return Handoff("203.0.113.10", 8083, UUID, PATH, ENCRYPTION, "Тест").validate()


class RenderTests(unittest.TestCase):
    def test_server_is_packet_up_and_vless_encrypted(self):
        config = render_xray_server_config(
            client_id=UUID, decryption=DECRYPTION, port=8083, path=PATH
        )
        inbound = config["inbounds"][0]
        self.assertEqual(inbound["settings"]["clients"][0]["id"], UUID)
        self.assertEqual(inbound["settings"]["decryption"], DECRYPTION)
        self.assertEqual(inbound["streamSettings"]["security"], "none")
        self.assertEqual(
            inbound["streamSettings"]["xhttpSettings"]["mode"], "packet-up"
        )

    def test_client_uses_tls_sni_host_and_packet_up(self):
        config = render_xray_client_config(
            handoff=handoff(),
            domain="front.example.org",
            socks_port=10808,
            front_address="198.51.100.20",
        )
        outbound = config["outbounds"][0]
        stream = outbound["streamSettings"]
        self.assertEqual(stream["security"], "tls")
        self.assertEqual(stream["tlsSettings"]["serverName"], "front.example.org")
        self.assertEqual(stream["xhttpSettings"]["host"], "front.example.org")
        self.assertEqual(stream["xhttpSettings"]["mode"], "packet-up")
        self.assertEqual(
            outbound["settings"]["vnext"][0]["users"][0]["encryption"], ENCRYPTION
        )
        self.assertEqual(outbound["settings"]["vnext"][0]["address"], "198.51.100.20")

    def test_uri_round_trip(self):
        uri = render_vless_uri(
            handoff(), "front.example.org", front_address="198.51.100.20"
        )
        parsed = urlsplit(uri)
        query = parse_qs(parsed.query)
        self.assertEqual(parsed.scheme, "vless")
        self.assertEqual(parsed.hostname, "198.51.100.20")
        self.assertEqual(parsed.port, 443)
        self.assertEqual(query["security"], ["tls"])
        self.assertEqual(query["encryption"], [ENCRYPTION])
        self.assertEqual(query["path"], [PATH])
        self.assertEqual(query["mode"], ["packet-up"])
        self.assertEqual(json.loads(query["extra"][0])["scMaxEachPostBytes"], 1_000_000)

    def test_htaccess_is_fixed_target_and_covers_suffix(self):
        block = render_htaccess_block(
            exit_address="203.0.113.10", exit_port=8083, path=PATH
        )
        self.assertIn("RewriteRule ^api/0123456789abcdef0123456789abcdef$", block)
        self.assertIn("RewriteRule ^api/0123456789abcdef0123456789abcdef/(.*)$", block)
        self.assertNotIn("%{HTTP_HOST}", block)
        self.assertEqual(block.count("http://203.0.113.10:8083"), 2)

    def test_managed_block_preserves_foreign_rules_and_replaces_once(self):
        first = render_htaccess_block(
            exit_address="203.0.113.10", exit_port=8083, path=PATH
        )
        merged = merge_managed_block("# user rule\nRewriteRule ^old$ /new [L]\n", first)
        second = render_htaccess_block(
            exit_address="203.0.113.11", exit_port=8084, path=PATH
        )
        updated = merge_managed_block(merged, second)
        self.assertIn("# user rule", updated)
        self.assertNotIn("203.0.113.10:8083", updated)
        self.assertEqual(updated.count(BEGIN_MARKER), 1)
        self.assertEqual(updated.count(END_MARKER), 1)

    def test_corrupt_managed_markers_fail_closed(self):
        with self.assertRaises(ValueError):
            merge_managed_block(BEGIN_MARKER + "\n", "block")
        with self.assertRaises(ValueError):
            merge_managed_block(
                f"{BEGIN_MARKER}\n{END_MARKER}\n{BEGIN_MARKER}\n{END_MARKER}", "block"
            )


if __name__ == "__main__":
    unittest.main()
