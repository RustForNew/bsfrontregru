import http.server
import os
import socket
import threading
import unittest
from unittest import mock

from xhttp_setup.doctor import _curl_through_socks
from xhttp_setup.osutil import command_exists


class _Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = b"ip=203.0.113.20\n"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        pass


class E2EGuardTests(unittest.TestCase):
    def test_no_proxy_star_cannot_bypass_explicit_socks(self):
        if not command_exists("curl"):
            self.skipTest("curl not installed")
        server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            unreachable_socks = unused.getsockname()[1]
        try:
            url = f"http://127.0.0.1:{server.server_port}/"
            with mock.patch.dict(os.environ, {"NO_PROXY": "*"}, clear=False):
                result = _curl_through_socks(
                    socks_port=unreachable_socks,
                    url=url,
                )
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


if __name__ == "__main__":
    unittest.main()
