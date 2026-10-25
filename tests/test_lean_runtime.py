import json
import subprocess
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import MagicMock, patch

from osint_tool.core.config import AppConfig
from osint_tool.core.http import build_session
from osint_tool.desktop.smoke import check_runtime
from osint_tool.modules.phone import PhoneModule


class RuntimeTests(unittest.TestCase):
    def run_isolated(self, source):
        result = subprocess.run([sys.executable, "-c", source], text=True, capture_output=True,
                                check=True, timeout=20)
        return json.loads(result.stdout)

    def test_idle_gui_does_not_load_network_or_phone_libraries(self):
        data = self.run_isolated("""
import json, sys
from osint_tool.desktop.app import DesktopApp
from osint_tool.core.engine import OSINTEngine
engine = OSINTEngine()
print(json.dumps({'modules': len(engine.available_modules), 'loaded': [name for name in
    ('requests', 'urllib3', 'dns', 'phonenumbers', 'flask') if name in sys.modules]}))
""")
        self.assertEqual(data, {"modules": 6, "loaded": []})

    def test_offline_phone_analysis_keeps_quality_without_loading_http(self):
        data = self.run_isolated("""
import json, sys
from osint_tool.modules.phone import PhoneModule
report = PhoneModule().run('+12025550123', 'phone')
validation = next(r for r in report.results if r.source == 'phonenumbers (libphonenumber)')
geo = next(r for r in report.results if r.source == 'Geolocation & Carrier')
print(json.dumps({'http_loaded': 'requests' in sys.modules, 'validation': validation.data,
                  'geo': geo.data, 'errors': report.errors}))
""")
        self.assertFalse(data["http_loaded"])
        self.assertEqual(data["errors"], [])
        self.assertTrue(data["validation"]["valid"])
        self.assertEqual(data["validation"]["formats"]["E164"], "+12025550123")
        self.assertEqual(data["geo"]["region"], "US")
        self.assertTrue(data["geo"]["timezones"])
        self.assertTrue(data["geo"]["location"])

    def test_optional_phone_api_still_uses_config_and_closes_session(self):
        config = AppConfig(api_keys={"numverify": "test-key"}, user_agent="test-agent", request_timeout=7)
        session = MagicMock()
        session.get.return_value.status_code = 200
        session.get.return_value.json.return_value = {"valid": True, "carrier": "Test carrier"}
        with patch("osint_tool.modules.phone.build_session") as factory:
            factory.return_value.__enter__.return_value = session
            report = PhoneModule(config).run("+12025550123", "phone")
            factory.assert_called_once_with(user_agent="test-agent")
            factory.return_value.__exit__.assert_called_once()
        self.assertEqual(session.get.call_args.kwargs["timeout"], 7)
        self.assertEqual(session.get.call_args.kwargs["params"]["access_key"], "test-key")
        self.assertTrue(any(r.data.get("carrier") == "Test carrier" for r in report.results))

    def test_all_regions_dns_types_and_tls_resources_are_available(self):
        result = check_runtime()
        self.assertGreaterEqual(result["phone_regions"], 240)
        self.assertEqual(result["dns_record_types"], 9)
        self.assertTrue(result["tls_and_http"])


class LocalHTTPTests(unittest.TestCase):
    def test_http_retry_redirect_cookies_and_encoding_are_preserved(self):
        attempts = []

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                attempts.append(self.path)
                if self.path == "/retry" and attempts.count("/retry") == 1:
                    self.send_response(503)
                    self.end_headers()
                elif self.path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", "/cookie")
                    self.send_header("Set-Cookie", "session=test-session; Path=/")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/plain; charset=iso-8859-1")
                    self.end_headers()
                    self.wfile.write((self.headers.get("Cookie", "") + " Grüße").encode("iso-8859-1"))

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with build_session(pool_size=8, allow_private=True) as session:
                # Der Testserver ist lokal und benötigt keinen Proxy.
                session.trust_env = False
                base = f"http://127.0.0.1:{server.server_port}"
                response = session.get(base + "/retry", timeout=2)
                self.assertEqual(response.status_code, 200)
                self.assertEqual(attempts.count("/retry"), 2)
                response = session.get(base + "/redirect", timeout=2)
                self.assertEqual(response.text, "session=test-session Grüße")
                self.assertEqual(len(response.history), 1)
                self.assertEqual(session.get_adapter(base)._pool_maxsize, 8)
                self.assertTrue(session.verify)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)


if __name__ == "__main__":
    unittest.main()
