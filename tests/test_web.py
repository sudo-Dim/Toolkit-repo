import json
import tempfile
import time
import unittest
from unittest.mock import patch

from osint_tool.core.config import AppConfig
from osint_tool.core.engine import ScanJob, ScanResult
from osint_tool.core.reporter import Reporter
from osint_tool.web import app as web


class ImmediateThread:
    def __init__(self, target, **kwargs):
        self.target = target

    def start(self):
        self.target()


class WebTests(unittest.TestCase):
    def setUp(self):
        web.scan_states.clear()
        self.client = web.app.test_client()
        self.client.get("/")
        self.client.environ_base["HTTP_X_OSINT_TOKEN"] = web.app.config["LOCAL_TOKEN"]

    def tearDown(self):
        web.scan_states.clear()

    def test_malformed_payloads_return_client_errors(self):
        for endpoint in ("/api/scan", "/api/detect-type"):
            for payload in ([], ["test"], "test", 42, {"input": 42},
                            {"input": None}, {"input": "x" * 2049}):
                with self.subTest(endpoint=endpoint, payload=str(payload)[:35]):
                    response = self.client.post(endpoint, data=json.dumps(payload),
                                                content_type="application/json")
                    self.assertEqual(response.status_code, 400)
                    self.assertIn("error", response.get_json())
            response = self.client.post(endpoint, data="{", content_type="application/json")
            self.assertEqual(response.status_code, 400)
        self.assertEqual(web.scan_states, {})

    def test_bad_types_rejected_before_background_work(self):
        with patch.object(web.threading, "Thread") as thread:
            for input_type in (42, [], "missing"):
                response = self.client.post("/api/scan", json={"input": "example", "type": input_type})
                self.assertEqual(response.status_code, 400)
            thread.assert_not_called()

    def test_empty_detection_is_preserved(self):
        response = self.client.post("/api/detect-type", json={"input": " "})
        self.assertEqual(response.status_code, 200)
        self.assertIsNone(response.get_json()["type"])

    def test_request_size_limit_returns_json(self):
        response = self.client.post("/api/scan", json={"input": "x" * (65 * 1024)})
        self.assertEqual(response.status_code, 413)
        self.assertIn("error", response.get_json())

    def test_parallel_phone_scans_keep_separate_downloads(self):
        # Reserved fictional number; this module works entirely offline without API keys.
        phone = "+12025550123"
        with tempfile.TemporaryDirectory() as output_dir, \
             patch.object(web, "reporter", Reporter(output_dir)), \
             patch.object(web, "config", AppConfig()), \
             patch.object(AppConfig, "load_api_keys"), \
             patch("requests.sessions.Session.request", side_effect=AssertionError("Unexpected network call")):
            scan_ids = [self.client.post("/api/scan", json={"input": phone}).get_json()["scan_id"]
                        for _ in range(2)]
            deadline = time.monotonic() + 5
            for scan_id in scan_ids:
                while True:
                    state = self.client.get(f"/api/scan/{scan_id}/status").get_json()
                    if state["status"] != "running":
                        break
                    self.assertLess(time.monotonic(), deadline, "Background scan timed out")
                    time.sleep(0.01)
                self.assertEqual(state["status"], "done", state.get("message"))
                self.assertEqual(state["results"]["summary"]["total_errors"], 0)
                validation = next(r for r in state["results"]["modules"][0]["results"]
                                  if r["source"] == "phonenumbers (libphonenumber)")
                self.assertEqual(validation["data"]["formats"]["E164"], phone)
                for fmt in ("json", "txt", "html"):
                    download = self.client.get(f"/api/scan/{scan_id}/export/{fmt}")
                    self.assertEqual(download.status_code, 200)
                    self.assertIn(phone.encode(), download.data)
                    if fmt == "json":
                        self.assertEqual(download.get_json(), state["results"])
                    download.close()
            first = set(web.scan_states[scan_ids[0]]["files"].values())
            second = set(web.scan_states[scan_ids[1]]["files"].values())
            self.assertTrue(first.isdisjoint(second))

    def test_auto_type_and_all_downloads(self):
        with tempfile.TemporaryDirectory(dir=".") as output_dir:
            with patch.object(web, "reporter", Reporter(output_dir)), \
                 patch.object(web.threading, "Thread", ImmediateThread), \
                 patch.object(web.OSINTEngine, "scan", return_value=ScanResult(ScanJob("example", "username"))):
                response = self.client.post("/api/scan", json={"input": " example ", "type": "auto"})
                self.assertEqual(response.status_code, 200)
                payload = response.get_json()
                self.assertEqual(payload["type"], "username")
                scan_id = payload["scan_id"]
                state = self.client.get(f"/api/scan/{scan_id}/status").get_json()
                self.assertEqual(state["status"], "done")
                for fmt in ("json", "txt", "html"):
                    with self.subTest(fmt=fmt):
                        download = self.client.get(f"/api/scan/{scan_id}/export/{fmt}")
                        self.assertEqual(download.status_code, 200)
                        self.assertIn("attachment", download.headers["Content-Disposition"])
                        self.assertIn(b"example", download.data)
                        download.close()

    def test_failed_results_are_not_reported_as_pending(self):
        web.scan_states["failed"] = {"status": "error", "message": "Scan failed"}
        response = self.client.get("/api/scan/failed/results")
        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.get_json()["error"], "Scan failed")

    def test_progress_is_bounded(self):
        web.scan_states["scan"] = {}
        callback = web.progress_callback_factory("scan")
        callback("domain", 12, 10, "Almost done")
        self.assertEqual(web.scan_states["scan"]["progress"], 100)
        callback("domain", -1, 10, "Starting")
        self.assertEqual(web.scan_states["scan"]["progress"], 0)


if __name__ == "__main__":
    unittest.main()
