import json
import os
import tempfile
import time
import unittest
import zipfile
from pathlib import Path
from unittest.mock import Mock, patch

from osint_tool import build
from osint_tool.core.config import AppConfig
from osint_tool.core.paths import desktop_data_directory
from osint_tool.desktop.app import DesktopApp, result_links, safe_link
from osint_tool.desktop.worker import ScanRunner


def waiting_worker(events, config, value, input_type):
    events.put(("progress", ("test", 1, 2, "Running")))
    time.sleep(30)


def crashing_worker(events, config, value, input_type):
    os._exit(7)


class PortableTests(unittest.TestCase):
    def test_frozen_config_is_loaded_next_to_executable(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            resources, portable, unrelated = [root / name for name in ("resources", "portable", "unrelated")]
            for folder in (resources, portable, unrelated):
                folder.mkdir()
            (resources / "config.json").write_text(json.dumps({"api_keys": {"hunter": "default-test"}}))
            (resources / "config.local.json").write_text(json.dumps({"api_keys": {"numverify": "bundled-secret-test"}}))
            (portable / "config.local.json").write_text(json.dumps({"api_keys": {"hunter": "portable-test"}}))
            (unrelated / "config.local.json").write_text(json.dumps({"api_keys": {"hunter": "wrong-test"}}))
            with patch("sys.frozen", True, create=True), \
                 patch("osint_tool.core.config.resource_directory", return_value=resources), \
                 patch("osint_tool.core.config.application_directory", return_value=portable), \
                 patch("pathlib.Path.cwd", return_value=unrelated), patch.dict(os.environ, {}, clear=True):
                config = AppConfig()
                config.load_api_keys()
                self.assertEqual(config.api_keys, {"hunter": "portable-test"})
                with patch.dict(os.environ, {"HUNTER_API_KEY": "environment-test"}):
                    config.load_api_keys()
                    self.assertEqual(config.get_api_key("hunter"), "environment-test")

    def test_portable_storage_and_read_only_fallback(self):
        with tempfile.TemporaryDirectory() as temporary, \
             patch("sys.frozen", True, create=True), patch("sys.platform", "win32"), \
             patch("osint_tool.core.paths.application_directory", return_value=Path(temporary)), \
             patch.dict(os.environ, {"LOCALAPPDATA": str(Path(temporary) / "profile")}):
            self.assertEqual(desktop_data_directory(), Path(temporary) / "user-data")
            with patch("tempfile.TemporaryFile", side_effect=PermissionError):
                self.assertEqual(desktop_data_directory(), Path(temporary) / "profile" / "OSINTReconTool")

    def test_packaging_includes_resources_and_no_local_configuration(self):
        with tempfile.TemporaryDirectory() as temporary:
            command = build.build_command(temporary)
            self.assertIn("--windowed", command)
            self.assertIn(f"{build.PACKAGE / 'data'}:osint_tool/data", command)
            self.assertNotIn(str(build.PACKAGE / "config.json"), " ".join(command))
            executable = Path(temporary) / "OSINTReconTool.exe"
            executable.write_bytes(b"test-executable")
            (Path(temporary) / "config.local.json").write_text('PRIVATE-TEST-VALUE')
            archive = build.package_portable(executable)
            with zipfile.ZipFile(archive) as bundle:
                self.assertEqual(set(bundle.namelist()), {executable.name, "config.local.example.json", "LIESMICH.txt", "START.bat"})
                self.assertNotIn(b"python", bundle.read("START.bat").lower())
                self.assertIn(b"OSINTReconTool.exe", bundle.read("START.bat"))
                self.assertEqual(json.loads(bundle.read("config.local.example.json")), {"api_keys": {}, "site_auth": {}})

    def test_desktop_links_are_explicit_and_safe(self):
        for value in ("javascript:alert(1)", "file:///tmp/private", "https://user:pass@example.com", "https://example.com/\n"):
            self.assertFalse(safe_link(value))
        result = {"url": "https://example.com", "data": {"links": [
            None, {"url": "https://example.com"}, {"url": "viber://chat?number=%2B12025550123"},
            {"url": "javascript:alert(1)"}], "_internal": "https://hidden.example"}}
        self.assertEqual(result_links(result), ["https://example.com", "viber://chat?number=%2B12025550123"])


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.runner = ScanRunner()
        self.addCleanup(self.runner.cancel)

    def collect_until(self, predicate):
        deadline = time.monotonic() + 10
        messages = []
        while not predicate(messages):
            messages.extend(self.runner.poll())
            self.assertLess(time.monotonic(), deadline, "Worker did not respond")
            time.sleep(0.01)
        return messages

    def test_cancel_terminates_process_and_allows_restart(self):
        with patch("osint_tool.desktop.worker.scan_worker", waiting_worker):
            self.runner.start(AppConfig(), "test", "username")
        process = self.runner.process
        self.collect_until(lambda messages: bool(messages))
        with self.assertRaises(RuntimeError):
            self.runner.start(AppConfig(), "test", "username")
        self.runner.cancel()
        self.assertFalse(self.runner.active)
        self.assertTrue(process._closed)
        self.runner.start(AppConfig(), "", "username")
        messages = self.collect_until(lambda messages: not self.runner.active)
        self.assertTrue(any(kind == "error" and "Keine Eingabe" in message for kind, message in messages))

    def test_unexpected_process_exit_reports_an_error(self):
        with patch("osint_tool.desktop.worker.scan_worker", crashing_worker):
            self.runner.start(AppConfig(), "test", "username")
        messages = self.collect_until(lambda messages: not self.runner.active)
        self.assertIn(("error", "Scan-Prozess unerwartet beendet (Code 7)"), messages)


class DesktopWidgetTests(unittest.TestCase):
    def setUp(self):
        import tkinter as tk
        try:
            self.root = tk.Tk()
        except tk.TclError as exc:
            self.skipTest(f"Display nicht verfügbar: {exc}")
        with patch.object(AppConfig, "load_api_keys"):
            self.app = DesktopApp(self.root, runner=Mock(active=False))
        self.addCleanup(self.app.close)

    def test_input_errors_and_window_close(self):
        self.app.start_scan()
        self.app.runner.start.assert_not_called()
        self.assertIn("Keine Eingabe", self.app.status.get())
        self.app.close()
        self.app.runner.cancel.assert_called_once()

    def test_default_view_hides_generated_email_search_links(self):
        from osint_tool.core.engine import ScanJob, ScanResult
        from osint_tool.modules.base import ModuleReport, OSINTResult, ResultSeverity
        result = ScanResult(ScanJob('test@example.com', 'email'), reports=[
            ModuleReport('email', 'test@example.com', 'email', results=[
                OSINTResult('Provider', 'email', 'Account', ResultSeverity.INFO, 'Nicht prüfbar', {'verdict': 'uncertain'}),
                OSINTResult('Google', 'email', 'Such-Link', ResultSeverity.INFO, 'Generierter Link', {'manual_check': True, 'verdict': 'manual'}, 'https://www.google.com/search?q=test'),
            ])])
        self.app.show_result(result)
        self.assertEqual(self.app.filter.get(), 'Prüfergebnisse')
        rows = self.app.tree.get_children()
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.app.tree.item(rows[0], 'values')[1], 'Provider')
        self.assertIn('0 Treffer', self.app.summary.get())
        self.assertIn('1 manuelle Quellen', self.app.summary.get())
        self.app.filter.set('Manuelle Quellen')
        self.app.render_rows()
        rows = self.app.tree.get_children()
        self.assertEqual(len(rows), 1)
        self.assertEqual(self.app.tree.item(rows[0], 'values')[0:2], ('Manuell', 'Google'))

    def test_results_filter_details_and_export(self):
        from osint_tool.core.engine import ScanJob, ScanResult
        from osint_tool.modules.base import ModuleReport, OSINTResult, ResultSeverity
        result = ScanResult(ScanJob("example", "username"), reports=[
            ModuleReport("username", "example", "username", results=[
                OSINTResult("Test", "username", "Category", ResultSeverity.FOUND, "Result",
                            {"count": 0, "valid": False}, url="https://example.com"),
                OSINTResult("Test", "username", "Category", ResultSeverity.CRITICAL, "Critical", {}),
            ], errors=["Source unavailable"])
        ])
        self.app.show_result(result)
        self.assertEqual(len(self.app.tree.get_children()), 3)
        self.assertIn('"count": 0', self.app.details.get("1.0", "end"))
        self.assertEqual(self.app.selected_links, ["https://example.com"])
        with patch("webbrowser.open") as browser:
            self.app.open_link()
            browser.assert_called_once_with("https://example.com")
        self.app.filter.set("Warnungen")
        self.app.render_rows()
        self.assertEqual(len(self.app.tree.get_children()), 2)
        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "result.json"
            self.app.export_format.set("JSON")
            with patch("osint_tool.desktop.app.desktop_data_directory", return_value=Path(temporary)), \
                 patch("osint_tool.desktop.app.filedialog.asksaveasfilename", return_value=str(destination)):
                self.app.export()
            self.assertEqual(json.loads(destination.read_text()), result.to_dict())


if __name__ == "__main__":
    unittest.main()
