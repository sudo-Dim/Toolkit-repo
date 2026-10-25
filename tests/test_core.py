import tempfile
import time
import unittest
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch

from osint_tool.core.config import AppConfig
from osint_tool.core.engine import OSINTEngine, ScanJob, ScanResult
from osint_tool.core.reporter import Reporter
from osint_tool.modules.base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from osint_tool.modules.domain import DomainModule
from osint_tool.light import Palette, run_once


class InterruptedModule(BaseModule):
    name = "example"
    description = "Offline test module"
    input_types = ["username"]

    def run(self, input_value, input_type):
        self.add_result(OSINTResult(
            source="test", module=self.name, category="test",
            severity=ResultSeverity.FOUND, title=input_value, data={},
        ))
        if input_value == "first":
            self.add_error("First scan failed")
            raise RuntimeError("Interrupted")
        return self.create_report(input_value, input_type, time.time(), time.time())


class EngineTests(unittest.TestCase):
    def setUp(self):
        with patch.object(AppConfig, "load_api_keys"):
            self.engine = OSINTEngine()

    def test_detection(self):
        cases = {
            "test@example.com": "email", "@someone": "username",
            "Max Mustermann": "name", "+1 202 555 0123": "phone",
            "192.0.2.1": "ip", "2001:db8::1": "ip",
            "::ffff:192.0.2.1": "ip", "999.999.999.999": "username",
            "dead:beef": "username", "api-v2.example.com": "domain",
            "example.co.at": "domain", "bücher.de": "domain",
            "HTTPS://api2.example.com:8443/path?q=1": "domain",
            "example.com?query=test": "domain", "https://[2001:db8::1]/": "ip",
            "https://example.com/picture.png?size=2": "image",
        }
        for value, expected in cases.items():
            with self.subTest(value=value):
                self.assertEqual(self.engine.detect_input_type(value), expected)

    def test_invalid_scan_never_runs_module(self):
        for module in self.engine.available_modules.values():
            module.run = Mock()
        for value, input_type in [("", "username"), ("  ", "username"),
                                  ([], "username"), ("x", "unknown"),
                                  ("x" * 2049, "username")]:
            with self.subTest(value=str(value)[:30], input_type=input_type):
                with self.assertRaises(ValueError):
                    self.engine.scan(value, input_type)

    def test_explicit_module_selection_is_validated(self):
        for module in self.engine.available_modules.values():
            module.run = Mock()
        for modules in [["missing"], ["phone"]]:
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                self.engine.scan("someone", "username", modules)

    def test_failed_scan_does_not_leak_into_next_scan(self):
        module = InterruptedModule()
        self.engine._modules = {module.name: module}
        first = self.engine.scan("first", "username", [module.name])
        second = self.engine.scan("second", "username", [module.name])
        self.assertTrue(first.reports[0].errors)
        self.assertEqual([r.title for r in second.reports[0].results], ["second"])
        self.assertEqual(second.reports[0].errors, [])

    def test_domain_normalization(self):
        for value, expected in [
            ("HTTPS://Example.COM:8443/path?x=1#part", "example.com"),
            ("example.com?x=1", "example.com"), ("bücher.de.", "xn--bcher-kva.de"),
            ("https://[2001:db8::1]:443/", "2001:db8::1"),
        ]:
            with self.subTest(value=value):
                self.assertEqual(DomainModule._clean_domain(value), expected)

    def test_light_cli_reports_invalid_input_without_traceback(self):
        output = StringIO()
        with redirect_stdout(output), patch("osint_tool.light.threading.Thread") as thread:
            result = run_once(self.engine, Mock(), Palette(enabled=False), "x" * 2049)
        self.assertIsNone(result)
        self.assertIn("Eingabe zu lang", output.getvalue())
        thread.assert_not_called()


class ReporterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.reporter = Reporter(self.tmp.name)
        self.scan = ScanResult(job=ScanJob("example", "username"))

    def test_repeated_exports_do_not_overwrite_and_share_a_stem(self):
        with patch("osint_tool.core.reporter.datetime") as clock:
            clock.now.return_value = datetime(2026, 10, 25, 12)
            first = self.reporter.export_all(self.scan)
            second = self.reporter.export_all(self.scan)
        self.assertTrue(set(first.values()).isdisjoint(second.values()))
        self.assertEqual(len({Path(p).stem for p in first.values()}), 1)
        self.assertTrue(all(Path(p).is_absolute() for p in first.values()))

    def test_errors_and_nested_data_are_in_reports(self):
        self.scan.reports = [ModuleReport("example", "example", "username", results=[
            OSINTResult("test", "example", "test", ResultSeverity.INFO, "Result",
                        {"formats": {"count": 0, "valid": False, "nested": {"a": "b"}}}),
        ], errors=["Source <unavailable>"])]
        txt = Path(self.reporter.export_txt(self.scan)).read_text(encoding="utf-8")
        html = Path(self.reporter.export_html(self.scan)).read_text(encoding="utf-8")
        self.assertIn("formats", txt)
        self.assertIn('"valid": false', txt)
        self.assertIn("Source &lt;unavailable&gt;", html)
        self.assertIn("count: 0", html)
        self.assertIn("valid: False", html)

    def test_html_only_links_supported_url_schemes(self):
        self.scan.reports = [ModuleReport("example", "example", "username", results=[
            OSINTResult("test", "example", "test", ResultSeverity.INFO, "Bad link", {},
                        url="javascript:alert(1)"),
            OSINTResult("test", "example", "test", ResultSeverity.INFO, "Good link", {},
                        url="https://example.com/?q=\"quoted\""),
        ])]
        html = Path(self.reporter.export_html(self.scan)).read_text(encoding="utf-8")
        self.assertNotIn('href="javascript:', html)
        self.assertIn('href="https://example.com/?q=&quot;quoted&quot;"', html)


if __name__ == "__main__":
    unittest.main()
