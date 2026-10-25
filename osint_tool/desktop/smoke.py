"""Offline-Ende-zu-Ende-Prüfung für die echte Desktop-App und den EXE-Build."""

import json
import time
from pathlib import Path

from ..core.config import USERNAME_PLATFORMS, load_data
from ..core.reporter import Reporter


def check_runtime():
    """Prüft DNS/TLS/HTTP und die weltweiten Telefon-Metadaten ohne Netzwerk."""
    import ssl
    import dns.rdata
    import dns.resolver
    import requests
    import phonenumbers
    from ..core.http import build_session

    records = {
        "A": "192.0.2.1", "AAAA": "2001:db8::1", "MX": "10 mail.example.",
        "NS": "ns.example.", "CNAME": "alias.example.",
        "TXT": '"v=spf1 -all"', "SOA": "ns.example. hostmaster.example. 1 3600 600 86400 60",
        "SRV": "1 5 443 service.example.", "CAA": '0 issue "example.org"',
    }
    for record_type, text in records.items():
        record = dns.rdata.from_text("IN", record_type, text)
        wire = record.to_wire()
        assert dns.rdata.from_wire("IN", record_type, wire, 0, len(wire)) == record
    dns.resolver.Resolver(configure=False)
    for region in phonenumbers.SUPPORTED_REGIONS:
        assert phonenumbers.PhoneMetadata.metadata_for_region(region) is not None, region
    for calling_code in phonenumbers.COUNTRY_CODES_FOR_NON_GEO_REGIONS:
        assert phonenumbers.PhoneMetadata.metadata_for_nongeo_region(calling_code) is not None
    with build_session() as session:
        assert session.verify is True
        assert session.trust_env is True
        prepared = session.prepare_request(requests.Request("GET", "https://example.com", params={"q": "ä +"}))
        assert "q=%C3%A4+%2B" in prepared.url
        assert session.get_adapter("https://").max_retries.total == 2
        ssl.create_default_context(cafile=requests.certs.where())
    return {"dns_record_types": len(records), "phone_regions": len(phonenumbers.SUPPORTED_REGIONS),
            "tls_and_http": True}


def run_smoke_test(app, report_path):
    deadline = time.monotonic() + 30
    phone = "+12025550123"  # Reservierte, fiktive US-Nummer.
    app.input.set(phone)
    app.type.set("Telefon")
    app.root.after(100, app.start_scan)

    def finish(error=None):
        try:
            if error:
                raise RuntimeError(error)
            result = app.result
            assert result is not None, app.status.get()
            assert USERNAME_PLATFORMS, "Plattform-Daten fehlen im Bundle"
            assert load_data("email_sources.json"), "E-Mail-Daten fehlen im Bundle"
            assert len(app.engine.available_modules) == 6
            assert result.to_dict()["summary"]["total_errors"] == 0
            validation = next(r for r in result.reports[0].results if r.source == "phonenumbers (libphonenumber)")
            assert validation.data["formats"]["E164"] == phone
            assert validation.data["region"] == "US"
            assert app.tree.get_children(), "Ergebnisse fehlen in der GUI"
            reporter = Reporter(str(report_path.parent / "smoke-results"))
            files = reporter.export_all(result)
            for filename in files.values():
                assert phone in Path(filename).read_text(encoding="utf-8")
            report = {"ok": True, "modules": 6, "results": len(app.rows), "exports": list(files),
                      "platforms": len(USERNAME_PLATFORMS), "runtime": check_runtime()}
        except Exception as exc:
            report = {"ok": False, "error": str(exc)}
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        app.close()

    def check():
        if time.monotonic() > deadline:
            finish("Desktop-Test nach 30 Sekunden abgebrochen")
        elif not app.runner.active:
            finish()
        else:
            app.root.after(100, check)

    app.root.after(250, check)
