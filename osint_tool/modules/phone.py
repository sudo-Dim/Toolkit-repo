"""
OSINT Tool - Telefonnummer-Modul (v2)
Reichhaltige Analyse mit Google libphonenumber (python 'phonenumbers'):
Land/Region, Geocoding, Carrier, Nummerntyp, Zeitzonen, alle Formate.
Dazu Messaging-App-Links (WhatsApp/Telegram/Viber), Reverse-Lookup-/
Telefonbuch-/Spam-Dienste und Such-Dorks. NumVerify/Twilio optional per Key.
"""

import re
import time
from typing import List, Optional
from urllib.parse import quote

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.http import build_session, DEFAULT_UA

# Fallback-Vorwahltabelle (nur falls 'phonenumbers' nicht installiert ist)
COUNTRY_CODES = {
    "1": "USA / Kanada", "7": "Russland/Kasachstan", "20": "Ägypten", "27": "Südafrika",
    "30": "Griechenland", "31": "Niederlande", "32": "Belgien", "33": "Frankreich",
    "34": "Spanien", "36": "Ungarn", "39": "Italien", "40": "Rumänien", "41": "Schweiz",
    "43": "Österreich", "44": "Vereinigtes Königreich", "45": "Dänemark", "46": "Schweden",
    "47": "Norwegen", "48": "Polen", "49": "Deutschland", "351": "Portugal", "352": "Luxemburg",
    "353": "Irland", "358": "Finnland", "380": "Ukraine", "420": "Tschechien", "421": "Slowakei",
    "61": "Australien", "64": "Neuseeland", "81": "Japan", "82": "Südkorea",
    "86": "China", "90": "Türkei", "91": "Indien", "971": "VAE", "972": "Israel",
}

# Regionen, die bei fehlender Ländervorwahl der Reihe nach probiert werden
_GUESS_REGIONS = ["DE", "AT", "CH", "US", "GB", "FR", "IT", "ES", "NL"]


class PhoneModule(BaseModule):

    @property
    def name(self) -> str:
        return "phone"

    @property
    def description(self) -> str:
        return ("Analysiert Telefonnummern (Land/Region, Carrier, Typ, Zeitzonen, "
                "Messaging-Apps, Reverse-Lookup-Links)")

    @property
    def input_types(self) -> List[str]:
        return ["phone"]

    # ── Normalisierung ────────────────────────────────────────
    @staticmethod
    def _normalize(phone: str) -> str:
        cleaned = re.sub(r"[^\d+]", "", phone)
        if not cleaned.startswith("+") and cleaned.startswith("00"):
            cleaned = "+" + cleaned[2:]
        return cleaned

    # ── phonenumbers-Parsing ──────────────────────────────────
    def _parse_lib(self, phone: str):
        try:
            import phonenumbers
        except ImportError:
            return None, None, "phonenumbers nicht installiert"
        norm = self._normalize(phone)
        # 1) Mit Ländervorwahl
        if norm.startswith("+"):
            try:
                p = phonenumbers.parse(norm, None)
                if phonenumbers.is_possible_number(p):
                    return phonenumbers, p, None
            except Exception:
                pass
        # 2) Ohne Vorwahl -> Regionen durchprobieren
        for region in _GUESS_REGIONS:
            try:
                p = phonenumbers.parse(phone, region)
                if phonenumbers.is_valid_number(p):
                    return phonenumbers, p, f"Region angenommen: {region}"
            except Exception:
                continue
        # 3) Letzter Versuch: erste mögliche Interpretation
        for region in _GUESS_REGIONS:
            try:
                p = phonenumbers.parse(phone, region)
                if phonenumbers.is_possible_number(p):
                    return phonenumbers, p, f"Region angenommen: {region} (nur möglich, nicht valide)"
            except Exception:
                continue
        return phonenumbers, None, "Konnte nicht geparst werden"

    def _lib_results(self, pn, p, assumption) -> List[OSINTResult]:
        from phonenumbers import carrier, geocoder, timezone, PhoneNumberFormat, number_type, PhoneNumberType
        results = []
        valid = pn.is_valid_number(p)
        possible = pn.is_possible_number(p)
        region = pn.region_code_for_number(p) or ""
        cc = p.country_code
        national = p.national_number

        type_names = {
            PhoneNumberType.MOBILE: "Mobil", PhoneNumberType.FIXED_LINE: "Festnetz",
            PhoneNumberType.FIXED_LINE_OR_MOBILE: "Festnetz/Mobil", PhoneNumberType.TOLL_FREE: "Gebührenfrei",
            PhoneNumberType.PREMIUM_RATE: "Premium-Rate", PhoneNumberType.VOIP: "VoIP",
            PhoneNumberType.PERSONAL_NUMBER: "Persönliche Nummer", PhoneNumberType.PAGER: "Pager",
            PhoneNumberType.UAN: "UAN", PhoneNumberType.VOICEMAIL: "Voicemail",
            PhoneNumberType.UNKNOWN: "Unbekannt",
        }
        ntype = type_names.get(number_type(p), "Unbekannt")
        carr = carrier.name_for_number(p, "de") or carrier.name_for_number(p, "en") or ""
        geo = geocoder.description_for_number(p, "de") or geocoder.description_for_number(p, "en") or ""
        tzs = list(timezone.time_zones_for_number(p))
        fmt = {
            "E164": pn.format_number(p, PhoneNumberFormat.E164),
            "International": pn.format_number(p, PhoneNumberFormat.INTERNATIONAL),
            "National": pn.format_number(p, PhoneNumberFormat.NATIONAL),
            "RFC3966": pn.format_number(p, PhoneNumberFormat.RFC3966),
        }

        results.append(OSINTResult(
            source="phonenumbers (libphonenumber)", module=self.name, category="Validation",
            severity=ResultSeverity.FOUND if valid else (ResultSeverity.WARNING if not possible else ResultSeverity.INFO),
            title=f"Nummer {'gültig' if valid else 'möglich' if possible else 'ungültig'} · {ntype}",
            data={"valid": valid, "possible": possible, "type": ntype,
                  "country_code": f"+{cc}", "region": region, "national_number": str(national),
                  "formats": fmt, "assumption": assumption}))

        results.append(OSINTResult(
            source="Geolocation & Carrier", module=self.name, category="Geolocation",
            severity=ResultSeverity.FOUND if (geo or carr) else ResultSeverity.INFO,
            title=f"{geo or region or 'Region unbekannt'}" + (f" · {carr}" if carr else ""),
            data={"location": geo, "carrier": carr, "region": region,
                  "timezones": tzs, "country_code": f"+{cc}"}))
        return results, fmt.get("E164", ""), region, ntype

    # ── Fallback ohne Lib ─────────────────────────────────────
    def _detect_country_fallback(self, phone: str) -> dict:
        norm = self._normalize(phone)
        if not norm.startswith("+"):
            return {"detected": False, "note": "Keine internationale Vorwahl erkannt"}
        digits = norm[1:]
        for length in (3, 2, 1):
            code = digits[:length]
            if code in COUNTRY_CODES:
                return {"detected": True, "country_code": f"+{code}",
                        "country": COUNTRY_CODES[code], "national_number": digits[length:]}
        return {"detected": False, "note": "Vorwahl nicht zugeordnet"}

    # ── Link-Generatoren ──────────────────────────────────────
    @staticmethod
    def _messaging_links(e164: str) -> List[dict]:
        digits = re.sub(r"\D", "", e164)
        if not digits:
            return []
        return [
            {"name": "WhatsApp (wa.me)", "url": f"https://wa.me/{digits}", "category": "Messaging"},
            {"name": "Telegram", "url": f"https://t.me/+{digits}", "category": "Messaging"},
            {"name": "Viber", "url": f"viber://chat?number=%2B{digits}", "category": "Messaging"},
        ]

    @staticmethod
    def _lookup_links(phone: str, e164: str, region: str) -> List[dict]:
        p_enc = quote(phone, safe="")
        e_enc = quote(e164 or phone, safe="")
        digits = re.sub(r"\D", "", e164 or phone)
        links = [
            {"name": "Truecaller", "url": f"https://www.truecaller.com/search/{(region or 'de').lower()}/{quote(e164 or phone)}", "category": "Reverse-Lookup"},
            {"name": "Sync.me", "url": f"https://sync.me/search/?number={e_enc}", "category": "Reverse-Lookup"},
            {"name": "tellows", "url": f"https://www.tellows.de/num/{digits}", "category": "Spam-Reputation"},
            {"name": "WhoCalledMe", "url": f"https://whocalledme.com/Phone-Number.aspx/{digits}", "category": "Spam-Reputation"},
            {"name": "Google", "url": f"https://www.google.com/search?q=%22{e_enc}%22", "category": "Suchmaschine"},
            {"name": "Bing", "url": f"https://www.bing.com/search?q=%22{e_enc}%22", "category": "Suchmaschine"},
        ]
        reg = (region or "").upper()
        if reg == "DE":
            links += [
                {"name": "Das Örtliche", "url": f"https://www.dasoertliche.de/?kw={p_enc}", "category": "Telefonbuch"},
                {"name": "Das Telefonbuch", "url": f"https://www.dastelefonbuch.de/R%C3%BCckw%C3%A4rtssuche/{digits}", "category": "Telefonbuch"},
            ]
        elif reg == "AT":
            links += [{"name": "Herold", "url": f"https://www.herold.at/telefonbuch/was_wer/{p_enc}/", "category": "Telefonbuch"}]
        elif reg == "CH":
            links += [{"name": "tel.search.ch", "url": f"https://tel.search.ch/?was={e_enc}", "category": "Telefonbuch"}]
        elif reg in ("US", "CA"):
            links += [{"name": "Whitepages", "url": f"https://www.whitepages.com/phone/{digits}", "category": "Telefonbuch"}]
        return links

    # ── NumVerify (optional) ──────────────────────────────────
    def _check_numverify(self, phone: str, session) -> Optional[dict]:
        key = self.config.get_api_key("numverify") if self.config else None
        if not key:
            return None
        try:
            r = session.get("https://apilayer.net/api/validate",
                            params={"access_key": key, "number": phone, "format": 1},
                            timeout=self.config.request_timeout if self.config else 12)
            if r.status_code == 200:
                d = r.json()
                if d.get("valid"):
                    return {"valid": True, "country": d.get("country_name"), "location": d.get("location"),
                            "carrier": d.get("carrier"), "line_type": d.get("line_type"),
                            "international_format": d.get("international_format")}
                return {"valid": False}
        except Exception as exc:
            self.add_error(f"NumVerify: {exc}")
        return None

    # ── Hauptlauf ─────────────────────────────────────────────
    def run(self, input_value: str, input_type: str = "phone") -> ModuleReport:
        start = time.time()
        phone = input_value.strip()
        session = build_session(user_agent=self.config.user_agent if self.config else DEFAULT_UA)
        steps = 5
        step = [0]

        def tick(msg):
            step[0] += 1
            self.report_progress(step[0], steps, msg)

        e164, region, ntype = "", "", ""

        # 1. Parsing (Lib bevorzugt)
        pn, parsed, assumption = self._parse_lib(phone)
        tick("Nummer geparst")
        if pn and parsed is not None:
            lib_res, e164, region, ntype = self._lib_results(pn, parsed, assumption)
            for r in lib_res:
                self.add_result(r)
        else:
            fb = self._detect_country_fallback(phone)
            self.add_result(OSINTResult(
                source="Ländererkennung (Fallback)", module=self.name, category="Geolocation",
                severity=ResultSeverity.FOUND if fb.get("detected") else ResultSeverity.INFO,
                title=f"Land: {fb.get('country', 'Unbekannt')}",
                data={**fb, "note": assumption or fb.get("note"),
                      "tipp": "Für genaue Carrier-/Typ-Erkennung: pip install phonenumbers"}))
            e164 = self._normalize(phone)

        # 2. Messaging-Apps
        msg = self._messaging_links(e164 or self._normalize(phone))
        if msg:
            self.add_result(OSINTResult(
                source="Messaging-Apps", module=self.name, category="Messaging",
                severity=ResultSeverity.INFO, title="Direktlinks zu WhatsApp/Telegram/Viber",
                data={"links": msg}))
        tick("Messaging-Links")

        # 3. Reverse-Lookup / Telefonbuch / Spam (einzeln klickbar)
        for lk in self._lookup_links(phone, e164, region):
            self.add_result(OSINTResult(
                source=lk["name"], module=self.name,
                category=f"Lookup · {lk['category']}", severity=ResultSeverity.INFO,
                title=lk["name"], data={}, url=lk["url"]))
        tick("Reverse-Lookup-Links")

        # 4. NumVerify (optional)
        nv = self._check_numverify(self._normalize(phone), session)
        if nv:
            self.add_result(OSINTResult(
                source="NumVerify API", module=self.name, category="Carrier",
                severity=ResultSeverity.FOUND if nv.get("valid") else ResultSeverity.INFO,
                title=f"NumVerify Carrier: {nv.get('carrier') or '—'}", data=nv))
        tick("NumVerify geprüft")

        tick("Telefon-Analyse abgeschlossen")
        return self.create_report(phone, input_type, start, time.time())
