"""
OSINT Tool - Telefonnummer-Modul
Analysiert Telefonnummern: Formatvalidierung, Carrier-Erkennung,
Länder-Zuordnung, Nummerntyp-Bestimmung.
"""

import re
import time
import requests
from typing import List, Optional
from urllib.parse import quote

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity


# Internationale Vorwahlen (Auswahl)
COUNTRY_CODES = {
    "1": "USA / Kanada",
    "7": "Russland",
    "20": "Ägypten",
    "27": "Südafrika",
    "30": "Griechenland",
    "31": "Niederlande",
    "32": "Belgien",
    "33": "Frankreich",
    "34": "Spanien",
    "36": "Ungarn",
    "39": "Italien",
    "40": "Rumänien",
    "41": "Schweiz",
    "43": "Österreich",
    "44": "Vereinigtes Königreich",
    "45": "Dänemark",
    "46": "Schweden",
    "47": "Norwegen",
    "48": "Polen",
    "49": "Deutschland",
    "51": "Peru",
    "52": "Mexiko",
    "53": "Kuba",
    "54": "Argentinien",
    "55": "Brasilien",
    "56": "Chile",
    "57": "Kolumbien",
    "58": "Venezuela",
    "60": "Malaysia",
    "61": "Australien",
    "62": "Indonesien",
    "63": "Philippinen",
    "64": "Neuseeland",
    "65": "Singapur",
    "66": "Thailand",
    "81": "Japan",
    "82": "Südkorea",
    "84": "Vietnam",
    "86": "China",
    "90": "Türkei",
    "91": "Indien",
    "92": "Pakistan",
    "93": "Afghanistan",
    "94": "Sri Lanka",
    "95": "Myanmar",
    "98": "Iran",
    "212": "Marokko",
    "213": "Algerien",
    "216": "Tunesien",
    "234": "Nigeria",
    "254": "Kenia",
    "255": "Tansania",
    "256": "Uganda",
    "351": "Portugal",
    "352": "Luxemburg",
    "353": "Irland",
    "354": "Island",
    "358": "Finnland",
    "370": "Litauen",
    "371": "Lettland",
    "372": "Estland",
    "380": "Ukraine",
    "381": "Serbien",
    "385": "Kroatien",
    "386": "Slowenien",
    "420": "Tschechien",
    "421": "Slowakei",
    "852": "Hongkong",
    "853": "Macau",
    "886": "Taiwan",
    "971": "VAE",
    "972": "Israel",
    "974": "Katar",
    "966": "Saudi-Arabien",
}


class PhoneModule(BaseModule):

    @property
    def name(self) -> str:
        return "phone"

    @property
    def description(self) -> str:
        return "Analysiert Telefonnummern (Land, Carrier, Typ, Validierung)"

    @property
    def input_types(self) -> List[str]:
        return ["phone"]

    def _normalize(self, phone: str) -> str:
        """Entfernt Formatierung, behält + und Ziffern."""
        cleaned = re.sub(r'[^\d+]', '', phone)
        if not cleaned.startswith("+"):
            # Versuche + hinzuzufügen falls es mit 00 beginnt
            if cleaned.startswith("00"):
                cleaned = "+" + cleaned[2:]
            elif cleaned.startswith("0"):
                # Annahme: Lokale Nummer, kann nicht eindeutig aufgelöst werden
                pass
        return cleaned

    def _detect_country(self, phone: str) -> dict:
        """Erkennt das Land anhand der Vorwahl."""
        if not phone.startswith("+"):
            return {"detected": False, "note": "Keine internationale Vorwahl erkannt"}

        digits = phone[1:]  # Ohne +

        # Versuche 3, 2, 1 stellige Vorwahlen
        for length in [3, 2, 1]:
            code = digits[:length]
            if code in COUNTRY_CODES:
                national = digits[length:]
                return {
                    "detected": True,
                    "country_code": f"+{code}",
                    "country": COUNTRY_CODES[code],
                    "national_number": national,
                    "digits_total": len(digits),
                }

        return {"detected": False, "note": "Vorwahl nicht zugeordnet"}

    def _check_phonebooks(self, phone: str) -> dict:
        """
        Gibt Hinweise auf öffentliche Telefonbuch-Dienste.
        Kein echtes Scraping - nur Links zu öffentlichen Diensten.
        """
        services = []

        normalized = self._normalize(phone)
        country = self._detect_country(normalized)
        p = quote(phone, safe="")  # URL-sichere Nutzereingabe

        if country.get("detected"):
            cc = country.get("country_code", "")

            if cc == "+49":  # Deutschland
                services.extend([
                    {"name": "Das Örtliche", "url": f"https://www.dasoertliche.de/?ph={p}"},
                    {"name": "11880", "url": f"https://www.11880.com/suche/{p}"},
                ])
            elif cc == "+43":  # Österreich
                services.extend([
                    {"name": "Herold", "url": f"https://www.herold.at/telefonbuch/?what={p}"},
                ])
            elif cc == "+41":  # Schweiz
                services.extend([
                    {"name": "local.ch", "url": f"https://tel.search.ch/?tel={p}"},
                ])
            elif cc == "+44":  # UK
                services.extend([
                    {"name": "BT Phonebook", "url": "https://www.thephonebook.bt.com/"},
                ])
            elif cc == "+1":  # USA/CA
                services.extend([
                    {"name": "Whitepages", "url": f"https://www.whitepages.com/phone/{p}"},
                    {"name": "TrueCaller", "url": "https://www.truecaller.com/"},
                ])

            # Allgemein
            services.extend([
                {"name": "TrueCaller Web", "url": "https://www.truecaller.com/"},
                {"name": "Sync.me", "url": "https://sync.me/"},
            ])

        return {"services": services}

    def _check_numverify(self, phone: str) -> dict:
        """Nutzt NumVerify API (kostenloser Plan) für Carrier/Typ-Info."""
        api_key = self.config.get_api_key("numverify") if self.config else None

        if not api_key:
            return {
                "checked": False,
                "note": "NumVerify API-Key nicht konfiguriert. "
                        "Setze NUMVERIFY_API_KEY für Carrier-Erkennung.",
            }

        try:
            r = requests.get(
                "http://apilayer.net/api/validate",
                params={
                    "access_key": api_key,
                    "number": phone,
                    "format": 1,
                },
                timeout=self.config.request_timeout if self.config else 10,
            )
            if r.status_code == 200:
                data = r.json()
                if data.get("valid"):
                    return {
                        "checked": True,
                        "valid": True,
                        "country": data.get("country_name", ""),
                        "location": data.get("location", ""),
                        "carrier": data.get("carrier", ""),
                        "line_type": data.get("line_type", ""),
                        "international_format": data.get("international_format", ""),
                    }
                else:
                    return {"checked": True, "valid": False}
        except Exception as e:
            self.add_error(f"NumVerify: {str(e)}")

        return {"checked": False}

    def _detect_type(self, phone: str) -> str:
        """Einfache Heuristik für Nummerntyp basierend auf Länge/Muster."""
        if re.match(r'^\+?1?8[0-9]{2}', phone.replace(" ", "")):
            return "Möglicherweise gebührenfreie Nummer"
        return "Unbekannt (ohne API nicht bestimmbar)"

    def run(self, input_value: str, input_type: str = "phone") -> ModuleReport:
        start = time.time()
        phone = input_value.strip()
        normalized = self._normalize(phone)

        steps = 5
        step = 0
        self.report_progress(step, steps, "Normalisiere Nummer...")

        # 1. Normalisierung
        step += 1
        self.add_result(OSINTResult(
            source="Formatierung",
            module=self.name,
            category="Validation",
            severity=ResultSeverity.INFO,
            title=f"Normalisiert: {normalized}",
            data={
                "original": phone,
                "normalized": normalized,
                "digits_only": re.sub(r'\D', '', phone),
                "digit_count": len(re.sub(r'\D', '', phone)),
            },
        ))

        # 2. Ländererkennung
        self.report_progress(step, steps, "Erkenne Land...")
        country = self._detect_country(normalized)
        step += 1

        self.add_result(OSINTResult(
            source="Ländererkennung",
            module=self.name,
            category="Geolocation",
            severity=ResultSeverity.FOUND if country["detected"] else ResultSeverity.INFO,
            title=f"Land: {country.get('country', 'Unbekannt')}",
            data=country,
        ))

        # 3. NumVerify API
        self.report_progress(step, steps, "Prüfe NumVerify...")
        numverify = self._check_numverify(normalized)
        step += 1

        if numverify.get("checked") and numverify.get("valid"):
            self.add_result(OSINTResult(
                source="NumVerify API",
                module=self.name,
                category="Carrier",
                severity=ResultSeverity.FOUND,
                title=f"Carrier: {numverify.get('carrier', 'Unbekannt')}",
                data=numverify,
            ))
        else:
            self.add_result(OSINTResult(
                source="NumVerify API",
                module=self.name,
                category="Carrier",
                severity=ResultSeverity.INFO,
                title="Carrier-Info nicht verfügbar",
                data=numverify,
            ))

        # 4. Telefonbuch-Dienste
        self.report_progress(step, steps, "Sammle Telefonbuch-Links...")
        phonebooks = self._check_phonebooks(phone)
        step += 1

        if phonebooks["services"]:
            self.add_result(OSINTResult(
                source="Telefonbücher",
                module=self.name,
                category="Directories",
                severity=ResultSeverity.INFO,
                title=f"{len(phonebooks['services'])} Telefonbuch-Dienste verfügbar",
                data=phonebooks,
            ))

        # 5. Typ-Erkennung
        self.report_progress(step, steps, "Bestimme Nummerntyp...")
        num_type = self._detect_type(normalized)
        step += 1

        self.add_result(OSINTResult(
            source="Typ-Analyse",
            module=self.name,
            category="Analysis",
            severity=ResultSeverity.INFO,
            title=f"Typ: {num_type}",
            data={"type_guess": num_type},
        ))

        self.report_progress(steps, steps, "Telefon-Analyse abgeschlossen")
        end = time.time()
        return self.create_report(phone, input_type, start, end)
