"""
OSINT Tool - E-Mail-Modul
Analysiert E-Mail-Adressen: Validierung, Provider-Erkennung,
Gravatar-Lookup, Breach-Checks (HIBP), DNS-MX-Prüfung.
"""

import re
import time
import hashlib
import socket
import requests
from typing import List, Optional
from urllib.parse import quote

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.config import EMAIL_PROVIDERS, GRAVATAR_URL, GRAVATAR_PROFILE_URL


class EmailModule(BaseModule):

    @property
    def name(self) -> str:
        return "email"

    @property
    def description(self) -> str:
        return "Analysiert E-Mail-Adressen (Validierung, Breaches, Gravatar, MX)"

    @property
    def input_types(self) -> List[str]:
        return ["email"]

    def _validate_format(self, email: str) -> bool:
        """Prüft das E-Mail-Format per Regex."""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def _identify_provider(self, domain: str) -> Optional[str]:
        """Erkennt den E-Mail-Provider anhand der Domain."""
        return EMAIL_PROVIDERS.get(domain.lower())

    def _check_mx_records(self, domain: str) -> dict:
        """Prüft ob die Domain gültige MX-Records hat."""
        try:
            import dns.resolver
            mx_records = dns.resolver.resolve(domain, "MX")
            records = []
            for mx in mx_records:
                records.append({
                    "host": str(mx.exchange).rstrip("."),
                    "priority": mx.preference,
                })
            return {"valid": True, "records": records}
        except ImportError:
            # Fallback ohne dnspython: einfacher Socket-Check
            try:
                socket.getaddrinfo(domain, 25)
                return {"valid": True, "records": [], "note": "MX vorhanden (Basis-Check)"}
            except socket.gaierror:
                return {"valid": False, "records": []}
        except Exception:
            return {"valid": False, "records": []}

    def _check_gravatar(self, email: str) -> dict:
        """Prüft Gravatar-Profil anhand des E-Mail-Hashs."""
        email_hash = hashlib.md5(email.lower().strip().encode()).hexdigest()

        result = {"has_avatar": False, "profile": None}

        try:
            # Avatar-Check
            headers = {"User-Agent": self.config.user_agent if self.config else ""}
            r = requests.head(
                GRAVATAR_URL.format(email_hash),
                headers=headers,
                timeout=self.config.request_timeout if self.config else 10,
            )
            result["has_avatar"] = r.status_code == 200
            if result["has_avatar"]:
                result["avatar_url"] = f"https://www.gravatar.com/avatar/{email_hash}"

            # Profil-Check (JSON)
            r2 = requests.get(
                GRAVATAR_PROFILE_URL.format(email_hash),
                headers=headers,
                timeout=self.config.request_timeout if self.config else 10,
            )
            if r2.status_code == 200:
                data = r2.json()
                if "entry" in data and len(data["entry"]) > 0:
                    entry = data["entry"][0]
                    result["profile"] = {
                        "display_name": entry.get("displayName", ""),
                        "about": entry.get("aboutMe", ""),
                        "location": entry.get("currentLocation", ""),
                        "urls": [
                            {"title": u.get("title", ""), "value": u.get("value", "")}
                            for u in entry.get("urls", [])
                        ],
                        "photos": [p.get("value", "") for p in entry.get("photos", [])],
                    }
        except Exception as e:
            self.add_error(f"Gravatar-Check: {str(e)}")

        return result

    def _check_hibp(self, email: str) -> dict:
        """
        Prüft Have I Been Pwned auf bekannte Datenlecks.
        Benötigt API-Key für v3 (kostenpflichtig).
        Ohne Key wird die kostenlose Passwort-API genutzt als Fallback.
        """
        result = {"checked": False, "breaches": [], "breach_count": 0}

        api_key = self.config.get_api_key("hibp") if self.config else None

        if api_key:
            try:
                headers = {
                    "hibp-api-key": api_key,
                    "User-Agent": "OSINT-Recon-Tool",
                }
                r = requests.get(
                    f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}",
                    headers=headers,
                    timeout=self.config.request_timeout if self.config else 10,
                    params={"truncateResponse": "false"},
                )
                result["checked"] = True
                if r.status_code == 200:
                    breaches = r.json()
                    result["breaches"] = [
                        {
                            "name": b.get("Name", ""),
                            "domain": b.get("Domain", ""),
                            "date": b.get("BreachDate", ""),
                            "count": b.get("PwnCount", 0),
                            "data_types": b.get("DataClasses", []),
                        }
                        for b in breaches
                    ]
                    result["breach_count"] = len(breaches)
                elif r.status_code == 404:
                    result["breaches"] = []
                    result["breach_count"] = 0
            except Exception as e:
                self.add_error(f"HIBP-Check: {str(e)}")
        else:
            result["note"] = (
                "HIBP API-Key nicht konfiguriert. "
                "Setze HIBP_API_KEY in config.json oder als Umgebungsvariable."
            )

        return result

    def _check_email_reputation(self, email: str) -> dict:
        """Prüft die E-Mail über emailrep.io (kostenlos, limitiert)."""
        try:
            headers = {
                "User-Agent": "OSINT-Recon-Tool",
                "Accept": "application/json",
            }
            r = requests.get(
                f"https://emailrep.io/{quote(email, safe='')}",
                headers=headers,
                timeout=self.config.request_timeout if self.config else 10,
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "checked": True,
                    "reputation": data.get("reputation", "unknown"),
                    "suspicious": data.get("suspicious", False),
                    "references": data.get("references", 0),
                    "details": data.get("details", {}),
                }
        except Exception as e:
            self.add_error(f"EmailRep-Check: {str(e)}")

        return {"checked": False}

    def run(self, input_value: str, input_type: str = "email") -> ModuleReport:
        start = time.time()
        email = input_value.strip().lower()
        steps = 6
        step = 0

        self.report_progress(step, steps, "Validiere E-Mail-Format...")

        # 1. Format-Validierung
        is_valid = self._validate_format(email)
        step += 1
        self.report_progress(step, steps, "Format geprüft")

        self.add_result(OSINTResult(
            source="Formatprüfung",
            module=self.name,
            category="Validation",
            severity=ResultSeverity.INFO if is_valid else ResultSeverity.WARNING,
            title=f"E-Mail-Format {'gültig' if is_valid else 'ungültig'}",
            data={"valid": is_valid, "email": email},
        ))

        if not is_valid:
            end = time.time()
            return self.create_report(email, input_type, start, end)

        # E-Mail aufteilen
        local_part, domain = email.split("@", 1)

        # 2. Provider-Erkennung
        provider = self._identify_provider(domain)
        step += 1
        self.report_progress(step, steps, "Provider erkannt")

        self.add_result(OSINTResult(
            source="Provider-Erkennung",
            module=self.name,
            category="Info",
            severity=ResultSeverity.INFO,
            title=f"Provider: {provider or 'Unbekannt / Eigene Domain'}",
            data={
                "provider": provider,
                "domain": domain,
                "local_part": local_part,
                "is_known_provider": provider is not None,
            },
        ))

        # 3. MX-Records
        self.report_progress(step, steps, "Prüfe MX-Records...")
        mx_data = self._check_mx_records(domain)
        step += 1

        self.add_result(OSINTResult(
            source="DNS MX-Check",
            module=self.name,
            category="Infrastructure",
            severity=ResultSeverity.FOUND if mx_data["valid"] else ResultSeverity.WARNING,
            title=f"MX-Records {'gefunden' if mx_data['valid'] else 'nicht gefunden'}",
            data=mx_data,
        ))

        # 4. Gravatar
        self.report_progress(step, steps, "Prüfe Gravatar...")
        gravatar = self._check_gravatar(email)
        step += 1

        if gravatar["has_avatar"] or gravatar["profile"]:
            self.add_result(OSINTResult(
                source="Gravatar",
                module=self.name,
                category="Profile",
                severity=ResultSeverity.FOUND,
                title="Gravatar-Profil gefunden",
                data=gravatar,
                url=gravatar.get("avatar_url"),
            ))
        else:
            self.add_result(OSINTResult(
                source="Gravatar",
                module=self.name,
                category="Profile",
                severity=ResultSeverity.NOT_FOUND,
                title="Kein Gravatar-Profil",
                data=gravatar,
            ))

        # 5. HIBP Breach-Check
        self.report_progress(step, steps, "Prüfe Datenlecks (HIBP)...")
        hibp = self._check_hibp(email)
        step += 1

        if hibp["checked"]:
            breach_count = hibp["breach_count"]
            severity = (
                ResultSeverity.CRITICAL if breach_count > 5
                else ResultSeverity.WARNING if breach_count > 0
                else ResultSeverity.FOUND
            )
            self.add_result(OSINTResult(
                source="Have I Been Pwned",
                module=self.name,
                category="Security",
                severity=severity,
                title=f"{breach_count} Datenleck(s) gefunden" if breach_count else "Keine Datenlecks",
                data=hibp,
                url=f"https://haveibeenpwned.com/account/{quote(email, safe='')}",
            ))
        else:
            self.add_result(OSINTResult(
                source="Have I Been Pwned",
                module=self.name,
                category="Security",
                severity=ResultSeverity.INFO,
                title="HIBP nicht geprüft (kein API-Key)",
                data=hibp,
            ))

        # 6. E-Mail-Reputation
        self.report_progress(step, steps, "Prüfe Reputation...")
        rep = self._check_email_reputation(email)
        step += 1

        if rep.get("checked"):
            self.add_result(OSINTResult(
                source="EmailRep.io",
                module=self.name,
                category="Reputation",
                severity=(
                    ResultSeverity.WARNING if rep.get("suspicious")
                    else ResultSeverity.FOUND
                ),
                title=f"Reputation: {rep.get('reputation', 'unbekannt')}",
                data=rep,
            ))

        self.report_progress(steps, steps, "E-Mail-Analyse abgeschlossen")
        end = time.time()
        return self.create_report(email, input_type, start, end)
