"""
OSINT Tool - Namens-Modul (v2)
Personensuche anhand des Namens:
  • Einzeln klickbare Such-/Dork-Links (Suchmaschinen, Social via Google-Dorks,
    People-Search US, DE/AT/EU-Verzeichnisse, Firmen-/Register, akademisch)
  • Username-Varianten (zur Weitergabe an das Username-Modul)
  • LIVE & strukturiert: ORCID-Forscher-Suche und GitHub-User-Suche per Name
"""

import time
import urllib.parse
from typing import List

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.http import build_session, DEFAULT_UA
from ..core.config import load_data

_UMLAUTS = {"ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss", "é": "e", "è": "e",
            "ê": "e", "á": "a", "à": "a", "í": "i", "ó": "o", "ú": "u",
            "ñ": "n", "ç": "c", "ø": "o", "å": "a"}


def _fold(s: str) -> str:
    s = s.lower()
    for a, b in _UMLAUTS.items():
        s = s.replace(a, b)
    return "".join(ch for ch in s if ch.isalnum())


class NameModule(BaseModule):

    @property
    def name(self) -> str:
        return "name_search"

    @property
    def description(self) -> str:
        return ("Personensuche per Name: klickbare Such-/Register-Links, "
                "Username-Varianten, live ORCID- & GitHub-Suche")

    @property
    def input_types(self) -> List[str]:
        return ["name"]

    @property
    def _timeout(self) -> int:
        return self.config.request_timeout if self.config else 12

    def _session(self):
        return build_session(user_agent=self.config.user_agent if self.config else DEFAULT_UA)

    # ── Token-Aufbau für Link-Vorlagen ─────────────────────────
    @staticmethod
    def _tokens(name: str) -> dict:
        parts = name.strip().split()
        first = _fold(parts[0]) if parts else ""
        last = _fold(parts[-1]) if len(parts) > 1 else ""
        return {
            "{q}": urllib.parse.quote_plus(name.strip()),
            "{first}": first, "{last}": last,
            "{first_last}": f"{first}-{last}" if last else first,
            "{First_Last}": f"{first.title()}-{last.title()}" if last else first.title(),
            "{first_plus_last}": f"{first}+{last}" if last else first,
        }

    @staticmethod
    def _tmpl(url: str, tokens: dict) -> str:
        for k, v in tokens.items():
            url = url.replace(k, v)
        return url

    def _username_variants(self, name: str) -> List[str]:
        parts = name.lower().strip().split()
        if not parts:
            return []
        if len(parts) == 1:
            return [_fold(parts[0])]
        first, last = _fold(parts[0]), _fold(parts[-1])
        variants = [
            f"{first}{last}", f"{first}.{last}", f"{first}_{last}", f"{first}-{last}",
            f"{first[0]}{last}", f"{first}{last[0]}", f"{last}{first}",
            f"{first[0]}.{last}", f"{last}.{first}", f"{first}{last}1",
        ]
        return list(dict.fromkeys(v for v in variants if v))

    # ── Live: ORCID ───────────────────────────────────────────
    def _orcid(self, first: str, last: str, session) -> list:
        if not first or not last:
            return []
        try:
            r = session.get(
                "https://pub.orcid.org/v3.0/expanded-search/",
                params={"q": f"given-names:{first} AND family-name:{last}", "rows": 5},
                headers={"Accept": "application/json"}, timeout=self._timeout)
            if r.status_code == 200:
                out = []
                for res in (r.json().get("expanded-result") or [])[:5]:
                    out.append({"orcid": res.get("orcid-id"),
                                "name": f"{res.get('given-names', '')} {res.get('family-names', '')}".strip(),
                                "institutions": res.get("institution-name", []),
                                "url": f"https://orcid.org/{res.get('orcid-id')}"})
                return out
        except Exception as exc:
            self.add_error(f"ORCID: {exc}")
        return []

    # ── Live: GitHub User-Suche ───────────────────────────────
    def _github_users(self, name: str, session) -> list:
        auth = {}
        if self.config and self.config.get_api_key("github"):
            auth["Authorization"] = f"Bearer {self.config.get_api_key('github')}"
        try:
            q = urllib.parse.quote(f"{name} in:name in:fullname")
            r = session.get(f"https://api.github.com/search/users?q={q}&per_page=5",
                            headers={"Accept": "application/vnd.github+json", **auth},
                            timeout=self._timeout)
            if r.status_code == 200:
                return [{"login": it.get("login"), "url": it.get("html_url"),
                         "avatar": it.get("avatar_url")}
                        for it in r.json().get("items", [])[:5]]
        except Exception as exc:
            self.add_error(f"GitHub: {exc}")
        return []

    # ── Hauptlauf ─────────────────────────────────────────────
    def run(self, input_value: str, input_type: str = "name") -> ModuleReport:
        start = time.time()
        name = input_value.strip()
        session = self._session()
        tokens = self._tokens(name)
        first, last = tokens["{first}"], tokens["{last}"]
        steps = 4
        step = [0]

        def tick(msg):
            step[0] += 1
            self.report_progress(step[0], steps, msg)

        # 1. Username-Varianten
        variants = self._username_variants(name)
        self.add_result(OSINTResult(
            source="Username-Varianten", module=self.name, category="Analyse",
            severity=ResultSeverity.INFO, title=f"{len(variants)} Username-Varianten generiert",
            data={"variants": variants,
                  "tipp": f"Im Username-Modul prüfen, z.B. '{variants[0] if variants else name}'."}))
        tick("Username-Varianten")

        # 2. Live ORCID + GitHub (echte, strukturierte Treffer)
        orcid = self._orcid(first, last, session)
        if orcid:
            self.add_result(OSINTResult(
                source="ORCID", module=self.name, category="Akademisch",
                severity=ResultSeverity.FOUND, title=f"{len(orcid)} ORCID-Treffer",
                data={"researchers": orcid}, url=orcid[0]["url"]))
        gh = self._github_users(name, session)
        if gh:
            self.add_result(OSINTResult(
                source="GitHub", module=self.name, category="Development",
                severity=ResultSeverity.FOUND, title=f"{len(gh)} GitHub-User (Namenstreffer)",
                data={"users": gh}, url=gh[0]["url"]))
        tick("ORCID & GitHub geprüft")

        # 3. Klickbare Such-/Register-Links (einzeln, gruppiert)
        links = load_data("name_sources.json", "links", [])
        for lk in links:
            self.add_result(OSINTResult(
                source=lk["name"], module=self.name,
                category=f"Link · {lk.get('category', '')}".strip(" ·"),
                severity=ResultSeverity.INFO, title=lk["name"], data={},
                url=self._tmpl(lk["url"], tokens)))
        tick("Suchlinks generiert")

        # 4. Zusammenfassung
        self.add_result(OSINTResult(
            source="Zusammenfassung", module=self.name, category="Summary",
            severity=ResultSeverity.INFO, title="Namenssuche abgeschlossen",
            data={"name": name, "links": len(links), "username_variants": len(variants),
                  "orcid_hits": len(orcid), "github_hits": len(gh),
                  "tipp": "Klicke die Links direkt an; Username-Varianten im Username-Modul prüfen."}))
        self.report_progress(steps, steps, "Namenssuche abgeschlossen")
        return self.create_report(name, input_type, start, time.time())
