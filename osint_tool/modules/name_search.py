"""
OSINT Tool - Namens-Modul
Sucht nach Personen anhand ihres Namens über öffentliche Quellen:
Suchmaschinen-Dorking, Social-Media-Suche, öffentliche Verzeichnisse.
"""

import time
import urllib.parse
import requests
from typing import List

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity


class NameModule(BaseModule):

    @property
    def name(self) -> str:
        return "name_search"

    @property
    def description(self) -> str:
        return "Sucht nach Personen anhand des Namens (Dorks, Verzeichnisse, Social Media)"

    @property
    def input_types(self) -> List[str]:
        return ["name"]

    def _generate_google_dorks(self, name: str) -> List[dict]:
        """Generiert Google-Dork-Links für die Namenssuche."""
        encoded = urllib.parse.quote_plus(f'"{name}"')
        dorks = [
            {
                "name": "Allgemeine Suche",
                "query": f'"{name}"',
                "url": f"https://www.google.com/search?q={encoded}",
            },
            {
                "name": "LinkedIn-Profile",
                "query": f'site:linkedin.com/in "{name}"',
                "url": f"https://www.google.com/search?q=site%3Alinkedin.com%2Fin+{encoded}",
            },
            {
                "name": "Facebook-Profile",
                "query": f'site:facebook.com "{name}"',
                "url": f"https://www.google.com/search?q=site%3Afacebook.com+{encoded}",
            },
            {
                "name": "Twitter/X-Profile",
                "query": f'site:x.com "{name}"',
                "url": f"https://www.google.com/search?q=site%3Ax.com+{encoded}",
            },
            {
                "name": "PDF-Dokumente",
                "query": f'"{name}" filetype:pdf',
                "url": f"https://www.google.com/search?q={encoded}+filetype%3Apdf",
            },
            {
                "name": "Nachrichtenartikel",
                "query": f'"{name}" (news OR artikel OR bericht)',
                "url": f"https://news.google.com/search?q={encoded}",
            },
            {
                "name": "GitHub-Profile",
                "query": f'site:github.com "{name}"',
                "url": f"https://www.google.com/search?q=site%3Agithub.com+{encoded}",
            },
            {
                "name": "Akademische Arbeiten",
                "query": f'"{name}" (university OR professor OR paper OR research)',
                "url": f"https://scholar.google.com/scholar?q={encoded}",
            },
            {
                "name": "Foren & Kommentare",
                "query": f'"{name}" (forum OR comment OR posted)',
                "url": f"https://www.google.com/search?q={encoded}+%28forum+OR+comment%29",
            },
            {
                "name": "Bildsuche",
                "query": f'"{name}"',
                "url": f"https://www.google.com/search?tbm=isch&q={encoded}",
            },
        ]
        return dorks

    def _generate_direct_links(self, name: str) -> List[dict]:
        """Generiert direkte Suchlinks für bekannte Plattformen."""
        encoded = urllib.parse.quote_plus(name)
        name_parts = name.strip().split()

        links = [
            {
                "platform": "LinkedIn",
                "url": f"https://www.linkedin.com/search/results/people/?keywords={encoded}",
                "category": "Professional",
            },
            {
                "platform": "Facebook",
                "url": f"https://www.facebook.com/search/people/?q={encoded}",
                "category": "Social Media",
            },
            {
                "platform": "Twitter/X",
                "url": f"https://x.com/search?q={encoded}&f=user",
                "category": "Social Media",
            },
            {
                "platform": "Instagram",
                "url": f"https://www.google.com/search?q=site:instagram.com+{encoded}",
                "category": "Social Media",
            },
            {
                "platform": "GitHub",
                "url": f"https://github.com/search?q={encoded}&type=users",
                "category": "Development",
            },
            {
                "platform": "Google Scholar",
                "url": f"https://scholar.google.com/scholar?q=author:{encoded}",
                "category": "Academic",
            },
            {
                "platform": "Reddit",
                "url": f"https://www.reddit.com/search/?q={encoded}&type=user",
                "category": "Social Media",
            },
            {
                "platform": "YouTube",
                "url": f"https://www.youtube.com/results?search_query={encoded}",
                "category": "Video",
            },
        ]

        return links

    def _generate_username_variants(self, name: str) -> List[str]:
        """Generiert mögliche Usernames aus einem Namen."""
        parts = name.lower().strip().split()
        if len(parts) < 2:
            return [parts[0]] if parts else []

        first = parts[0]
        last = parts[-1]

        # Umlaute ersetzen
        replacements = {
            "ä": "ae", "ö": "oe", "ü": "ue", "ß": "ss",
            "é": "e", "è": "e", "ê": "e",
            "á": "a", "à": "a",
            "ñ": "n", "ç": "c",
        }
        for old, new in replacements.items():
            first = first.replace(old, new)
            last = last.replace(old, new)

        variants = [
            f"{first}{last}",           # maxmustermann
            f"{first}.{last}",          # max.mustermann
            f"{first}_{last}",          # max_mustermann
            f"{first}-{last}",          # max-mustermann
            f"{first[0]}{last}",        # mmustermann
            f"{first}{last[0]}",        # maxm
            f"{last}{first}",           # mustermannmax
            f"{first}{last}123",        # maxmustermann123
            f"{last}.{first}",          # mustermann.max
            f"{first[0]}.{last}",       # m.mustermann
        ]

        return list(dict.fromkeys(variants))  # Deduplizieren, Reihenfolge beibehalten

    def _check_peekyou(self, name: str) -> dict:
        """Prüft PeekYou als People-Search-Engine."""
        try:
            parts = name.strip().split()
            if len(parts) >= 2:
                url = f"https://www.peekyou.com/{parts[0]}_{parts[-1]}"
                r = requests.head(
                    url,
                    headers={"User-Agent": self.config.user_agent if self.config else ""},
                    timeout=self.config.request_timeout if self.config else 10,
                    allow_redirects=True,
                )
                return {
                    "available": True,
                    "url": url,
                    "status": r.status_code,
                }
        except Exception:
            pass
        return {"available": False}

    def run(self, input_value: str, input_type: str = "name") -> ModuleReport:
        start = time.time()
        name = input_value.strip()

        steps = 5
        step = 0

        self.report_progress(step, steps, f"Suche nach '{name}'...")

        # 1. Google Dorks generieren
        step += 1
        self.report_progress(step, steps, "Generiere Suchlinks...")
        dorks = self._generate_google_dorks(name)
        self.add_result(OSINTResult(
            source="Google Dorks",
            module=self.name,
            category="Search",
            severity=ResultSeverity.INFO,
            title=f"{len(dorks)} Suchstrategien generiert",
            data={"dorks": dorks},
        ))

        # 2. Direkte Plattform-Links
        step += 1
        self.report_progress(step, steps, "Erstelle Plattform-Links...")
        direct = self._generate_direct_links(name)
        self.add_result(OSINTResult(
            source="Plattform-Suche",
            module=self.name,
            category="Social Media",
            severity=ResultSeverity.INFO,
            title=f"{len(direct)} Plattform-Suchlinks erstellt",
            data={"links": direct},
        ))

        # 3. Username-Varianten
        step += 1
        self.report_progress(step, steps, "Generiere Username-Varianten...")
        variants = self._generate_username_variants(name)
        self.add_result(OSINTResult(
            source="Username-Generator",
            module=self.name,
            category="Analysis",
            severity=ResultSeverity.INFO,
            title=f"{len(variants)} Username-Varianten generiert",
            data={
                "variants": variants,
                "hint": "Diese Varianten können im Username-Modul geprüft werden",
            },
        ))

        # 4. People-Search-Engines
        step += 1
        self.report_progress(step, steps, "Prüfe People-Search-Engines...")

        people_engines = [
            {"name": "PeekYou", "type": "check"},
            {"name": "Pipl", "url": f"https://pipl.com/search/?q={urllib.parse.quote_plus(name)}"},
            {"name": "That's Them", "url": f"https://thatsthem.com/name/{name.replace(' ', '-')}"},
            {"name": "Webmii", "url": f"https://webmii.com/people?n={urllib.parse.quote_plus(name)}"},
        ]

        peekyou = self._check_peekyou(name)
        engine_results = []
        for engine in people_engines:
            if engine["name"] == "PeekYou":
                engine_results.append({
                    "name": engine["name"],
                    "url": peekyou.get("url", ""),
                    "available": peekyou.get("available", False),
                })
            else:
                engine_results.append({
                    "name": engine["name"],
                    "url": engine.get("url", ""),
                    "available": True,
                })

        self.add_result(OSINTResult(
            source="People Search Engines",
            module=self.name,
            category="Directories",
            severity=ResultSeverity.INFO,
            title=f"{len(engine_results)} Personensuchmaschinen verfügbar",
            data={"engines": engine_results},
        ))

        # 5. Zusammenfassung
        step += 1
        self.report_progress(step, steps, "Erstelle Zusammenfassung...")

        self.add_result(OSINTResult(
            source="Zusammenfassung",
            module=self.name,
            category="Summary",
            severity=ResultSeverity.INFO,
            title="Namenssuche abgeschlossen",
            data={
                "name": name,
                "total_dorks": len(dorks),
                "total_platform_links": len(direct),
                "username_variants": len(variants),
                "people_engines": len(engine_results),
                "tip": (
                    "Öffne die generierten Links manuell im Browser. "
                    "Username-Varianten können mit dem Username-Modul geprüft werden."
                ),
            },
        ))

        self.report_progress(steps, steps, "Namenssuche abgeschlossen")
        end = time.time()
        return self.create_report(name, input_type, start, end)
