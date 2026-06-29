"""
OSINT Tool - Username-Modul (v2)
Prüft, ob ein Username auf vielen Plattformen existiert — mit dem
Sherlock/Maigret-Detektionsmodell statt naivem "HTTP 200 == gefunden".

Pro Plattform ein präzises Nicht-gefunden-Signal:
  • status_code : Nicht-gefunden-Codes (meist 404)
  • message     : bestimmte Textbausteine im Body bedeuten "nicht gefunden"
  • response_url: Redirect auf ein bestimmtes Ziel bedeutet "nicht gefunden"

Seiten, die anonym/aus Datacenter-IPs nicht zuverlässig prüfbar sind
(Instagram, X, TikTok, LinkedIn, StackOverflow …), werden NICHT geraten,
sondern nur als manueller Link ausgegeben (severity INFO). Damit verschwinden
die früheren False Positives (z.B. StackOverflow-/users-Suchseite == 200).
"""

import re
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.http import build_session, DEFAULT_UA
from ..core.config import USERNAME_PLATFORMS


class UsernameModule(BaseModule):

    @property
    def name(self) -> str:
        return "username"

    @property
    def description(self) -> str:
        return ("Prüft Username-Existenz auf vielen Plattformen (präzise "
                "Detektion, keine False Positives)")

    @property
    def input_types(self) -> List[str]:
        return ["username"]

    def _session(self):
        ua = self.config.user_agent if self.config else DEFAULT_UA
        return build_session(user_agent=ua)

    # ── Detektionslogik ────────────────────────────────────────
    @staticmethod
    def _verdict(platform: dict, status: int, text: str, final_url: str,
                 username: str) -> str:
        """Gibt 'found' | 'not_found' | 'uncertain' zurück."""
        etype = platform.get("error_type", "status_code")

        if etype == "status_code":
            codes = platform.get("error_code") or [404]
            if status in codes:
                return "not_found"
            if 200 <= status < 300:
                return "found"
            return "uncertain"

        if etype == "message":
            msgs = platform.get("error_msg") or []
            if any(m and m in text for m in msgs):
                return "not_found"
            if status == 200:
                return "found"
            if status in (404, 410):
                return "not_found"
            return "uncertain"

        if etype == "response_url":
            err = (platform.get("error_url") or "").replace("{}", username)
            if err and (final_url == err or final_url.startswith(err) or err in final_url):
                return "not_found"
            if 200 <= status < 300:
                return "found"
            if status in (404, 410):
                return "not_found"
            return "uncertain"

        return "uncertain"

    def _check_platform(self, platform: dict, username: str, session) -> dict:
        name = platform["name"]
        category = platform.get("category", "Other")
        profile_url = platform["url"].replace("{}", username)
        probe_url = platform.get("url_probe", platform["url"]).replace("{}", username)
        method = platform.get("request_method", "GET").upper()
        headers = dict(platform.get("request_headers") or {})
        headers.setdefault("User-Agent", self.config.user_agent if self.config else DEFAULT_UA)

        # Hinterlegtes Login anwenden (ermöglicht Prüfung sonst gesperrter Seiten)
        auth = self.config.get_site_auth(name) if self.config else None
        if auth:
            if auth.get("cookie"):
                headers["Cookie"] = auth["cookie"]
            if auth.get("bearer"):
                headers["Authorization"] = f"Bearer {auth['bearer']}"
            if isinstance(auth.get("headers"), dict):
                headers.update(auth["headers"])

        base = {"name": name, "category": category, "profile_url": profile_url,
                "reliability": platform.get("reliability", "medium"),
                "authed": bool(auth)}
        try:
            timeout = self.config.request_timeout if self.config else 12
            if method == "HEAD":
                resp = session.head(probe_url, headers=headers, timeout=timeout, allow_redirects=True)
                text = ""
            else:
                resp = session.get(probe_url, headers=headers, timeout=timeout, allow_redirects=True)
                text = resp.text if resp.text else ""
            verdict = self._verdict(platform, resp.status_code, text, str(resp.url), username)
            base.update({"verdict": verdict, "status_code": resp.status_code})
        except Exception as exc:
            base.update({"verdict": "uncertain", "error": str(exc)})
        return base

    # ── Hauptlauf ──────────────────────────────────────────────
    def run(self, input_value: str, input_type: str = "username") -> ModuleReport:
        start = time.time()
        username = input_value.strip().lstrip("@")
        session = self._session()
        probe_unreliable = bool(getattr(self.config, "probe_unreliable", False)) if self.config else False

        # Plattformen aufteilen: prüfbar / nur-Link / regex-ungültig
        checkable, link_only = [], []
        for p in USERNAME_PLATFORMS:
            rgx = p.get("regex_check")
            if rgx:
                try:
                    if not re.search(rgx, username):
                        continue  # Username für diese Plattform syntaktisch unmöglich
                except re.error:
                    pass
            has_auth = bool(self.config and self.config.get_site_auth(p["name"]))
            if p.get("anonymous_checkable", True) or probe_unreliable or has_auth:
                checkable.append(p)
            else:
                link_only.append(p)

        total = (len(checkable) + len(link_only)) or 1
        done = 0
        self.report_progress(0, total, "Starte Username-Suche...")

        # Nur-Link-Plattformen direkt ausgeben (keine Requests)
        for p in link_only:
            done += 1
            self.add_result(OSINTResult(
                source=p["name"], module=self.name, category=p.get("category", "Other"),
                severity=ResultSeverity.INFO,
                title=f"{p['name']}: nur manuell prüfbar (anonym nicht zuverlässig)",
                data={"reason": p.get("notes", "Seite blockt automatisierte Prüfung / benötigt Login."),
                      "manual_check": True},
                url=p["url"].replace("{}", username)))
            self.report_progress(done, total, f"{p['name']} (nur Link)")

        # Prüfbare Plattformen parallel abfragen
        workers = self.config.max_concurrent_requests if self.config else 20
        if checkable:
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = {ex.submit(self._check_platform, p, username, session): p["name"]
                        for p in checkable}
                for fut in as_completed(futs):
                    done += 1
                    try:
                        info = fut.result()
                    except Exception as exc:
                        self.add_error(f"{futs[fut]}: {exc}")
                        self.report_progress(done, total, f"{futs[fut]} (Fehler)")
                        continue
                    verdict = info.get("verdict")
                    if verdict == "found":
                        self.add_result(OSINTResult(
                            source=info["name"], module=self.name, category=info["category"],
                            severity=ResultSeverity.FOUND, title=f"Gefunden auf {info['name']}",
                            data={"exists": True, "status_code": info.get("status_code"),
                                  "reliability": info.get("reliability"),
                                  **({"via_login": True} if info.get("authed") else {})},
                            url=info["profile_url"]))
                    elif verdict == "not_found":
                        self.add_result(OSINTResult(
                            source=info["name"], module=self.name, category=info["category"],
                            severity=ResultSeverity.NOT_FOUND, title=f"Nicht gefunden auf {info['name']}",
                            data={"exists": False, "status_code": info.get("status_code")}))
                    else:  # uncertain
                        self.add_result(OSINTResult(
                            source=info["name"], module=self.name, category=info["category"],
                            severity=ResultSeverity.INFO,
                            title=f"Unklar bei {info['name']} (blockiert/Rate-Limit)",
                            data={"exists": None, "status_code": info.get("status_code"),
                                  "error": info.get("error")},
                            url=info["profile_url"]))
                    self.report_progress(done, total, f"{info.get('name', '?')} geprüft")

        return self.create_report(username, input_type, start, time.time())
