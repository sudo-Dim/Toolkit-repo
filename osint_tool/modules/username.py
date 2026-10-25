"""Username lookup with exact API evidence and negative controls for HTML profiles."""

import re
import secrets
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List
from urllib.parse import quote, urlsplit

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.http import build_session, DEFAULT_UA
from ..core.evidence import profile_evidence
from ..core.config import USERNAME_PLATFORMS


class UsernameModule(BaseModule):

    @property
    def name(self) -> str:
        return "username"

    @property
    def description(self) -> str:
        return ("Prüft öffentliche Profile mit Belegen; unklare Quellen bleiben unbestätigt")

    @property
    def input_types(self) -> List[str]:
        return ["username"]

    def _session(self):
        ua = self.config.user_agent if self.config else DEFAULT_UA
        return build_session(user_agent=ua)

    @staticmethod
    def _verdict(platform, status, text, final_url, username):
        verdict, _ = profile_evidence(platform, status, text, final_url, username)
        return 'uncertain' if verdict == 'candidate' else verdict

    @staticmethod
    def _read_response(session, url, headers, timeout):
        # Bound untrusted pages; retain pooling by consuming/closing each response.
        with session.get(url, headers=headers, timeout=timeout, allow_redirects=True, stream=True) as response:
            body = bytearray()
            for chunk in response.iter_content(16384):
                body.extend(chunk)
                if len(body) > 2 * 1024 * 1024:
                    raise ValueError('Antwort überschreitet 2 MiB; nicht sicher auswertbar')
            encoding = response.encoding or 'utf-8'
            return response.status_code, bytes(body).decode(encoding, errors='replace'), str(response.url)

    @staticmethod
    def _control_username(platform):
        pattern = platform.get('regex_check')
        for candidate in ('osint' + secrets.token_hex(6), 'o' + secrets.token_hex(4)):
            if not pattern or re.fullmatch(pattern, candidate):
                return candidate
        return None

    def _check_platform(self, platform: dict, username: str, session) -> dict:
        name = platform["name"]
        category = platform.get("category", "Other")
        encoded = quote(username, safe="")
        profile_url = platform["url"].replace("{}", encoded)
        probe_url = platform.get("url_probe", platform["url"]).replace("{}", encoded)
        headers = dict(platform.get("request_headers") or {})
        headers.setdefault("User-Agent", self.config.user_agent if self.config else DEFAULT_UA)
        if name == 'GitHub' and self.config and self.config.get_api_key('github'):
            headers['Authorization'] = f"Bearer {self.config.get_api_key('github')}"

        # Hinterlegtes Login anwenden (ermöglicht Prüfung sonst gesperrter Seiten)
        auth = self.config.get_site_auth(name) if self.config else None
        profile_origin, probe_origin = urlsplit(profile_url), urlsplit(probe_url)
        if (profile_origin.scheme, profile_origin.netloc.casefold()) != (probe_origin.scheme, probe_origin.netloc.casefold()):
            # A profile cookie must not migrate to a newly introduced API host.
            # API-specific tokens (currently GitHub) are configured separately above.
            auth = None
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
            status, text, final_url = self._read_response(session, probe_url, headers, timeout)
            verdict, reason = profile_evidence(platform, status, text, final_url, username)
            if verdict == 'candidate':
                control = self._control_username(platform)
                if control:
                    control_url = platform.get('url_probe', platform['url']).replace('{}', quote(control, safe=''))
                    control_response = self._read_response(session, control_url, headers, timeout)
                    control_verdict, _ = profile_evidence(platform, *control_response, control)
                    if control_verdict == 'not_found':
                        verdict, reason = 'found', 'Exakte Profil-Metadaten; zufälliger Kontrollname wird als fehlend erkannt'
                    else:
                        verdict, reason = 'uncertain', 'Gegenprobe nicht eindeutig: mögliche Soft-404-/Sperrseite'
                else:
                    verdict, reason = 'uncertain', 'Keine syntaktisch gültige Gegenprobe möglich'
            base.update({'verdict': verdict, 'status_code': status, 'reason': reason,
                         'checked_url': probe_url, 'final_url': final_url})
        except Exception as exc:
            base.update({"verdict": "uncertain", "error": self.redact(str(exc)), "reason": "Anfrage fehlgeschlagen; kein Existenzurteil"})
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
                    if not re.fullmatch(rgx, username):
                        continue  # Username für diese Plattform syntaktisch unmöglich
                except re.error:
                    pass
            has_auth = bool(self.config and self.config.get_site_auth(p["name"]))
            if p.get("evidence") and (p.get("anonymous_checkable", True) or probe_unreliable or has_auth):
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
                      "manual_check": True, "verdict": "manual"},
                url=p["url"].replace("{}", quote(username, safe=""))))
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
                            severity=ResultSeverity.FOUND, title=f"Öffentliches Profil auf {info['name']} belegt",
                            data={"exists": True, "status_code": info.get("status_code"),
                                  "reliability": info.get("reliability"),
                                  "reason": info.get("reason"), "checked_url": info.get("checked_url"),
                                  "identity_verified": False, "verdict": "found",
                                  "note": "Gleicher Username belegt nicht dieselbe Person.",
                                  **({"via_login": True} if info.get("authed") else {})},
                            url=info["profile_url"]))
                    elif verdict == "not_found":
                        self.add_result(OSINTResult(
                            source=info["name"], module=self.name, category=info["category"],
                            severity=ResultSeverity.NOT_FOUND, title=f"Nicht gefunden auf {info['name']}",
                            data={"exists": False, "status_code": info.get("status_code"),
                                  "verdict": "not_found", "reason": info.get("reason")}))
                    else:  # uncertain
                        self.add_result(OSINTResult(
                            source=info["name"], module=self.name, category=info["category"],
                            severity=ResultSeverity.INFO,
                            title=f"Unbestätigt bei {info['name']}",
                            data={"exists": None, "status_code": info.get("status_code"),
                                  "error": info.get("error"), "reason": info.get("reason"),
                                  "verdict": "uncertain"},
                            url=info["profile_url"]))
                    self.report_progress(done, total, f"{info.get('name', '?')} geprüft")

        session.close()
        return self.create_report(username, input_type, start, time.time())
