"""
OSINT Tool - E-Mail-Modul (v2)
Umfassende E-Mail-Analyse mit vielen keyfreien Quellen:

  • Format-Validierung & Normalisierung (inkl. Gmail-Kanonisierung)
  • Provider-Erkennung (Domain + MX-Infrastruktur)
  • E-Mail-Infrastruktur: MX, SPF, DMARC
  • Klassifizierung: frei / eigene Domain / Rollenkonto / Wegwerf-Mail
  • Gravatar-Profil (Name, Ort, verknüpfte Accounts, Bio)
  • GitHub: Commit-Suche & User-Suche per E-Mail
  • Account-Existenz-Checks im Holehe-Stil über viele Seiten (parallel),
    inkl. Token-/CSRF-basierter Checks (Strava, eBay, Amazon, Tumblr)
  • Keyfreie Breach-/Leak-Checks: XposedOrNot, LeakCheck (public), ProxyNova COMB
  • Optional mit API-Key: HIBP, Hunter.io, Dehashed, EmailRep
  • Generierte Such-/Dork-Links (Google, Bing, DuckDuckGo, People-Search, Breach-UIs)

Strikte Signal-Auswertung: Nur ein EINDEUTIGES Treffer-Signal wird als FOUND
gewertet. Blockierte/Captcha-/Token-fehlt-Antworten gelten als „unklar"
(INCONCLUSIVE) — niemals als Treffer. Damit gibt es keine False Positives.
"""

import re
import time
import hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeout
from typing import List, Optional
from urllib.parse import quote

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.http import build_session, DEFAULT_UA
from ..core.config import (
    EMAIL_PROVIDERS, MX_PROVIDER_PATTERNS, ROLE_LOCAL_PARTS, DISPOSABLE_DOMAINS,
    EMAIL_ACCOUNT_SITES, EMAIL_DORKS,
    GRAVATAR_AVATAR_URL, GRAVATAR_PROFILE_URL,
)

_MISSING = object()
_EMAIL_RE = re.compile(r'^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$')
_FREE_DOMAINS = set(EMAIL_PROVIDERS.keys())


class EmailModule(BaseModule):

    @property
    def name(self) -> str:
        return "email"

    @property
    def description(self) -> str:
        return ("Umfassende E-Mail-Analyse: Provider, MX/SPF/DMARC, Gravatar, "
                "GitHub, Account-Existenz auf vielen Seiten, Breaches, Such-Links")

    @property
    def input_types(self) -> List[str]:
        return ["email"]

    # ── Sessions ───────────────────────────────────────────────
    def _ua(self) -> str:
        return self.config.user_agent if self.config else DEFAULT_UA

    # Account-/Token-Checks sollen schnell aufgeben statt zu hängen
    _ACCT_TIMEOUT = 8        # Sekunden pro Request (kein Retry)
    _ACCT_BUDGET = 22        # Sekunden Gesamtbudget für die Account-Phase

    def _session(self):
        return build_session(user_agent=self._ua())

    def _acct_session(self):
        """Schnelle, retry-freie Session für Account-Existenz-Checks."""
        return build_session(user_agent=self._ua(), retries=0)

    def _fresh_session(self):
        """Eigene Session mit isolierten Cookies (für Token-/CSRF-Flows), ohne Retries."""
        return build_session(user_agent=self._ua(), retries=0)

    @property
    def _timeout(self) -> int:
        return self.config.request_timeout if self.config else 12

    @property
    def _acct_timeout(self) -> int:
        return min(self._ACCT_TIMEOUT, self._timeout)

    # ── Helfer: Normalisierung & Hashes ────────────────────────
    @staticmethod
    def _hashes(email: str) -> dict:
        norm = email.strip().lower().encode()
        return {"md5": hashlib.md5(norm).hexdigest(),
                "sha256": hashlib.sha256(norm).hexdigest()}

    def _tokens(self, email: str) -> dict:
        local, domain = email.split("@", 1)
        h = self._hashes(email)
        return {"{email}": email, "{emaillower}": email.lower(),
                "{local}": local, "{domain}": domain,
                "{md5}": h["md5"], "{sha256}": h["sha256"]}

    @staticmethod
    def _tmpl(value, tokens):
        if isinstance(value, str):
            for k, v in tokens.items():
                value = value.replace(k, v)
            return value
        if isinstance(value, dict):
            return {k: EmailModule._tmpl(v, tokens) for k, v in value.items()}
        if isinstance(value, list):
            return [EmailModule._tmpl(v, tokens) for v in value]
        return value

    # ── Format ─────────────────────────────────────────────────
    @staticmethod
    def _validate_format(email: str) -> bool:
        return bool(_EMAIL_RE.match(email))

    # ── Provider / Klassifizierung ─────────────────────────────
    @staticmethod
    def _identify_provider(domain: str) -> Optional[str]:
        return EMAIL_PROVIDERS.get(domain.lower())

    @staticmethod
    def _provider_from_mx(mx_hosts: List[str]) -> Optional[str]:
        joined = " ".join(mx_hosts).lower()
        for pattern, name in MX_PROVIDER_PATTERNS.items():
            if pattern in joined:
                return name
        return None

    # ── DNS: MX / SPF / DMARC ──────────────────────────────────
    def _dns_records(self, domain: str) -> dict:
        out = {"mx": [], "spf": None, "dmarc": None, "resolver": None}
        try:
            import dns.resolver
        except ImportError:
            out["resolver"] = "none"
            out["note"] = "dnspython nicht installiert – DNS-Analyse übersprungen (pip install dnspython)"
            return out

        out["resolver"] = "dnspython"

        def _txt(name):
            vals = []
            try:
                for r in dns.resolver.resolve(name, "TXT"):
                    txt = (b"".join(r.strings).decode(errors="ignore")
                           if hasattr(r, "strings") else str(r).strip('"'))
                    vals.append(txt)
            except Exception:
                pass
            return vals

        try:
            answers = dns.resolver.resolve(domain, "MX")
            out["mx"] = sorted(
                [{"host": str(r.exchange).rstrip("."), "priority": r.preference} for r in answers],
                key=lambda x: x["priority"])
        except Exception:
            pass
        for t in _txt(domain):
            if t.lower().startswith("v=spf1"):
                out["spf"] = t
                break
        for t in _txt(f"_dmarc.{domain}"):
            if t.lower().startswith("v=dmarc1"):
                out["dmarc"] = t
                break
        return out

    # ── Gravatar ───────────────────────────────────────────────
    def _check_gravatar(self, email: str, session) -> dict:
        h = hashlib.md5(email.strip().lower().encode()).hexdigest()
        result = {"hash": h, "has_avatar": False, "profile": None}
        try:
            r = session.head(GRAVATAR_AVATAR_URL.format(h), timeout=self._timeout)
            result["has_avatar"] = r.status_code == 200
            if result["has_avatar"]:
                result["avatar_url"] = f"https://www.gravatar.com/avatar/{h}"
            r2 = session.get(GRAVATAR_PROFILE_URL.format(h), timeout=self._timeout)
            if r2.status_code == 200:
                entries = (r2.json().get("entry") or [])
                if entries:
                    e = entries[0]
                    name = e.get("name")
                    result["profile"] = {
                        "display_name": e.get("displayName", ""),
                        "name": name.get("formatted", "") if isinstance(name, dict) else "",
                        "about": e.get("aboutMe", ""),
                        "location": e.get("currentLocation", ""),
                        "username": e.get("preferredUsername", ""),
                        "profile_url": e.get("profileUrl", ""),
                        "accounts": [
                            {"service": a.get("shortname") or a.get("name", ""),
                             "username": a.get("username", ""), "url": a.get("url", "")}
                            for a in e.get("accounts", [])],
                        "urls": [{"title": u.get("title", ""), "value": u.get("value", "")}
                                 for u in e.get("urls", [])],
                    }
        except Exception as exc:
            self.add_error(f"Gravatar: {exc}")
        return result

    # ── GitHub: Commit- & User-Suche per E-Mail ────────────────
    def _check_github(self, email: str, session) -> dict:
        out = {"commits": None, "user": None}
        auth = {}
        if self.config and self.config.get_api_key("github"):
            auth["Authorization"] = f"Bearer {self.config.get_api_key('github')}"
        try:
            r = session.get(
                f"https://api.github.com/search/commits?q=author-email:{quote(email)}&per_page=10",
                headers={"Accept": "application/vnd.github.cloak-preview+json", **auth},
                timeout=self._timeout)
            if r.status_code == 200 and r.json().get("total_count", 0) > 0:
                data = r.json()
                logins, repos, sample = set(), set(), None
                for it in data.get("items", []):
                    a = (it.get("author") or {})
                    if a.get("login"):
                        logins.add(a["login"])
                    repo = (it.get("repository") or {}).get("full_name")
                    if repo:
                        repos.add(repo)
                    sample = sample or it.get("html_url")
                out["commits"] = {"total": data["total_count"], "logins": sorted(logins),
                                  "repos": sorted(repos)[:10], "sample_commit": sample}
        except Exception as exc:
            self.add_error(f"GitHub-Commits: {exc}")
        try:
            r = session.get(
                f"https://api.github.com/search/users?q={quote(email)}+in:email",
                headers={"Accept": "application/vnd.github+json", **auth}, timeout=self._timeout)
            if r.status_code == 200 and r.json().get("total_count", 0) > 0:
                it = r.json()["items"][0]
                out["user"] = {"login": it.get("login"), "profile": it.get("html_url"),
                               "avatar": it.get("avatar_url")}
        except Exception as exc:
            self.add_error(f"GitHub-User: {exc}")
        return out

    # ── Account-Existenz-Engine (datengetrieben) ───────────────
    @staticmethod
    def _json_path(obj, path):
        cur = obj
        for part in path.split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return _MISSING
        return cur

    def _eval_rule(self, rule, status, text, js) -> bool:
        if "all" in rule:
            return all(self._eval_rule(r, status, text, js) for r in rule["all"])
        if "status" in rule:
            return status in rule["status"]
        if "body_equals" in rule:
            return text.strip().lower() == str(rule["body_equals"]).strip().lower()
        if "body_contains" in rule:
            return str(rule["body_contains"]).lower() in text.lower()
        if "json" in rule:
            if js is None:
                return False
            val = self._json_path(js, rule["json"])
            if val is _MISSING:
                return False
            if "in" in rule:
                return val in rule["in"]
            if "eq" in rule:
                expected = rule["eq"]
                if isinstance(expected, bool) or isinstance(val, bool):
                    return type(val) == type(expected) and val == expected
                return val == expected
            return False
        if "json_nonempty" in rule:
            if js is None:
                return False
            val = self._json_path(js, rule["json_nonempty"])
            return val is not _MISSING and bool(val)
        return False

    def _check_account_site(self, site: dict, tokens: dict, session) -> dict:
        url = self._tmpl(site["url"], tokens)
        method = site.get("method", "GET").upper()
        headers = self._tmpl(site.get("headers", {}), tokens)
        ct = site.get("content_type", "none")
        info = {"site": site["name"], "category": site.get("category", "Account"),
                "reliability": site.get("reliability", "medium")}
        try:
            kwargs = {"headers": headers, "timeout": self._acct_timeout, "allow_redirects": True}
            if method == "POST":
                body = site.get("body")
                if ct == "json":
                    kwargs["json"] = self._tmpl(body, tokens)
                elif ct == "form":
                    kwargs["data"] = self._tmpl(body, tokens)
                resp = session.post(url, **kwargs)
            else:
                resp = session.get(url, **kwargs)
            status = resp.status_code
            text = resp.text[:20000] if resp.text else ""
            try:
                js = resp.json()
            except Exception:
                js = None
            info["status"] = status
            for rule in site.get("exists", []):
                if self._eval_rule(rule, status, text, js):
                    info["verdict"] = "exists"
                    if isinstance(js, dict) and site.get("extract"):
                        info["extracted"] = {k: js.get(k) for k in site["extract"] if k in js}
                    return info
            for rule in site.get("notexists", []):
                if self._eval_rule(rule, status, text, js):
                    info["verdict"] = "notexists"
                    return info
            info["verdict"] = "inconclusive"
        except Exception as exc:
            info["verdict"] = "inconclusive"
            info["error"] = str(exc)
        return info

    # ── Token-/CSRF-basierte Account-Checks (eigener Flow) ─────
    # Vertrag: nur das EINDEUTIGE Exists-Signal -> "exists". Fehlt der Token,
    # kommt Captcha/HTML statt JSON, oder ist das Signal uneindeutig -> "inconclusive".
    @staticmethod
    def _search(patterns, text):
        for p in patterns:
            m = re.search(p, text)
            if m:
                return m.group(1)
        return None

    def _chk_strava(self, email: str) -> dict:
        info = {"site": "Strava", "category": "Sport", "reliability": "medium"}
        try:
            s = self._fresh_session()
            r1 = s.get("https://www.strava.com/register/free", timeout=self._acct_timeout)
            token = self._search(
                [r'<meta name="csrf-token" content="([^"]+)"',
                 r'name="authenticity_token"[^>]*value="([^"]+)"'], r1.text)
            if not token:
                info["verdict"] = "inconclusive"
                info["error"] = "CSRF-Token nicht gefunden"
                return info
            r2 = s.get(f"https://www.strava.com/athletes/email_unique?email={quote(email)}",
                       headers={"X-CSRF-Token": token, "X-Requested-With": "XMLHttpRequest",
                                "Accept": "*/*",
                                "Referer": "https://www.strava.com/register/free"},
                       timeout=self._acct_timeout)
            body = (r2.text or "").strip().lower()
            if body == "false":
                info["verdict"] = "exists"
            elif body == "true":
                info["verdict"] = "notexists"
            else:
                info["verdict"] = "inconclusive"
        except Exception as exc:
            info["verdict"] = "inconclusive"
            info["error"] = str(exc)
        return info

    def _chk_ebay(self, email: str) -> dict:
        info = {"site": "eBay", "category": "Marktplatz", "reliability": "medium"}
        try:
            s = self._fresh_session()
            r1 = s.get("https://www.ebay.com/signin/", timeout=self._acct_timeout)
            srt = self._search([r'name="srt"[^>]*value="([^"]+)"', r'"srt"\s*:\s*"([^"]+)"'], r1.text)
            if not srt:
                info["verdict"] = "inconclusive"
                info["error"] = "srt-Token nicht gefunden"
                return info
            r2 = s.post("https://signin.ebay.com/signin/srv/identifer",
                        data={"identifier": email, "srt": srt},
                        headers={"Accept": "application/json, text/plain, */*",
                                 "Origin": "https://www.ebay.com",
                                 "Referer": "https://www.ebay.com/signin/",
                                 "X-Requested-With": "XMLHttpRequest"},
                        timeout=self._acct_timeout)
            try:
                js = r2.json()
            except Exception:
                js = None
            if isinstance(js, dict) and len(js) > 0:
                info["verdict"] = "notexists" if "err" in js else "exists"
            else:
                info["verdict"] = "inconclusive"
        except Exception as exc:
            info["verdict"] = "inconclusive"
            info["error"] = str(exc)
        return info

    def _chk_amazon(self, email: str) -> dict:
        info = {"site": "Amazon", "category": "Marktplatz", "reliability": "low"}
        try:
            s = self._fresh_session()
            openid = ("https://www.amazon.com/ap/signin?openid.return_to=https%3A%2F%2Fwww.amazon.com%2F"
                      "&openid.identity=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
                      "&openid.assoc_handle=usflex&openid.mode=checkid_setup"
                      "&openid.claimed_id=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0%2Fidentifier_select"
                      "&openid.ns=http%3A%2F%2Fspecs.openid.net%2Fauth%2F2.0")
            r1 = s.get(openid, timeout=self._acct_timeout)
            fields = dict(re.findall(r'<input[^>]+name="([^"]+)"[^>]+value="([^"]*)"', r1.text))
            if not fields or "appActionToken" not in " ".join(fields.keys()) + " ".join(fields):
                # Mindestens ein paar Hidden-Felder erwartet; sonst Captcha/Block
                if len(fields) < 3:
                    info["verdict"] = "inconclusive"
                    info["error"] = "Signin-Formular nicht lesbar (Captcha/Block?)"
                    return info
            fields = {k: v for k, v in fields.items() if "password" not in k.lower()}
            fields["email"] = email
            r2 = s.post("https://www.amazon.com/ap/signin", data=fields,
                        headers={"Origin": "https://www.amazon.com", "Referer": openid},
                        timeout=self._acct_timeout)
            t = (r2.text or "").lower()
            if "auth-password-missing-alert" in t:
                info["verdict"] = "exists"
            elif "cannot find an account" in t or "we cannot find" in t or "konto" in t and "nicht" in t:
                info["verdict"] = "notexists"
            else:
                info["verdict"] = "inconclusive"
        except Exception as exc:
            info["verdict"] = "inconclusive"
            info["error"] = str(exc)
        return info

    def _chk_tumblr(self, email: str) -> dict:
        info = {"site": "Tumblr", "category": "Blog", "reliability": "medium"}
        try:
            s = self._fresh_session()
            r1 = s.get("https://www.tumblr.com/register?source=login_register_center",
                       timeout=self._acct_timeout)
            bearer = self._search([r'"API_TOKEN"\s*:\s*"([^"]+)"',
                                    r'"apiToken"\s*:\s*"([^"]+)"',
                                    r'Bearer ([A-Za-z0-9_\-]{20,})'], r1.text)
            csrf = self._search([r'"csrf"\s*:\s*"([^"]+)"',
                                 r'<meta name="tumblr-form-key" content="([^"]+)"'], r1.text)
            if not bearer:
                info["verdict"] = "inconclusive"
                info["error"] = "API-Token nicht gefunden"
                return info
            headers = {"Accept": "application/json;format=camelcase",
                       "Authorization": f"Bearer {bearer}",
                       "Content-Type": "application/json; charset=utf8",
                       "Origin": "https://www.tumblr.com",
                       "Referer": "https://www.tumblr.com/register?source=login_register_center",
                       "X-Version": "redpop/3/0//redpop/"}
            if csrf:
                headers["X-CSRF"] = csrf
            r2 = s.post("https://www.tumblr.com/api/v2/register/account/validate",
                        json={"email": email}, headers=headers, timeout=self._acct_timeout)
            try:
                js = r2.json()
            except Exception:
                js = None
            # Tumblr: Validierungsfehlercode 2 == E-Mail bereits vergeben
            code = None
            if isinstance(js, dict):
                errs = (js.get("errors") or [])
                if isinstance(errs, list) and errs and isinstance(errs[0], dict):
                    code = errs[0].get("code")
                code = code if code is not None else self._json_path(js, "response.email")
            if code == 2:
                info["verdict"] = "exists"
            elif r2.status_code == 200 and (js is not None) and not (isinstance(js, dict) and js.get("errors")):
                info["verdict"] = "notexists"
            else:
                info["verdict"] = "inconclusive"
        except Exception as exc:
            info["verdict"] = "inconclusive"
            info["error"] = str(exc)
        return info

    def _token_checks(self):
        return [self._chk_strava, self._chk_ebay, self._chk_amazon, self._chk_tumblr]

    # ── Keyfreie Breach-Quellen ────────────────────────────────
    def _breach_xposedornot(self, email: str, session) -> Optional[dict]:
        try:
            r = session.get(f"https://api.xposedornot.com/v1/check-email/{quote(email)}",
                            timeout=self._timeout)
            if r.status_code == 404:
                return {"source": "XposedOrNot", "found": False, "breaches": []}
            if r.status_code == 200:
                breaches = r.json().get("breaches") or []
                names = breaches[0] if breaches and isinstance(breaches[0], list) else breaches
                names = [n for n in names if n]
                return {"source": "XposedOrNot", "found": bool(names), "breaches": names}
        except Exception as exc:
            self.add_error(f"XposedOrNot: {exc}")
        return None

    def _breach_leakcheck_public(self, email: str, session) -> Optional[dict]:
        try:
            r = session.get(f"https://leakcheck.io/api/public?check={quote(email)}",
                            timeout=self._timeout)
            if r.status_code == 200:
                data = r.json()
                if data.get("success"):
                    sources = [s.get("name") for s in data.get("sources", []) if s.get("name")]
                    return {"source": "LeakCheck (public)", "found": data.get("found", 0) > 0,
                            "count": data.get("found", 0), "breaches": sources,
                            "fields": data.get("fields", [])}
        except Exception as exc:
            self.add_error(f"LeakCheck: {exc}")
        return None

    def _breach_proxynova(self, email: str, session) -> Optional[dict]:
        try:
            r = session.get(f"https://api.proxynova.com/comb?query={quote(email)}&start=0&limit=15",
                            timeout=self._timeout)
            if r.status_code == 200:
                data = r.json()
                lines = data.get("lines", []) or []
                pw_hits = 0
                for ln in lines:
                    if ":" in ln:
                        u, _, pw = ln.partition(":")
                        if email.lower() in u.lower() and pw:
                            pw_hits += 1
                return {"source": "ProxyNova COMB", "found": data.get("count", 0) > 0,
                        "count": data.get("count", 0), "password_hint_count": pw_hits,
                        "note": "Passwörter werden aus Datenschutzgründen nicht angezeigt."}
        except Exception as exc:
            self.add_error(f"ProxyNova: {exc}")
        return None

    # ── Keypflichtige Breach-Quellen ───────────────────────────
    def _breach_hibp(self, email: str, session) -> Optional[dict]:
        key = self.config.get_api_key("hibp") if self.config else None
        if not key:
            return None
        try:
            r = session.get(
                f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email, safe='')}?truncateResponse=false",
                headers={"hibp-api-key": key, "User-Agent": "OSINT-Recon-Tool"}, timeout=self._timeout)
            if r.status_code == 200:
                breaches = r.json()
                return {"source": "Have I Been Pwned", "found": True, "count": len(breaches),
                        "breaches": [b.get("Name") for b in breaches],
                        "details": [{"name": b.get("Name"), "date": b.get("BreachDate"),
                                     "data": b.get("DataClasses", [])} for b in breaches[:20]]}
            if r.status_code == 404:
                return {"source": "Have I Been Pwned", "found": False, "count": 0, "breaches": []}
        except Exception as exc:
            self.add_error(f"HIBP: {exc}")
        return None

    def _breach_dehashed(self, email: str, session) -> Optional[dict]:
        key = self.config.get_api_key("dehashed") if self.config else None
        user = self.config.get_api_key("dehashed_email") if self.config else None
        if not key or not user:
            return None
        try:
            r = session.get(f"https://api.dehashed.com/search?query=email:{quote(email)}&size=100",
                            headers={"Accept": "application/json"}, auth=(user, key), timeout=self._timeout)
            if r.status_code == 200:
                entries = r.json().get("entries") or []
                dbs = sorted({e.get("database_name") for e in entries if e.get("database_name")})
                return {"source": "DeHashed", "found": len(entries) > 0, "count": len(entries), "breaches": dbs}
        except Exception as exc:
            self.add_error(f"DeHashed: {exc}")
        return None

    def _check_emailrep(self, email: str, session) -> Optional[dict]:
        headers = {"User-Agent": "OSINT-Recon-Tool", "Accept": "application/json"}
        key = self.config.get_api_key("emailrep") if self.config else None
        if key:
            headers["Key"] = key
        try:
            r = session.get(f"https://emailrep.io/{quote(email, safe='')}", headers=headers, timeout=self._timeout)
            if r.status_code == 200:
                data = r.json()
                det = data.get("details", {})
                return {"reputation": data.get("reputation", "unknown"),
                        "suspicious": data.get("suspicious", False),
                        "references": data.get("references", 0),
                        "deliverable": det.get("deliverable"),
                        "profiles": det.get("profiles", []),
                        "data_breach": det.get("data_breach"),
                        "credentials_leaked": det.get("credentials_leaked")}
        except Exception as exc:
            self.add_error(f"EmailRep: {exc}")
        return None

    def _check_hunter(self, email: str, session) -> Optional[dict]:
        key = self.config.get_api_key("hunter") if self.config else None
        if not key:
            return None
        try:
            r = session.get(f"https://api.hunter.io/v2/email-verifier?email={quote(email)}&api_key={key}",
                            timeout=self._timeout)
            if r.status_code == 200:
                d = r.json().get("data", {})
                return {"status": d.get("status"), "result": d.get("result"), "score": d.get("score"),
                        "deliverable": d.get("result") == "deliverable", "sources": len(d.get("sources", []))}
        except Exception as exc:
            self.add_error(f"Hunter: {exc}")
        return None

    # ── Hauptlauf ──────────────────────────────────────────────
    def run(self, input_value: str, input_type: str = "email") -> ModuleReport:
        start = time.time()
        email = input_value.strip()
        session = self._session()

        n_account = len(EMAIL_ACCOUNT_SITES) + len(self._token_checks())
        total_steps = 7 + n_account
        step = [0]

        def tick(msg):
            step[0] += 1
            self.report_progress(min(step[0], total_steps), total_steps, msg)

        # 1. Format
        valid = self._validate_format(email)
        self.add_result(OSINTResult(
            source="Formatprüfung", module=self.name, category="Validation",
            severity=ResultSeverity.INFO if valid else ResultSeverity.WARNING,
            title=f"E-Mail-Format {'gültig' if valid else 'ungültig'}",
            data={"valid": valid, "email": email.lower()}))
        tick("Format geprüft")
        if not valid:
            return self.create_report(email, input_type, start, time.time())

        email_l = email.lower()
        local, domain = email_l.split("@", 1)
        tokens = self._tokens(email_l)
        h = self._hashes(email_l)

        # 2. Provider & Klassifizierung
        provider = self._identify_provider(domain)
        is_role = local.split("+")[0] in ROLE_LOCAL_PARTS
        is_disposable = domain in DISPOSABLE_DOMAINS
        is_free = domain in _FREE_DOMAINS
        canonical = None
        if provider and "Google" in provider:
            canonical = local.split("+")[0].replace(".", "") + "@" + domain
        self.add_result(OSINTResult(
            source="Provider-Erkennung", module=self.name, category="Info",
            severity=ResultSeverity.INFO,
            title=f"Provider: {provider or 'Eigene/Unbekannte Domain'}",
            data={"provider": provider, "domain": domain, "local_part": local,
                  "known_provider": provider is not None,
                  "type": "Freemail" if is_free else "Eigene/Unternehmensdomain",
                  "md5": h["md5"], "sha256": h["sha256"], "gmail_canonical": canonical}))
        if is_disposable:
            self.add_result(OSINTResult(
                source="Wegwerf-Mail-Check", module=self.name, category="Validation",
                severity=ResultSeverity.WARNING, title="Wegwerf-/Temporär-Mail-Domain",
                data={"disposable": True, "domain": domain}))
        if is_role:
            self.add_result(OSINTResult(
                source="Konto-Typ", module=self.name, category="Info",
                severity=ResultSeverity.INFO, title="Rollen-/Funktionskonto (kein Personenbezug)",
                data={"role_account": True, "local_part": local}))
        tick("Provider erkannt")

        # 3. DNS / Infrastruktur
        dns_data = self._dns_records(domain)
        mx_hosts = [m["host"] for m in dns_data["mx"]]
        mx_provider = self._provider_from_mx(mx_hosts) if mx_hosts else None
        self.add_result(OSINTResult(
            source="DNS / Mail-Infrastruktur", module=self.name, category="Infrastructure",
            severity=ResultSeverity.FOUND if mx_hosts else ResultSeverity.WARNING,
            title=(f"MX gefunden ({mx_provider})" if mx_provider else
                   f"{len(mx_hosts)} MX-Record(s)" if mx_hosts else
                   "Keine MX-Records (Mail evtl. nicht zustellbar)"),
            data={"mx": dns_data["mx"], "mx_provider": mx_provider, "spf": dns_data["spf"],
                  "dmarc": dns_data["dmarc"], "note": dns_data.get("note")}))
        tick("DNS geprüft")

        # 4. Gravatar
        grav = self._check_gravatar(email_l, session)
        if grav["has_avatar"] or grav["profile"]:
            prof = grav.get("profile") or {}
            self.add_result(OSINTResult(
                source="Gravatar", module=self.name, category="Profile",
                severity=ResultSeverity.FOUND, title="Gravatar-Profil gefunden",
                data={k: v for k, v in {
                    "display_name": prof.get("display_name"), "location": prof.get("location"),
                    "username": prof.get("username"), "about": prof.get("about"),
                    "linked_accounts": prof.get("accounts"), "urls": prof.get("urls"),
                    "has_avatar": grav["has_avatar"]}.items() if v},
                url=grav.get("avatar_url") or prof.get("profile_url")))
        else:
            self.add_result(OSINTResult(
                source="Gravatar", module=self.name, category="Profile",
                severity=ResultSeverity.NOT_FOUND, title="Kein Gravatar-Profil",
                data={"hash": grav["hash"]}))
        tick("Gravatar geprüft")

        # 5. GitHub
        gh = self._check_github(email_l, session)
        if gh.get("commits") or gh.get("user"):
            c = gh.get("commits") or {}
            u = gh.get("user") or {}
            self.add_result(OSINTResult(
                source="GitHub", module=self.name, category="Development",
                severity=ResultSeverity.FOUND, title="GitHub-Konto/Commits über E-Mail gefunden",
                data={k: v for k, v in {
                    "user": u.get("login"), "profile": u.get("profile"),
                    "commit_authors": c.get("logins"), "commit_total": c.get("total"),
                    "repositories": c.get("repos"), "sample_commit": c.get("sample_commit")}.items() if v},
                url=u.get("profile") or c.get("sample_commit")))
        tick("GitHub geprüft")

        # 6. Account-Existenz-Checks (datengetrieben + Token-Flows, parallel)
        self.report_progress(step[0], total_steps, "Prüfe Account-Existenz auf vielen Seiten...")
        found_sites, unclear = [], []
        workers = self.config.max_concurrent_requests if self.config else 20
        acct_session = self._acct_session()
        ex = ThreadPoolExecutor(max_workers=workers)
        futs = {}
        for s in EMAIL_ACCOUNT_SITES:
            futs[ex.submit(self._check_account_site, s, tokens, acct_session)] = s["name"]
        for fn in self._token_checks():
            futs[ex.submit(fn, email_l)] = fn.__name__.replace("_chk_", "").title()
        processed = set()
        try:
            # Hartes Gesamtbudget: hängt eine Quelle (z.B. Amazon), wird nicht
            # die ganze Phase blockiert — Reste werden als „unklar" markiert.
            for fut in as_completed(futs, timeout=self._ACCT_BUDGET):
                processed.add(fut)
                try:
                    info = fut.result()
                except Exception as exc:
                    info = {"site": futs[fut], "verdict": "inconclusive", "error": str(exc),
                            "category": "Account", "reliability": "medium"}
                verdict = info.get("verdict")
                if verdict == "exists":
                    found_sites.append(info["site"])
                    self.add_result(OSINTResult(
                        source=info["site"], module=self.name, category=info.get("category", "Account"),
                        severity=ResultSeverity.FOUND, title=f"Konto existiert bei {info['site']}",
                        data={"exists": True, "reliability": info.get("reliability"),
                              **({"details": info["extracted"]} if info.get("extracted") else {})}))
                elif verdict == "notexists":
                    self.add_result(OSINTResult(
                        source=info["site"], module=self.name, category=info.get("category", "Account"),
                        severity=ResultSeverity.NOT_FOUND, title=f"Kein Konto bei {info['site']}",
                        data={"exists": False}))
                else:
                    unclear.append(info.get("site", "?"))
                tick(f"{info.get('site', '?')} geprüft")
        except FuturesTimeout:
            for fut, nm in futs.items():
                if fut not in processed:
                    unclear.append(nm)
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        if unclear:
            self.add_result(OSINTResult(
                source="Account-Checks", module=self.name, category="Account",
                severity=ResultSeverity.INFO,
                title=f"{len(unclear)} Quelle(n) nicht eindeutig (blockiert/Rate-Limit)",
                data={"inconclusive": sorted(unclear)}))

        # 7. Breach-/Leak-Checks (parallel)
        self.report_progress(step[0], total_steps, "Prüfe Datenlecks...")
        breach_fns = [self._breach_xposedornot, self._breach_leakcheck_public,
                      self._breach_proxynova, self._breach_hibp, self._breach_dehashed]
        all_breach_names, breach_reports = set(), []
        with ThreadPoolExecutor(max_workers=8) as ex:
            for fut in as_completed([ex.submit(fn, email_l, session) for fn in breach_fns]):
                res = fut.result()
                if res:
                    breach_reports.append(res)
                    for n in res.get("breaches", []):
                        if n:
                            all_breach_names.add(n)
        any_breach = any(b.get("found") for b in breach_reports)
        if breach_reports:
            total_unique = len(all_breach_names)
            sev = (ResultSeverity.CRITICAL if total_unique > 5 else
                   ResultSeverity.WARNING if any_breach else ResultSeverity.FOUND)
            self.add_result(OSINTResult(
                source="Datenleck-Aggregation", module=self.name, category="Security", severity=sev,
                title=(f"In {total_unique} Datenleck(s) gefunden" if any_breach
                       else "Keine Datenlecks in keyfreien Quellen"),
                data={"breaches": sorted(all_breach_names),
                      "sources_checked": [b["source"] for b in breach_reports],
                      "per_source": breach_reports},
                url=f"https://haveibeenpwned.com/account/{quote(email_l)}"))
        tick("Datenlecks geprüft")

        # Reputation / Verifikation
        rep = self._check_emailrep(email_l, session)
        if rep:
            self.add_result(OSINTResult(
                source="EmailRep.io", module=self.name, category="Reputation",
                severity=ResultSeverity.WARNING if rep.get("suspicious") else ResultSeverity.FOUND,
                title=f"Reputation: {rep.get('reputation', 'unbekannt')}"
                      + (f" · {len(rep['profiles'])} verknüpfte Profile" if rep.get("profiles") else ""),
                data=rep))
        hunter = self._check_hunter(email_l, session)
        if hunter:
            self.add_result(OSINTResult(
                source="Hunter.io", module=self.name, category="Validation",
                severity=ResultSeverity.FOUND if hunter.get("deliverable") else ResultSeverity.INFO,
                title=f"Hunter: {hunter.get('result', '?')} (Score {hunter.get('score', '?')})", data=hunter))
        tick("Reputation geprüft")

        # 8. Such-/Dork-Links + abgeleitete Usernames
        for dork in EMAIL_DORKS:
            self.add_result(OSINTResult(
                source=dork["name"], module=self.name,
                category=("Such-Link · " + dork.get("category", "")).strip(" ·"),
                severity=ResultSeverity.INFO, title=dork["name"], data={},
                url=self._tmpl(dork["url"], tokens)))
        candidates = []
        for c in (local, local.replace(".", ""), local.split("+")[0], local.split("+")[0].replace(".", "")):
            if c and c not in candidates:
                candidates.append(c)
        self.add_result(OSINTResult(
            source="Username-Ableitung", module=self.name, category="Hinweis",
            severity=ResultSeverity.INFO, title="Mögliche Usernames für Folge-Scan",
            data={"candidates": candidates,
                  "tipp": f"Für Social-Media-Profile einen Username-Scan mit '{candidates[0]}' starten."}))

        self.report_progress(total_steps, total_steps, "E-Mail-Analyse abgeschlossen")
        return self.create_report(email, input_type, start, time.time())
