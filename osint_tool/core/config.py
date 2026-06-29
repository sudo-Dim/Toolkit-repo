"""
OSINT Tool - Konfiguration
Zentrale Konfigurationsdatei für alle Module und Einstellungen.

Große Datentabellen (Username-Plattformen, E-Mail-Account-Checks, Breach-APIs,
Dork-Vorlagen, Wegwerf-Domains) liegen als JSON unter osint_tool/data/ und
werden hier lazy geladen.
"""

import os
import json
import pathlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

# ──────────────────────────────────────────────
# Daten-Verzeichnis & JSON-Loader
# ──────────────────────────────────────────────
DATA_DIR = pathlib.Path(__file__).resolve().parent.parent / "data"


def load_data(filename: str, key: Optional[str] = None, default=None):
    """Lädt eine JSON-Datendatei aus osint_tool/data/.

    Args:
        filename: Dateiname (z.B. "username_platforms.json")
        key: Optional - gib nur diesen Top-Level-Schlüssel zurück
        default: Rückgabewert falls Datei/Schlüssel fehlt
    """
    path = DATA_DIR / filename
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data.get(key, default) if key else data
    except (FileNotFoundError, json.JSONDecodeError):
        return default if default is not None else ([] if key else {})


@dataclass
class AppConfig:
    """Hauptkonfiguration der Anwendung."""
    app_name: str = "OSINT Recon Tool"
    version: str = "1.1.0"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/122.0.0.0 Safari/537.36"
    )
    request_timeout: int = 12
    max_concurrent_requests: int = 20
    delay_between_requests: float = 0.0
    output_dir: str = "results"
    export_formats: List[str] = field(default_factory=lambda: ["json", "txt", "html"])

    # Wenn True werden auch Quellen abgefragt, die anonym/aus Datacenter-IPs
    # unzuverlässig sind (Instagram, X, LinkedIn ...). Standardmäßig werden
    # diese nur als manueller Link ausgegeben, um False Positives zu vermeiden.
    probe_unreliable: bool = False

    # Optionale API-Keys (werden aus Umgebungsvariablen oder config.json geladen)
    api_keys: Dict[str, str] = field(default_factory=dict)

    # Optionale hinterlegte Logins für Seiten, die anonym nicht prüfbar sind
    # (Instagram, X, LinkedIn, Reddit, TikTok ...). Format pro Plattformname:
    #   {"Instagram": {"cookie": "sessionid=...; csrftoken=..."},
    #    "Reddit":    {"bearer": "..."},
    #    "Twitter/X": {"headers": {"Cookie": "auth_token=...; ct0=..."}}}
    # Ist für eine Plattform ein Login hinterlegt, wird sie geprüft statt nur
    # als manueller Link ausgegeben.
    site_auth: Dict[str, dict] = field(default_factory=dict)

    def load_api_keys(self, config_path: str = "config.json"):
        """Lädt API-Keys & Site-Logins aus config.json / config.local.json
        oder Umgebungsvariablen.

        Reihenfolge (spätere überschreiben frühere):
        1. config.json (im Programmordner)
        2. config.local.json (gitignored, für echte Keys/Logins)
        3. Umgebungsvariablen
        """
        here = pathlib.Path(__file__).resolve().parent.parent

        for candidate in (config_path, str(here / "config.json"),
                          "config.local.json", str(here / "config.local.json")):
            try:
                if os.path.exists(candidate):
                    with open(candidate, "r", encoding="utf-8") as f:
                        data = json.load(f)
                        self.api_keys.update(
                            {k: v for k, v in data.get("api_keys", {}).items() if v}
                        )
                        for site, auth in (data.get("site_auth") or {}).items():
                            if auth:
                                self.site_auth[site] = auth
            except (json.JSONDecodeError, OSError):
                continue

        # Umgebungsvariablen überschreiben Datei-Werte
        env_mappings = {
            "HIBP_API_KEY": "hibp",
            "HUNTER_API_KEY": "hunter",
            "SHODAN_API_KEY": "shodan",
            "NUMVERIFY_API_KEY": "numverify",
            "EMAILREP_API_KEY": "emailrep",
            "DEHASHED_EMAIL": "dehashed_email",
            "DEHASHED_API_KEY": "dehashed",
            "INTELX_API_KEY": "intelx",
            "LEAKCHECK_API_KEY": "leakcheck",
            "GITHUB_TOKEN": "github",
        }
        for env_var, key_name in env_mappings.items():
            val = os.environ.get(env_var)
            if val:
                self.api_keys[key_name] = val

    def get_api_key(self, service: str) -> Optional[str]:
        return self.api_keys.get(service) or None

    def has_key(self, service: str) -> bool:
        return bool(self.api_keys.get(service))

    def get_site_auth(self, name: str) -> Optional[dict]:
        """Hinterlegtes Login für eine Plattform (Name case-insensitive)."""
        if not self.site_auth:
            return None
        if name in self.site_auth:
            return self.site_auth[name]
        low = name.lower()
        for k, v in self.site_auth.items():
            if k.lower() == low:
                return v
        return None


# ──────────────────────────────────────────────
# Username-Modul: Plattformen (Sherlock-Detektionsmodell)
# Geladen aus data/username_platforms.json — Liste von Spec-Dicts mit
# präzisem Nicht-gefunden-Signal pro Plattform.
# ──────────────────────────────────────────────
USERNAME_PLATFORMS: List[dict] = load_data("username_platforms.json", "platforms", [])


# ──────────────────────────────────────────────
# E-Mail-Modul: Provider-Erkennung
# ──────────────────────────────────────────────
EMAIL_PROVIDERS = {
    "gmail.com": "Google Mail",
    "googlemail.com": "Google Mail",
    "yahoo.com": "Yahoo Mail",
    "yahoo.de": "Yahoo Mail (DE)",
    "ymail.com": "Yahoo Mail",
    "outlook.com": "Microsoft Outlook",
    "outlook.de": "Microsoft Outlook (DE)",
    "hotmail.com": "Microsoft Hotmail",
    "hotmail.de": "Microsoft Hotmail (DE)",
    "live.com": "Microsoft Live",
    "live.de": "Microsoft Live (DE)",
    "msn.com": "Microsoft MSN",
    "protonmail.com": "ProtonMail (verschlüsselt)",
    "proton.me": "ProtonMail (verschlüsselt)",
    "pm.me": "ProtonMail (verschlüsselt)",
    "tutanota.com": "Tutanota (verschlüsselt)",
    "tuta.io": "Tutanota (verschlüsselt)",
    "icloud.com": "Apple iCloud",
    "me.com": "Apple iCloud",
    "mac.com": "Apple iCloud",
    "aol.com": "AOL Mail",
    "gmx.de": "GMX (DE)",
    "gmx.at": "GMX (AT)",
    "gmx.net": "GMX",
    "gmx.com": "GMX",
    "web.de": "Web.de",
    "t-online.de": "T-Online",
    "freenet.de": "Freenet",
    "mail.ru": "Mail.ru (RU)",
    "yandex.ru": "Yandex (RU)",
    "yandex.com": "Yandex",
    "zoho.com": "Zoho Mail",
    "fastmail.com": "Fastmail",
    "hey.com": "HEY",
}

# Mapping: Substring im MX-Host -> erkannter Mail-Provider/Infrastruktur.
# Erlaubt Provider-Erkennung auch bei eigenen Domains.
MX_PROVIDER_PATTERNS = {
    "aspmx.l.google.com": "Google Workspace",
    "googlemail.com": "Google Workspace",
    "google.com": "Google Workspace",
    "protection.outlook.com": "Microsoft 365 (Exchange Online)",
    "outlook.com": "Microsoft 365",
    "pphosted.com": "Proofpoint",
    "mimecast.com": "Mimecast",
    "protonmail.ch": "Proton Mail",
    "proton.me": "Proton Mail",
    "zoho.eu": "Zoho Mail (EU)",
    "zoho.com": "Zoho Mail",
    "messagingengine.com": "Fastmail",
    "secureserver.net": "GoDaddy",
    "ionos.de": "IONOS / 1&1",
    "kundenserver.de": "IONOS / 1&1",
    "emig.gmx.net": "GMX",
    "gmx.net": "GMX / United Internet",
    "mail.ru": "Mail.ru",
    "yandex.net": "Yandex",
    "amazonaws.com": "Amazon SES / WorkMail",
    "mailgun.org": "Mailgun",
    "sendgrid.net": "SendGrid",
    "ovh.net": "OVH",
    "one.com": "One.com",
    "registrar-servers.com": "Namecheap Private Email",
    "improvmx.com": "ImprovMX (Forwarding)",
}

# Rollen-/Funktions-Konten (kein Personenbezug)
ROLE_LOCAL_PARTS = {
    "admin", "administrator", "info", "support", "contact", "kontakt",
    "sales", "office", "hello", "hi", "team", "help", "service",
    "noreply", "no-reply", "donotreply", "webmaster", "postmaster",
    "abuse", "security", "billing", "marketing", "newsletter", "press",
    "jobs", "career", "careers", "hr", "mail", "email", "all", "root",
}

# Gravatar
GRAVATAR_AVATAR_URL = "https://www.gravatar.com/avatar/{}?d=404"
GRAVATAR_PROFILE_URL = "https://en.gravatar.com/{}.json"
GRAVATAR_API_V3 = "https://api.gravatar.com/v3/profiles/{}"
# Rückwärtskompatible Aliase
GRAVATAR_URL = GRAVATAR_AVATAR_URL


# ──────────────────────────────────────────────
# E-Mail-Account-Checks (Holehe-Stil) & Breach-Quellen & Dorks
# Geladen aus data/email_sources.json (sofern vorhanden).
# ──────────────────────────────────────────────
_EMAIL_SOURCES = load_data("email_sources.json", default={})
EMAIL_ACCOUNT_SITES: List[dict] = _EMAIL_SOURCES.get("account_sites", [])
EMAIL_BREACH_SOURCES: List[dict] = _EMAIL_SOURCES.get("breach_sources", [])
EMAIL_DORKS: List[dict] = _EMAIL_SOURCES.get("dorks", [])

# Wegwerf-/Temporär-Mail-Domains (Teilmenge gängiger Anbieter)
DISPOSABLE_DOMAINS: set = set(load_data("disposable_domains.json", "domains", []))


# ──────────────────────────────────────────────
# Domain-Modul: DNS-Record-Typen
# ──────────────────────────────────────────────
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "SRV"]


# ──────────────────────────────────────────────
# Exportformate & Farben
# ──────────────────────────────────────────────
SEVERITY_COLORS = {
    "info": "#3498db",
    "found": "#2ecc71",
    "warning": "#f39c12",
    "critical": "#e74c3c",
    "not_found": "#95a5a6",
}
