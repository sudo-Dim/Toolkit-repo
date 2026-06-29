"""
OSINT Tool - Konfiguration
Zentrale Konfigurationsdatei für alle Module und Einstellungen.
"""

import os
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class AppConfig:
    """Hauptkonfiguration der Anwendung."""
    app_name: str = "OSINT Recon Tool"
    version: str = "1.0.0"
    user_agent: str = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/120.0.0.0 Safari/537.36"
    )
    request_timeout: int = 10
    max_concurrent_requests: int = 10
    delay_between_requests: float = 0.5
    output_dir: str = "results"
    export_formats: List[str] = field(default_factory=lambda: ["json", "txt", "html"])

    # Optionale API-Keys (werden aus Umgebungsvariablen oder config.json geladen)
    api_keys: Dict[str, str] = field(default_factory=dict)

    def load_api_keys(self, config_path: str = "config.json"):
        """Lädt API-Keys aus config.json oder Umgebungsvariablen."""
        # Zuerst aus Datei
        if os.path.exists(config_path):
            with open(config_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.api_keys.update(data.get("api_keys", {}))

        # Umgebungsvariablen überschreiben Datei-Werte
        env_mappings = {
            "HIBP_API_KEY": "hibp",
            "HUNTER_API_KEY": "hunter",
            "SHODAN_API_KEY": "shodan",
            "NUMVERIFY_API_KEY": "numverify",
        }
        for env_var, key_name in env_mappings.items():
            val = os.environ.get(env_var)
            if val:
                self.api_keys[key_name] = val

    def get_api_key(self, service: str) -> Optional[str]:
        return self.api_keys.get(service)


# ──────────────────────────────────────────────
# Username-Modul: Plattformen zum Prüfen
# ──────────────────────────────────────────────
USERNAME_PLATFORMS = {
    "GitHub": {
        "url": "https://github.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Development",
    },
    "GitLab": {
        "url": "https://gitlab.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Development",
    },
    "Twitter/X": {
        "url": "https://x.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Social Media",
    },
    "Instagram": {
        "url": "https://www.instagram.com/{}/",
        "check_method": "status_code",
        "expected": 200,
        "category": "Social Media",
    },
    "Reddit": {
        "url": "https://www.reddit.com/user/{}/",
        "check_method": "status_code",
        "expected": 200,
        "category": "Social Media",
    },
    "Pinterest": {
        "url": "https://www.pinterest.com/{}/",
        "check_method": "status_code",
        "expected": 200,
        "category": "Social Media",
    },
    "TikTok": {
        "url": "https://www.tiktok.com/@{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Social Media",
    },
    "YouTube": {
        "url": "https://www.youtube.com/@{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Video",
    },
    "Twitch": {
        "url": "https://www.twitch.tv/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Video",
    },
    "Steam": {
        "url": "https://steamcommunity.com/id/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Gaming",
    },
    "LinkedIn": {
        "url": "https://www.linkedin.com/in/{}/",
        "check_method": "status_code",
        "expected": 200,
        "category": "Professional",
    },
    "Medium": {
        "url": "https://medium.com/@{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Blog",
    },
    "Keybase": {
        "url": "https://keybase.io/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Security",
    },
    "HackerOne": {
        "url": "https://hackerone.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Security",
    },
    "Gravatar": {
        "url": "https://en.gravatar.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Other",
    },
    "About.me": {
        "url": "https://about.me/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Other",
    },
    "Flickr": {
        "url": "https://www.flickr.com/people/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Photo",
    },
    "SoundCloud": {
        "url": "https://soundcloud.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Music",
    },
    "Spotify": {
        "url": "https://open.spotify.com/user/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Music",
    },
    "StackOverflow": {
        "url": "https://stackoverflow.com/users/?tab=accounts&SearchTerm={}",
        "check_method": "content",
        "content_match": "users/",
        "category": "Development",
    },
    "NPM": {
        "url": "https://www.npmjs.com/~{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Development",
    },
    "PyPI": {
        "url": "https://pypi.org/user/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Development",
    },
    "Docker Hub": {
        "url": "https://hub.docker.com/u/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Development",
    },
    "Telegram": {
        "url": "https://t.me/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Messaging",
    },
    "VK": {
        "url": "https://vk.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Social Media",
    },
    "DeviantArt": {
        "url": "https://www.deviantart.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Art",
    },
    "Tumblr": {
        "url": "https://{}.tumblr.com",
        "check_method": "status_code",
        "expected": 200,
        "category": "Blog",
    },
    "Patreon": {
        "url": "https://www.patreon.com/{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Other",
    },
    "Replit": {
        "url": "https://replit.com/@{}",
        "check_method": "status_code",
        "expected": 200,
        "category": "Development",
    },
}


# ──────────────────────────────────────────────
# E-Mail-Modul: Dienste und Prüfungen
# ──────────────────────────────────────────────
EMAIL_PROVIDERS = {
    "gmail.com": "Google Mail",
    "googlemail.com": "Google Mail",
    "yahoo.com": "Yahoo Mail",
    "outlook.com": "Microsoft Outlook",
    "hotmail.com": "Microsoft Hotmail",
    "live.com": "Microsoft Live",
    "protonmail.com": "ProtonMail (verschlüsselt)",
    "proton.me": "ProtonMail (verschlüsselt)",
    "tutanota.com": "Tutanota (verschlüsselt)",
    "icloud.com": "Apple iCloud",
    "me.com": "Apple iCloud",
    "aol.com": "AOL Mail",
    "gmx.de": "GMX (DE)",
    "gmx.at": "GMX (AT)",
    "web.de": "Web.de",
    "t-online.de": "T-Online",
    "freenet.de": "Freenet",
    "mail.ru": "Mail.ru (RU)",
    "yandex.ru": "Yandex (RU)",
    "zoho.com": "Zoho Mail",
}

# Gravatar-Hash-URL
GRAVATAR_URL = "https://www.gravatar.com/avatar/{}?d=404"
GRAVATAR_PROFILE_URL = "https://en.gravatar.com/{}.json"


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
