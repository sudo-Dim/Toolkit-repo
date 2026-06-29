"""
OSINT Tool - HTTP-Hilfsfunktionen
Gemeinsame requests.Session mit Connection-Pooling, Retries und
sinnvollen Default-Headern für alle Module.
"""

import requests
from requests.adapters import HTTPAdapter

try:
    from urllib3.util.retry import Retry
    _HAS_RETRY = True
except Exception:  # pragma: no cover
    _HAS_RETRY = False

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


def build_session(pool_size: int = 32, user_agent: str = DEFAULT_UA) -> requests.Session:
    """Erstellt eine Session mit großem Connection-Pool und Retries.

    Die Session ist für nebenläufige Nutzung aus mehreren Threads geeignet.
    """
    session = requests.Session()
    session.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })

    if _HAS_RETRY:
        retry = Retry(
            total=2,
            connect=2,
            read=1,
            backoff_factor=0.4,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=pool_size,
            pool_maxsize=pool_size,
        )
    else:  # pragma: no cover
        adapter = HTTPAdapter(pool_connections=pool_size, pool_maxsize=pool_size)

    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session


# Modulweite Standard-Session für einfache Nutzung
_default_session: requests.Session = None


def get_session() -> requests.Session:
    global _default_session
    if _default_session is None:
        _default_session = build_session()
    return _default_session
