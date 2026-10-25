"""
OSINT Tool - HTTP-Hilfsfunktionen
Gemeinsame requests.Session mit Connection-Pooling, Retries und
sinnvollen Default-Headern für alle Module.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from urllib.parse import urlsplit

if TYPE_CHECKING:
    import requests

DEFAULT_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/122.0.0.0 Safari/537.36"
)


def build_session(pool_size: int = 32, user_agent: str = DEFAULT_UA,
                  retries: int = 2, *, allow_private: bool = False) -> requests.Session:
    """Erstellt eine Session mit großem Connection-Pool und optionalen Retries.

    Die Session ist für nebenläufige Nutzung aus mehreren Threads geeignet.

    Args:
        retries: Anzahl Wiederholungen bei Verbindungsfehlern. 0 = keine Retries
                 (z.B. für schnelle, fehlertolerante Account-Checks, die nicht
                 lange an einer hängenden Seite warten sollen).
    """
    # GUI und reine Offline-Analysen benötigen den HTTP-Stack noch nicht.
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    from urllib3.connection import HTTPConnection, HTTPSConnection
    from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
    from .network import public_addresses

    class PublicConnection:
        def _new_conn(self):
            original = self._dns_host
            error = None
            # A numeric connection target prevents a second DNS lookup from rebinding locally.
            for address in public_addresses(original, self.port):
                try:
                    self._dns_host = address
                    return super()._new_conn()
                except OSError as exc:
                    error = exc
                finally:
                    self._dns_host = original
            raise error

    class PublicHTTPConnection(PublicConnection, HTTPConnection):
        pass

    class PublicHTTPSConnection(PublicConnection, HTTPSConnection):
        pass

    class PublicHTTPPool(HTTPConnectionPool):
        ConnectionCls = PublicHTTPConnection

    class PublicHTTPSPool(HTTPSConnectionPool):
        ConnectionCls = PublicHTTPSConnection

    class ResearchAdapter(HTTPAdapter):
        def init_poolmanager(self, *args, **kwargs):
            super().init_poolmanager(*args, **kwargs)
            if not allow_private:
                self.poolmanager.pool_classes_by_scheme = {'http': PublicHTTPPool, 'https': PublicHTTPSPool}

        def send(self, request, **kwargs):
            if not allow_private and kwargs.get('proxies'):
                target = urlsplit(request.url)
                # Configured proxies are trusted gateways; still reject locally-resolved private targets.
                public_addresses(target.hostname, target.port or (443 if target.scheme == 'https' else 80))
            return super().send(request, **kwargs)

    class ExplicitAuth(requests.auth.AuthBase):
        def __call__(self, request):
            return request

    class ResearchSession(requests.Session):
        def rebuild_auth(self, prepared_request, response):
            # Never pick up personal ~/.netrc credentials. Keep environment proxy/CA support.
            old = urlsplit(response.request.url)
            new = urlsplit(prepared_request.url)
            if (old.scheme, old.hostname, old.port) != (new.scheme, new.hostname, new.port):
                # API keys and custom platform login headers must not cross origins.
                for header in list(prepared_request.headers):
                    if header.lower() not in {
                        "user-agent", "accept", "accept-language", "accept-encoding",
                        "connection", "content-length", "content-type",
                    }:
                        del prepared_request.headers[header]
                if prepared_request.body:
                    raise requests.exceptions.InvalidURL("Cross-origin redirect with request body blocked")
            if old.scheme == "https" and new.scheme != "https":
                raise requests.exceptions.InvalidURL("HTTPS downgrade redirect blocked")

    session = ResearchSession()
    session.auth = ExplicitAuth()
    session.headers.update({
        "User-Agent": user_agent,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    })

    if retries > 0:
        retry = Retry(
            total=retries,
            connect=retries,
            read=1,
            backoff_factor=0.4,
            status_forcelist=(500, 502, 503, 504),
            allowed_methods=frozenset(["GET", "HEAD"]),
            raise_on_status=False,
        )
        adapter = ResearchAdapter(max_retries=retry, pool_connections=pool_size,
                              pool_maxsize=pool_size)
    else:
        adapter = ResearchAdapter(max_retries=0, pool_connections=pool_size,
                              pool_maxsize=pool_size)

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
