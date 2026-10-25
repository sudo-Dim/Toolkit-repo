"""Small, dependency-free response checks. HTTP success is never profile evidence."""

import json
import re
from html.parser import HTMLParser
from urllib.parse import quote, unquote, urljoin, urlsplit


class PageMetadata(HTMLParser):
    def __init__(self, text):
        super().__init__(convert_charrefs=True)
        self.urls = []
        self.title = ''
        self._title = False
        self.challenge = False
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == 'title':
            self._title = True
        if tag == 'link' and 'canonical' in (attrs.get('rel') or '').lower().split():
            self.urls.append(attrs.get('href') or '')
        if tag == 'meta' and (attrs.get('property') or '').lower() == 'og:url':
            self.urls.append(attrs.get('content') or '')
        if tag in ('form', 'script', 'iframe'):
            values = ' '.join(str(attrs.get(key) or '') for key in ('id', 'action', 'src'))
            if any(marker in values.lower() for marker in ('challenge-platform', 'captcha', 'cf-chl', 'challenge-form')):
                self.challenge = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self._title = False

    def handle_data(self, text):
        if self._title:
            self.title += text


def url_key(url):
    parsed = urlsplit(url)
    return ((parsed.hostname or '').lower().removeprefix('www.'),
            parsed.port or (443 if parsed.scheme == 'https' else 80),
            unquote(parsed.path).rstrip('/'), parsed.query)


def response_problem(status, text, final_url, expected_url=None):
    if status in (401, 403, 407, 408, 425, 429, 451) or status >= 500:
        return f'Quelle nicht auswertbar (HTTP {status})'
    path = urlsplit(final_url).path.lower()
    if re.search(r'/(?:login|log-in|signin|sign-in|auth|captcha|challenge|consent)(?:/|$)', path):
        return 'Login-, Consent- oder Sicherheitsprüfung statt Profil'
    if '<' in text[:1000]:
        page = PageMetadata(text)
        title = page.title.strip().casefold()
        if page.challenge or re.search(r'just a moment|access denied|attention required|verify (?:you|your)|checking your browser|sign in|log in|service unavailable', title):
            return 'Sperr-, Login- oder Fehlerseite statt auswertbarer Antwort'
    if expected_url and url_key(final_url) != url_key(expected_url):
        return 'Weiterleitung auf eine andere Seite; Profilzuordnung nicht belegt'
    return None


def values_at(value, path):
    """Walk a bounded JSON path; '*' expands a list, never executes expressions."""
    values = [value]
    for key in path.split('.') if path else []:
        next_values = []
        for current in values:
            if key == '*' and isinstance(current, list):
                next_values.extend(current)
            elif isinstance(current, dict) and key in current:
                next_values.append(current[key])
        values = next_values
    return values


def profile_evidence(platform, status, text, final_url, username):
    """Return verdict, reason. HTML 'candidate' requires a separate negative control."""
    encoded = quote(username, safe='')
    probe = platform.get('url_probe', platform['url']).replace('{}', encoded)
    problem = response_problem(status, text, final_url)
    if problem:
        return 'uncertain', problem
    if status in (404, 410):
        return 'not_found', f'Quelle meldet HTTP {status}; kein öffentliches Profil'
    if status != 200:
        return 'uncertain', f'Keine verwertbare Antwort (HTTP {status})'
    problem = response_problem(status, text, final_url, probe)
    if problem:
        return 'uncertain', problem
    spec = platform.get('evidence') or {}
    if spec.get('kind') == 'json':
        try:
            payload = json.loads(text)
        except (ValueError, TypeError):
            return 'uncertain', 'Erwartete Profil-API liefert kein gültiges JSON'
        if isinstance(payload, dict) and (payload.get('error') or payload.get('errors')):
            return 'uncertain', 'API meldet einen Fehler statt eines gültigen Profils'
        if ('absent_value' in spec and type(payload) is type(spec['absent_value'])
                and payload == spec['absent_value']):
            return 'not_found', 'Profil-API meldet ausdrücklich keinen Datensatz'
        records = values_at(payload, spec.get('records', ''))
        expected = spec.get('expected', '{}').replace('{}', username)
        for record in records:
            names = values_at(record, spec['identity'])
            matches = any(isinstance(name, str) and
                          (name == expected if spec.get('case_sensitive') else name.casefold() == expected.casefold())
                          for name in names)
            required = all(any(isinstance(value, (str, int, float)) and value != '' and not isinstance(value, bool)
                               for value in values_at(record, path)) for path in spec.get('required', []))
            if matches and required:
                return 'found', f"Profil-API bestätigt den exakten Bezeichner ({spec['identity']})"
        return 'uncertain', 'Kein passender, vollständiger Profil-Datensatz in der API-Antwort'
    if spec.get('kind') != 'html':
        return 'uncertain', 'Keine verlässliche automatische Profilregel für diese Quelle'
    if any(message.casefold() in text.casefold() for message in platform.get('error_msg', []) if message):
        return 'not_found', 'Quelle liefert ihr bekanntes Nicht-gefunden-Signal'
    page = PageMetadata(text)
    if re.search(r'(?:page|user|profile|account) (?:not found|does not exist)|\b404\s*[-:–]?\s*(?:not found|page not found)|seite nicht gefunden|profil nicht gefunden', page.title, re.I):
        return 'not_found', 'Seite kennzeichnet das Profil ausdrücklich als fehlend'
    expected_url = platform['url'].replace('{}', encoded)
    route = unquote(urlsplit(expected_url).path).strip('/').casefold()
    if route in {'about', 'about-us', 'help', 'contact', 'pricing', 'signup', 'register', 'terms',
                 'privacy', 'settings', 'search', 'explore', 'discover', 'jobs', 'blog', 'news', 'api', 'feed'}:
        return 'uncertain', 'Reservierter Seitenpfad; kein eindeutiger Profilnachweis'
    if any(url_key(urljoin(final_url, value)) == url_key(expected_url) for value in page.urls if value):
        return 'candidate', 'Profil-URL in canonical/og:url; Gegenprobe ausstehend'
    return 'uncertain', 'Kein exakter Profilbezug in den Seiten-Metadaten'
