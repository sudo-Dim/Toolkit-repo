"""
OSINT Tool - Domain/IP-Modul
Analysiert Domains und IP-Adressen: DNS-Records, WHOIS, HTTP-Header,
Technologie-Erkennung, Subdomain-Enumeration.
"""

import re
import time
import socket
import requests
from typing import List
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor, as_completed

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.config import DNS_RECORD_TYPES


class DomainModule(BaseModule):

    @property
    def name(self) -> str:
        return "domain"

    @property
    def description(self) -> str:
        return "Analysiert Domains/IPs (DNS, WHOIS, Header, Technologien)"

    @property
    def input_types(self) -> List[str]:
        return ["domain", "ip"]

    def _is_ip(self, value: str) -> bool:
        """Prüft ob der Wert eine IP-Adresse ist."""
        try:
            socket.inet_aton(value)
            return True
        except socket.error:
            pass
        try:
            socket.inet_pton(socket.AF_INET6, value)
            return True
        except socket.error:
            return False

    def _clean_domain(self, domain: str) -> str:
        """Entfernt Protokoll und Pfad."""
        domain = re.sub(r'^https?://', '', domain)
        domain = domain.split('/')[0]
        domain = domain.split('?')[0]
        return domain.lower().strip()

    def _resolve_dns(self, domain: str) -> dict:
        """Löst DNS-Records auf."""
        results = {}

        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5

            for rtype in DNS_RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain, rtype)
                    records = []
                    for rdata in answers:
                        records.append(str(rdata))
                    if records:
                        results[rtype] = records
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN,
                        dns.resolver.NoNameservers):
                    pass
                except Exception:
                    pass

        except ImportError:
            # Fallback ohne dnspython (mit Timeout, damit es bei kaputtem DNS nicht haengt)
            old_timeout = socket.getdefaulttimeout()
            socket.setdefaulttimeout(5)
            try:
                ips = socket.getaddrinfo(domain, None)
                seen = set()
                a_records = []
                aaaa_records = []
                for info in ips:
                    ip = info[4][0]
                    family = info[0]
                    if ip not in seen:
                        seen.add(ip)
                        if family == socket.AF_INET:
                            a_records.append(ip)
                        elif family == socket.AF_INET6:
                            aaaa_records.append(ip)
                if a_records:
                    results["A"] = a_records
                if aaaa_records:
                    results["AAAA"] = aaaa_records
                results["_note"] = "Nur A/AAAA verfügbar (dnspython nicht installiert)"
            except socket.gaierror:
                results["_error"] = "Domain konnte nicht aufgelöst werden"
            finally:
                socket.setdefaulttimeout(old_timeout)

        return results

    def _reverse_dns(self, ip: str) -> dict:
        """Reverse-DNS-Lookup für eine IP."""
        try:
            hostname = socket.gethostbyaddr(ip)
            return {
                "hostname": hostname[0],
                "aliases": hostname[1],
            }
        except (socket.herror, socket.gaierror):
            return {"hostname": None}

    def _get_whois_info(self, domain: str) -> dict:
        """Ruft WHOIS-Daten ab (über öffentliche API)."""
        try:
            r = requests.get(
                f"https://whois.arin.net/rest/net?q={quote(domain)}&format=json"
                if self._is_ip(domain)
                else f"https://rdap.org/domain/{quote(domain)}",
                headers={"Accept": "application/json"},
                timeout=self.config.request_timeout if self.config else 10,
            )
            if r.status_code == 200:
                data = r.json()

                if self._is_ip(domain):
                    return {"raw": data, "source": "ARIN RDAP"}

                # Domain RDAP
                result = {
                    "source": "RDAP",
                    "status": data.get("status", []),
                    "events": [],
                    "nameservers": [],
                    "entities": [],
                }

                for event in data.get("events", []):
                    result["events"].append({
                        "action": event.get("eventAction", ""),
                        "date": event.get("eventDate", ""),
                    })

                for ns in data.get("nameservers", []):
                    result["nameservers"].append(
                        ns.get("ldhName", ns.get("objectClassName", ""))
                    )

                for entity in data.get("entities", []):
                    roles = entity.get("roles", [])
                    vcard = entity.get("vcardArray", [])
                    result["entities"].append({
                        "roles": roles,
                        "handle": entity.get("handle", ""),
                    })

                return result
        except Exception as e:
            self.add_error(f"WHOIS/RDAP: {str(e)}")

        return {"source": "none", "error": "WHOIS-Daten nicht verfügbar"}

    def _check_http_headers(self, domain: str) -> dict:
        """Analysiert HTTP-Response-Header."""
        result = {"checked": False}

        for scheme in ["https", "http"]:
            try:
                r = requests.head(
                    f"{scheme}://{domain}",
                    headers={"User-Agent": self.config.user_agent if self.config else ""},
                    timeout=self.config.request_timeout if self.config else 10,
                    allow_redirects=True,
                )
                headers = dict(r.headers)

                # Sicherheitsrelevante Header
                security_headers = {}
                for h in ["Strict-Transport-Security", "Content-Security-Policy",
                           "X-Frame-Options", "X-Content-Type-Options",
                           "X-XSS-Protection", "Referrer-Policy",
                           "Permissions-Policy"]:
                    if h.lower() in {k.lower(): k for k in headers}:
                        key = next(k for k in headers if k.lower() == h.lower())
                        security_headers[h] = headers[key]

                # Technologie-Hinweise
                tech_hints = {}
                server = headers.get("Server", headers.get("server", ""))
                powered = headers.get("X-Powered-By", headers.get("x-powered-by", ""))
                if server:
                    tech_hints["server"] = server
                if powered:
                    tech_hints["powered_by"] = powered

                result = {
                    "checked": True,
                    "scheme": scheme,
                    "status_code": r.status_code,
                    "final_url": str(r.url),
                    "security_headers": security_headers,
                    "missing_security_headers": [
                        h for h in ["Strict-Transport-Security",
                                    "Content-Security-Policy",
                                    "X-Frame-Options",
                                    "X-Content-Type-Options"]
                        if h not in security_headers
                    ],
                    "tech_hints": tech_hints,
                    "all_headers": {k: v for k, v in headers.items()},
                }
                break

            except Exception:
                continue

        return result

    def _check_ssl(self, domain: str) -> dict:
        """Prüft SSL-Zertifikat-Informationen."""
        import ssl
        import datetime

        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()

            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))

            # Ablaufdatum
            not_after = cert.get("notAfter", "")
            not_before = cert.get("notBefore", "")

            # SANs (Subject Alternative Names)
            sans = []
            for type_val, name in cert.get("subjectAltName", []):
                sans.append(name)

            return {
                "valid": True,
                "subject": subject,
                "issuer": issuer,
                "not_before": not_before,
                "not_after": not_after,
                "serial_number": cert.get("serialNumber", ""),
                "version": cert.get("version", ""),
                "sans": sans,
            }
        except Exception as e:
            return {"valid": False, "error": str(e)}

    def _enumerate_subdomains(self, domain: str) -> dict:
        """
        Einfache Subdomain-Enumeration über crt.sh (Certificate Transparency).
        """
        subdomains = set()

        try:
            r = requests.get(
                f"https://crt.sh/?q=%.{quote(domain)}&output=json",
                timeout=self.config.request_timeout if self.config else 10,
            )
            if r.status_code == 200:
                data = r.json()
                for entry in data:
                    name = entry.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lower()
                        if sub.endswith(domain) and sub != domain:
                            # Entferne Wildcards
                            sub = sub.lstrip("*.")
                            if sub and sub != domain:
                                subdomains.add(sub)
        except Exception as e:
            self.add_error(f"Subdomain-Enumeration: {str(e)}")

        return {
            "source": "crt.sh (Certificate Transparency)",
            "count": len(subdomains),
            "subdomains": sorted(subdomains)[:100],  # Max 100
        }

    def _check_robots_txt(self, domain: str) -> dict:
        """Liest robots.txt der Domain."""
        try:
            r = requests.get(
                f"https://{domain}/robots.txt",
                headers={"User-Agent": self.config.user_agent if self.config else ""},
                timeout=self.config.request_timeout if self.config else 10,
            )
            if r.status_code == 200 and "user-agent" in r.text.lower():
                # Parse interessante Pfade
                disallowed = []
                sitemaps = []
                for line in r.text.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path:
                            disallowed.append(path)
                    elif line.lower().startswith("sitemap:"):
                        sitemaps.append(line.split(":", 1)[1].strip())

                return {
                    "found": True,
                    "disallowed_paths": disallowed[:50],
                    "sitemaps": sitemaps,
                    "total_rules": len(disallowed),
                }
        except Exception:
            pass

        return {"found": False}

    def run(self, input_value: str, input_type: str = "domain") -> ModuleReport:
        start = time.time()

        is_ip = self._is_ip(input_value)
        target = input_value if is_ip else self._clean_domain(input_value)

        steps = 7 if not is_ip else 4
        step = 0

        self.report_progress(step, steps, f"Analysiere {'IP' if is_ip else 'Domain'}...")

        # 1. DNS / Reverse DNS
        step += 1
        self.report_progress(step, steps, "DNS-Auflösung...")

        if is_ip:
            rdns = self._reverse_dns(target)
            self.add_result(OSINTResult(
                source="Reverse DNS",
                module=self.name,
                category="DNS",
                severity=ResultSeverity.FOUND if rdns["hostname"] else ResultSeverity.INFO,
                title=f"Reverse DNS: {rdns.get('hostname', 'Nicht verfügbar')}",
                data=rdns,
            ))
        else:
            dns_data = self._resolve_dns(target)
            record_count = sum(len(v) for k, v in dns_data.items() if not k.startswith("_"))
            self.add_result(OSINTResult(
                source="DNS-Records",
                module=self.name,
                category="DNS",
                severity=ResultSeverity.FOUND if record_count > 0 else ResultSeverity.WARNING,
                title=f"{record_count} DNS-Records gefunden",
                data=dns_data,
            ))

        # 2. WHOIS / RDAP
        step += 1
        self.report_progress(step, steps, "WHOIS-Abfrage...")
        whois = self._get_whois_info(target)
        self.add_result(OSINTResult(
            source="WHOIS/RDAP",
            module=self.name,
            category="Registration",
            severity=ResultSeverity.FOUND if whois.get("source") != "none" else ResultSeverity.INFO,
            title="WHOIS-Daten abgerufen",
            data=whois,
        ))

        if not is_ip:
            # 3. HTTP-Header
            step += 1
            self.report_progress(step, steps, "HTTP-Header-Analyse...")
            headers = self._check_http_headers(target)

            if headers.get("checked"):
                missing = headers.get("missing_security_headers", [])
                severity = (
                    ResultSeverity.WARNING if len(missing) > 2
                    else ResultSeverity.FOUND
                )
                self.add_result(OSINTResult(
                    source="HTTP-Header",
                    module=self.name,
                    category="Security",
                    severity=severity,
                    title=f"Server: {headers.get('tech_hints', {}).get('server', 'Unbekannt')}",
                    data=headers,
                    url=headers.get("final_url"),
                ))

            # 4. SSL-Zertifikat
            step += 1
            self.report_progress(step, steps, "SSL-Zertifikat...")
            ssl_info = self._check_ssl(target)
            self.add_result(OSINTResult(
                source="SSL-Zertifikat",
                module=self.name,
                category="Security",
                severity=ResultSeverity.FOUND if ssl_info.get("valid") else ResultSeverity.WARNING,
                title=f"SSL {'gültig' if ssl_info.get('valid') else 'ungültig/nicht vorhanden'}",
                data=ssl_info,
            ))

            # 5. Subdomain-Enumeration
            step += 1
            self.report_progress(step, steps, "Subdomain-Suche (crt.sh)...")
            subdomains = self._enumerate_subdomains(target)
            self.add_result(OSINTResult(
                source="Subdomain-Enumeration",
                module=self.name,
                category="Discovery",
                severity=ResultSeverity.FOUND if subdomains["count"] > 0 else ResultSeverity.INFO,
                title=f"{subdomains['count']} Subdomains gefunden",
                data=subdomains,
            ))

            # 6. robots.txt
            step += 1
            self.report_progress(step, steps, "robots.txt...")
            robots = self._check_robots_txt(target)
            if robots["found"]:
                self.add_result(OSINTResult(
                    source="robots.txt",
                    module=self.name,
                    category="Discovery",
                    severity=ResultSeverity.FOUND,
                    title=f"robots.txt: {robots['total_rules']} Regeln",
                    data=robots,
                    url=f"https://{target}/robots.txt",
                ))

        # IP-spezifisch: Shodan (falls API-Key vorhanden)
        if is_ip:
            step += 1
            self.report_progress(step, steps, "Shodan-Abfrage...")
            shodan_data = self._check_shodan(target)
            if shodan_data.get("checked"):
                self.add_result(OSINTResult(
                    source="Shodan",
                    module=self.name,
                    category="Infrastructure",
                    severity=ResultSeverity.FOUND,
                    title=f"Shodan: {shodan_data.get('ports_count', 0)} offene Ports",
                    data=shodan_data,
                    url=f"https://www.shodan.io/host/{target}",
                ))

        self.report_progress(steps, steps, "Domain/IP-Analyse abgeschlossen")
        end = time.time()
        return self.create_report(target, input_type, start, end)

    def _check_shodan(self, ip: str) -> dict:
        """Shodan-Lookup (benötigt API-Key)."""
        api_key = self.config.get_api_key("shodan") if self.config else None

        if not api_key:
            return {
                "checked": False,
                "note": "Shodan API-Key nicht konfiguriert.",
            }

        try:
            r = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}?key={api_key}",
                timeout=self.config.request_timeout if self.config else 10,
            )
            if r.status_code == 200:
                data = r.json()
                return {
                    "checked": True,
                    "ip": data.get("ip_str", ip),
                    "org": data.get("org", ""),
                    "os": data.get("os", ""),
                    "ports": data.get("ports", []),
                    "ports_count": len(data.get("ports", [])),
                    "hostnames": data.get("hostnames", []),
                    "vulns": data.get("vulns", []),
                    "isp": data.get("isp", ""),
                    "country": data.get("country_name", ""),
                    "city": data.get("city", ""),
                }
        except Exception as e:
            self.add_error(f"Shodan: {str(e)}")

        return {"checked": False}
