"""
OSINT Tool - Domain/IP-Modul (v2)
Umfassende Domain-/IP-Aufklärung, größtenteils keyfrei:

  • DNS (A/AAAA/MX/NS/TXT/SOA/CNAME/SRV/CAA) via dnspython, DoH-Fallback
  • E-Mail-Sicherheit: SPF, DMARC, DKIM-Selektor-Probe
  • RDAP/WHOIS (Domain & IP): Registrar, Anlage/Ablauf, Status, Nameserver
  • TLS-Zertifikat (Issuer, SAN, Gültigkeit)
  • HTTP-Header + Security-Header-Bewertung + Tech-Fingerprint
  • Subdomain-Enumeration via crt.sh (Certificate Transparency)
  • robots.txt / sitemap.xml / security.txt
  • IP-Geolocation + ASN/ISP (ipwho.is, ip-api) und offene Ports/CVEs
    via Shodan InternetDB (keyfrei!) + BGPView
  • Reverse DNS, Wayback-Machine-Verfügbarkeit
  • Optional mit Key: Shodan-Host-Details
"""

import re
import ssl
import time
import socket
from typing import List, Optional
from urllib.parse import quote
from concurrent.futures import ThreadPoolExecutor

from .base import BaseModule, ModuleReport, OSINTResult, ResultSeverity
from ..core.http import build_session, DEFAULT_UA
from ..core.config import DNS_RECORD_TYPES, DKIM_SELECTORS


class DomainModule(BaseModule):

    @property
    def name(self) -> str:
        return "domain"

    @property
    def description(self) -> str:
        return ("Domain/IP-Recon: DNS, SPF/DMARC/DKIM, RDAP, TLS, Header, "
                "Subdomains, Geo/ASN, offene Ports (InternetDB), Wayback")

    @property
    def input_types(self) -> List[str]:
        return ["domain", "ip"]

    @property
    def _timeout(self) -> int:
        return self.config.request_timeout if self.config else 12

    def _session(self):
        return build_session(user_agent=self.config.user_agent if self.config else DEFAULT_UA)

    # ── Helfer ─────────────────────────────────────────────────
    @staticmethod
    def _is_ip(value: str) -> bool:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                socket.inet_pton(fam, value)
                return True
            except (socket.error, OSError):
                continue
        return False

    @staticmethod
    def _clean_domain(domain: str) -> str:
        domain = re.sub(r"^https?://", "", domain.strip())
        return domain.split("/")[0].split("?")[0].lower().strip()

    # ── DNS (dnspython + DoH-Fallback) ─────────────────────────
    def _doh(self, name: str, rtype: str, session) -> List[str]:
        """DNS-over-HTTPS Fallback (Google + Cloudflare)."""
        for url, hdr in (("https://dns.google/resolve", {}),
                         ("https://cloudflare-dns.com/dns-query",
                          {"accept": "application/dns-json"})):
            try:
                r = session.get(url, params={"name": name, "type": rtype},
                                headers=hdr, timeout=self._timeout)
                if r.status_code == 200:
                    data = r.json()
                    return [a.get("data", "") for a in data.get("Answer", [])
                            if str(a.get("type"))]
            except Exception:
                continue
        return []

    def _resolve_dns(self, domain: str, session) -> dict:
        results = {}
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 5
            resolver.lifetime = 5
            for rtype in DNS_RECORD_TYPES:
                try:
                    answers = resolver.resolve(domain, rtype)
                    recs = [str(r) for r in answers]
                    if recs:
                        results[rtype] = recs
                except Exception:
                    pass
        except ImportError:
            results["_resolver"] = "DoH (dnspython nicht installiert)"
            for rtype in ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "CAA"]:
                recs = self._doh(domain, rtype, session)
                if recs:
                    results[rtype] = recs
        return results

    def _email_security(self, domain: str, session) -> dict:
        """SPF, DMARC, DKIM-Selektor-Probe."""
        out = {"spf": None, "dmarc": None, "dkim_selectors": []}

        def txt(name):
            try:
                import dns.resolver
                return [b"".join(r.strings).decode(errors="ignore") if hasattr(r, "strings")
                        else str(r).strip('"') for r in dns.resolver.resolve(name, "TXT")]
            except ImportError:
                return [t.strip('"') for t in self._doh(name, "TXT", session)]
            except Exception:
                return []

        for t in txt(domain):
            if t.lower().startswith("v=spf1"):
                out["spf"] = t
                break
        for t in txt(f"_dmarc.{domain}"):
            if t.lower().startswith("v=dmarc1"):
                out["dmarc"] = t
                break

        # DKIM-Selektor-Probe parallel (sonst zu langsam)
        def _probe(sel):
            recs = txt(f"{sel}._domainkey.{domain}")
            return sel if any("dkim1" in r.lower() or "p=" in r.lower() for r in recs) else None

        workers = self.config.max_concurrent_requests if self.config else 12
        with ThreadPoolExecutor(max_workers=min(workers, len(DKIM_SELECTORS))) as ex:
            out["dkim_selectors"] = sorted(s for s in ex.map(_probe, DKIM_SELECTORS) if s)
        return out

    # ── Reverse DNS ───────────────────────────────────────────
    @staticmethod
    def _reverse_dns(ip: str) -> dict:
        try:
            host = socket.gethostbyaddr(ip)
            return {"hostname": host[0], "aliases": host[1]}
        except (socket.herror, socket.gaierror, OSError):
            return {"hostname": None}

    def _resolve_ip(self, domain: str, session) -> Optional[str]:
        try:
            return socket.gethostbyname(domain)
        except (socket.gaierror, OSError):
            recs = self._doh(domain, "A", session)
            return recs[0] if recs else None

    # ── IP-Intelligence (Geo/ASN/Ports) ──────────────────────
    def _ip_intel(self, ip: str, session) -> dict:
        out = {"ip": ip}
        # ipwho.is (HTTPS, key-frei)
        try:
            r = session.get(f"https://ipwho.is/{ip}", timeout=self._timeout)
            if r.status_code == 200:
                d = r.json()
                if d.get("success"):
                    conn = d.get("connection", {})
                    out.update({"country": d.get("country"), "region": d.get("region"),
                                "city": d.get("city"), "lat": d.get("latitude"),
                                "lon": d.get("longitude"), "isp": conn.get("isp"),
                                "org": conn.get("org"), "asn": conn.get("asn"),
                                "asn_org": conn.get("org")})
        except Exception as exc:
            self.add_error(f"ipwho.is: {exc}")
        # ip-api Fallback
        if "country" not in out:
            try:
                r = session.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=self._timeout)
                if r.status_code == 200:
                    d = r.json()
                    if d.get("status") == "success":
                        out.update({"country": d.get("country"), "region": d.get("regionName"),
                                    "city": d.get("city"), "lat": d.get("lat"), "lon": d.get("lon"),
                                    "isp": d.get("isp"), "org": d.get("org"), "asn": d.get("as")})
            except Exception:
                pass
        return out

    def _internetdb(self, ip: str, session) -> Optional[dict]:
        """Shodan InternetDB (keyfrei): offene Ports, CPEs, CVEs, Tags."""
        try:
            r = session.get(f"https://internetdb.shodan.io/{ip}", timeout=self._timeout)
            if r.status_code == 200:
                d = r.json()
                if d.get("ports") or d.get("vulns") or d.get("cpes"):
                    return {"ports": d.get("ports", []), "cpes": d.get("cpes", []),
                            "vulns": d.get("vulns", []), "hostnames": d.get("hostnames", []),
                            "tags": d.get("tags", [])}
        except Exception as exc:
            self.add_error(f"InternetDB: {exc}")
        return None

    # ── RDAP ──────────────────────────────────────────────────
    def _rdap(self, target: str, is_ip: bool, session) -> dict:
        url = f"https://rdap.org/ip/{quote(target)}" if is_ip else f"https://rdap.org/domain/{quote(target)}"
        try:
            r = session.get(url, headers={"Accept": "application/json"}, timeout=self._timeout)
            if r.status_code == 200:
                d = r.json()
                events = {e.get("eventAction"): e.get("eventDate") for e in d.get("events", [])}
                registrar = ""
                for ent in d.get("entities", []):
                    if "registrar" in ent.get("roles", []):
                        va = ent.get("vcardArray", [])
                        if len(va) > 1:
                            for f in va[1]:
                                if f[0] == "fn":
                                    registrar = f[3]
                return {"source": "RDAP", "handle": d.get("handle"),
                        "name": d.get("name") or d.get("ldhName"),
                        "status": d.get("status", []),
                        "registrar": registrar,
                        "registered": events.get("registration"),
                        "expires": events.get("expiration"),
                        "updated": events.get("last changed") or events.get("last update of RDAP database"),
                        "nameservers": [ns.get("ldhName") for ns in d.get("nameservers", [])]}
        except Exception as exc:
            self.add_error(f"RDAP: {exc}")
        return {"source": "none"}

    # ── TLS ───────────────────────────────────────────────────
    def _tls(self, domain: str) -> dict:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=8) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                    cert = ss.getpeercert()
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            sans = [n for _, n in cert.get("subjectAltName", [])]
            return {"valid": True, "subject_cn": subject.get("commonName"),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "not_before": cert.get("notBefore"), "not_after": cert.get("notAfter"),
                    "sans": sans[:50], "san_count": len(sans)}
        except Exception as exc:
            return {"valid": False, "error": str(exc)}

    # ── HTTP-Header ───────────────────────────────────────────
    _SEC_HEADERS = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options",
                    "X-Content-Type-Options", "Referrer-Policy", "Permissions-Policy"]

    def _http(self, domain: str, session) -> dict:
        for scheme in ("https", "http"):
            try:
                r = session.get(f"{scheme}://{domain}", timeout=self._timeout, allow_redirects=True)
                headers = {k: v for k, v in r.headers.items()}
                lower = {k.lower(): v for k, v in headers.items()}
                present = {h: lower[h.lower()] for h in self._SEC_HEADERS if h.lower() in lower}
                missing = [h for h in self._SEC_HEADERS if h.lower() not in lower]
                grade = max(0, len(self._SEC_HEADERS) - len(missing))
                return {"checked": True, "scheme": scheme, "status_code": r.status_code,
                        "final_url": str(r.url), "server": lower.get("server"),
                        "powered_by": lower.get("x-powered-by"),
                        "security_headers": present, "missing_security_headers": missing,
                        "security_score": f"{grade}/{len(self._SEC_HEADERS)}"}
            except Exception:
                continue
        return {"checked": False}

    # ── crt.sh Subdomains ─────────────────────────────────────
    def _subdomains(self, domain: str, session) -> dict:
        subs = set()
        try:
            r = session.get(f"https://crt.sh/?q=%25.{quote(domain)}&output=json", timeout=20)
            if r.status_code == 200:
                for e in r.json():
                    for nm in (e.get("name_value", "") or "").split("\n"):
                        nm = nm.strip().lower().lstrip("*.")
                        if nm.endswith(domain) and nm != domain:
                            subs.add(nm)
        except Exception as exc:
            self.add_error(f"crt.sh: {exc}")
        return {"source": "crt.sh (Certificate Transparency)", "count": len(subs),
                "subdomains": sorted(subs)[:150]}

    # ── robots / sitemap / security.txt ───────────────────────
    def _discovery(self, domain: str, session) -> dict:
        out = {}
        try:
            r = session.get(f"https://{domain}/robots.txt", timeout=self._timeout)
            if r.status_code == 200 and "user-agent" in r.text.lower():
                disallow, sitemaps = [], []
                for line in r.text.splitlines():
                    ls = line.strip().lower()
                    if ls.startswith("disallow:"):
                        p = line.split(":", 1)[1].strip()
                        if p:
                            disallow.append(p)
                    elif ls.startswith("sitemap:"):
                        sitemaps.append(line.split(":", 1)[1].strip())
                out["robots"] = {"disallowed": disallow[:60], "sitemaps": sitemaps}
        except Exception:
            pass
        try:
            for path in ("/.well-known/security.txt", "/security.txt"):
                r = session.get(f"https://{domain}{path}", timeout=self._timeout)
                if r.status_code == 200 and ("contact" in r.text.lower()):
                    out["security_txt"] = {"path": path, "content": r.text[:1000]}
                    break
        except Exception:
            pass
        return out

    # ── Wayback ───────────────────────────────────────────────
    def _wayback(self, target: str, session) -> Optional[dict]:
        try:
            r = session.get(f"https://archive.org/wayback/available?url={quote(target)}",
                            timeout=self._timeout)
            if r.status_code == 200:
                snap = (r.json().get("archived_snapshots") or {}).get("closest")
                if snap and snap.get("available"):
                    return {"available": True, "url": snap.get("url"), "timestamp": snap.get("timestamp")}
        except Exception:
            pass
        return None

    # ── Shodan (Key) ──────────────────────────────────────────
    def _shodan(self, ip: str, session) -> Optional[dict]:
        key = self.config.get_api_key("shodan") if self.config else None
        if not key:
            return None
        try:
            r = session.get(f"https://api.shodan.io/shodan/host/{ip}?key={key}", timeout=self._timeout)
            if r.status_code == 200:
                d = r.json()
                return {"org": d.get("org"), "os": d.get("os"), "ports": d.get("ports", []),
                        "hostnames": d.get("hostnames", []), "vulns": d.get("vulns", []),
                        "isp": d.get("isp"), "country": d.get("country_name"), "city": d.get("city")}
        except Exception as exc:
            self.add_error(f"Shodan: {exc}")
        return None

    # ── Hauptlauf ─────────────────────────────────────────────
    def run(self, input_value: str, input_type: str = "domain") -> ModuleReport:
        start = time.time()
        is_ip = self._is_ip(input_value.strip())
        target = input_value.strip() if is_ip else self._clean_domain(input_value)
        session = self._session()
        step = [0]

        def prog(msg):
            step[0] += 1
            self.report_progress(step[0], 10, msg)

        ip_for_intel = target if is_ip else None

        if not is_ip:
            # DNS
            prog("DNS-Auflösung...")
            dns_data = self._resolve_dns(target, session)
            count = sum(len(v) for k, v in dns_data.items() if not k.startswith("_") and isinstance(v, list))
            self.add_result(OSINTResult(
                source="DNS-Records", module=self.name, category="DNS",
                severity=ResultSeverity.FOUND if count else ResultSeverity.WARNING,
                title=f"{count} DNS-Records", data=dns_data))

            # E-Mail-Sicherheit
            prog("SPF/DMARC/DKIM...")
            esec = self._email_security(target, session)
            dmarc_policy = ""
            if esec.get("dmarc"):
                m = re.search(r"p=(\w+)", esec["dmarc"])
                dmarc_policy = m.group(1) if m else ""
            self.add_result(OSINTResult(
                source="E-Mail-Sicherheit", module=self.name, category="Security",
                severity=ResultSeverity.FOUND if esec.get("spf") or esec.get("dmarc") else ResultSeverity.WARNING,
                title=(f"SPF: {'ja' if esec.get('spf') else 'nein'} · "
                       f"DMARC: {dmarc_policy or ('ja' if esec.get('dmarc') else 'nein')} · "
                       f"DKIM-Selektoren: {len(esec['dkim_selectors'])}"),
                data=esec))

            ip_for_intel = self._resolve_ip(target, session)

        # RDAP
        prog("RDAP/WHOIS...")
        rdap = self._rdap(target, is_ip, session)
        self.add_result(OSINTResult(
            source="RDAP/WHOIS", module=self.name, category="Registration",
            severity=ResultSeverity.FOUND if rdap.get("source") != "none" else ResultSeverity.INFO,
            title=(f"Registrar: {rdap.get('registrar')}" if rdap.get("registrar")
                   else f"RDAP: {rdap.get('name') or target}"),
            data=rdap))

        # IP-Intelligence (für IP-Eingabe oder aufgelöste Domain-IP)
        if ip_for_intel:
            prog("IP-Geolocation / ASN...")
            intel = self._ip_intel(ip_for_intel, session)
            rdns = self._reverse_dns(ip_for_intel)
            intel["reverse_dns"] = rdns.get("hostname")
            self.add_result(OSINTResult(
                source="IP-Intelligence", module=self.name, category="Infrastructure",
                severity=ResultSeverity.FOUND if intel.get("country") else ResultSeverity.INFO,
                title=(f"{intel.get('city') or ''} {intel.get('country') or ''}".strip()
                       + (f" · {intel.get('asn')}" if intel.get("asn") else "")) or f"IP {ip_for_intel}",
                data=intel, url=f"https://bgp.he.net/ip/{ip_for_intel}"))

            prog("Offene Ports / CVEs (InternetDB)...")
            idb = self._internetdb(ip_for_intel, session)
            if idb:
                self.add_result(OSINTResult(
                    source="Shodan InternetDB", module=self.name, category="Infrastructure",
                    severity=ResultSeverity.CRITICAL if idb["vulns"] else
                             (ResultSeverity.WARNING if idb["ports"] else ResultSeverity.INFO),
                    title=f"{len(idb['ports'])} offene Ports" +
                          (f" · {len(idb['vulns'])} CVE(s)" if idb["vulns"] else ""),
                    data=idb, url=f"https://www.shodan.io/host/{ip_for_intel}"))
        else:
            prog("IP-Intelligence übersprungen")

        if not is_ip:
            # TLS
            prog("TLS-Zertifikat...")
            tls = self._tls(target)
            self.add_result(OSINTResult(
                source="TLS-Zertifikat", module=self.name, category="Security",
                severity=ResultSeverity.FOUND if tls.get("valid") else ResultSeverity.WARNING,
                title=(f"Zertifikat von {tls.get('issuer')}" if tls.get("valid") else "Kein gültiges TLS-Zertifikat"),
                data=tls))

            # HTTP-Header
            prog("HTTP-Header...")
            http = self._http(target, session)
            if http.get("checked"):
                self.add_result(OSINTResult(
                    source="HTTP-Header", module=self.name, category="Security",
                    severity=ResultSeverity.WARNING if len(http["missing_security_headers"]) > 3 else ResultSeverity.FOUND,
                    title=f"Server: {http.get('server') or 'unbekannt'} · Security {http.get('security_score')}",
                    data=http, url=http.get("final_url")))

            # Subdomains
            prog("Subdomains (crt.sh)...")
            subs = self._subdomains(target, session)
            self.add_result(OSINTResult(
                source="Subdomain-Enumeration", module=self.name, category="Discovery",
                severity=ResultSeverity.FOUND if subs["count"] else ResultSeverity.INFO,
                title=f"{subs['count']} Subdomains (crt.sh)", data=subs))

            # Discovery (robots/sitemap/security.txt) + Wayback
            prog("robots/sitemap/security.txt + Wayback...")
            disc = self._discovery(target, session)
            if disc.get("robots") or disc.get("security_txt"):
                self.add_result(OSINTResult(
                    source="Content-Discovery", module=self.name, category="Discovery",
                    severity=ResultSeverity.FOUND,
                    title=("security.txt gefunden" if disc.get("security_txt")
                           else f"robots.txt: {len(disc.get('robots', {}).get('disallowed', []))} Regeln"),
                    data=disc, url=f"https://{target}/robots.txt"))
            wb = self._wayback(target, session)
            if wb:
                self.add_result(OSINTResult(
                    source="Wayback Machine", module=self.name, category="History",
                    severity=ResultSeverity.FOUND, title=f"Archiv-Snapshot ({wb['timestamp']})",
                    data=wb, url=wb["url"]))
        else:
            # Shodan (Key) für IP
            prog("Shodan (Key)...")
            sho = self._shodan(target, session)
            if sho:
                self.add_result(OSINTResult(
                    source="Shodan", module=self.name, category="Infrastructure",
                    severity=ResultSeverity.FOUND, title=f"Shodan: {len(sho['ports'])} Ports",
                    data=sho, url=f"https://www.shodan.io/host/{target}"))

        self.report_progress(10, 10, "Domain/IP-Analyse abgeschlossen")
        return self.create_report(target, input_type, start, time.time())
