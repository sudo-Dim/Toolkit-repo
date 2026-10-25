"""Gemeinsame Eingabegrenzen und Host-Normalisierung für CLI und Web."""

import ipaddress
import re
from urllib.parse import urlsplit

MAX_INPUT_LENGTH = 2048


def clean_input(value: str, *, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        raise ValueError("Die Eingabe muss ein Text sein")
    value = value.strip()
    if not value and not allow_empty:
        raise ValueError("Keine Eingabe")
    if len(value) > MAX_INPUT_LENGTH:
        raise ValueError(f"Eingabe zu lang (maximal {MAX_INPUT_LENGTH} Zeichen)")
    if any(ord(char) < 32 for char in value):
        raise ValueError("Die Eingabe enthält ungültige Steuerzeichen")
    return value


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_host(value: str) -> str:
    """Extrahiert den Host, ohne Ports/Pfade an DNS oder RDAP weiterzugeben."""
    value = clean_input(value)
    if is_ip(value):
        return value.lower()
    if any(char.isspace() for char in value):
        raise ValueError("Ungültiger Host")
    parsed = urlsplit(value if "://" in value else "//" + value)
    if parsed.scheme and parsed.scheme.lower() not in ("http", "https"):
        raise ValueError("Nur HTTP- und HTTPS-Adressen werden unterstützt")
    # Der Zugriff auf port validiert auch ungültige bzw. zu große Portnummern.
    parsed.port
    host = parsed.hostname
    if not host or parsed.username is not None or parsed.password is not None:
        raise ValueError("Ungültiger Host")
    if is_ip(host):
        return host.lower()
    try:
        return host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Ungültiger Domainname") from exc


def is_domain(host: str) -> bool:
    labels = host.split(".")
    return (
        len(host) <= 253 and len(labels) >= 2
        and all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                for label in labels)
        and bool(re.fullmatch(r"[a-z]{2,63}|xn--[a-z0-9-]{2,59}", labels[-1]))
    )
