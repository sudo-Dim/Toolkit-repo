"""Public OSINT targets only; pin direct socket connections after DNS validation."""

import ipaddress
import socket
import re


def public_addresses(host, port):
    if not host or host.lower().rstrip('.') in {'localhost', 'localhost.localdomain'}:
        raise ValueError('Lokale Netzwerkziele sind nicht erlaubt')
    addresses = list(dict.fromkeys(item[4][0] for item in
                                  socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)))
    parsed = [ipaddress.ip_address(address.split('%')[0]) for address in addresses]
    if not addresses or any(not address.is_global or address.is_multicast or address.is_reserved for address in parsed):
        raise ValueError('Private, lokale und reservierte Netzwerkziele sind nicht erlaubt')
    return addresses


def public_socket(host, port, timeout):
    error = None
    for address in public_addresses(host, port):
        try:
            return socket.create_connection((address, port), timeout=timeout)
        except OSError as exc:
            error = exc
    raise error


def public_proxy_target(host, port):
    """A configured proxy may provide DNS when the client has no DNS route."""
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        name = host.lower().rstrip('.')
        if ('.' not in name or name.endswith(('.localhost', '.local', '.internal', '.home.arpa'))
                or re.fullmatch(r'(?:0x[0-9a-f]+|[0-9]+)(?:\.(?:0x[0-9a-f]+|[0-9]+))*', name)):
            raise ValueError('Lokale Netzwerkziele sind nicht erlaubt')
    else:
        if not address.is_global or address.is_multicast or address.is_reserved:
            raise ValueError('Private Netzwerkziele sind nicht erlaubt')
    try:
        public_addresses(host, port)
    except socket.gaierror:
        # Trust the explicitly configured proxy's DNS/network policy; never bypass it.
        pass
