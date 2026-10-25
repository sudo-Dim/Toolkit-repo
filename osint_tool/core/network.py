"""Public OSINT targets only; pin direct socket connections after DNS validation."""

import ipaddress
import socket


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
