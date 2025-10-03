import socket
from typing import Optional

def reverse_dns_lookup(ip_address: str) -> Optional[str]:
    """
    Performs a reverse DNS lookup on an IP address.
    Returns the first associated domain name, or None if not found.
    """
    try:
        # getfqdn returns the first fully qualified domain name from the reverse lookup
        domain = socket.getfqdn(ip_address)
        # If the result is the same as the input, no PTR record was found
        return domain if domain != ip_address else None
    except (socket.herror, socket.gaierror, OSError):
        # Handle errors (no reverse, invalid IP, etc.)
        return None
    
def resolve_to_ip(hostname: str) -> str:
    """Resolves a hostname to an IP address."""
    try:
        # Check if it's already an IP
        socket.inet_aton(hostname)
        return hostname
    except socket.error:
        try:
            return socket.gethostbyname(hostname)
        except socket.gaierror:
            return hostname
