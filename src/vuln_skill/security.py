"""Content integrity, evidence matching and restricted paths."""
from __future__ import annotations

import hashlib
import ipaddress
import re
import socket
from pathlib import Path, PurePosixPath
from urllib.parse import urlparse


KNOWN_HOSTS = {
    "cveawg.mitre.org", "api.github.com", "github.com", "www.github.com",
    "www.wordfence.com", "wordfence.com", "plugins.trac.wordpress.org",
    "nvd.nist.gov", "www.cve.org", "cve.org", "www.rubyonrails.org",
    "rubyonrails.org", "www.php.net", "www.openssl.org",
    "security-tracker.debian.org", "www.debian.org", "gitlab.com",
    "www.oracle.com", "access.redhat.com", "ubuntu.com", "www.cisa.gov",
}


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def normalize(s: str) -> str:
    return re.sub(r"\s+", " ", s).strip().casefold()


def quote_is_present(quote: str, source_text: str) -> bool:
    """Exact contiguous evidence substring after whitespace normalization; no fuzzy matching."""
    return len(normalize(quote)) >= 15 and normalize(quote) in normalize(source_text)


def safe_relative_path(root: Path, value: str) -> Path:
    """Reject traversal and symlinks in each component; target remains read-only."""
    if not value or "\\" in value or "\x00" in value:
        raise ValueError("Unsafe or empty relative path")
    path = PurePosixPath(value)
    if path.is_absolute() or any(x in ("", ".", "..") for x in path.parts):
        raise ValueError("Unsafe target-relative path")
    root = root.resolve(strict=True)
    candidate = root
    for part in path.parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise ValueError("Symlink access is not permitted")
    if not candidate.resolve(strict=False).is_relative_to(root):
        raise ValueError("Path escapes target root")
    return candidate


def url_allowed(url: str) -> bool:
    parsed = urlparse(url)
    return (parsed.scheme == "https" and parsed.hostname in KNOWN_HOSTS and
            parsed.username is None and parsed.password is None and
            (parsed.port is None or parsed.port == 443))


def host_has_public_addresses(host: str) -> bool:
    """Extra protection for advisory URL retrieval (does not prevent DNS rebinding)."""
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
        return bool(addresses) and all(ipaddress.ip_address(a[4][0]).is_global for a in addresses)
    except (OSError, ValueError):
        return False
