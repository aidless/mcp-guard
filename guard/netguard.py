"""SSRF destination guards for upstream connections.

A security scanner that connects to whatever endpoint it is handed becomes an
SSRF launchpad.  The specific prize is the cloud instance-metadata service: on
AWS/GCP it hands out IAM credentials over plain HTTP with no auth, on Alibaba
Cloud it does the same at 100.100.100.200.  An attacker who can influence the
upstream URL (a malicious ``mcp.json``, a tempting ``--upstream`` value pasted
from a gist) turns our own proxy into the exfiltration channel.

The design is borrowed from ``snyk-agent-scan``, which refuses to resolve to
link-local / cloud-metadata endpoints and does not follow HTTP redirects while
still permitting loopback and RFC1918 upstreams.  The latter matters for us: an
MCP server normally lives on ``127.0.0.1:PORT`` or somewhere on the LAN, so
blanket-refusing private addresses would make the proxy useless.

What is refused (unconditionally, no flag):
  * ``169.254.0.0/16``                   link-local IPv4; holds AWS/GCP IMDS
                                        (169.254.169.254) and ECS task metadata
                                        (169.254.170.2)
  * ``fe80::/10``                        link-local IPv6
  * ``fd00:ec2::254``                    AWS IMDS over IPv6
  * ``100.100.100.0/24``                 Alibaba Cloud metadata
  * a small name blocklist              ``metadata.google.internal`` and friends,
                                        which also covers resolvers that are
                                        offline or lying

What is allowed: loopback, RFC1918 / ULA private space, and ordinary public
addresses.  ``allow_link_local=True`` is an explicit escape hatch for tests and
lab setups; it is intentionally *not* reachable from a config file.

Residual risk, stated honestly: we validate the address *before* connecting, so
a resolver that answers differently on the second lookup (classic DNS rebinding)
can still slip through the gap between check and connect.  snyk has the same
window and says so; closing it properly needs socket-level pinning, which is not
worth the complexity here.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlsplit

#: Hostnames that mean "instance metadata" no matter what DNS says.
METADATA_HOSTNAMES = frozenset(
    {
        "metadata",
        "metadata.google.internal",
        "metadata.goog",
        "instance-data",
        "instance-data.ec2.internal",
        "metadata.azure.com",
    }
)

#: Explicit address blocks that carry credentials or link-local surprises.
#: ``is_link_local`` already covers 169.254.0.0/16 and fe80::/10; the rest are
#: listed because they are *not* link-local but are still metadata endpoints.
METADATA_NETWORKS = (
    ipaddress.ip_network("169.254.0.0/16"),  # AWS/GCP IMDS, ECS task metadata
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local
    ipaddress.ip_network("fd00:ec2::254/128"),  # AWS IMDS over IPv6
    ipaddress.ip_network("100.100.100.0/24"),  # Alibaba Cloud metadata
)


class BlockedUpstream(Exception):
    """Raised when an upstream URL points at a destination we refuse to contact."""


def _ip_reason(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str | None:
    """Return a human reason if this address must not be contacted."""
    for net in METADATA_NETWORKS:
        if ip.version == net.version and ip in net:
            if ip.is_link_local:
                return "link-local (cloud instance-metadata range)"
            return "cloud instance-metadata endpoint"
    if ip.is_link_local:  # defence in depth for ranges ipaddress flags itself
        return "link-local (cloud instance-metadata range)"
    return None


def describe_block(host: str) -> str:
    """Explain why ``host`` is refused.  Pure string/parse work, no I/O.

    Kept separate so the error message can name the exact reason: an operator who
    is told only "blocked" will go looking for an escape hatch.
    """
    bare = host.strip("[]").strip()
    if bare.lower() in METADATA_HOSTNAMES:
        return f"{host} is a cloud instance-metadata hostname"
    try:
        ip = ipaddress.ip_address(bare)
    except ValueError:
        return f"{host} could not be parsed as an address"
    reason = _ip_reason(ip)
    if reason is not None:
        return f"{host} is {reason}"
    return f"{host} is not a blocked destination"


def _default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    return [info[4][0] for info in infos]


def check_upstream(
    url: str,
    *,
    resolver=None,
    allow_link_local: bool = False,
) -> None:
    """Refuse an upstream URL that resolves to a metadata / link-local endpoint.

    Raises :class:`BlockedUpstream` with a reason-bearing message.  Returns None
    when the URL is acceptable.  ``resolver`` is injectable for tests so no
    network is touched.
    """
    parts = urlsplit(url)
    host = parts.hostname
    if not host:
        raise BlockedUpstream(f"{url!r} has no host component")
    port = parts.port or (443 if parts.scheme == "https" else 80)

    if host.lower() in METADATA_HOSTNAMES:
        raise BlockedUpstream(
            f"refusing upstream {url!r}: {host} is a cloud instance-metadata hostname"
        )

    # A literal IP is checked directly; a name is resolved and *every* answer is
    # checked, because one bad record is enough to reach the metadata service.
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if literal is not None:
        candidates = [str(literal)]
    else:
        resolve = resolver or _default_resolver
        try:
            candidates = resolve(host, port)
        except OSError as exc:
            # Unresolvable is not a security decision — let the connect fail later
            # with a normal error rather than blaming SSRF.
            raise BlockedUpstream(
                f"refusing upstream {url!r}: cannot resolve {host} ({exc})"
            ) from None

    for cand in candidates:
        try:
            ip = ipaddress.ip_address(cand)
        except ValueError:
            continue
        reason = _ip_reason(ip)
        if reason is None:
            continue
        if allow_link_local and ip.is_link_local:
            continue
        raise BlockedUpstream(
            f"refusing upstream {url!r}: {cand} is {reason}; "
            f"this endpoint hands out credentials to anyone who asks"
        )
