# Baysöz Labs <baysozlabs@proton.me> — baysoz-ssrfcanon
"""Per-runtime URL authority interpretation profiles.

Baysöz Labs <baysozlabs@proton.me>
"""

from __future__ import annotations

import re
from urllib.parse import unquote, urlsplit

from .ipcanon import (
    classify_dns_name,
    classify_ip,
    parse_ipv4_extended,
    parse_ipv4_strict,
    parse_ipv6,
)
from .model import AddressInfo, AddressClass, Authority

PROFILES = ("python-313", "whatwg", "go-124", "libc-numeric")
SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})
_PORT = re.compile(r"[0-9]*\Z")


def _invalid(url: str, profile: str, note: str) -> Authority:
    return Authority(
        profile=profile,
        url=url,
        scheme="",
        raw_host="",
        host="",
        port=None,
        info=AddressInfo("", AddressClass.INVALID, note, False),
        notes=(note,),
    )


def analyze(url: str, profile: str) -> Authority:
    """Interpret a URL's authority exactly as one supported stack would."""
    if profile not in PROFILES:
        message = f"unknown profile: {profile}"
        raise ValueError(message)

    notes: list[str] = []
    normalized = url
    try:
        scheme = urlsplit(url).scheme.lower()
    except ValueError:
        return _invalid(url, profile, "malformed-authority")
    if profile == "whatwg" and scheme in SPECIAL_SCHEMES and "\\" in url:
        normalized = url.replace("\\", "/")
        notes.append("backslash-treated-as-separator")

    try:
        parts = urlsplit(normalized)
    except ValueError:
        return _invalid(url, profile, "malformed-authority")
    if not parts.netloc:
        return _invalid(url, profile, "missing-authority")

    netloc = parts.netloc
    if "@" in netloc:
        notes.append("userinfo-stripped-at-last-at")
    hostport = netloc.rpartition("@")[2]
    if not hostport:
        return _invalid(url, profile, "empty-host")

    if hostport.startswith("["):
        closing = hostport.find("]")
        if closing < 0:
            return _invalid(url, profile, "unterminated-ipv6-literal")
        bare = hostport[1:closing]
        rest = hostport[closing + 1 :]
        port_text = rest[1:] if rest.startswith(":") else ""
        notes.append("bracketed-ipv6-literal")
    elif hostport.count(":") > 1:
        bare = hostport
        port_text = ""
        notes.append("unbracketed-ipv6-literal")
    elif ":" in hostport:
        bare, port_text = hostport.rsplit(":", 1)
    else:
        bare, port_text = hostport, ""

    if profile in {"whatwg", "go-124"}:
        decoded = unquote(bare)
        if decoded != bare:
            notes.append("percent-decoded-host")
        bare = decoded
    if profile == "whatwg":
        lowered = bare.lower()
        try:
            bare = lowered.encode("idna").decode("ascii")
        except UnicodeError:
            bare = lowered
        if bare != lowered:
            notes.append("idna-to-ascii")

    port: int | None = None
    if port_text and not _PORT.fullmatch(port_text):
        notes.append("invalid-port")
    elif port_text:
        port = int(port_text)

    canonical: str | None = None
    if ":" in bare:
        canonical = parse_ipv6(bare, allow_zone=profile in {"whatwg", "go-124"})
        if canonical is None and "%" in bare:
            notes.append("zone-id-rejected")
    elif profile in {"whatwg", "libc-numeric"}:
        canonical = parse_ipv4_extended(bare)
    else:
        canonical = parse_ipv4_strict(bare)

    if canonical is not None:
        if canonical != bare:
            notes.append("numeric-form-normalized")
        info = classify_ip(canonical)
        host = canonical
    elif ":" in bare:
        host = bare.lower()
        info = AddressInfo(host, AddressClass.INVALID, "unparsed-ipv6-literal", False)
    else:
        host = bare.lower()
        info = classify_dns_name(host)

    return Authority(
        profile=profile,
        url=url,
        scheme=scheme,
        raw_host=hostport,
        host=host,
        port=port,
        info=info,
        notes=tuple(notes),
    )
