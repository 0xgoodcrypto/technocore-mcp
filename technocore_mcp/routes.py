"""The only way this package reaches the network.

There is no entry point here that accepts a path string -- not public, not
internal. `fetch_technocore` takes a **route template identifier plus validated
segments**, and assembles the path itself.

That shape is the point. If a caller can assemble a path, the confusion happens
at assembly: technocore reads and writes are adjacent routes, so a `key` of
`"x/set/<value>"` turns `/kv/<ns>/<key>` into a write on the correct host. The
origin check below would pass it, because the host really is technocore.

Two different questions, and passing one is not evidence for the other:

  which host do we reach?   -> the origin check (verify_url)
  what do we do there?      -> the template set + validated segments

No write-route template exists here. Signed posting goes through the vendored
`say_signed`, which builds its own URL from BASE.
"""

import os
import re
import unicodedata
import urllib.error
import urllib.parse
import urllib.request

DEFAULT_HOST = "technocore.chat"
USER_AGENT = "technocore-mcp/0.1 (+https://github.com/0xgoodcrypto/technocore-mcp)"
TIMEOUT = 20
DEFAULT_MAX_BYTES = 8 * 1024 * 1024

# A host we would accept as configuration: lowercase, ASCII, no userinfo, no
# port, no trailing dot. Validated at load rather than at use, so a bad value
# fails at startup instead of at the first request.
HOST_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")

# Categories that render as nothing. Same set the server sweeps and the vendored
# client signs after; a path must not carry them at all.
INVISIBLE = ("Cc", "Cf", "Cs", "Co", "Zl", "Zp")

ROUTE_ROOM = "room"
ROUTE_ROOM_EXPORT = "room_export"
ROUTE_KV_READ = "kv_read"
ROUTE_ROOMS = "rooms"

# template -> (path pattern, required segment names).
# Enumerated constants. The model cannot choose from this set: a tool handler
# names one literally.
TEMPLATES = {
    ROUTE_ROOM: ("/r/{room}", ("room",)),
    ROUTE_ROOM_EXPORT: ("/r/{room}/export", ("room",)),
    ROUTE_KV_READ: ("/kv/{ns}/{key}", ("ns", "key")),
    ROUTE_ROOMS: ("/rooms", ()),
}

# Query parameters are advisory server-side (clamped, never refused), but we
# still coerce locally so no model-supplied string reaches the query at all.
_QUERY_SPEC = {
    "since": ("int", 0, 2 ** 63 - 1),
    "wait": ("int", 0, 10),
    "limit": ("int", 1, 200),
    "format": ("literal", "json"),
}


class RouteError(ValueError):
    """A route was named, or a segment given, that we will not send."""


class OriginError(RouteError):
    """The assembled URL does not address the configured technocore host."""


def configured_host() -> str:
    host = os.environ.get("TECHNOCORE_MCP_HOST", DEFAULT_HOST).strip().lower()
    if not HOST_RE.match(host):
        raise OriginError(
            f"TECHNOCORE_MCP_HOST={host!r} is not a plain hostname. "
            "No userinfo, no port, no scheme, no trailing dot."
        )
    return host


class Fetched:
    __slots__ = ("body", "headers", "url", "status")

    def __init__(self, body, headers, url, status):
        self.body = body
        self.headers = headers
        self.url = url
        self.status = status


def _check_path(path: str) -> None:
    """Guards on the path we just built. Not a filter on caller input.

    Nothing arbitrary arrives here -- segments are NAME_RE and the template is a
    constant. These catch *our* construction mistakes, which is why they run on
    the assembled result rather than on anything a caller handed us.
    """
    if not path.startswith("/"):
        raise RouteError(f"assembled path is not origin-relative: {path!r}")
    if path.startswith("//"):
        raise RouteError(f"assembled path starts an authority: {path!r}")
    if "\\" in path:
        raise RouteError(f"assembled path contains a backslash: {path!r}")
    for ch in path:
        if unicodedata.category(ch) in INVISIBLE:
            raise RouteError(f"assembled path contains an invisible character: {path!r}")


def verify_url(url: str, host: str) -> None:
    """The load-bearing check: look at the result, not at the input.

    Everything above inspects what we were given and can always be
    under-written -- an earlier revision of this design rejected full URLs,
    scheme-bearing strings and '//' prefixes, and still let `.evil.com/x`
    through, because `BASE` has no trailing slash. This looks at what was
    actually built, so a gap upstream of it still stops here.
    """
    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "https":
        raise OriginError(f"refusing a non-https destination: {url!r}")
    if parts.hostname != host:
        raise OriginError(
            f"refusing {parts.hostname!r}: the configured host is {host!r} ({url!r})")
    # hostname strips userinfo and port; netloc does not. Compare both so
    # `host@evil.example` and `host:8443` cannot slip past the hostname test.
    if parts.netloc != host:
        raise OriginError(f"refusing an authority of {parts.netloc!r} ({url!r})")


def build_url(route: str, segments: dict = None, query: dict = None) -> str:
    """Assemble a URL from a template id and validated segments. Never from a path.

    There is deliberately no `host` parameter. An earlier revision had one "for
    tests", which made the destination caller-selectable and made the origin
    check self-consistent -- it verified against whatever host the caller had
    just asked for, so it could not fail. The host comes from configuration and
    nowhere else.
    """
    from . import vendor_facade  # late import: startup wires this once

    host = configured_host()
    try:
        pattern, required = TEMPLATES[route]
    except KeyError:
        raise RouteError(
            f"unknown route {route!r}. Routes are constants in this module; "
            f"known: {sorted(TEMPLATES)}"
        ) from None

    segments = segments or {}
    if set(segments) != set(required):
        raise RouteError(
            f"route {route!r} needs exactly {sorted(required)}, got {sorted(segments)}")

    safe = {}
    for name, raw in segments.items():
        if not isinstance(raw, str):
            raise RouteError(f"segment {name!r} must be a string")
        # NAME_RE or nothing. This is what stops /kv/<ns>/<key> from growing a
        # /set/<value> tail: a segment cannot contain a separator.
        checked = vendor_facade().validate_name(raw, name)
        safe[name] = urllib.parse.quote(checked, safe="")

    path = pattern.format(**safe)
    _check_path(path)

    pairs = []
    for key, raw in (query or {}).items():
        spec = _QUERY_SPEC.get(key)
        if spec is None:
            raise RouteError(f"unknown query parameter {key!r}")
        if spec[0] == "int":
            value = int(raw)
            if not (spec[1] <= value <= spec[2]):
                raise RouteError(f"{key}={value} is outside {spec[1]}..{spec[2]}")
            pairs.append((key, str(value)))
        else:
            if raw != spec[1]:
                raise RouteError(f"{key} may only be {spec[1]!r}")
            pairs.append((key, spec[1]))

    url = urllib.parse.urlunsplit(
        ("https", host, path, urllib.parse.urlencode(pairs), ""))
    verify_url(url, host)
    return url


def fetch_technocore(route: str, segments: dict = None, query: dict = None,
                     max_bytes: int = DEFAULT_MAX_BYTES, timeout: int = TIMEOUT) -> Fetched:
    """The single outbound path. Takes a route id, never a path or a URL."""
    url = build_url(route, segments, query)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            # Redirects are followed by urllib; re-check what we actually got.
            verify_url(response.geturl(), configured_host())
            raw = response.read(max_bytes + 1)
            if len(raw) > max_bytes:
                raise RouteError(
                    f"response from {route} exceeds the {max_bytes} byte cap")
            return Fetched(raw.decode("utf-8", "replace"),
                           dict(response.headers), response.geturl(), response.status)
    except urllib.error.HTTPError as exc:
        body = exc.read(4096).decode("utf-8", "replace")
        return Fetched(body, dict(exc.headers or {}), url, exc.code)
