#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# dependencies = ["websockets>=14"]
# ///
"""Connectivity + capability probe for the ObsidianIRC server list.

Each server advertises two transports in servers.json: a WebSocket endpoint
(wss, what the web Discover page actually connects to) and a direct TLS IRC
endpoint (ircs).  Either may be served by a different daemon, so both are
probed independently and their advertised capabilities are merged.

For every server we open the transport, send `CAP LS 302`, read the (possibly
multi-line) capability list, and derive three booleans the server list cares
about:

  - obsidian: the server runs ObbyIRCd (advertises obsidianirc/* or
    obby.world/* vendor capabilities)
  - sasl:     SASL authentication is offered
  - voice:    the voice/RTC capability (obsidianirc/voice or obby.world/voice)

ObbyIRCd is TLS-only and the Discover page connects from a browser, which
rejects invalid certificates over wss.  We therefore require a fully valid,
hostname-matching TLS certificate: a self-signed or mismatched cert means the
real client cannot connect either, so it disqualifies the server and the TLS
error is recorded as the reason (surfaced in the PR / removal proposal).

Server icons follow the IRCv3 network-icon spec: a server publishes its icon as
an `ICON=<url>` (or work-in-progress `draft/ICON=<url>`) ISUPPORT token in the
RPL_ISUPPORT 005 burst, which is only sent after connection registration.  Capability detection deliberately
stops at `CAP LS` and never registers, so icon collection is a separate,
heavier mode used only by the daily crawl (`--apply`): there the probe also
sends `CAP END` + NICK/USER, reads the welcome burst, extracts the icon URL,
downloads the image into server-icons/ and records its path in servers.json.
The icon is re-fetched each crawl and rewritten only when it actually changed,
so the list tracks the server's current icon without needless churn; the field
is left empty for servers that advertise none.
"""
import argparse
import asyncio
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import subprocess
import sys
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from urllib.parse import urlsplit

import websockets
from websockets import Origin

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVERS_FILE = REPO_ROOT / "servers.json"
ICON_DIR = REPO_ROOT / "server-icons"

VOICE_CAPS = ("obsidianirc/voice", "obby.world/voice")
OBBY_VENDOR_PREFIXES = ("obsidianirc/", "obby.world/")

# IRCv3 network-icon: the icon URL is advertised as an ISUPPORT token.  The spec
# is migrating from the work-in-progress `draft/ICON` to the final unprefixed
# `ICON`; servers run either, so accept both (final preferred when both appear).
ICON_ISUPPORT_TOKENS = ("ICON", "draft/ICON")

# Canonical key order so --apply keeps servers.json tidy and new fields land in
# a predictable place rather than at the end of each object.
FIELD_ORDER = ("name", "description", "wss", "ircs", "obsidian", "sasl", "voice", "icon")

DEFAULT_TIMEOUT = 12.0
DEFAULT_IRCS_PORT = 6697

# A real browser WebSocket always sends an Origin header, and some IRC
# WebSocket gateways reject upgrades without one (HTTP 403).  Mirroring the
# Discover page's browser client avoids spurious "unreachable" verdicts.
WSS_USER_AGENT = "Mozilla/5.0 (compatible; ObsidianIRC-probe/1.0)"

# Browsers refuse to load an http image on the https Discover page (mixed
# content), so an http icon URL is useless to us; require https.  Servers are
# untrusted, so the download is size-capped and the response content-type, not
# the URL, decides the on-disk extension.
MAX_ICON_BYTES = 512 * 1024
ICON_FETCH_TIMEOUT = 15.0
CONTENT_TYPE_EXT = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/svg+xml": ".svg",
    "image/webp": ".webp",
    "image/gif": ".gif",
    "image/x-icon": ".ico",
    "image/vnd.microsoft.icon": ".ico",
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


@dataclass
class Detection:
    obsidian: bool
    sasl: bool
    voice: bool


@dataclass
class TransportProbe:
    """Full result of probing one transport, including the raw caps/isupport
    used only internally to derive detection -- not serialized into the
    report."""

    transport: str
    url: str
    reachable: bool
    error: str | None
    caps: dict[str, str]
    isupport: dict[str, str]


@dataclass
class EndpointStatus:
    transport: str
    url: str
    reachable: bool
    error: str | None


@dataclass
class ServerResult:
    name: str
    endpoints: list[EndpointStatus]
    any_reachable: bool
    detected: Detection | None
    icon_url: str | None


@dataclass
class FetchedIcon:
    data: bytes
    ext: str


class Negotiator:
    """State machine that drives one transport's IRC handshake.

    `feed(line)` consumes a single received line and returns any lines to send
    back, so the wss and ircs read loops differ only in their I/O mechanics.

    A `CAP LS 302` reply is split across one or more lines, each carrying a `*`
    continuation marker until the last.  In caps-only mode the handshake ends
    there.  When `register` is set we then complete registration (`CAP END`,
    the caller having already sent NICK/USER) and keep reading the welcome
    burst to collect the RPL_ISUPPORT (005) tokens that carry the icon URL,
    finishing at end-of-MOTD (376/422) or a registration error.
    """

    # Numerics that end the welcome burst (success or terminal failure) and so
    # mean no further ISUPPORT lines are coming.
    _REGISTRATION_END = {"376", "422", "432", "464", "465", "466"}

    def __init__(self, nick: str, register: bool) -> None:
        self.nick = nick
        self.register = register
        self.caps: dict[str, str] = {}
        self.isupport: dict[str, str] = {}
        self.caps_done = False
        self.finished = False
        self._nick_tries = 0

    def feed(self, line: str) -> list[str]:
        line = line.rstrip()
        if not line:
            return []
        if line.startswith("PING"):
            return ["PONG" + line[4:]]

        head, _, trailing = line.partition(" :")
        parts = head.split()

        if "CAP" in parts:
            return self._feed_cap(parts, trailing)
        if len(parts) >= 2 and parts[1].isdigit():
            return self._feed_numeric(parts[1], parts[3:])
        if parts and parts[0] == "ERROR":
            self.finished = True
        return []

    def _feed_cap(self, parts: list[str], trailing: str) -> list[str]:
        idx = parts.index("CAP")
        if len(parts) <= idx + 2 or parts[idx + 2] != "LS":
            return []
        more = len(parts) > idx + 3 and parts[idx + 3] == "*"
        for token in trailing.split():
            name, _, value = token.partition("=")
            self.caps[name] = value
        if more or self.caps_done:
            return []
        self.caps_done = True
        if not self.register:
            self.finished = True
            return []
        return ["CAP END"]

    def _feed_numeric(self, code: str, params: list[str]) -> list[str]:
        if code == "005":
            for token in params:
                name, _, value = token.partition("=")
                self.isupport[name] = value
        elif code == "433" and self._nick_tries < 3:
            self._nick_tries += 1
            self.nick = f"{self.nick[:6]}{self._nick_tries}"
            return [f"NICK {self.nick}"]
        elif code in self._REGISTRATION_END:
            self.finished = True
        return []


def detect(caps: dict[str, str]) -> Detection:
    names = caps.keys()
    return Detection(
        obsidian=any(n.startswith(OBBY_VENDOR_PREFIXES) for n in names),
        sasl="sasl" in caps,
        voice=any(v in caps for v in VOICE_CAPS),
    )


def icon_url_from(isupport: dict[str, str]) -> str | None:
    """ISUPPORT token names are case-insensitive, so fold before matching."""
    folded = {name.casefold(): value for name, value in isupport.items()}
    for token in ICON_ISUPPORT_TOKENS:
        value = folded.get(token.casefold())
        if value:
            return value
    return None


def _registration_nick() -> str:
    return f"ob{secrets.token_hex(3)}"


def _initial_send(nick: str, register: bool) -> str:
    lines = ["CAP LS 302"]
    if register:
        lines += [f"NICK {nick}", f"USER {nick} 0 * :{nick}"]
    return "".join(line + "\r\n" for line in lines)


TRANSPORT_ATTEMPTS = 3
RETRY_BACKOFF = 0.75

# A failed TLS trust check is deterministic -- retrying wastes time and can't
# change the verdict, unlike a timeout or a rate-limit reset.
DETERMINISTIC_ERROR = "CERTIFICATE_VERIFY_FAILED"


async def _with_retries(attempt) -> TransportProbe:
    result = await attempt()
    for i in range(1, TRANSPORT_ATTEMPTS):
        if result.reachable or (result.error and DETERMINISTIC_ERROR in result.error):
            break
        await asyncio.sleep(RETRY_BACKOFF * i)
        result = await attempt()
    return result


def _first_non_public(infos) -> str | None:
    """The shared SSRF rule: every address a host resolves to must be globally
    routable.  Returns the first loopback/private/link-local/reserved address
    (e.g. cloud metadata at 169.254.169.254), or None if all are public."""
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return str(ip)
    return None


async def _non_public_target(host: str, port: int) -> str | None:
    """Reject a target whose host resolves to a non-public address.

    The PR-validation workflow probes contributor-supplied hosts and echoes the
    result into a public comment, so an unchecked target lets a PR use the
    runner to reach internal addresses.
    """
    loop = asyncio.get_running_loop()
    bad = _first_non_public(await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM))
    return f"refused non-public address {bad}" if bad else None


def _host_port(url: str, default_port: int) -> tuple[str | None, int, str | None]:
    """Parse a transport URL into (host, port, error).

    A malformed URL -- e.g. a port outside 0-65535 from a bad PR entry -- yields
    an error string instead of raising, so one bad server can't crash the run.
    """
    try:
        parsed = urlsplit(url)
        return parsed.hostname, parsed.port or default_port, None
    except ValueError as exc:
        return None, default_port, f"invalid URL: {exc}"


async def probe_wss(url: str, timeout: float, register: bool) -> TransportProbe:
    return await _with_retries(lambda: _attempt_wss(url, timeout, register))


async def _attempt_wss(url: str, timeout: float, register: bool) -> TransportProbe:
    nego = Negotiator(_registration_nick(), register)
    error: str | None = None
    host, port, url_error = _host_port(url, 443)
    if url_error:
        return TransportProbe("wss", url, False, url_error, {}, {})
    origin = Origin(f"https://{host}") if host else None
    try:
        async with asyncio.timeout(timeout):
            blocked = await _non_public_target(host or "", port)
            if blocked:
                return TransportProbe("wss", url, False, blocked, {}, {})
            async with websockets.connect(
                url,
                ssl=ssl.create_default_context(),
                open_timeout=timeout,
                close_timeout=3,
                max_size=None,
                origin=origin,
                user_agent_header=WSS_USER_AGENT,
            ) as ws:
                await ws.send(_initial_send(nego.nick, register))
                while not nego.finished:
                    message = await ws.recv()
                    text = message if isinstance(message, str) else message.decode("utf-8", "replace")
                    for line in text.replace("\r", "").split("\n"):
                        for reply in nego.feed(line):
                            await ws.send(reply + "\r\n")
    except (OSError, ssl.SSLError, asyncio.TimeoutError, websockets.WebSocketException) as exc:
        error = f"{type(exc).__name__}: {exc}".strip()
    if not nego.caps_done and error is None:
        error = "connection closed before capability list"
    return TransportProbe("wss", url, nego.caps_done, error, nego.caps, nego.isupport)


async def probe_ircs(url: str, timeout: float, register: bool) -> TransportProbe:
    return await _with_retries(lambda: _attempt_ircs(url, timeout, register))


async def _attempt_ircs(url: str, timeout: float, register: bool) -> TransportProbe:
    host, port, url_error = _host_port(url, DEFAULT_IRCS_PORT)
    if url_error:
        return TransportProbe("ircs", url, False, url_error, {}, {})
    host = host or ""
    nego = Negotiator(_registration_nick(), register)
    error: str | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(timeout):
            blocked = await _non_public_target(host, port)
            if blocked:
                return TransportProbe("ircs", url, False, blocked, {}, {})
            reader, writer = await asyncio.open_connection(
                host, port, ssl=ssl.create_default_context(), server_hostname=host
            )
            writer.write(_initial_send(nego.nick, register).encode())
            await writer.drain()
            buffer = ""
            while not nego.finished:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", "replace")
                lines = buffer.split("\n")
                buffer = lines.pop()
                for line in lines:
                    for reply in nego.feed(line):
                        writer.write((reply + "\r\n").encode())
                        await writer.drain()
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
        error = f"{type(exc).__name__}: {exc}".strip()
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (OSError, asyncio.TimeoutError):
                pass
    if not nego.caps_done and error is None:
        error = "connection closed before capability list"
    return TransportProbe("ircs", url, nego.caps_done, error, nego.caps, nego.isupport)


async def probe_server(entry: dict, timeout: float) -> ServerResult:
    coros = []
    if entry.get("wss"):
        coros.append(probe_wss(entry["wss"], timeout, register=False))
    if entry.get("ircs"):
        coros.append(probe_ircs(entry["ircs"], timeout, register=False))

    probes = await asyncio.gather(*coros)

    merged_caps: dict[str, str] = {}
    for probe in probes:
        if probe.reachable:
            merged_caps.update(probe.caps)

    any_reachable = any(p.reachable for p in probes)
    return ServerResult(
        name=entry.get("name", "?"),
        endpoints=[EndpointStatus(p.transport, p.url, p.reachable, p.error) for p in probes],
        any_reachable=any_reachable,
        detected=detect(merged_caps) if any_reachable else None,
        icon_url=None,
    )


async def harvest_icon(entry: dict, timeout: float) -> str | None:
    """Best-effort icon URL from the IRCv3 network-icon ISUPPORT token.

    Reading ISUPPORT requires completing registration -- a heavier handshake
    than capability detection that some daemons throttle -- so it runs only
    during the crawl and is kept entirely separate from probe_server: a server
    is never marked unreachable or dropped because this extra pass failed.  The
    advertised URL is authoritative, so a server that publishes an icon wins
    over a hand-added one; a hand-added icon survives only while the server
    advertises none.
    """
    coros = []
    if entry.get("wss"):
        coros.append(probe_wss(entry["wss"], timeout, register=True))
    if entry.get("ircs"):
        coros.append(probe_ircs(entry["ircs"], timeout, register=True))

    probes = await asyncio.gather(*coros)

    merged_isupport: dict[str, str] = {}
    for probe in probes:
        merged_isupport.update(probe.isupport)
    return icon_url_from(merged_isupport)


def load_servers() -> list[dict]:
    return json.loads(SERVERS_FILE.read_text(encoding="utf-8"))


def changed_servers(servers: list[dict], base_ref: str) -> list[dict]:
    """Entries whose connectivity changed versus a git ref.

    Only new servers or edits to a transport URL warrant re-probing; a
    description-only edit should not block a PR on unrelated downtime.  If the
    base file is missing (servers.json is brand new) every entry is in scope.
    """
    try:
        base_json = subprocess.run(
            ["git", "show", f"{base_ref}:servers.json"],
            capture_output=True, text=True, cwd=REPO_ROOT, check=True,
        ).stdout
        base_by_name = {s.get("name"): s for s in json.loads(base_json)}
    except (subprocess.CalledProcessError, json.JSONDecodeError):
        return servers
    return [
        s for s in servers
        if base_by_name.get(s.get("name")) is None
        or base_by_name[s["name"]].get("wss") != s.get("wss")
        or base_by_name[s["name"]].get("ircs") != s.get("ircs")
    ]


def reorder(entry: dict) -> dict:
    ordered = {k: entry[k] for k in FIELD_ORDER if k in entry}
    for k, v in entry.items():
        if k not in ordered:
            ordered[k] = v
    return ordered


def failure_reason(result: ServerResult) -> str:
    detail = "; ".join(f"{e.transport}: {e.error}" for e in result.endpoints if e.error)
    return detail or "no capabilities returned"


def slugify(name: str) -> str:
    return _SLUG_RE.sub("-", name.lower()).strip("-") or "server"


def _icon_target_is_public(host: str, port: int) -> bool:
    return _first_non_public(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)) is None


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse redirects so a public icon URL can't bounce to an internal one,
    bypassing the destination check below.  This does not defend against a
    server whose host re-resolves to a private address between the check and the
    fetch (DNS rebinding); the list is human-curated, which is the mitigation."""

    def redirect_request(self, *_args, **_kwargs):
        return None


_ICON_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch_icon(url: str) -> FetchedIcon | None:
    """Download an icon URL, or None if it is unsafe, unreachable, oversized,
    or not a recognized image type."""
    try:
        parsed = urlsplit(url)
        host, port = parsed.hostname, parsed.port or 443
    except ValueError:
        return None
    if parsed.scheme != "https" or not host:
        return None
    try:
        if not _icon_target_is_public(host, port):
            return None
        request = urllib.request.Request(url, headers={"User-Agent": WSS_USER_AGENT})
        with _ICON_OPENER.open(request, timeout=ICON_FETCH_TIMEOUT) as response:
            ext = CONTENT_TYPE_EXT.get(response.headers.get_content_type())
            if ext is None:
                return None
            data = response.read(MAX_ICON_BYTES + 1)
    except (urllib.error.URLError, OSError, ValueError):
        return None
    if not data or len(data) > MAX_ICON_BYTES:
        return None
    return FetchedIcon(data, ext)


def download_icons(results: list[ServerResult]) -> dict[str, str]:
    """Fetch every advertised icon and return a name -> repo-relative path map.

    The image is re-fetched each crawl so the list tracks the server's current
    icon, but it is written back only when its bytes differ from the file
    already on disk -- an unchanged icon is left untouched, a changed one is
    refreshed to the newest.  A server whose icon could not be fetched (no
    token, or a throttled/timed-out harvest) is absent from the map, so
    apply_corrections keeps whatever icon it already had rather than flapping it
    off.  Distinct names that slugify to the same value get a hash suffix so one
    server can't silently overwrite another's file.
    """
    ICON_DIR.mkdir(exist_ok=True)
    paths: dict[str, str] = {}
    used: set[str] = set()
    for result in results:
        if not result.icon_url:
            continue
        fetched = fetch_icon(result.icon_url)
        if fetched is None:
            continue
        slug = slugify(result.name)
        if slug in used:
            slug = f"{slug}-{hashlib.sha1(result.name.encode()).hexdigest()[:8]}"
        used.add(slug)
        filename = f"{slug}{fetched.ext}"
        target = ICON_DIR / filename
        if not (target.exists() and target.read_bytes() == fetched.data):
            target.write_bytes(fetched.data)
        paths[result.name] = f"{ICON_DIR.name}/{filename}"
    return paths


def prune_orphan_icons(servers: list[dict]) -> None:
    """Delete files in server-icons/ that no entry references, so a removed
    server -- or an icon whose filename changed -- leaves nothing behind.

    Pruning is driven by the final server list, not by what was fetched this
    run, so a server keeping a previously downloaded icon (or one untouched by a
    partial --base run) is never deleted.
    """
    if not ICON_DIR.is_dir():
        return
    referenced = {Path(s["icon"]).name for s in servers if s.get("icon")}
    for existing in ICON_DIR.iterdir():
        if existing.is_file() and not existing.name.startswith(".") and existing.name not in referenced:
            existing.unlink()


def apply_corrections(
    servers: list[dict], results: list[ServerResult], fetched_icons: dict[str, str]
) -> tuple[list[dict], list[str], list[str], list[str]]:
    """Returns (updated servers, capability changes, removed names, icon changes).

    Servers that answered on neither transport are dropped from the list; the
    crawl opens this as a PR so a human reviews every removal before it lands.
    An icon is only set when a fresh one was downloaded this run -- a server
    whose icon could not be re-fetched keeps the one it already had rather than
    losing it, since the icon harvest is best-effort.  Files for dropped servers
    are reclaimed separately by prune_orphan_icons.
    """
    by_name = {r.name: r for r in results}
    changes: list[str] = []
    removed: list[str] = []
    icon_changes: list[str] = []
    updated: list[dict] = []
    for entry in servers:
        name = entry.get("name")
        result = by_name.get(name) if isinstance(name, str) else None
        if result is not None and not result.any_reachable:
            removed.append(result.name)
            continue
        if result is not None and result.detected is not None:
            for field in fields(Detection):
                value = getattr(result.detected, field.name)
                if entry.get(field.name) != value:
                    changes.append(f"{entry['name']}: {field.name} {entry.get(field.name)} -> {value}")
                    entry[field.name] = value
        if result is not None:
            fetched_icon = fetched_icons.get(result.name)
            if fetched_icon and fetched_icon != entry.get("icon"):
                icon_changes.append(f"{result.name}: icon {entry.get('icon')} -> {fetched_icon}")
                entry["icon"] = fetched_icon
        updated.append(reorder(entry))
    return updated, changes, removed, icon_changes


_MARK = {True: "✅", False: "❌", None: "—"}


def render_report(
    results: list[ServerResult],
    changes: list[str],
    removed: list[str],
    icon_changes: list[str],
    icons_checked: bool = False,
    scope: str | None = None,
) -> str:
    lines = ["## Server list probe", ""]
    if scope:
        lines += [f"_{scope}_", ""]
    if not results:
        lines += ["No connectivity-affecting changes to validate. ✅", ""]
        return "\n".join(lines) + "\n"

    lines += ["| Server | wss | ircs | obsidian | sasl | voice | icon |", "|---|---|---|---|---|---|---|"]
    for r in results:
        by_transport = {e.transport: e for e in r.endpoints}

        def cell(transport: str) -> str:
            endpoint = by_transport.get(transport)
            return _MARK[endpoint.reachable] if endpoint else "—"

        def flag(name: str) -> str:
            if r.detected is None:
                return "—"
            return _MARK[getattr(r.detected, name)]

        icon_cell = _MARK[bool(r.icon_url)] if icons_checked else "—"
        lines.append(
            f"| {r.name} | {cell('wss')} | {cell('ircs')} | "
            f"{flag('obsidian')} | {flag('sasl')} | {flag('voice')} | {icon_cell} |"
        )

    removed_set = set(removed)
    dropped = [r for r in results if r.name in removed_set]
    failed = [r for r in results if not r.any_reachable and r.name not in removed_set]
    degraded = [r for r in results if r.any_reachable and any(not e.reachable for e in r.endpoints)]

    if dropped:
        lines += ["", "### Removed — unreachable, dropped from list", ""]
        lines += [f"- **{r.name}** — {failure_reason(r)}" for r in dropped]
    if failed:
        lines += ["", "### Failed — unreachable on every transport", ""]
        lines += [f"- **{r.name}** — {failure_reason(r)}" for r in failed]
    if degraded:
        lines += ["", "### Degraded — one transport unreachable", ""]
        for r in degraded:
            errs = "; ".join(f"{e.transport}: {e.error}" for e in r.endpoints if e.error)
            lines.append(f"- **{r.name}** — {errs}")
    if changes:
        lines += ["", "### Capability corrections", ""]
        lines += [f"- {c}" for c in changes]
    if icon_changes:
        lines += ["", "### Icon updates", ""]
        lines += [f"- {c}" for c in icon_changes]
    return "\n".join(lines) + "\n"


async def run(args: argparse.Namespace) -> int:
    servers = load_servers()

    to_probe = servers
    scope = None
    if args.base:
        to_probe = changed_servers(servers, args.base)
        scope = f"Scope: {len(to_probe)} server(s) changed vs `{args.base}`"

    results = list(await asyncio.gather(*(probe_server(s, args.timeout) for s in to_probe)))

    changes: list[str] = []
    removed: list[str] = []
    icon_changes: list[str] = []
    if args.apply:
        icon_urls = await asyncio.gather(*(harvest_icon(s, args.timeout) for s in to_probe))
        for result, icon_url in zip(results, icon_urls):
            result.icon_url = icon_url
        fetched_icons = download_icons(results)
        updated, changes, removed, icon_changes = apply_corrections(servers, results, fetched_icons)
        SERVERS_FILE.write_text(
            json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )
        prune_orphan_icons(updated)

    report = render_report(results, changes, removed, icon_changes, icons_checked=args.apply, scope=scope)
    print(json.dumps([asdict(r) for r in results], indent=2))
    if args.report:
        Path(args.report).write_text(report, encoding="utf-8")

    if args.check:
        failing = [r.name for r in results if not r.endpoints or not all(e.reachable for e in r.endpoints)]
        if failing:
            print(f"servers failing connectivity: {', '.join(failing)}", file=sys.stderr)
            return 1
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Probe ObsidianIRC server list connectivity and caps")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-endpoint timeout in seconds")
    parser.add_argument("--report", help="write a Markdown report to this path")
    parser.add_argument("--apply", action="store_true", help="write detected caps + icons back into servers.json")
    parser.add_argument("--check", action="store_true", help="exit non-zero if any probed endpoint is unreachable")
    parser.add_argument("--base", help="git ref to diff against; only probe servers whose transport changed")
    args = parser.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
