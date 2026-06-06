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
"""
import argparse
import asyncio
import ipaddress
import json
import socket
import ssl
import subprocess
import sys
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from urllib.parse import urlsplit

import websockets
from websockets import Origin

REPO_ROOT = Path(__file__).resolve().parent.parent
SERVERS_FILE = REPO_ROOT / "servers.json"

VOICE_CAPS = ("obsidianirc/voice", "obby.world/voice")
OBBY_VENDOR_PREFIXES = ("obsidianirc/", "obby.world/")

# Canonical key order so --apply keeps servers.json tidy and new fields land in
# a predictable place rather than at the end of each object.
FIELD_ORDER = ("name", "description", "wss", "ircs", "obsidian", "sasl", "voice")

DEFAULT_TIMEOUT = 12.0
DEFAULT_IRCS_PORT = 6697

# A real browser WebSocket always sends an Origin header, and some IRC
# WebSocket gateways reject upgrades without one (HTTP 403).  Mirroring the
# Discover page's browser client avoids spurious "unreachable" verdicts.
WSS_USER_AGENT = "Mozilla/5.0 (compatible; ObsidianIRC-probe/1.0)"


@dataclass
class Detection:
    obsidian: bool
    sasl: bool
    voice: bool


@dataclass
class TransportProbe:
    """Full result of probing one transport, including the raw caps used only
    internally to derive detection -- not serialized into the report."""

    transport: str
    url: str
    reachable: bool
    error: str | None
    caps: dict[str, str]


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


class CapCollector:
    """State machine that consumes raw IRC lines and assembles a CAP LS reply.

    A `CAP LS 302` response is split across one or more lines; every line but
    the last carries a `*` continuation marker between `LS` and the trailing
    capability list.
    """

    def __init__(self) -> None:
        self.caps: dict[str, str] = {}
        self.done = False
        self.pong: str | None = None

    def feed(self, line: str) -> None:
        line = line.rstrip()
        if not line:
            return
        if line.startswith("PING"):
            self.pong = "PONG" + line[4:]
            return
        head, _, trailing = line.partition(" :")
        parts = head.split()
        if "CAP" not in parts:
            return
        idx = parts.index("CAP")
        if len(parts) <= idx + 2 or parts[idx + 2] != "LS":
            return
        more = len(parts) > idx + 3 and parts[idx + 3] == "*"
        for token in trailing.split():
            name, _, value = token.partition("=")
            self.caps[name] = value
        if not more:
            self.done = True


def detect(caps: dict[str, str]) -> Detection:
    names = caps.keys()
    return Detection(
        obsidian=any(n.startswith(OBBY_VENDOR_PREFIXES) for n in names),
        sasl="sasl" in caps,
        voice=any(v in caps for v in VOICE_CAPS),
    )


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


async def _non_public_target(host: str, port: int) -> str | None:
    """Reject loopback/private/link-local/reserved destinations.

    The PR-validation workflow probes contributor-supplied hosts and echoes the
    result into a public comment, so an unchecked target lets a PR use the
    runner to reach internal addresses (e.g. cloud metadata at 169.254.169.254).
    """
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            return f"refused non-public address {ip}"
    return None


async def probe_wss(url: str, timeout: float) -> TransportProbe:
    return await _with_retries(lambda: _attempt_wss(url, timeout))


async def _attempt_wss(url: str, timeout: float) -> TransportProbe:
    collector = CapCollector()
    error: str | None = None
    parsed = urlsplit(url)
    origin = Origin(f"https://{parsed.hostname}") if parsed.hostname else None
    try:
        async with asyncio.timeout(timeout):
            blocked = await _non_public_target(parsed.hostname or "", parsed.port or 443)
            if blocked:
                return TransportProbe("wss", url, False, blocked, {})
            async with websockets.connect(
                url,
                ssl=ssl.create_default_context(),
                open_timeout=timeout,
                close_timeout=3,
                max_size=None,
                origin=origin,
                user_agent_header=WSS_USER_AGENT,
            ) as ws:
                await ws.send("CAP LS 302\r\n")
                while not collector.done:
                    message = await ws.recv()
                    text = message if isinstance(message, str) else message.decode("utf-8", "replace")
                    for line in text.replace("\r", "").split("\n"):
                        collector.feed(line)
                        if collector.pong:
                            await ws.send(collector.pong + "\r\n")
                            collector.pong = None
    except (OSError, ssl.SSLError, asyncio.TimeoutError, websockets.WebSocketException) as exc:
        error = f"{type(exc).__name__}: {exc}".strip()
    return TransportProbe("wss", url, collector.done, error, collector.caps)


async def probe_ircs(url: str, timeout: float) -> TransportProbe:
    return await _with_retries(lambda: _attempt_ircs(url, timeout))


async def _attempt_ircs(url: str, timeout: float) -> TransportProbe:
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    port = parsed.port or DEFAULT_IRCS_PORT
    collector = CapCollector()
    error: str | None = None
    writer: asyncio.StreamWriter | None = None
    try:
        async with asyncio.timeout(timeout):
            blocked = await _non_public_target(host, port)
            if blocked:
                return TransportProbe("ircs", url, False, blocked, {})
            reader, writer = await asyncio.open_connection(
                host, port, ssl=ssl.create_default_context(), server_hostname=host
            )
            writer.write(b"CAP LS 302\r\n")
            await writer.drain()
            buffer = ""
            while not collector.done:
                chunk = await reader.read(4096)
                if not chunk:
                    break
                buffer += chunk.decode("utf-8", "replace")
                lines = buffer.split("\n")
                buffer = lines.pop()
                for line in lines:
                    collector.feed(line)
                    if collector.pong:
                        writer.write((collector.pong + "\r\n").encode())
                        await writer.drain()
                        collector.pong = None
    except (OSError, ssl.SSLError, asyncio.TimeoutError) as exc:
        error = f"{type(exc).__name__}: {exc}".strip()
    finally:
        if writer is not None:
            writer.close()
            try:
                await asyncio.wait_for(writer.wait_closed(), timeout=2)
            except (OSError, asyncio.TimeoutError):
                pass
    return TransportProbe("ircs", url, collector.done, error, collector.caps)


async def probe_server(entry: dict, timeout: float) -> ServerResult:
    coros = []
    if entry.get("wss"):
        coros.append(probe_wss(entry["wss"], timeout))
    if entry.get("ircs"):
        coros.append(probe_ircs(entry["ircs"], timeout))

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
    )


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


def apply_corrections(
    servers: list[dict], results: list[ServerResult]
) -> tuple[list[dict], list[str], list[str]]:
    """Returns (updated servers, capability changes, removed names).

    Servers that answered on neither transport are dropped from the list; the
    crawl opens this as a PR so a human reviews every removal before it lands.
    """
    by_name = {r.name: r for r in results}
    changes: list[str] = []
    removed: list[str] = []
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
        updated.append(reorder(entry))
    return updated, changes, removed


_MARK = {True: "✅", False: "❌", None: "—"}


def render_report(
    results: list[ServerResult],
    changes: list[str],
    removed: list[str],
    scope: str | None = None,
) -> str:
    lines = ["## Server list probe", ""]
    if scope:
        lines += [f"_{scope}_", ""]
    if not results:
        lines += ["No connectivity-affecting changes to validate. ✅", ""]
        return "\n".join(lines) + "\n"

    lines += ["| Server | wss | ircs | obsidian | sasl | voice |", "|---|---|---|---|---|---|"]
    for r in results:
        by_transport = {e.transport: e for e in r.endpoints}

        def cell(transport: str) -> str:
            endpoint = by_transport.get(transport)
            return _MARK[endpoint.reachable] if endpoint else "—"

        def flag(name: str) -> str:
            if r.detected is None:
                return "—"
            return _MARK[getattr(r.detected, name)]

        lines.append(
            f"| {r.name} | {cell('wss')} | {cell('ircs')} | "
            f"{flag('obsidian')} | {flag('sasl')} | {flag('voice')} |"
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
    if args.apply:
        updated, changes, removed = apply_corrections(servers, results)
        SERVERS_FILE.write_text(
            json.dumps(updated, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
        )

    report = render_report(results, changes, removed, scope=scope)
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
    parser.add_argument("--apply", action="store_true", help="write detected caps back into servers.json")
    parser.add_argument("--check", action="store_true", help="exit non-zero if any probed endpoint is unreachable")
    parser.add_argument("--base", help="git ref to diff against; only probe servers whose transport changed")
    args = parser.parse_args()
    return asyncio.run(run(args))


if __name__ == "__main__":
    raise SystemExit(main())
