"""Who may use the server, and how it knows: the pieces shared by its three access channels.

Each request falls into exactly one channel, decided in one place (`Access.channel`) from how the server
was started and from the address the request really came from:

- local:   the server was started on a loopback address. Nothing here changes its rules.
- ingress: started with --ingress, and the peer is the Home Assistant supervisor (`SUPERVISOR`).
- lan:     everything else on a non-loopback bind: a host allowlist and a password.

The peer is always the address of the TCP connection. A header (X-Forwarded-For, X-Ingress-Path,
X-Remote-User-Id...) is something any client can write, so no access decision rests on one. (The one header the server reads, X-Forwarded-Proto, only decides whether the session cookie is marked Secure.)
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import os
import secrets
import socket
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

SUPERVISOR = "172.30.32.2"   # where Home Assistant's ingress proxy connects from; no flag changes it (see Access.supervisor)
LOCAL, INGRESS, LAN = "local", "ingress", "lan"
COOKIE = "zlm_session"
SESSION_TTL = 7 * 24 * 3600   # seconds since the session was last used
PASSWORD_ENV = "ZLM_PASSWORD"


class AccessError(ValueError):
    """A start-up setting that cannot be accepted; the message says what to change."""


def ip_of(text: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """An address as written by a socket or a Host header, with IPv4-mapped IPv6 (::ffff:a.b.c.d) as the IPv4 it is."""
    if not text:
        return None
    try:
        ip = ipaddress.ip_address(text.partition("%")[0].strip("[]"))   # a scope id (fe80::1%en0) names an interface, not a host
    except ValueError:
        return None
    return (ip.ipv4_mapped or ip) if ip.version == 6 else ip


def literal(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """How a browser writes this address in a URL."""
    return f"[{ip}]" if ip.version == 6 else str(ip)


def is_loopback(host: str) -> bool:
    """Whether binding `host` keeps the server reachable from this computer only. A name counts only if every address it has does."""
    if host.lower() == "localhost":
        return True
    ip = ip_of(host)
    if ip is not None:
        return ip.is_loopback
    if not host:
        return False   # an empty host binds every interface
    try:
        found = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError:
        return False
    return bool(found) and all((addr := ip_of(a)) is not None and addr.is_loopback for a in found)


def authority(text: str) -> tuple[str, int | None] | None:
    """(lower-case host name or address, port) of a Host header or an --allowed-host value; None when it is not a plain authority."""
    if not text or any(c in text for c in "@/?#\\ \t") or "://" in text:
        return None
    try:
        parts = urlsplit("//" + text)
        return (parts.hostname.lower(), parts.port) if parts.hostname else None
    except ValueError:
        return None


def parse_allowed_host(text: str) -> tuple[str, int | None]:
    found = authority(text.strip())
    if found is None:
        raise AccessError(f"--allowed-host {text!r} is not a host name: give a name such as zigbee.home.example, with or without :port")
    return found


def read_password(env: Mapping[str, str], path: str | None) -> str | None:
    """From --password-file (its first line) or else ZLM_PASSWORD; never from a command-line value, which any user could read in the process list."""
    if path is not None:
        try:
            lines = Path(path).expanduser().read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError) as exc:
            raise AccessError(f"cannot read the file given to --password-file ({getattr(exc, 'strerror', None) or 'not UTF-8 text'})") from None
        value = lines[0] if lines else ""
        where = "the first line of the --password-file file"
    elif PASSWORD_ENV in env:
        value, where = env[PASSWORD_ENV], f"the {PASSWORD_ENV} environment variable"
    else:
        return None
    if not value.strip():
        raise AccessError(f"{where} is empty: an empty password would let everyone in")
    return value


@dataclass(frozen=True)
class Access:
    """How the server was started. The default is today's behaviour: loopback only."""

    host: str = "127.0.0.1"
    password: str | None = field(default=None, repr=False)
    ingress: bool = False
    allowed_hosts: tuple[tuple[str, int | None], ...] = ()
    # A parameter so tests can play the supervisor; the command line has no flag for it. Trusting some other peer
    # (a loopback one, say) without a Host check would reopen DNS rebinding.
    supervisor: str = SUPERVISOR
    loopback: bool = field(init=False, default=True)

    def __post_init__(self) -> None:
        object.__setattr__(self, "loopback", is_loopback(self.host))
        if self.password is not None and not self.password.strip():
            raise AccessError("the password is empty: an empty password would let everyone in")
        if not self.loopback and self.password is None and not self.ingress:
            raise AccessError(f"{self.host} is reachable from your network, so it needs a password: set the {PASSWORD_ENV} environment "
                              "variable or pass --password-file FILE (or --ingress when it runs behind Home Assistant). "
                              "To keep it on this computer, use --host 127.0.0.1")

    def channel(self, peer: str | None) -> str:
        """The one place the channel of a request is decided. `peer` is the address of the TCP connection."""
        if self.loopback:
            return LOCAL
        if self.ingress and (ip := ip_of(peer)) is not None and ip == ip_of(self.supervisor):
            return INGRESS
        return LAN

    # -- lan channel: who the request says it is addressed to
    def host_ok(self, host: str, socket_ip: str, port: int) -> bool:
        """The Host must be the address of the socket the request arrived on (with the port), or an --allowed-host name."""
        found = authority(host)
        if found is None:
            return False
        name, given = found
        mine = ip_of(socket_ip)
        if mine is not None and ip_of(name) == mine and given == port:
            return True
        return any(name == allowed and given in ((wanted,) if wanted is not None else (None, port)) for allowed, wanted in self.allowed_hosts)

    def origin_ok(self, origin: str, socket_ip: str) -> bool:
        """An Origin names a host without a reliable port (browsers and extensions rewrite it), so only the host is compared."""
        try:
            name = urlsplit(origin).hostname
        except ValueError:
            return False
        if not name:
            return False
        mine = ip_of(socket_ip)
        return (mine is not None and ip_of(name) == mine) or any(name.lower() == allowed for allowed, _ in self.allowed_hosts)

    def password_ok(self, given: str) -> bool:
        """Constant time, and on digests so that neither the content nor the length of the password shows in the timing."""
        if self.password is None:
            return False
        return hmac.compare_digest(_digest(given), _digest(self.password))

    def url(self, port: int) -> str:
        """Where to point a browser on this computer: the bind address itself, or the loopback address when the bind is a wildcard."""
        ip = ip_of(self.host)
        if ip is None:
            return f"http://{self.host}:{port}/" if self.host else f"http://127.0.0.1:{port}/"
        if ip.is_unspecified:
            return f"http://{'[::1]' if ip.version == 6 else '127.0.0.1'}:{port}/"
        return f"http://{literal(ip)}:{port}/"


def _digest(text: str) -> bytes:
    return hashlib.sha256(text.encode("utf-8", "replace")).digest()


def from_args(args, env: Mapping[str, str] | None = None) -> Access:
    """The access settings of a parsed command line. An argument set that has none of the network options (an older caller) is a loopback bind."""
    return Access(host=getattr(args, "host", Access.host), password=read_password(os.environ if env is None else env, getattr(args, "password_file", None)),
                  ingress=getattr(args, "ingress", False), allowed_hosts=tuple(parse_allowed_host(h) for h in getattr(args, "allowed_host", [])))


class Sessions:
    """Signed-in browsers, in memory only: a restart signs everyone out."""

    MAX = 64

    def __init__(self, clock: Callable[[], float] = time.monotonic, ttl: float = SESSION_TTL) -> None:
        self.clock, self.ttl = clock, ttl
        self._last_used: dict[str, float] = {}

    def start(self) -> str:
        now = self.clock()
        for stale in [sid for sid, used in self._last_used.items() if now - used > self.ttl]:
            del self._last_used[stale]
        while len(self._last_used) >= self.MAX:
            del self._last_used[min(self._last_used, key=self._last_used.get)]
        sid = secrets.token_urlsafe(32)
        self._last_used[sid] = now
        return sid

    def valid(self, sid: str | None) -> bool:
        used = self._last_used.get(sid or "")
        if used is None:
            return False
        now = self.clock()
        if now - used > self.ttl:
            del self._last_used[sid]
            return False
        self._last_used[sid] = now
        return True

    def end(self, sid: str | None) -> None:
        self._last_used.pop(sid or "", None)


class Throttle:
    """After `free` failures in a row, each further failure doubles the wait (base, 2*base... up to `cap` seconds)."""

    FORGET = 600.0   # seconds without a failure after which the count starts again
    MAX_KEYS = 1024

    def __init__(self, free: int, clock: Callable[[], float], base: float = 1.0, cap: float = 60.0) -> None:
        self.free, self.clock, self.base, self.cap = free, clock, base, cap
        self._state: dict[str, tuple[int, float, float]] = {}   # key -> failures, locked until, last failure

    def wait(self, key: str) -> float:
        _failures, until, _last = self._state.get(key, (0, 0.0, 0.0))
        return max(0.0, until - self.clock())

    def failed(self, key: str) -> None:
        now = self.clock()
        count, _until, last = self._state.get(key, (0, 0.0, 0.0))
        count = 1 if now - last > self.FORGET else count + 1
        delay = min(self.cap, self.base * 2 ** (count - self.free - 1)) if count > self.free else 0.0
        if key not in self._state and len(self._state) >= self.MAX_KEYS:
            del self._state[min(self._state, key=lambda k: self._state[k][2])]
        self._state[key] = (count, now + delay, now)

    def cleared(self, key: str) -> None:
        self._state.pop(key, None)


class LoginGuard:
    """Makes guessing the password impractical, without ever sleeping and without judging an attempt that is made too early.

    Each peer address gets a few free failures, then waits that double up to a minute. A second, global counter with a
    higher allowance covers an attacker with many addresses, and the peer a reverse proxy presents is one address for all.
    While a wait is running the password is not even compared: otherwise the refusal itself would tell a right guess from a wrong one.
    """

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self.peers, self.everyone = Throttle(3, clock), Throttle(20, clock)

    def wait(self, peer: str) -> float:
        return max(self.peers.wait(peer), self.everyone.wait("*"))

    def failed(self, peer: str) -> None:
        self.peers.failed(peer)
        self.everyone.failed("*")

    def succeeded(self, peer: str) -> None:
        self.peers.cleared(peer)
