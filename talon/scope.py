"""Scope & authorization gate.

This is the single most important module for staying on the right side of the
line between "security researcher" and "unauthorized access". Talon refuses to
touch a target unless the operator has explicitly asserted authorization, and
it hard-limits every request to the authorized origins.

Rules enforced here:
  * No scan runs without an explicit authorization assertion (--authorize).
  * Only the exact origins (scheme + host + port) derived from the provided
    targets are ever contacted. A different port on the same host, and any
    link/redirect to another origin, is catalogued but never probed.
  * Cloud metadata / link-local addresses are ALWAYS blocked, even with
    --allow-local, including hostnames that *resolve* to them.
  * Loopback / private addresses are blocked unless the operator opted in with
    --allow-local. This is checked by resolving the hostname, so a public name
    that points at 127.0.0.1 / a private IP (DNS-rebinding-style) is caught.
"""
from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlparse

# Cloud metadata / link-local — never probe these even if asked; an SSRF-style
# redirect into them is exactly the kind of thing we must not chase.
_ALWAYS_BLOCK_HOSTS = {"169.254.169.254", "metadata.google.internal"}
_LOCAL_NAMES = {"localhost", "localhost.localdomain"}
_DEFAULT_PORT = {"http": 80, "https": 443}


class ScopeError(Exception):
    """Raised when an action would fall outside the authorized scope."""


def _origin_of(url: str) -> tuple[str, int]:
    """(host, port) for a URL, defaulting the port from the scheme."""
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower()
    port = parsed.port or _DEFAULT_PORT.get(parsed.scheme, 443)
    return host, port


@dataclass
class Scope:
    # Exact authorized origins as (host, port) pairs.
    allowed_origins: set[tuple[str, int]] = field(default_factory=set)
    allow_local: bool = False
    authorized: bool = False
    _dns_cache: dict[str, list] = field(default_factory=dict, repr=False)

    @property
    def allowed_hosts(self) -> set[str]:
        """Hostnames in scope (kept for reporting / disclosure)."""
        return {h for h, _ in self.allowed_origins}

    @classmethod
    def from_targets(
        cls, targets: list[str], *, authorized: bool, allow_local: bool = False
    ) -> "Scope":
        origins: set[tuple[str, int]] = set()
        for t in targets:
            host, port = _origin_of(t)
            if not host:
                raise ScopeError(f"Cannot determine host for target: {t!r}")
            origins.add((host, port))
        return cls(
            allowed_origins=origins, allow_local=allow_local, authorized=authorized
        )

    def require_authorized(self) -> None:
        if not self.authorized:
            raise ScopeError(
                "Refusing to scan: authorization was not asserted. Re-run with "
                "--authorize to confirm you own these targets or they are in "
                "scope for a disclosure/bug-bounty program."
            )

    # --- address resolution -------------------------------------------------
    def _resolve(self, host: str) -> list[ipaddress._BaseAddress]:
        """Resolve `host` to IP objects. A literal IP resolves to itself.

        DNS failures return [] (treated as "nothing proven local"): we never
        want a lookup error to silently *widen* scope, and the origin-membership
        check is the real gate anyway.
        """
        if host in self._dns_cache:
            return self._dns_cache[host]
        try:
            ips = [ipaddress.ip_address(host)]
        except ValueError:
            ips = []
            try:
                for info in socket.getaddrinfo(host, None):
                    try:
                        ips.append(ipaddress.ip_address(info[4][0]))
                    except ValueError:
                        continue
            except (socket.gaierror, OSError):
                ips = []
        self._dns_cache[host] = ips
        return ips

    def _host_rules(self, host: str) -> None:
        """Raise ScopeError for metadata/link-local (always) and, unless
        --allow-local, for loopback/private addresses — including names that
        resolve to them."""
        if not host:
            raise ScopeError("Empty host")
        if host in _ALWAYS_BLOCK_HOSTS:
            raise ScopeError(
                f"Host {host} is always out of scope (metadata/link-local)"
            )
        ips = self._resolve(host)
        for ip in ips:
            if ip.is_link_local or str(ip) in _ALWAYS_BLOCK_HOSTS:
                raise ScopeError(
                    f"Host {host} resolves to link-local/metadata address {ip}; "
                    f"always out of scope"
                )
        if not self.allow_local:
            is_local = host in _LOCAL_NAMES or any(
                ip.is_loopback or ip.is_private for ip in ips
            )
            if is_local:
                where = f" (resolves to {ips[0]})" if ips else ""
                raise ScopeError(
                    f"Host {host} looks local{where}; pass --allow-local only "
                    f"for your own test environments."
                )

    def check_host(self, host: str) -> None:
        """Raise ScopeError if `host` must not be contacted at all.

        Host-level only (no port): metadata/local rules plus membership in the
        authorized host set. Per-request checks use check_url, which also pins
        the port.
        """
        host = (host or "").lower()
        self._host_rules(host)
        if host not in self.allowed_hosts:
            raise ScopeError(f"Host {host} is outside the authorized scope")

    def check_url(self, url: str) -> None:
        """Raise ScopeError if this exact origin (host + port) is out of scope.

        Membership is checked first so an out-of-scope origin fails fast without
        a DNS lookup.
        """
        host, port = _origin_of(url)
        if not host:
            raise ScopeError("Empty host")
        if (host, port) not in self.allowed_origins:
            raise ScopeError(
                f"{host}:{port} is outside the authorized scope "
                f"(only the exact origins you named are in scope)"
            )
        self._host_rules(host)

    def check_targets(self, targets: list[str]) -> None:
        """Raise ScopeError if any seed target itself may not be contacted.

        Without this, a blocked target (e.g. localhost without --allow-local)
        is silently skipped and the scan looks like a clean result.
        """
        for t in targets:
            try:
                self.check_url(t)
            except ScopeError as e:
                raise ScopeError(f"Cannot scan target {t!r}: {e}") from None

    def in_scope(self, url: str) -> bool:
        """Non-throwing variant used by the crawler to filter links."""
        try:
            self.check_url(url)
            return True
        except ScopeError:
            return False

    def banner(self) -> str:
        origins = ", ".join(
            f"{h}:{p}" for h, p in sorted(self.allowed_origins)
        ) or "(none)"
        return (
            "AUTHORIZED-USE-ONLY | in-scope origins: " + origins +
            ("  [local testing enabled]" if self.allow_local else "")
        )
