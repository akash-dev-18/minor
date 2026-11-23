from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from app.core.config import Settings

logger = logging.getLogger(__name__)

ALLOWED_SCHEMES = {"http", "https"}
ALLOWED_PORTS = {80, 443, 8080, 8443}
USER_AGENT = "Sentinel/0.1 (email security analysis)"


class UnsafeTargetError(Exception):
    pass


class TargetUnresolvedError(UnsafeTargetError):
    pass


def is_disallowed_ip(value: str, allow_private: bool = False) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return True
    if allow_private:
        return False
    return (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    )


async def resolve_host(host: str) -> list[str]:
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.getaddrinfo(host, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetUnresolvedError(f"Host could not be resolved: {host}") from exc
    addresses = []
    for info in infos:
        address = info[4][0]
        if address not in addresses:
            addresses.append(address)
    if not addresses:
        raise TargetUnresolvedError(f"Host resolved to no addresses: {host}")
    return addresses


async def validate_target(url: str, settings: Settings) -> list[str]:
    try:
        parts = urlsplit(url)
    except ValueError as exc:
        raise UnsafeTargetError("Malformed URL") from exc

    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeTargetError("Only HTTP and HTTPS URLs may be fetched")
    if not parts.hostname:
        raise UnsafeTargetError("URL has no hostname")
    if len(url) > 4096:
        raise UnsafeTargetError("URL is too long")

    port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    if port not in ALLOWED_PORTS:
        raise UnsafeTargetError(f"Port {port} is not allowed for URL inspection")

    host = parts.hostname.strip("[]")
    addresses: list[str]
    try:
        addresses = [str(ipaddress.ip_address(host))]
    except ValueError:
        addresses = await resolve_host(host)

    for address in addresses:
        if is_disallowed_ip(address, settings.allow_private_url_fetch):
            raise UnsafeTargetError("URL resolves to a private or reserved address")
    return addresses


@dataclass
class RedirectHop:
    url: str
    status: int | None = None
    location: str | None = None
    error: str | None = None


@dataclass
class FetchResult:
    chain: list[RedirectHop] = field(default_factory=list)
    final_url: str | None = None
    body_bytes: int = 0
    error: str | None = None
    blocked: bool = False

    def to_dict(self) -> dict:
        return {
            "chain": [
                {
                    "url": hop.url,
                    "status": hop.status,
                    "location": hop.location,
                    "error": hop.error,
                }
                for hop in self.chain
            ],
            "final_url": self.final_url,
            "body_bytes": self.body_bytes,
            "error": self.error,
            "blocked": self.blocked,
        }


async def fetch_redirect_chain(url: str, settings: Settings) -> FetchResult:
    result = FetchResult()
    current = url

    if not settings.url_fetch_enabled:
        result.error = "URL fetching is disabled by configuration"
        return result

    try:
        await validate_target(current, settings)
    except TargetUnresolvedError as exc:
        result.error = str(exc)
        return result
    except UnsafeTargetError as exc:
        result.error = str(exc)
        result.blocked = True
        return result

    timeout = httpx.Timeout(settings.url_fetch_timeout_seconds)
    async with httpx.AsyncClient(
        timeout=timeout,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Accept": "*/*"},
    ) as client:
        for _ in range(settings.url_max_redirects + 1):
            try:
                async with client.stream("GET", current) as response:
                    hop = RedirectHop(url=current, status=response.status_code)
                    result.chain.append(hop)
                    location = response.headers.get("location")

                    if response.status_code in {301, 302, 303, 307, 308} and location:
                        next_url = urljoin(current, location)
                        hop.location = next_url
                        try:
                            await validate_target(next_url, settings)
                        except TargetUnresolvedError as exc:
                            result.error = f"Redirect target could not be resolved: {exc}"
                            return result
                        except UnsafeTargetError as exc:
                            result.error = f"Redirect blocked: {exc}"
                            result.blocked = True
                            return result
                        current = next_url
                        continue

                    result.final_url = current
                    received = 0
                    async for chunk in response.aiter_bytes():
                        received += len(chunk)
                        if received >= settings.url_max_response_bytes:
                            break
                    result.body_bytes = received
                    return result
            except (httpx.HTTPError, OSError) as exc:
                result.chain.append(RedirectHop(url=current, error=type(exc).__name__))
                result.error = f"Request failed: {type(exc).__name__}"
                result.final_url = current
                return result

    result.error = "Too many redirects"
    return result
