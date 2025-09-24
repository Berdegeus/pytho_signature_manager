from __future__ import annotations

"""Minimal HTTP primitives used by the manual HTTP server.

The goal is to avoid the helpers from :mod:`http.server` and provide the
building blocks necessary to implement our own handler chain.
"""

from dataclasses import dataclass, field
from typing import Callable, Dict, Optional, Pattern, Tuple


@dataclass(slots=True)
class HttpRequest:
    """Represents an HTTP/1.1 request received by the server."""

    method: str
    target: str
    path: str
    query: str
    headers: Dict[str, str]
    body: bytes
    client: Optional[Tuple[str, int]] = None


@dataclass(slots=True)
class HttpResponse:
    """Represents an HTTP/1.1 response produced by the handlers."""

    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    def ensure_content_length(self) -> None:
        """Guarantee the ``Content-Length`` header is present."""

        if "Content-Length" not in self.headers:
            self.headers["Content-Length"] = str(len(self.body))


class Handler:
    """Chain-of-responsibility handler interface."""

    def set_next(self, handler: "Handler") -> "Handler":
        raise NotImplementedError

    def handle(self, ctx: "RequestContext") -> HttpResponse:
        raise NotImplementedError


@dataclass(slots=True)
class RequestContext:
    """Mutable context passed across the handler chain."""

    request: HttpRequest
    response: Optional[HttpResponse] = None
    route: Optional["Route"] = None
    params: Dict[str, str] = field(default_factory=dict)
    claims: Optional[Dict[str, object]] = None


@dataclass(slots=True)
class Route:
    """Metadata describing a single HTTP route."""

    name: str
    pattern: Pattern[str]
    methods: set[str]
    handler: Callable[["RequestContext"], HttpResponse]
    requires_auth: bool = False
    authorize: Optional[Callable[["RequestContext"], Optional[HttpResponse]]] = None


__all__ = [
    "Handler",
    "HttpRequest",
    "HttpResponse",
    "RequestContext",
    "Route",
]

