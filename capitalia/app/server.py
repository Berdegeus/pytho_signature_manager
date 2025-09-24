from __future__ import annotations

"""Manual HTTP/1.1 server implemented directly over sockets."""

import json
import socket
import threading
from contextlib import suppress
from http import HTTPStatus
from typing import Protocol, Tuple
from urllib.parse import urlsplit

from .http import HttpRequest, HttpResponse

MAX_HEADER_BYTES = 16 * 1024
MAX_BODY_BYTES = 5 * 1024 * 1024


class RequestHandler(Protocol):
    def handle(self, request: HttpRequest) -> HttpResponse:
        """Process ``request`` and return an HTTP response."""


def run_server(handler: RequestHandler, port: int) -> None:
    """Start a blocking TCP server that delegates to ``handler``."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("0.0.0.0", port))
        sock.listen(128)
        print(f"[server] Listening on 0.0.0.0:{port}")
        try:
            while True:
                conn, addr = sock.accept()
                thread = threading.Thread(target=_serve_connection, args=(conn, addr, handler), daemon=True)
                thread.start()
        except KeyboardInterrupt:
            print("\n[server] Shutting down...")


def _serve_connection(conn: socket.socket, addr: Tuple[str, int], handler: RequestHandler) -> None:
    with conn:
        conn.settimeout(30)
        try:
            request = _read_request(conn, addr)
            if request is None:
                return
        except ValueError as exc:
            _send_simple_response(conn, HTTPStatus.BAD_REQUEST, str(exc))
            return
        except Exception:
            _send_simple_response(conn, HTTPStatus.BAD_REQUEST, "Malformed request")
            return

        try:
            response = handler.handle(request)
        except Exception:  # noqa: BLE001
            response = HttpResponse(
                int(HTTPStatus.INTERNAL_SERVER_ERROR),
                {
                    "Content-Type": "application/json",
                },
                json.dumps({"error": "Internal Server Error"}).encode(),
            )
            response.ensure_content_length()
            response.headers.setdefault("Access-Control-Allow-Origin", "*")

        _send_response(conn, request, response)


def _read_request(conn: socket.socket, addr: Tuple[str, int]) -> HttpRequest | None:
    buffer = bytearray()
    while b"\r\n\r\n" not in buffer:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buffer.extend(chunk)
        if len(buffer) > MAX_HEADER_BYTES:
            raise ValueError("header section too large")

    header_part, body_part = buffer.split(b"\r\n\r\n", 1)
    lines = header_part.split(b"\r\n")
    if not lines:
        raise ValueError("invalid request line")
    request_line = lines[0].decode("iso-8859-1").strip()
    parts = request_line.split()
    if len(parts) != 3:
        raise ValueError("invalid request line")
    method, target, version = parts
    method = method.upper()
    if version not in {"HTTP/1.1", "HTTP/1.0"}:
        raise ValueError("unsupported HTTP version")

    headers: dict[str, str] = {}
    for raw in lines[1:]:
        if not raw:
            continue
        if b":" not in raw:
            raise ValueError("invalid header")
        name, value = raw.split(b":", 1)
        headers[name.decode("ascii", "ignore").strip().lower()] = value.decode("iso-8859-1").strip()

    content_length = 0
    if "content-length" in headers:
        with suppress(ValueError):
            content_length = int(headers["content-length"]) if headers["content-length"] else 0
    content_length = max(0, min(content_length, MAX_BODY_BYTES))

    body = bytearray(body_part[:content_length])
    while len(body) < content_length:
        chunk = conn.recv(min(65536, content_length - len(body)))
        if not chunk:
            break
        body.extend(chunk)

    parsed = urlsplit(target)
    path = parsed.path or "/"

    return HttpRequest(
        method=method,
        target=target,
        path=path,
        query=parsed.query,
        headers=headers,
        body=bytes(body[:content_length]),
        client=addr,
    )


def _send_response(conn: socket.socket, request: HttpRequest, response: HttpResponse) -> None:
    response.headers.setdefault("Connection", "close")
    response.ensure_content_length()
    try:
        reason = HTTPStatus(response.status).phrase
    except ValueError:
        reason = "OK"
    status_line = f"HTTP/1.1 {int(response.status)} {reason}\r\n"
    header_lines = "".join(f"{name.title()}: {value}\r\n" for name, value in response.headers.items())
    conn.sendall(status_line.encode("iso-8859-1"))
    conn.sendall(header_lines.encode("iso-8859-1"))
    conn.sendall(b"\r\n")
    if request.method != "HEAD" and response.body:
        conn.sendall(response.body)


def _send_simple_response(conn: socket.socket, status: HTTPStatus, message: str) -> None:
    payload = json.dumps({"error": message}).encode()
    status_line = f"HTTP/1.1 {int(status)} {status.phrase}\r\n"
    headers = (
        "Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        "Access-Control-Allow-Origin: *\r\n"
        "Connection: close\r\n"
    )
    conn.sendall(status_line.encode("iso-8859-1"))
    conn.sendall(headers.encode("iso-8859-1"))
    conn.sendall(b"\r\n")
    conn.sendall(payload)
