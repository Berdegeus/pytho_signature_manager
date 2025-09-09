from __future__ import annotations

from http.server import HTTPServer
from typing import Type


def run_server(handler_cls: Type, port: int) -> None:
    httpd = HTTPServer(("0.0.0.0", port), handler_cls)
    print(f"[server] Listening on 0.0.0.0:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] Shutting down...")
    finally:
        httpd.server_close()

