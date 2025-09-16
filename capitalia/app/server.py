from __future__ import annotations

"""
Servidor HTTP puro usando a biblioteca padrão (`http.server.HTTPServer`).

Atende ao requisito de "servidor nativo da linguagem" (sem frameworks web),
expondo os handlers construídos em `app/handlers.py`.
"""

from http.server import HTTPServer
from typing import Type


def run_server(handler_cls: Type, port: int) -> None:
    # allow quick restarts without TIME_WAIT issues
    HTTPServer.allow_reuse_address = True
    httpd = HTTPServer(("0.0.0.0", port), handler_cls)
    print(f"[server] Listening on 0.0.0.0:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[server] Shutting down...")
    finally:
        httpd.server_close()
