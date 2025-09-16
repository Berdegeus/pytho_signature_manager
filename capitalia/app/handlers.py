from __future__ import annotations

import json
import re
from urllib.parse import urlsplit
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from typing import Dict, Any

from ..adapters.jwt_auth import sign as jwt_sign, verify as jwt_verify
from ..domain.errors import NotFoundError, ValidationError
from ..ports.clock import RealClock
from ..domain.services import SubscriptionService


def build_handler(uow_factory, jwt_secret: str, clock=None):
    clock = clock or RealClock()

    class Handler(BaseHTTPRequestHandler):
        server_version = "CapitaliaHTTP/1.0"
        _routes = {
            "GET": [
                (re.compile(r"^/health$"), "health"),
                (re.compile(r"^/user/(?P<uid>\d+)/status$"), "get_status"),
            ],
            "POST": [
                (re.compile(r"^/login$"), "login"),
                (re.compile(r"^/user/(?P<uid>\d+)/upgrade$"), "upgrade"),
                (re.compile(r"^/user/(?P<uid>\d+)/downgrade$"), "downgrade"),
                (re.compile(r"^/user/(?P<uid>\d+)/suspend$"), "suspend"),
                (re.compile(r"^/user/(?P<uid>\d+)/reactivate$"), "reactivate"),
            ],
        }

        def _json(self, code: int, data: Dict[str, Any]):
            self._resp_code = code
            body = json.dumps(data).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def _read_json(self) -> Dict[str, Any]:
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length > 0 else b"{}"
            try:
                return json.loads(raw.decode() or "{}")
            except json.JSONDecodeError:
                raise ValidationError("invalid JSON body")

        def _unauthorized(self, msg: str = "Unauthorized"):
            self._json(HTTPStatus.UNAUTHORIZED, {"error": msg})

        def _not_found(self):
            self._json(HTTPStatus.NOT_FOUND, {"error": "Not Found"})

        def _error(self, msg: str = "Internal Server Error"):
            self._json(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": msg})

        def _forbidden(self, msg: str = "Forbidden"):
            self._json(HTTPStatus.FORBIDDEN, {"error": msg})

        def _bad_request(self, msg: str = "Bad Request"):
            self._json(HTTPStatus.BAD_REQUEST, {"error": msg})

        def _method_not_allowed(self, allowed: set[str]):
            self._resp_code = HTTPStatus.METHOD_NOT_ALLOWED
            body = json.dumps({"error": "Method Not Allowed"}).encode()
            self.send_response(HTTPStatus.METHOD_NOT_ALLOWED)
            self.send_header("Content-Type", "application/json")
            self.send_header("Allow", ", ".join(sorted(allowed)))
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(body)

        def _parse_auth(self) -> Dict[str, Any]:
            header = self.headers.get("Authorization")
            if not header or not header.startswith("Bearer "):
                raise ValueError("missing bearer token")
            token = header.split(" ", 1)[1].strip()
            return jwt_verify(token, jwt_secret)

        def _authorize_user(self, uid: int) -> bool:
            try:
                sub = self.claims.get("sub")
                if sub is None:
                    return False
                return int(sub) == int(uid)
            except Exception:  # noqa: BLE001
                return False

        def _route(self, method: str, path: str):
            for regex, name in self._routes.get(method, []):
                match = regex.match(path)
                if match:
                    return name, match.groupdict()
            return None, {}

        def _allowed_methods_for_path(self, path: str) -> set[str]:
            allowed = set()
            for m, routes in self._routes.items():
                for regex, _ in routes:
                    if regex.match(path):
                        allowed.add(m)
                        break
            return allowed

        def _log(self, start: float, code: int):
            dur_ms = round((time.time() - start) * 1000, 1)
            entry = {
                "ts": int(time.time() * 1000),
                "method": self.command,
                "path": self.path,
                "status": int(code),
                "ms": dur_ms,
                "remote": self.client_address[0] if self.client_address else None,
            }
            try:
                print(json.dumps(entry, separators=(",", ":")))
            except Exception:  # noqa: BLE001
                pass

        def _send_headers(self, code: int, allowed: set[str] | None = None):
            self._resp_code = code
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "0")
            self.send_header("Access-Control-Allow-Origin", "*")
            if allowed:
                self.send_header("Allow", ", ".join(sorted(allowed)))
            self.end_headers()

        def do_GET(self):  # noqa: N802
            start = time.time()
            self._resp_code = 500
            try:
                route_path = urlsplit(self.path).path
                name, params = self._route("GET", route_path)
                if name is None:
                    allowed = self._allowed_methods_for_path(route_path)
                    if allowed:
                        self._method_not_allowed(allowed)
                    else:
                        self._not_found()
                    return
                if name not in {"login", "health"}:
                    try:
                        self.claims = self._parse_auth()
                    except Exception as e:  # noqa: BLE001
                        self._unauthorized(str(e))
                        return
                if name == "health":
                    self._json(HTTPStatus.OK, {"status": "ok"})
                elif name == "get_status":
                    uid = int(params["uid"])
                    if not self._authorize_user(uid):
                        self._forbidden("cannot access another user's status")
                        return
                    self._handle_get_status(uid)
                else:
                    self._not_found()
            except Exception:  # noqa: BLE001
                self._error()
            finally:
                self._log(start, getattr(self, "_resp_code", 500))

        def do_HEAD(self):  # noqa: N802
            start = time.time()
            self._resp_code = 500
            try:
                route_path = urlsplit(self.path).path
                name, params = self._route("GET", route_path)
                if name is None:
                    allowed = self._allowed_methods_for_path(route_path)
                    if allowed:
                        self._send_headers(HTTPStatus.METHOD_NOT_ALLOWED, allowed)
                    else:
                        self._send_headers(HTTPStatus.NOT_FOUND)
                    return
                if name not in {"login", "health"}:
                    try:
                        self.claims = self._parse_auth()
                    except Exception as e:  # noqa: BLE001
                        self._send_headers(HTTPStatus.UNAUTHORIZED)
                        return
                if name in {"health", "get_status"}:
                    self._send_headers(HTTPStatus.OK)
                else:
                    self._send_headers(HTTPStatus.NOT_FOUND)
            except Exception:  # noqa: BLE001
                self._send_headers(HTTPStatus.INTERNAL_SERVER_ERROR)
            finally:
                self._log(start, getattr(self, "_resp_code", 500))

        def do_OPTIONS(self):  # noqa: N802
            start = time.time()
            self._resp_code = 204
            try:
                route_path = urlsplit(self.path).path
                allowed = self._allowed_methods_for_path(route_path)
                if not allowed:
                    allowed = {"GET", "POST"}
                allowed_with_options = set(allowed) | {"OPTIONS"}
                self.send_response(HTTPStatus.NO_CONTENT)
                self.send_header("Allow", ", ".join(sorted(allowed_with_options)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "Authorization, Content-Type")
                self.send_header("Access-Control-Allow-Methods", ", ".join(sorted(allowed)))
                self.send_header("Content-Length", "0")
                self.end_headers()
            finally:
                self._log(start, getattr(self, "_resp_code", 204))

        def do_POST(self):  # noqa: N802
            start = time.time()
            self._resp_code = 500
            try:
                route_path = urlsplit(self.path).path
                name, params = self._route("POST", route_path)
                if name is None:
                    allowed = self._allowed_methods_for_path(route_path)
                    if allowed:
                        self._method_not_allowed(allowed)
                    else:
                        self._not_found()
                    return
                if name == "login":
                    ct = (self.headers.get("Content-Type") or "").lower()
                    if "application/json" not in ct:
                        self._bad_request("Content-Type must be application/json")
                        return
                    self._handle_login()
                    return
                try:
                    self.claims = self._parse_auth()
                except Exception as e:  # noqa: BLE001
                    self._unauthorized(str(e))
                    return
                uid = int(params.get("uid"))
                if not self._authorize_user(uid):
                    self._forbidden("cannot modify another user's plan")
                    return
                if name == "upgrade":
                    self._handle_upgrade(uid)
                elif name == "downgrade":
                    self._handle_downgrade(uid)
                elif name == "suspend":
                    self._handle_suspend(uid)
                elif name == "reactivate":
                    self._handle_reactivate(uid)
                else:
                    self._not_found()
            except ValidationError as ve:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(ve)})
            except Exception:  # noqa: BLE001
                self._error()
            finally:
                self._log(start, getattr(self, "_resp_code", 500))

        # Handlers
        def _handle_login(self):
            body = self._read_json()
            email = (body.get("email") or "").strip()
            password = body.get("password") or ""
            if not email or not password:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": "email and password required"})
                return
            # authenticate
            with uow_factory() as uow:
                user = uow.users.get_by_email(email)
                if not user:
                    self._unauthorized("invalid credentials")
                    return
                import hashlib

                ph = hashlib.sha256((user.salt + password).encode()).hexdigest()
                if ph != user.password_hash:
                    self._unauthorized("invalid credentials")
                    return
                token = jwt_sign({"sub": user.id, "email": user.email, "plan": user.plan}, jwt_secret, 3600)
                self._json(HTTPStatus.OK, {"token": token})

        def _handle_get_status(self, uid: int):
            svc = SubscriptionService(uow_factory, clock)
            try:
                result = svc.read_effective_status(uid)
                self._json(HTTPStatus.OK, result)
            except NotFoundError:
                self._not_found()

        def _handle_upgrade(self, uid: int):
            svc = SubscriptionService(uow_factory, clock)
            try:
                result = svc.upgrade(uid)
                self._json(HTTPStatus.OK, result)
            except NotFoundError:
                self._not_found()
            except ValidationError as ve:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(ve)})

        def _handle_downgrade(self, uid: int):
            svc = SubscriptionService(uow_factory, clock)
            try:
                result = svc.downgrade(uid)
                self._json(HTTPStatus.OK, result)
            except NotFoundError:
                self._not_found()
            except ValidationError as ve:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(ve)})

        def _handle_suspend(self, uid: int):
            svc = SubscriptionService(uow_factory, clock)
            try:
                result = svc.suspend(uid)
                self._json(HTTPStatus.OK, result)
            except NotFoundError:
                self._not_found()
            except ValidationError as ve:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(ve)})

        def _handle_reactivate(self, uid: int):
            svc = SubscriptionService(uow_factory, clock)
            try:
                result = svc.reactivate(uid)
                self._json(HTTPStatus.OK, result)
            except NotFoundError:
                self._not_found()
            except ValidationError as ve:
                self._json(HTTPStatus.UNPROCESSABLE_ENTITY, {"error": str(ve)})

        # Quiet default logging
        def log_message(self, format, *args):  # noqa: A003 - http.server API
            return

    return Handler
