from __future__ import annotations

import hashlib
import json
import re
import time
from http import HTTPStatus
from typing import Any, Callable, Dict, Iterable, Optional

from ..adapters.jwt_auth import sign as jwt_sign, verify as jwt_verify
from ..domain.errors import NotFoundError, ValidationError
from ..domain.services import SubscriptionService
from ..ports.clock import RealClock
from .http import Handler, HttpRequest, HttpResponse, RequestContext, Route


JsonDict = Dict[str, Any]


def make_json_response(status: HTTPStatus | int, data: JsonDict) -> HttpResponse:
    body = json.dumps(data).encode()
    headers = {
        "Content-Type": "application/json",
        "Content-Length": str(len(body)),
    }
    return HttpResponse(int(status), headers, body)


def make_empty_response(status: HTTPStatus | int, headers: Optional[Dict[str, str]] = None) -> HttpResponse:
    final_headers = {"Content-Length": "0"}
    if headers:
        final_headers.update(headers)
    return HttpResponse(int(status), final_headers, b"")


def json_error(status: HTTPStatus | int, message: str, *, extra_headers: Optional[Dict[str, str]] = None) -> HttpResponse:
    resp = make_json_response(status, {"error": message})
    if extra_headers:
        resp.headers.update(extra_headers)
    return resp


def unauthorized(message: str = "Unauthorized") -> HttpResponse:
    return json_error(HTTPStatus.UNAUTHORIZED, message)


def forbidden(message: str = "Forbidden") -> HttpResponse:
    return json_error(HTTPStatus.FORBIDDEN, message)


def not_found() -> HttpResponse:
    return json_error(HTTPStatus.NOT_FOUND, "Not Found")


def bad_request(message: str = "Bad Request") -> HttpResponse:
    return json_error(HTTPStatus.BAD_REQUEST, message)


class AbstractHandler(Handler):
    def __init__(self) -> None:
        self._next: Optional[Handler] = None

    def set_next(self, handler: Handler) -> Handler:
        self._next = handler
        return handler

    def _handle_next(self, ctx: RequestContext) -> HttpResponse:
        if self._next is None:
            if ctx.response is None:
                ctx.response = json_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Unhandled request")
            return ctx.response
        return self._next.handle(ctx)


class ErrorHandler(AbstractHandler):
    def handle(self, ctx: RequestContext) -> HttpResponse:  # noqa: D401
        try:
            return self._handle_next(ctx)
        except Exception:  # noqa: BLE001
            ctx.response = json_error(HTTPStatus.INTERNAL_SERVER_ERROR, "Internal Server Error")
            return ctx.response


class LoggingHandler(AbstractHandler):
    def handle(self, ctx: RequestContext) -> HttpResponse:  # noqa: D401
        start = time.time()
        response = self._handle_next(ctx)
        duration_ms = round((time.time() - start) * 1000, 1)
        entry = {
            "ts": int(time.time() * 1000),
            "method": ctx.request.method,
            "path": ctx.request.path,
            "status": int(response.status),
            "ms": duration_ms,
            "remote": ctx.request.client[0] if ctx.request.client else None,
        }
        try:
            print(json.dumps(entry, separators=(",", ":")))
        except Exception:  # noqa: BLE001
            pass
        return response


class OptionsHandler(AbstractHandler):
    def __init__(self, routes: Iterable[Route]) -> None:
        super().__init__()
        self._routes = list(routes)

    def handle(self, ctx: RequestContext) -> HttpResponse:  # noqa: D401
        if ctx.request.method != "OPTIONS":
            return self._handle_next(ctx)
        allowed = self._allowed_methods(ctx.request.path)
        if not allowed:
            allowed = {"GET", "POST"}
        allow_header = ", ".join(sorted(allowed | {"OPTIONS"}))
        headers = {
            "Allow": allow_header,
            "Access-Control-Allow-Headers": "Authorization, Content-Type",
            "Access-Control-Allow-Methods": ", ".join(sorted(allowed)),
        }
        ctx.response = make_empty_response(HTTPStatus.NO_CONTENT, headers)
        return ctx.response

    def _allowed_methods(self, path: str) -> set[str]:
        allowed: set[str] = set()
        for route in self._routes:
            if route.pattern.match(path):
                allowed |= route.methods
        result = set()
        for method in allowed:
            result.add(method)
            if method == "GET":
                result.add("HEAD")
        return result


class RoutingHandler(AbstractHandler):
    def __init__(self, routes: Iterable[Route]) -> None:
        super().__init__()
        self._routes = list(routes)

    def handle(self, ctx: RequestContext) -> HttpResponse:  # noqa: D401
        path = ctx.request.path
        request_method = ctx.request.method
        is_head = request_method == "HEAD"
        for route in self._routes:
            match = route.pattern.match(path)
            if not match:
                continue
            ctx.route = route
            ctx.params = match.groupdict()
            allowed = set(route.methods)
            if "GET" in route.methods:
                allowed.add("HEAD")
            method_to_check = "GET" if is_head and "GET" in route.methods else request_method
            if method_to_check not in route.methods:
                headers = {"Allow": ", ".join(sorted(allowed))}
                ctx.response = json_error(HTTPStatus.METHOD_NOT_ALLOWED, "Method Not Allowed", extra_headers=headers)
                return ctx.response
            return self._handle_next(ctx)
        ctx.response = not_found()
        return ctx.response


class AuthHandler(AbstractHandler):
    def __init__(self, jwt_secret: str) -> None:
        super().__init__()
        self._jwt_secret = jwt_secret

    def handle(self, ctx: RequestContext) -> HttpResponse:  # noqa: D401
        route = ctx.route
        if route is None or not route.requires_auth:
            return self._handle_next(ctx)
        auth_header = ctx.request.headers.get("authorization")
        if not auth_header or not auth_header.lower().startswith("bearer "):
            ctx.response = unauthorized("missing bearer token")
            return ctx.response
        token = auth_header.split(" ", 1)[1].strip()
        try:
            ctx.claims = jwt_verify(token, self._jwt_secret)
        except Exception as exc:  # noqa: BLE001
            ctx.response = unauthorized(str(exc))
            return ctx.response
        if route.authorize:
            custom = route.authorize(ctx)
            if custom is not None:
                ctx.response = custom
                return ctx.response
        return self._handle_next(ctx)


class HeadHandler(AbstractHandler):
    def handle(self, ctx: RequestContext) -> HttpResponse:  # noqa: D401
        if ctx.request.method != "HEAD":
            return self._handle_next(ctx)
        if ctx.route is None:
            ctx.response = not_found()
        else:
            ctx.response = make_empty_response(HTTPStatus.OK)
        return ctx.response


class DispatchHandler(AbstractHandler):
    def handle(self, ctx: RequestContext) -> HttpResponse:  # noqa: D401
        if ctx.route is None:
            ctx.response = not_found()
            return ctx.response
        try:
            response = ctx.route.handler(ctx)
        except ValidationError as ve:
            response = json_error(HTTPStatus.UNPROCESSABLE_ENTITY, str(ve))
        except NotFoundError:
            response = not_found()
        ctx.response = response
        return response


class RequestProcessor:
    """Facade executed by the manual HTTP server."""

    def __init__(self, entry: Handler) -> None:
        self._entry = entry

    def handle(self, request: HttpRequest) -> HttpResponse:
        ctx = RequestContext(request=request)
        response = self._entry.handle(ctx)
        response.headers.setdefault("Access-Control-Allow-Origin", "*")
        response.ensure_content_length()
        return response


def build_handler(uow_factory, jwt_secret: str, clock=None):
    clock = clock or RealClock()

    def read_json(request: HttpRequest) -> JsonDict:
        raw = request.body or b"{}"
        try:
            text = raw.decode() or "{}"
        except UnicodeDecodeError as exc:
            raise ValidationError("invalid JSON body") from exc
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            raise ValidationError("invalid JSON body") from exc

    def make_service() -> SubscriptionService:
        return SubscriptionService(uow_factory, clock)

    def handle_login(ctx: RequestContext) -> HttpResponse:
        content_type = (ctx.request.headers.get("content-type") or "").lower()
        if "application/json" not in content_type:
            return bad_request("Content-Type must be application/json")
        body = read_json(ctx.request)
        email = (body.get("email") or "").strip()
        password = body.get("password") or ""
        if not email or not password:
            return json_error(HTTPStatus.UNPROCESSABLE_ENTITY, "email and password required")
        with uow_factory() as uow:
            user = uow.users.get_by_email(email)
            if not user:
                return unauthorized("invalid credentials")
            password_hash = hashlib.sha256((user.salt + password).encode()).hexdigest()
            if password_hash != user.password_hash:
                return unauthorized("invalid credentials")
            token = jwt_sign({"sub": user.id, "email": user.email, "plan": user.plan}, jwt_secret, 3600)
        return make_json_response(HTTPStatus.OK, {"token": token})

    def handle_health(_: RequestContext) -> HttpResponse:
        return make_json_response(HTTPStatus.OK, {"status": "ok"})

    def handle_get_status(ctx: RequestContext) -> HttpResponse:
        svc = make_service()
        uid = int(ctx.params["uid"])
        result = svc.read_effective_status(uid)
        return make_json_response(HTTPStatus.OK, result)

    def handle_upgrade(ctx: RequestContext) -> HttpResponse:
        svc = make_service()
        uid = int(ctx.params["uid"])
        result = svc.upgrade(uid)
        return make_json_response(HTTPStatus.OK, result)

    def handle_downgrade(ctx: RequestContext) -> HttpResponse:
        svc = make_service()
        uid = int(ctx.params["uid"])
        result = svc.downgrade(uid)
        return make_json_response(HTTPStatus.OK, result)

    def handle_suspend(ctx: RequestContext) -> HttpResponse:
        svc = make_service()
        uid = int(ctx.params["uid"])
        result = svc.suspend(uid)
        return make_json_response(HTTPStatus.OK, result)

    def handle_reactivate(ctx: RequestContext) -> HttpResponse:
        svc = make_service()
        uid = int(ctx.params["uid"])
        result = svc.reactivate(uid)
        return make_json_response(HTTPStatus.OK, result)

    def ensure_same_user(message: str) -> Callable[[RequestContext], Optional[HttpResponse]]:
        def checker(ctx: RequestContext) -> Optional[HttpResponse]:
            uid = ctx.params.get("uid")
            try:
                subject = ctx.claims.get("sub") if ctx.claims else None
                if uid is None or subject is None or int(subject) != int(uid):
                    return forbidden(message)
            except Exception:  # noqa: BLE001
                return forbidden(message)
            return None

        return checker

    routes: list[Route] = [
        Route("health", re.compile(r"^/health$"), {"GET"}, handle_health, requires_auth=False),
        Route(
            "get_status",
            re.compile(r"^/user/(?P<uid>\\d+)/status$"),
            {"GET"},
            handle_get_status,
            requires_auth=True,
            authorize=ensure_same_user("cannot access another user's status"),
        ),
        Route("login", re.compile(r"^/login$"), {"POST"}, handle_login, requires_auth=False),
        Route(
            "upgrade",
            re.compile(r"^/user/(?P<uid>\\d+)/upgrade$"),
            {"POST"},
            handle_upgrade,
            requires_auth=True,
            authorize=ensure_same_user("cannot modify another user's plan"),
        ),
        Route(
            "downgrade",
            re.compile(r"^/user/(?P<uid>\\d+)/downgrade$"),
            {"POST"},
            handle_downgrade,
            requires_auth=True,
            authorize=ensure_same_user("cannot modify another user's plan"),
        ),
        Route(
            "suspend",
            re.compile(r"^/user/(?P<uid>\\d+)/suspend$"),
            {"POST"},
            handle_suspend,
            requires_auth=True,
            authorize=ensure_same_user("cannot modify another user's plan"),
        ),
        Route(
            "reactivate",
            re.compile(r"^/user/(?P<uid>\\d+)/reactivate$"),
            {"POST"},
            handle_reactivate,
            requires_auth=True,
            authorize=ensure_same_user("cannot modify another user's plan"),
        ),
    ]

    logging_handler = LoggingHandler()
    error_handler = ErrorHandler()
    options_handler = OptionsHandler(routes)
    routing_handler = RoutingHandler(routes)
    auth_handler = AuthHandler(jwt_secret)
    head_handler = HeadHandler()
    dispatch_handler = DispatchHandler()

    logging_handler.set_next(error_handler)
    error_handler.set_next(options_handler)
    options_handler.set_next(routing_handler)
    routing_handler.set_next(auth_handler)
    auth_handler.set_next(head_handler)
    head_handler.set_next(dispatch_handler)

    return RequestProcessor(logging_handler)


__all__ = [
    "build_handler",
    "RequestProcessor",
]

