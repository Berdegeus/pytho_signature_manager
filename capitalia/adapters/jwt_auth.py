from __future__ import annotations

import base64
import hmac
import json
import time
from hashlib import sha256
from typing import Dict, Any


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(data: str) -> bytes:
    pad = '=' * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def sign(payload: Dict[str, Any], secret: str, ttl_seconds: int = 3600) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    now = int(time.time())
    body = dict(payload)
    if "iat" not in body:
        body["iat"] = now
    if "exp" not in body:
        body["exp"] = now + ttl_seconds

    header_b64 = _b64url(json.dumps(header, separators=(",", ":")).encode())
    payload_b64 = _b64url(json.dumps(body, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}".encode()
    signature = hmac.new(secret.encode(), signing_input, sha256).digest()
    sig_b64 = _b64url(signature)
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify(token: str, secret: str) -> Dict[str, Any]:
    try:
        header_b64, payload_b64, sig_b64 = token.split('.')
    except ValueError:
        raise ValueError("invalid token format")
    signing_input = f"{header_b64}.{payload_b64}".encode()
    expected = hmac.new(secret.encode(), signing_input, sha256).digest()
    actual = _b64url_decode(sig_b64)
    if not hmac.compare_digest(expected, actual):
        raise ValueError("invalid signature")
    payload = json.loads(_b64url_decode(payload_b64))
    exp = int(payload.get("exp", 0))
    if exp and int(time.time()) > exp:
        raise ValueError("token expired")
    return payload

