#!/usr/bin/env python3
"""Nginx auth_request helper: verify JWT then delegate authorization to OPA."""
import os

import requests
from flask import Flask, Response, request

from jwt_auth import verify_session_token

from state_paths import ensure_state_dirs

app = Flask(__name__)
OPA_URL = os.getenv(
    "OPA_URL",
    "http://opa:8181/v1/data/govportal/authz/allow",
)

PUBLIC_PATHS = {
    "/health",
    "/.well-known/jwks.json",
    "/api/storage/login",
    "/api/storage/officers/login",
    "/api/storage/register",
    "/api/storage/register/officer",
    "/api/storage/register/thirdparty",
    "/api/storage/qr-register",
}


def _normalize_path(path: str) -> str:
    if not path:
        return "/"
    return path.split("?", 1)[0]


def _is_public(path: str) -> bool:
    path = _normalize_path(path)
    if path in PUBLIC_PATHS:
        return True
    return path.startswith("/api/storage/register/")


@app.route("/auth", methods=["GET", "POST"])
def authorize():
    path = _normalize_path(request.headers.get("X-Original-URI", request.path))
    method = request.headers.get("X-Original-Method", request.method)

    if _is_public(path):
        return Response(status=200)

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return Response(status=401)

    token = auth_header.removeprefix("Bearer ").strip()
    claims = verify_session_token(token)
    if not claims:
        return Response(status=401)

    try:
        resp = requests.post(
            OPA_URL,
            json={
                "input": {
                    "method": method,
                    "path": path,
                    "user_id": claims["sub"],
                    "user_type": claims["user_type"],
                }
            },
            timeout=3,
        )
        resp.raise_for_status()
        allowed = bool(resp.json().get("result"))
    except Exception:
        return Response(status=503)

    return Response(status=200 if allowed else 403)


if __name__ == "__main__":
    ensure_state_dirs()
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "9191")), debug=False)
