"""JWT session tokens signed with dedicated ECDSA P-256 keys (ES256).

JWT keys and JWKS live under STATE_ROOT/jwt (default /state/jwt in Docker).
Separate from mTLS, PKI, and ML-DSA document-signing material.
"""
import base64
import json
import logging
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from state_paths import (
    JWT_DIR,
    JWT_PRIVATE_KEY_FILE,
    JWT_PUBLIC_KEY_FILE,
    JWKS_FILE,
    ensure_state_dirs,
)

logger = logging.getLogger("storage-service")

JWT_ALG = "ES256"
JWT_KID = "govportal-jwt-es256-v1"
JWT_ISSUER = "govportal-storage-service"
JWT_TTL_SECONDS = int(__import__("os").getenv("JWT_TTL_SECONDS", "3600"))

_private_key = None
_public_key = None


def _write_pem(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _b64url_uint(value: int) -> str:
    length = (value.bit_length() + 7) // 8
    return base64.urlsafe_b64encode(value.to_bytes(length, "big")).decode("ascii").rstrip("=")


def build_jwks_document(public_key=None) -> dict:
    ensure_jwt_keys()
    key = public_key or _public_key
    numbers = key.public_key().public_numbers() if hasattr(key, "public_key") else key.public_numbers()
    if not isinstance(numbers.curve, ec.SECP256R1):
        raise ValueError("JWKS builder expects ECDSA P-256 public key")
    return {
        "keys": [
            {
                "kty": "EC",
                "crv": "P-256",
                "kid": JWT_KID,
                "use": "sig",
                "alg": JWT_ALG,
                "x": _b64url_uint(numbers.x),
                "y": _b64url_uint(numbers.y),
            }
        ]
    }


def ensure_jwks_file() -> Path:
    ensure_state_dirs()
    document = build_jwks_document()
    JWKS_FILE.write_text(json.dumps(document, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return JWKS_FILE


def load_jwks_document() -> dict:
    ensure_jwks_file()
    return json.loads(JWKS_FILE.read_text(encoding="utf-8"))


def ensure_jwt_keys() -> None:
    global _private_key, _public_key
    if _private_key is not None and _public_key is not None:
        return

    ensure_state_dirs()
    if not JWT_PRIVATE_KEY_FILE.exists() or not JWT_PUBLIC_KEY_FILE.exists():
        logger.info("Generating dedicated ECDSA P-256 JWT key pair in %s", JWT_DIR)
        key = ec.generate_private_key(ec.SECP256R1())
        private_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        public_pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        _write_pem(JWT_PRIVATE_KEY_FILE, private_pem)
        _write_pem(JWT_PUBLIC_KEY_FILE, public_pem)

    private_pem = JWT_PRIVATE_KEY_FILE.read_bytes()
    public_pem = JWT_PUBLIC_KEY_FILE.read_bytes()
    _private_key = serialization.load_pem_private_key(private_pem, password=None)
    _public_key = serialization.load_pem_public_key(public_pem)
    ensure_jwks_file()


def create_session_token(user_id: str, user_type: str):
    """Return (jwt_token, jti, expires_at)."""
    ensure_jwt_keys()
    jti = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(seconds=JWT_TTL_SECONDS)
    payload = {
        "sub": user_id,
        "user_type": user_type,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "iss": JWT_ISSUER,
    }
    headers = {"kid": JWT_KID}
    token = jwt.encode(payload, _private_key, algorithm=JWT_ALG, headers=headers)
    if isinstance(token, bytes):
        token = token.decode("ascii")
    return token, jti, expires_at


def verify_session_token(token: str):
    """Verify JWT signature and return payload dict, or None if invalid."""
    if not token or token.count(".") != 2:
        return None
    ensure_jwt_keys()
    try:
        return jwt.decode(
            token,
            _public_key,
            algorithms=[JWT_ALG],
            issuer=JWT_ISSUER,
            options={"require": ["sub", "user_type", "jti", "exp"]},
        )
    except jwt.PyJWTError as exc:
        logger.debug("JWT verification failed: %s", exc)
        return None
