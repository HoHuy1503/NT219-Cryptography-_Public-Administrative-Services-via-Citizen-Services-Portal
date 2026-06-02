"""Canonical paths for cryptographic material under state/.

Layout (relative to STATE_ROOT, default DEPLOY/D2/state when running locally):

  jwt/       jwt_ec_private.pem, jwt_ec_public.pem, jwks.json
  mtls/      ca/, gateway/, services/, clients/
  pki/       ca_key.pem, ca_cert.pem, ca_public.pem, issued_certs.json
  mldsa/     ml_dsa_priv.pem, ml_dsa_pub.pem, pub_published.json
             (legacy: priv.bin, pub.bin)

Set STATE_ROOT explicitly for local runs, e.g.:
  export STATE_ROOT="$(pwd)/state"
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Sequence

_MODULE_DIR = Path(__file__).resolve().parent


def resolve_state_root() -> Path:
    explicit = os.getenv("STATE_ROOT", "").strip()
    if explicit:
        return Path(explicit).expanduser().resolve()

    docker_mount = Path("/state")
    if (docker_mount / "jwt").is_dir() or (docker_mount / "pki").is_dir():
        return docker_mount

    local = _MODULE_DIR / "state"
    if local.is_dir():
        return local.resolve()

    return docker_mount


STATE_ROOT = resolve_state_root()

# JWT session tokens (ES256) — not used for document signing or mTLS
JWT_DIR = Path(os.getenv("JWT_DIR", str(STATE_ROOT / "jwt"))).resolve()
JWKS_FILE = Path(os.getenv("JWKS_FILE", str(JWT_DIR / "jwks.json"))).resolve()
JWT_PRIVATE_KEY_FILE = JWT_DIR / "jwt_ec_private.pem"
JWT_PUBLIC_KEY_FILE = JWT_DIR / "jwt_ec_public.pem"

# mTLS trust (gateway ↔ services)
MTLS_DIR = STATE_ROOT / "mtls"
MTLS_CA_CERT = MTLS_DIR / "ca" / "ca.crt"
MTLS_CA_KEY = MTLS_DIR / "ca" / "ca.key"
MTLS_GATEWAY_SERVER_CERT = MTLS_DIR / "gateway" / "server.crt"
MTLS_GATEWAY_SERVER_KEY = MTLS_DIR / "gateway" / "server.key"
MTLS_GATEWAY_CLIENT_CERT = MTLS_DIR / "gateway" / "client.crt"
MTLS_GATEWAY_CLIENT_KEY = MTLS_DIR / "gateway" / "client.key"

# Document PKI (officer certificates)
PKI_DIR = Path(os.getenv("PKI_DIR", str(STATE_ROOT / "pki"))).resolve()
PKI_CA_KEY = PKI_DIR / "ca_key.pem"
PKI_CA_CERT = PKI_DIR / "ca_cert.pem"
PKI_CA_PUBLIC = PKI_DIR / "ca_public.pem"
PKI_CERT_STORE = PKI_DIR / "issued_certs.json"

# ML-DSA document signing
MLDSA_DIR = Path(os.getenv("MLDSA_DIR", str(STATE_ROOT / "mldsa"))).resolve()
MLDSA_PUBLISHED_JSON = MLDSA_DIR / "pub_published.json"
MLDSA_PRIV_PEM = MLDSA_DIR / "ml_dsa_priv.pem"
MLDSA_PUB_PEM = MLDSA_DIR / "ml_dsa_pub.pem"
MLDSA_PRIV_LEGACY = MLDSA_DIR / "priv.bin"
MLDSA_PUB_LEGACY = MLDSA_DIR / "pub.bin"

MLDSA_PRIV_CANDIDATES = (MLDSA_PRIV_PEM, MLDSA_PRIV_LEGACY)
MLDSA_PUB_CANDIDATES = (MLDSA_PUB_PEM, MLDSA_PUB_LEGACY)


def first_existing(*paths: Sequence[Path] | Path) -> Optional[Path]:
    flat: list[Path] = []
    for item in paths:
        if isinstance(item, Path):
            flat.append(item)
        else:
            flat.extend(item)
    for path in flat:
        if path.is_file():
            return path
    return None


def read_text_file(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def read_bytes_file(*candidates: Path) -> Optional[bytes]:
    found = first_existing(*candidates)
    return found.read_bytes() if found else None


def write_text_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def write_bytes_file(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)


def ensure_state_dirs() -> None:
    for directory in (JWT_DIR, PKI_DIR, MLDSA_DIR, MTLS_DIR):
        directory.mkdir(parents=True, exist_ok=True)
