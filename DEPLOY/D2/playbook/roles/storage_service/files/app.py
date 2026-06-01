#!/usr/bin/env python3

import base64
import json
import logging
import os
import uuid
import hashlib
import secrets
import requests
from datetime import datetime, timezone
from functools import wraps

HVAC_AVAILABLE = False
import time
import random
from datetime import datetime, timedelta, timezone
from flask import Flask, jsonify, request, Response, g
from flask_cors import CORS
from psycopg2 import connect, OperationalError
from psycopg2.extras import Json, RealDictCursor
from cryptography.hazmat.primitives.serialization import load_pem_public_key

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("storage-service")

app = Flask(__name__)
# Configure CORS to allow custom headers used by the portals (X-User-ID, X-User-Type)
# and allow requests from any origin for UI development.
CORS(app, resources={r"/api/*": {"origins": "*"}}, allow_headers=["Content-Type", "Authorization", "X-Requested-With", "X-User-ID", "X-User-Type", "x-user-id", "x-user-type"]) 

@app.after_request
def _add_cors_headers(response):
    response.headers.setdefault("Access-Control-Allow-Origin", "*")
    response.headers.setdefault("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With, X-User-ID, X-User-Type")
    response.headers.setdefault("Access-Control-Allow-Methods", "GET, POST, OPTIONS, PUT, DELETE")
    return response

# Vault removed for local/develop deployments - secrets are provided via env/files
STORAGE_DB_URL = os.getenv("STORAGE_DATABASE_URL", "") or os.getenv("DATABASE_URL", "")
STORAGE_DB_HOST = os.getenv("STORAGE_DB_HOST", "storage-postgres")
STORAGE_DB_PORT = int(os.getenv("STORAGE_DB_PORT", "5432"))
STORAGE_DB_NAME = os.getenv("STORAGE_DB_NAME", "govportal_storage")
STORAGE_DB_USER = os.getenv("STORAGE_DB_USER", "govportal_storage")
STORAGE_DB_PASSWORD = os.getenv("STORAGE_DB_PASSWORD", "")
STORAGE_DB_SSLMODE = os.getenv("STORAGE_DB_SSLMODE", "disable")
SERVICE_NAME = "storage-service"
SERVICE_LISTEN = os.getenv("SERVICE_LISTEN", "0.0.0.0")
SERVICE_PORT = int(os.getenv("SERVICE_PORT", "9003"))
DOC_SERVICE_URL = os.getenv("DOC_SERVICE_URL", "http://doc_service:5000")
LOCAL_MODE = os.getenv("LOCAL_MODE", "false").lower() == "true"
SCHEMA_READY = False
ALLOWED_OFFICER_KEY_ALGORITHMS = {"ML-DSA", "ML-DSA-44"}


# Vault client logic removed. Vault is not used in this deployment.


def get_db_connection(retries: int = 5, initial_delay: float = 1.0):
    delay = initial_delay
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            if STORAGE_DB_URL:
                conn = connect(STORAGE_DB_URL)
            else:
                conn = connect(
                    host=STORAGE_DB_HOST,
                    port=STORAGE_DB_PORT,
                    dbname=STORAGE_DB_NAME,
                    user=STORAGE_DB_USER,
                    password=STORAGE_DB_PASSWORD,
                    sslmode=STORAGE_DB_SSLMODE,
                )
            return conn
        except Exception as exc:
            last_exc = exc
            logger.warning("DB connect attempt %d failed: %s", attempt, exc)
            if attempt == retries:
                break
            sleep = delay + random.uniform(0, delay)
            time.sleep(sleep)
            delay *= 2
    raise OperationalError(f"Could not connect to DB after {retries} attempts: {last_exc}")


def ensure_schema():
    global SCHEMA_READY
    if SCHEMA_READY:
        return

    conn = get_db_connection(retries=10, initial_delay=1.0)
    cur = conn.cursor()
    try:
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS documents (
                doc_id TEXT PRIMARY KEY,
                citizen_id TEXT NOT NULL REFERENCES citizens(citizen_id) ON DELETE CASCADE,
                doc_type TEXT NOT NULL,
                doc_title TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                created_by TEXT,
                signed_by TEXT,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                signed_at TIMESTAMPTZ,
                archived_at TIMESTAMPTZ
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS signatures (
                sig_id TEXT PRIMARY KEY,
                doc_id TEXT NOT NULL REFERENCES documents(doc_id) ON DELETE CASCADE,
                officer_id TEXT,
                signature_data TEXT NOT NULL,
                signature_algorithm TEXT NOT NULL,
                key_version INTEGER NOT NULL DEFAULT 1,
                signed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                verified_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id BIGSERIAL PRIMARY KEY,
                action TEXT NOT NULL,
                actor_id TEXT,
                actor_role TEXT NOT NULL,
                resource_type TEXT NOT NULL,
                resource_id TEXT NOT NULL,
                timestamp TIMESTAMPTZ NOT NULL,
                details JSONB NOT NULL DEFAULT '{}'::jsonb,
                status TEXT NOT NULL,
                error_message TEXT
            )
            """
        )
        # Separate tables for each user type - no RBAC
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS citizens (
                citizen_id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT,
                password_salt TEXT,
                phone TEXT,
                region_code TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                verified BOOLEAN NOT NULL DEFAULT FALSE,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS officers (
                officer_id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT,
                password_salt TEXT,
                department TEXT,
                phone TEXT,
                region_code TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute("ALTER TABLE citizens ADD COLUMN IF NOT EXISTS region_code TEXT")
        cur.execute("ALTER TABLE officers ADD COLUMN IF NOT EXISTS region_code TEXT")
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS storage_admins (
                admin_id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT,
                password_salt TEXT,
                phone TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS pki_admins (
                admin_id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                name TEXT NOT NULL,
                password_hash TEXT,
                password_salt TEXT,
                phone TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS thirdparty_users (
                thirdparty_id TEXT PRIMARY KEY,
                email TEXT UNIQUE,
                org_name TEXT NOT NULL,
                contact_person TEXT,
                password_hash TEXT,
                password_salt TEXT,
                phone TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                last_login TIMESTAMPTZ,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS thirdparty_requests (
                request_id TEXT PRIMARY KEY,
                citizen_id TEXT NOT NULL REFERENCES citizens(citizen_id) ON DELETE CASCADE,
                thirdparty_id TEXT NOT NULL REFERENCES thirdparty_users(thirdparty_id) ON DELETE CASCADE,
                resource_id TEXT,
                resource_type TEXT,
                reason TEXT,
                status TEXT NOT NULL DEFAULT 'PENDING',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        # Existing databases may already have documents without the FK; add it if missing.
        cur.execute(
            """
            DO $$
            BEGIN
                IF NOT EXISTS (
                    SELECT 1
                    FROM pg_constraint
                    WHERE conname = 'fk_documents_citizen_id'
                ) THEN
                    ALTER TABLE documents
                    ADD CONSTRAINT fk_documents_citizen_id
                    FOREIGN KEY (citizen_id)
                    REFERENCES citizens(citizen_id)
                    ON DELETE CASCADE;
                END IF;
            END $$;
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS document_sign_requests (
                request_id TEXT PRIMARY KEY,
                doc_id TEXT NOT NULL UNIQUE,
                citizen_id TEXT NOT NULL REFERENCES citizens(citizen_id) ON DELETE CASCADE,
                officer_id TEXT NOT NULL REFERENCES officers(officer_id) ON DELETE CASCADE,
                doc_type TEXT NOT NULL,
                doc_title TEXT NOT NULL,
                content_hash TEXT NOT NULL,
                document_base64 TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                reason TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                reviewed_at TIMESTAMPTZ,
                reviewed_by TEXT,
                signed_at TIMESTAMPTZ,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_document_sign_requests_officer_status
            ON document_sign_requests (officer_id, status, created_at DESC)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_document_sign_requests_citizen_status
            ON document_sign_requests (citizen_id, status, created_at DESC)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_thirdparty_requests_thirdparty
            ON thirdparty_requests (thirdparty_id)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_thirdparty_requests_citizen
            ON thirdparty_requests (citizen_id)
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS officer_keys (
                key_id TEXT PRIMARY KEY,
                officer_id TEXT NOT NULL REFERENCES officers(officer_id) ON DELETE CASCADE,
                public_key_pem TEXT NOT NULL,
                key_type TEXT NOT NULL,
                is_current BOOLEAN NOT NULL DEFAULT FALSE,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ,
                rotated_at TIMESTAMPTZ,
                auto_rotate_at TIMESTAMPTZ,
                key_version INTEGER NOT NULL DEFAULT 1
            )
            """
        )
        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_officer_keys_one_current
            ON officer_keys (officer_id)
            WHERE is_current
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_officer_keys_officer_current
            ON officer_keys (officer_id, is_current)
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                user_type TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_sessions_user_id
            ON sessions (user_id, user_type)
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS officer_key_requests (
                request_id TEXT PRIMARY KEY,
                officer_id TEXT NOT NULL REFERENCES officers(officer_id) ON DELETE CASCADE,
                requested_by TEXT NOT NULL,
                reason TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                resolved_at TIMESTAMPTZ,
                resolved_by TEXT,
                old_key_id TEXT,
                new_key_id TEXT,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_officer_key_requests_officer_status
            ON officer_key_requests (officer_id, status, created_at DESC)
            """
        )
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS document_qr (
                qr_id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL,
                document_type TEXT NOT NULL,
                key_b64 TEXT NOT NULL,
                encrypted_data TEXT NOT NULL,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_by TEXT,
                accessed_count INTEGER DEFAULT 0,
                last_accessed_at TIMESTAMPTZ
            )
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_document_qr_doc_id
            ON document_qr (document_id)
            """
        )
        cur.execute(
            """
            CREATE INDEX IF NOT EXISTS ix_document_qr_created_at
            ON document_qr (created_at)
            """
        )
        conn.commit()

        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS officer_certificates (
                cert_id TEXT PRIMARY KEY,
                officer_id TEXT NOT NULL REFERENCES officers(officer_id) ON DELETE CASCADE,
                cert_pem TEXT NOT NULL,
                thumbprint TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT TRUE,
                revoked_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                expires_at TIMESTAMPTZ NOT NULL
            )
            """
        )
        cur.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS ux_officer_certs_one_active
            ON officer_certificates (officer_id)
            WHERE is_active = TRUE
            """
        )
        # Certificate requests table for PKI admin approval workflow
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS officer_cert_requests (
                request_id TEXT PRIMARY KEY,
                officer_id TEXT NOT NULL REFERENCES officers(officer_id) ON DELETE CASCADE,
                public_key_pem TEXT NOT NULL,
                common_name TEXT,
                organization TEXT,
                country TEXT,
                st TEXT,
                l TEXT,
                ou TEXT,
                status TEXT NOT NULL DEFAULT 'PENDING',
                cert_id TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                reviewed_at TIMESTAMPTZ,
                reviewed_by TEXT,
                metadata JSONB NOT NULL DEFAULT '{}'::jsonb
            )
            """
        )
        # Seed PKI and Storage admin accounts if not present (pre-initialized credentials)
        try:
            # PKI admin
            cur.execute("SELECT admin_id FROM pki_admins WHERE admin_id = %s", ("pki_admin",))
            if not cur.fetchone():
                p_hash, p_salt = hash_password("pki_adm")
                cur.execute(
                    "INSERT INTO pki_admins (admin_id, email, name, password_hash, password_salt) VALUES (%s, %s, %s, %s, %s)",
                    ("pki_admin", "pki@gov.vn", "PKI Admin", p_hash, p_salt),
                )


    # Seed PKI and Storage admin accounts if not present (pre-initialized credentials)
            # Storage admin
            cur.execute("SELECT admin_id FROM storage_admins WHERE admin_id = %s", ("storage_admin",))
            if not cur.fetchone():
                s_hash, s_salt = hash_password("storage_adm")
                cur.execute(
                    "INSERT INTO storage_admins (admin_id, email, name, password_hash, password_salt) VALUES (%s, %s, %s, %s, %s)",
                    ("storage_admin", "storage@gov.vn", "Storage Admin", s_hash, s_salt),
                )
            conn.commit()

        except Exception as exc:
            logger.warning("admin seeding failed: %s", exc)

        SCHEMA_READY = True
    finally:
        cur.close()
        conn.close()


def _validate_ml_dsa_public_key(public_key_pem: str):
    try:
        public_key = load_pem_public_key(public_key_pem.encode("utf-8"))
    except Exception:
        return False, "Invalid public key PEM"

    key_name = public_key.__class__.__name__.lower()
    if "rsa" in key_name:
        return False, "RSA public keys are not supported"
    if "mldsa" in key_name or "ml_dsa" in key_name:
        return True, None
    return False, "Only ML-DSA public keys are supported"


def write_audit(action, actor_id, resource_type, resource_id, status="SUCCESS", details=None, error_message=None):
    payload = {
        "action": action,
        "actor_id": actor_id,
        "actor_role": "service",
        "resource_type": resource_type,
        "resource_id": resource_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "details": details or {},
        "status": status,
        "error_message": error_message,
    }
    try:
        ensure_schema()
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO audit_log (action, actor_id, actor_role, resource_type, resource_id,
                                   timestamp, details, status, error_message)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                action,
                actor_id,
                payload["actor_role"],
                resource_type,
                resource_id,
                payload["timestamp"],
                Json(payload["details"]),
                status,
                error_message,
            ),
        )
        conn.commit()
        cur.close()
        conn.close()
    except Exception as exc:
        logger.warning("audit insert failed: %s", exc)

    # Vault disabled in this deployment; audit writes to Vault are skipped.
    if not LOCAL_MODE:
        logger.debug("Vault audit write skipped (Vault removed for this deployment)")


def _extract_region_code(metadata, fallback=None):
    if isinstance(metadata, dict):
        region_code = metadata.get("region_code")
        if region_code:
            return str(region_code)
    if fallback:
        return str(fallback)
    return None


def hash_password(password: str, salt: str = None):
    """Hash password using PBKDF2-SHA256"""
    if not salt:
        salt = secrets.token_hex(32)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return pwd_hash.hex(), salt


def verify_password(password: str, pwd_hash: str, salt: str):
    """Verify password against stored hash"""
    try:
        computed_hash, _ = hash_password(password, salt)
        return computed_hash == pwd_hash
    except Exception:
        return False


def require_auth(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if LOCAL_MODE:
            g.current_user_id = request.headers.get("X-User-ID", "local")
            g.current_user_type = request.headers.get("X-User-Type", "local")
            return view(*args, **kwargs)
        header = request.headers.get("Authorization", "")
        if not header.startswith("Bearer "):
            return jsonify({"error": "Missing Bearer token"}), 401
        token = header.removeprefix("Bearer ").strip()
        try:
            ensure_schema()
            conn = get_db_connection()
            cur = conn.cursor(cursor_factory=RealDictCursor)
            try:
                cur.execute(
                    """
                    SELECT session_id, user_id, user_type
                    FROM sessions
                    WHERE session_id = %s AND expires_at > NOW()
                    """,
                    (token,),
                )
                session = cur.fetchone()
            finally:
                cur.close()
                conn.close()
            if not session:
                return jsonify({"error": "Invalid token"}), 401
            g.current_user_id = session["user_id"]
            g.current_user_type = session["user_type"]
            g.current_session_id = session["session_id"]
        except Exception as exc:
            logger.warning("session lookup failed: %s", exc)
            return jsonify({"error": "Invalid token"}), 401
        return view(*args, **kwargs)

    return wrapped


def require_user_type(*allowed_types):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if LOCAL_MODE:
                return view(*args, **kwargs)
            if getattr(g, "current_user_type", None) not in allowed_types:
                return jsonify({"error": "Forbidden"}), 403
            return view(*args, **kwargs)

        return wrapped

    return decorator


@app.route("/health", methods=["GET"])
def health():
    if LOCAL_MODE:
        try:
            ensure_schema()
            conn = get_db_connection()
            conn.close()
            return jsonify({"status": "healthy", "service": SERVICE_NAME, "vault": "disabled", "database": "healthy"}), 200
        except Exception as exc:
            logger.warning("db health degraded: %s", exc)
            return jsonify({"status": "degraded", "service": SERVICE_NAME, "vault": "disabled", "database": "unreachable"}), 200

    try:
        ensure_schema()
        conn = get_db_connection()
        conn.close()
        # Vault is not configured in this deployment
        return jsonify({
            "status": "healthy",
            "service": SERVICE_NAME,
            "vault": "disabled",
            "database": "healthy"
        }), 200
    except Exception as exc:
        logger.warning("db health degraded: %s", exc)
        return jsonify({"status": "degraded", "service": SERVICE_NAME, "vault": "unavailable", "database": "unreachable"}), 200


@app.route("/api/storage/status", methods=["GET"])
@require_auth
def status():
    if LOCAL_MODE:
        try:
            ensure_schema()
            conn = get_db_connection()
            conn.close()
            return jsonify({"service": SERVICE_NAME, "vault": "disabled", "database": "healthy"}), 200
        except Exception as exc:
            logger.error("status failed: %s", exc)
            return jsonify({"service": SERVICE_NAME, "vault": "disabled", "database": "unhealthy", "error": str(exc)}), 503
    try:
        ensure_schema()
        conn = get_db_connection()
        conn.close()
        # Vault is not configured in this deployment
        return jsonify({
            "service": SERVICE_NAME,
            "vault": "disabled",
            "database": "healthy"
        }), 200
    except Exception as exc:
        logger.error("status failed: %s", exc)
        return jsonify({"service": SERVICE_NAME, "vault": "unavailable", "database": "unhealthy", "error": str(exc)}), 503


@app.route("/api/storage/documents", methods=["POST"])
@require_auth
def create_document():
    data = request.get_json(force=True)
    required = ["doc_id", "citizen_id", "doc_type", "doc_title", "content_hash"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        write_audit("CREATE", data.get("officer_id"), "DOCUMENT", data.get("doc_id"), status="FAILURE", error_message=f"missing {missing[0]}")
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    doc_id = data["doc_id"]
    status_value = data.get("status", "signed" if data.get("signature_data") else "draft")
    metadata = data.get("metadata", {})
    created_by = data.get("created_by") or data["citizen_id"]
    signed_by = data.get("signed_by") if data.get("signed_by") is not None else data.get("officer_id")
    requested_region = _extract_region_code(metadata)
    officer_id = data.get("officer_id")

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT citizen_id, metadata, region_code FROM citizens WHERE citizen_id = %s", (data["citizen_id"],))
        citizen = cur.fetchone()
        if not citizen:
            return jsonify({"error": "Citizen not found"}), 404

        officer_region = None
        if officer_id:
            cur.execute("SELECT officer_id, department, metadata, region_code FROM officers WHERE officer_id = %s", (officer_id,))
            officer = cur.fetchone()
            if not officer:
                return jsonify({"error": "Officer not found"}), 404
            officer_region = _extract_region_code(officer.get("metadata"), officer.get("region_code") or officer.get("department"))
            
            # If officer is trying to sign, check if they have a current key from PKI
            if data.get("signature_data"):
                cur.execute(
                    "SELECT key_id FROM officer_keys WHERE officer_id = %s AND is_current = TRUE",
                    (officer_id,)
                )
                current_key = cur.fetchone()
                if not current_key:
                    write_audit("SIGN_ATTEMPT", officer_id, "DOCUMENT", doc_id, status="FAILURE", 
                               error_message="Officer has no current key issued by PKI")
                    return jsonify({
                        "error": "Officer cannot sign without a current key",
                        "message": "Submit a key request to PKI admin for initial key issuance"
                    }), 403

        citizen_region = _extract_region_code(citizen.get("metadata"), citizen.get("region_code"))
        if requested_region and officer_region and requested_region != officer_region:
            return jsonify({"error": "Region mismatch between QR payload and officer assignment"}), 403
        if citizen_region and officer_region and citizen_region != officer_region:
            return jsonify({"error": "Citizen region does not match officer assignment"}), 403

        cur.execute(
            """
            INSERT INTO documents (doc_id, citizen_id, doc_type, doc_title, content_hash,
                                   status, created_by, signed_by, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (doc_id) DO UPDATE
              SET citizen_id = EXCLUDED.citizen_id,
                  doc_type = EXCLUDED.doc_type,
                  doc_title = EXCLUDED.doc_title,
                  content_hash = EXCLUDED.content_hash,
                  status = EXCLUDED.status,
                  signed_by = EXCLUDED.signed_by,
                  metadata = EXCLUDED.metadata,
                  archived_at = CASE WHEN EXCLUDED.status IN ('signed', 'archived') THEN NOW() ELSE documents.archived_at END
            RETURNING doc_id, created_at
            """,
            (
                doc_id,
                data["citizen_id"],
                data["doc_type"],
                data["doc_title"],
                data["content_hash"],
                status_value,
                created_by,
                signed_by,
                Json(metadata),
            ),
        )
        result = cur.fetchone()

        if data.get("signature_data"):
            sig_id = data.get("sig_id", str(uuid.uuid4()))
            cur.execute(
                """
                INSERT INTO signatures (sig_id, doc_id, officer_id, signature_data,
                                         signature_algorithm, key_version)
                VALUES (%s, %s, %s, %s, %s, %s)
                ON CONFLICT (sig_id) DO UPDATE
                  SET signature_data = EXCLUDED.signature_data,
                      signature_algorithm = EXCLUDED.signature_algorithm,
                      key_version = EXCLUDED.key_version,
                      verified_at = NOW()
                """,
                (
                    sig_id,
                    doc_id,
                    data.get("officer_id"),
                    data["signature_data"],
                    data.get("signature_algorithm", "ML-DSA"),
                    data.get("key_version", 1),
                ),
            )
            cur.execute(
                "UPDATE documents SET status='signed', signed_at=NOW(), archived_at=NOW() WHERE doc_id = %s",
                (doc_id,),
            )

        conn.commit()
        write_audit("CREATE", officer_id, "DOCUMENT", doc_id, details={"doc_type": data["doc_type"], "status": status_value})
        return jsonify({"doc_id": doc_id, "created_at": result["created_at"].isoformat(), "status": status_value}), 201
    except Exception as exc:
        conn.rollback()
        write_audit("CREATE", officer_id, "DOCUMENT", doc_id, status="FAILURE", error_message=str(exc))
        logger.error("create_document failed: %s", exc)
        return jsonify({"error": "Document storage failed"}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/thirdparty/request-access", methods=["POST"])
def create_thirdparty_request():
    """Create a third-party access request initiated by a citizen (or citizen acting through UI).
    Expected JSON: citizen_id, thirdparty_id, resource_type, resource_id (optional), reason (optional)
    """
    data = request.get_json(force=True)
    required = ["citizen_id", "thirdparty_id"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    citizen_id = data["citizen_id"]
    thirdparty_id = data["thirdparty_id"]
    resource_type = data.get("resource_type")
    resource_id = data.get("resource_id")
    reason = data.get("reason")

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # ensure referenced users exist
        cur.execute("SELECT citizen_id FROM citizens WHERE citizen_id = %s", (citizen_id,))
        if not cur.fetchone():
            return jsonify({"error": "Citizen not found"}), 404
        cur.execute("SELECT thirdparty_id FROM thirdparty_users WHERE thirdparty_id = %s", (thirdparty_id,))
        if not cur.fetchone():
            return jsonify({"error": "Third-party not found"}), 404

        request_id = f"req-{uuid.uuid4().hex[:12]}"
        cur.execute(
            "INSERT INTO thirdparty_requests (request_id, citizen_id, thirdparty_id, resource_id, resource_type, reason, status) VALUES (%s,%s,%s,%s,%s,%s,%s)",
            (request_id, citizen_id, thirdparty_id, resource_id, resource_type, reason, 'PENDING'),
        )
        conn.commit()
        write_audit("THIRDPARTY_REQUEST_CREATED", request_id, "THIRDPARTY_REQUEST", citizen_id, details={"thirdparty_id": thirdparty_id, "resource_type": resource_type, "resource_id": resource_id})
        return jsonify({"request_id": request_id, "status": "PENDING"}), 201
    except Exception as exc:
        conn.rollback()
        logger.error("create_thirdparty_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/thirdparty/requests", methods=["GET"])
def list_thirdparty_requests():
    """List third-party requests. Query params: thirdparty_id OR citizen_id. If none provided, returns all (admin use)."""
    thirdparty_id = request.args.get("thirdparty_id")
    citizen_id = request.args.get("citizen_id")

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        if thirdparty_id:
            cur.execute("SELECT * FROM thirdparty_requests WHERE thirdparty_id = %s ORDER BY created_at DESC", (thirdparty_id,))
        elif citizen_id:
            cur.execute("SELECT * FROM thirdparty_requests WHERE citizen_id = %s ORDER BY created_at DESC", (citizen_id,))
        else:
            cur.execute("SELECT * FROM thirdparty_requests ORDER BY created_at DESC")
        rows = cur.fetchall()
        return jsonify({"requests": rows}), 200
    except Exception as exc:
        logger.error("list_thirdparty_requests failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/thirdparty/requests/<request_id>/approve", methods=["POST"])
def approve_thirdparty_request(request_id):
    """Approve a pending third-party request. Caller must be the target third-party (or admin)."""
    data = request.get_json(silent=True) or {}
    actor = data.get("actor")  # optional identifier for audit

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT status, citizen_id, thirdparty_id FROM thirdparty_requests WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Request not found"}), 404
        status, citizen_id, thirdparty_id = row
        if status != 'PENDING':
            return jsonify({"error": "Request not pending"}), 400
        cur.execute("UPDATE thirdparty_requests SET status = %s, updated_at = NOW() WHERE request_id = %s", ('APPROVED', request_id))
        conn.commit()
        write_audit("THIRDPARTY_REQUEST_APPROVED", request_id, "THIRDPARTY_REQUEST", actor or thirdparty_id, details={"actor": actor or thirdparty_id})
        return jsonify({"request_id": request_id, "status": "APPROVED"}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("approve_thirdparty_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/thirdparty/requests/<request_id>/deny", methods=["POST"])
def deny_thirdparty_request(request_id):
    data = request.get_json(silent=True) or {}
    actor = data.get("actor")

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT status, citizen_id, thirdparty_id FROM thirdparty_requests WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Request not found"}), 404
        status, citizen_id, thirdparty_id = row
        if status != 'PENDING':
            return jsonify({"error": "Request not pending"}), 400
        cur.execute("UPDATE thirdparty_requests SET status = %s, updated_at = NOW() WHERE request_id = %s", ('DENIED', request_id))
        conn.commit()
        write_audit("THIRDPARTY_REQUEST_DENIED", request_id, "THIRDPARTY_REQUEST", actor or thirdparty_id, details={"actor": actor or thirdparty_id})
        return jsonify({"request_id": request_id, "status": "DENIED"}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("deny_thirdparty_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/document-sign-requests", methods=["POST"])
@require_auth
def create_document_sign_request():
    data = request.get_json(force=True) or {}
    required = ["citizen_id", "officer_id", "doc_id", "doc_type", "doc_title", "document_base64"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    citizen_id = data["citizen_id"]
    officer_id = data["officer_id"]
    doc_id = data["doc_id"]
    doc_type = data["doc_type"]
    doc_title = data["doc_title"]
    document_base64 = data["document_base64"]
    reason = data.get("reason")
    metadata = data.get("metadata") or {}

    try:
        document_bytes = base64.b64decode(document_base64)
    except Exception:
        return jsonify({"error": "Invalid document_base64"}), 400

    content_hash = hashlib.sha256(document_bytes).hexdigest()

    if g.current_user_type == "citizen" and g.current_user_id != citizen_id:
        return jsonify({"error": "Forbidden"}), 403
    if g.current_user_type == "officer" and g.current_user_id != officer_id:
        return jsonify({"error": "Forbidden"}), 403

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT citizen_id FROM citizens WHERE citizen_id = %s", (citizen_id,))
        if not cur.fetchone():
            return jsonify({"error": "Citizen not found"}), 404

        cur.execute("SELECT officer_id FROM officers WHERE officer_id = %s", (officer_id,))
        if not cur.fetchone():
            return jsonify({"error": "Officer not found"}), 404

        request_id = data.get("request_id") or f"sign-req-{uuid.uuid4().hex[:12]}"
        cur.execute(
            """
            INSERT INTO document_sign_requests (
                request_id, doc_id, citizen_id, officer_id, doc_type, doc_title,
                content_hash, document_base64, status, reason, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (request_id) DO UPDATE SET
                doc_id = EXCLUDED.doc_id,
                citizen_id = EXCLUDED.citizen_id,
                officer_id = EXCLUDED.officer_id,
                doc_type = EXCLUDED.doc_type,
                doc_title = EXCLUDED.doc_title,
                content_hash = EXCLUDED.content_hash,
                document_base64 = EXCLUDED.document_base64,
                status = EXCLUDED.status,
                reason = EXCLUDED.reason,
                metadata = EXCLUDED.metadata
            RETURNING request_id, created_at
            """,
            (
                request_id,
                doc_id,
                citizen_id,
                officer_id,
                doc_type,
                doc_title,
                content_hash,
                document_base64,
                "pending",
                reason,
                Json(metadata),
            ),
        )

        cur.execute(
            """
            INSERT INTO documents (
                doc_id, citizen_id, doc_type, doc_title, content_hash,
                status, created_by, signed_by, metadata
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (doc_id) DO UPDATE SET
                citizen_id = EXCLUDED.citizen_id,
                doc_type = EXCLUDED.doc_type,
                doc_title = EXCLUDED.doc_title,
                content_hash = EXCLUDED.content_hash,
                status = EXCLUDED.status,
                created_by = EXCLUDED.created_by,
                signed_by = EXCLUDED.signed_by,
                metadata = EXCLUDED.metadata,
                archived_at = CASE WHEN EXCLUDED.status IN ('signed', 'archived') THEN NOW() ELSE documents.archived_at END
            RETURNING doc_id, created_at
            """,
            (
                doc_id,
                citizen_id,
                doc_type,
                doc_title,
                content_hash,
                "pending_signature",
                citizen_id,
                None,
                Json({**metadata, "request_id": request_id}),
            ),
        )
        row = cur.fetchone()
        conn.commit()
        write_audit(
            "DOCUMENT_SIGN_REQUEST_CREATED",
            citizen_id,
            "DOCUMENT_SIGN_REQUEST",
            request_id,
            details={"doc_id": doc_id, "officer_id": officer_id},
        )
        return jsonify({
            "request_id": request_id,
            "doc_id": doc_id,
            "status": "pending",
            "created_at": row["created_at"].isoformat() if row and row.get("created_at") else datetime.now(timezone.utc).isoformat(),
        }), 201
    except Exception as exc:
        conn.rollback()
        logger.error("create_document_sign_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/document-sign-requests", methods=["GET"])
@require_auth
def list_document_sign_requests():
    citizen_id = request.args.get("citizen_id")
    officer_id = request.args.get("officer_id")
    status_value = request.args.get("status")

    query = "SELECT request_id, doc_id, citizen_id, officer_id, doc_type, doc_title, content_hash, status, reason, created_at, reviewed_at, reviewed_by, signed_at, metadata FROM document_sign_requests WHERE 1=1"
    params = []
    if citizen_id:
        query += " AND citizen_id = %s"
        params.append(citizen_id)
    if officer_id:
        query += " AND officer_id = %s"
        params.append(officer_id)
    if status_value:
        query += " AND status = %s"
        params.append(status_value)
    query += " ORDER BY created_at DESC"

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(query, params)
        rows = cur.fetchall()
        return jsonify({"requests": [dict(row) for row in rows], "count": len(rows)}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/document-sign-requests/<request_id>", methods=["GET"])
@require_auth
def get_document_sign_request(request_id):
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM document_sign_requests WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Request not found"}), 404
        if g.current_user_type == "citizen" and g.current_user_id != row["citizen_id"]:
            return jsonify({"error": "Forbidden"}), 403
        return jsonify({"request": dict(row)}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/document-sign-requests/<request_id>/complete", methods=["POST"])
@require_auth
def complete_document_sign_request(request_id):
    data = request.get_json(silent=True) or {}
    # Force the signer to be the authenticated officer when called by an officer.
    # Allow storage_admin to optionally supply a different signer in the body.
    if g.current_user_type == "officer":
        signed_by = g.current_user_id
    else:
        signed_by = data.get("signed_by") or g.current_user_id

    if g.current_user_type not in ("officer", "storage_admin"):
        return jsonify({"error": "Forbidden"}), 403

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Block officer signing when the officer has no active, non-expired certificate.
        if g.current_user_type == "officer":
            cur.execute(
                """
                SELECT cert_id
                FROM officer_certificates
                WHERE officer_id = %s
                  AND is_active = TRUE
                  AND expires_at > NOW()
                ORDER BY created_at DESC
                LIMIT 1
                """,
                (signed_by,),
            )
            active_cert = cur.fetchone()
            if not active_cert:
                return jsonify({"error": "Officer has no active certificate. Signing is blocked."}), 403

        cur.execute("SELECT request_id, citizen_id, officer_id, status, doc_id FROM document_sign_requests WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Request not found"}), 404
        if row["status"] == "signed":
            return jsonify({"request_id": request_id, "status": "signed"}), 200

        # Persist signature if provided
        signature_b64 = data.get("signature") or data.get("signature_data")
        signature_algorithm = data.get("signature_algorithm") or data.get("signatureAlgorithm") or "ML-DSA"
        key_version = int(data.get("key_version") or data.get("keyVersion") or 1)

        # Update document_sign_requests
        cur.execute(
            """
            UPDATE document_sign_requests
            SET status = 'signed', reviewed_at = COALESCE(reviewed_at, NOW()), reviewed_by = %s, signed_at = NOW(), metadata = metadata || %s::jsonb
            WHERE request_id = %s
            """,
            (signed_by, Json({"signed_by": signed_by}), request_id),
        )

        # Insert signature record if provided
        doc_id = row.get("doc_id")
        if signature_b64 and doc_id:
            sig_id = data.get("sig_id") or f"sig-{uuid.uuid4().hex[:12]}"
            cur.execute(
                """
                INSERT INTO signatures (sig_id, doc_id, officer_id, signature_data, signature_algorithm, key_version, signed_at, verified_at)
                VALUES (%s, %s, %s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (sig_id) DO UPDATE SET
                    signature_data = EXCLUDED.signature_data,
                    signature_algorithm = EXCLUDED.signature_algorithm,
                    key_version = EXCLUDED.key_version,
                    verified_at = NOW()
                """,
                (sig_id, doc_id, signed_by, signature_b64, signature_algorithm, key_version),
            )

        # Always mark the document as signed when the request is completed
        if doc_id:
            cur.execute(
                "UPDATE documents SET status='signed', signed_at=NOW(), signed_by=%s, archived_at=NOW() WHERE doc_id = %s",
                (signed_by, doc_id),
            )

        conn.commit()
        write_audit(
            "DOCUMENT_SIGN_REQUEST_COMPLETED",
            signed_by,
            "DOCUMENT_SIGN_REQUEST",
            request_id,
            details={"officer_id": row.get("officer_id"), "citizen_id": row.get("citizen_id"), "doc_id": row.get("doc_id")},
        )
        return jsonify({"request_id": request_id, "status": "signed", "signed_by": signed_by}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("complete_document_sign_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/documents/<doc_id>", methods=["GET"])
@require_auth
def get_document(doc_id):
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM documents WHERE doc_id = %s", (doc_id,))
        document = cur.fetchone()
        if not document:
            write_audit("RETRIEVE", request.headers.get("X-User-ID"), "DOCUMENT", doc_id, status="FAILURE", error_message="not found")
            return jsonify({"error": "Document not found"}), 404

        cur.execute(
            """
            SELECT sig_id, officer_id, signature_data, signature_algorithm, key_version, signed_at
            FROM signatures WHERE doc_id = %s ORDER BY signed_at ASC
            """,
            (doc_id,),
        )
        signatures = cur.fetchall()
        write_audit("RETRIEVE", request.headers.get("X-User-ID"), "DOCUMENT", doc_id)
        return jsonify({"document": dict(document), "signatures": [dict(item) for item in signatures]}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/documents", methods=["GET"])
@require_auth
def list_documents():
    citizen_id = request.args.get("citizen_id")
    signed_by = request.args.get("signed_by")
    status_value = request.args.get("status")
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    query = "SELECT * FROM documents WHERE 1=1"
    params = []
    if citizen_id:
        query += " AND citizen_id = %s"
        params.append(citizen_id)
    if signed_by:
        query += " AND signed_by = %s"
        params.append(signed_by)
    if status_value:
        query += " AND status = %s"
        params.append(status_value)
    query += " ORDER BY created_at DESC LIMIT %s OFFSET %s"
    params.extend([limit, offset])

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(query, params)
        rows = cur.fetchall()
        return jsonify({"documents": [dict(row) for row in rows], "count": len(rows), "limit": limit, "offset": offset}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/audit-log", methods=["GET"])
@require_auth
def get_audit_log():
    doc_id = request.args.get("doc_id")
    if not doc_id:
        return jsonify({"error": "doc_id required"}), 400

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT * FROM audit_log WHERE resource_id = %s ORDER BY timestamp DESC LIMIT %s",
            (doc_id, min(int(request.args.get("limit", 100)), 200)),
        )
        rows = cur.fetchall()
        return jsonify({"doc_id": doc_id, "audit_entries": [dict(row) for row in rows]}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/.well-known/jwks.json", methods=["GET"])
@require_auth
def jwks_placeholder():
    # Legacy JWKS endpoint removed — clients should use the doc-service PKI
    # endpoint. The doc-service exposes the Root CA at '/.well-known/ca.pem'
    # and X.509 officer certificates via '/api/pki/certificates'.
    return jsonify({"error": "JWKS endpoint deprecated; use doc-service PKI endpoints (/.well-known/ca.pem or /api/pki/certificates)"}), 410


@app.route("/api/storage/register", methods=["POST"])
def register_citizen():
    """Public registration endpoint for CITIZEN accounts. No RBAC - just citizens table."""
    data = request.get_json(force=True)
    required = ["citizen_id", "email", "name", "password"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    citizen_id = data["citizen_id"]
    email = data["email"]
    password = data["password"]
    region_code = data.get("region_code")
    
    # Validate
    if not citizen_id.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "citizen_id must be alphanumeric"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    pwd_hash, salt = hash_password(password)

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Check if already exists
        cur.execute("SELECT citizen_id FROM citizens WHERE citizen_id = %s OR email = %s", (citizen_id, email))
        if cur.fetchone():
            return jsonify({"error": "Citizen already exists"}), 409

        # Create citizen account
        cur.execute(
            "INSERT INTO citizens (citizen_id, email, name, password_hash, password_salt, region_code, verified) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (citizen_id, email, data["name"], pwd_hash, salt, region_code, False),
        )
        conn.commit()
        write_audit("CITIZEN_REGISTER", citizen_id, "CITIZEN", citizen_id, details={"email": email})
        return jsonify({
            "citizen_id": citizen_id,
            "email": email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "message": "Citizen account created."
        }), 201
    except Exception as exc:
        conn.rollback()
        logger.error("register_citizen failed: %s", exc)
        return jsonify({"error": str(exc)}), 409
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/citizens/<citizen_id>", methods=["DELETE"])
@require_auth
@require_user_type("storage_admin")
def delete_citizen(citizen_id):
    """Delete a citizen account and cascade related data. Storage admins only."""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT citizen_id FROM citizens WHERE citizen_id = %s", (citizen_id,))
        if not cur.fetchone():
            return jsonify({"error": "Citizen not found"}), 404

        cur.execute("DELETE FROM citizens WHERE citizen_id = %s", (citizen_id,))
        conn.commit()
        write_audit("DELETE_CITIZEN", getattr(g, 'current_user_id', 'system'), "CITIZEN", citizen_id)
        return jsonify({"message": "Citizen deleted", "citizen_id": citizen_id}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("delete_citizen failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/citizens", methods=["GET"])
@require_auth
@require_user_type("storage_admin")
def list_citizens():
    """List all citizen accounts. Storage admins only."""
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT citizen_id, email, name, region_code, verified, created_at FROM citizens ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (limit, offset),
        )
        rows = cur.fetchall()
        return jsonify({"citizens": [dict(row) for row in rows], "count": len(rows)}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/pki-admins", methods=["POST"])
def create_pki_admin_blocked():
    """PKI admin accounts cannot be created via API. Use deployment seeding."""
    return jsonify({
        "error": "PKI admin accounts are not creatable via API",
        "message": "PKI admin must be initialized during deployment and cannot be created via runtime API.",
    }), 403


@app.route("/api/storage/storage-admins", methods=["POST"])
def create_storage_admin_blocked():
    """Storage admin accounts cannot be created via API. Use deployment seeding."""
    return jsonify({
        "error": "Storage admin accounts are not creatable via API",
        "message": "Storage admin must be initialized during deployment and cannot be created via runtime API.",
    }), 403


@app.route("/api/storage/register/officer", methods=["POST"])
def register_officer():
    """Registration endpoint for OFFICER accounts with immediate certificate request."""
    data = request.get_json(force=True)
    required = ["officer_id", "email", "name", "password", "public_key_pem"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    officer_id = data["officer_id"]
    email = data["email"]
    password = data["password"]
    department = data.get("department", "")
    region_code = data.get("region_code")
    public_key_pem = data.get("public_key_pem", "").strip()
    subject_st = (data.get("st") or "HCM").strip()
    subject_l = (data.get("l") or "Q12").strip()
    subject_ou = (data.get("ou") or f"CA {subject_l}").strip()
    
    # Validate
    if not officer_id.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "officer_id must be alphanumeric"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400
    if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
        return jsonify({"error": "public_key_pem must be a valid PEM public key"}), 400

    is_valid_key, validation_error = _validate_ml_dsa_public_key(public_key_pem)
    if not is_valid_key:
        return jsonify({"error": validation_error}), 400

    pwd_hash, salt = hash_password(password)

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Check if already exists
        cur.execute("SELECT officer_id FROM officers WHERE officer_id = %s OR email = %s", (officer_id, email))
        if cur.fetchone():
            return jsonify({"error": "Officer already exists"}), 409

        # Create officer account (no auto key request)
        cur.execute(
            "INSERT INTO officers (officer_id, email, name, password_hash, password_salt, department, region_code) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (officer_id, email, data["name"], pwd_hash, salt, department, region_code),
        )

        # Store officer key as current key immediately (no key request workflow)
        key_id = f"key-{officer_id}-{uuid.uuid4().hex[:8]}"
        cur.execute(
            """
            INSERT INTO officer_keys (key_id, officer_id, public_key_pem, key_type, is_current, created_at, expires_at, key_version)
            VALUES (%s, %s, %s, %s, TRUE, NOW(), NOW() + INTERVAL '365 days', 1)
            """,
            (key_id, officer_id, public_key_pem, "ML-DSA-44"),
        )
        conn.commit()

        # Instead of issuing certificate immediately, create a pending cert request
        request_id = f"certreq-{uuid.uuid4().hex[:12]}"
        cur.execute(
            "INSERT INTO officer_cert_requests (request_id, officer_id, public_key_pem, common_name, organization, country, st, l, ou, status) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",
            (request_id, officer_id, public_key_pem, subject_ou, 'OFFICER', 'VN', subject_st, subject_l, subject_ou, 'PENDING')
        )
        conn.commit()
        write_audit("OFFICER_REGISTER", officer_id, "OFFICER", officer_id, details={"email": email, "department": department, "request_id": request_id, "key_id": key_id})
        return jsonify({
            "officer_id": officer_id,
            "email": email,
            "department": department,
            "key_id": key_id,
            "request_id": request_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "message": "Officer account created. Certificate request pending PKI approval."
        }), 201
    except Exception as exc:
        conn.rollback()
        logger.error("register_officer failed: %s", exc)
        return jsonify({"error": str(exc)}), 409
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/register/thirdparty", methods=["POST"])
def register_thirdparty():
    """Registration endpoint for THIRDPARTY accounts (self-registration)."""
    data = request.get_json(force=True)
    required = ["thirdparty_id", "email", "org_name", "password"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    thirdparty_id = data["thirdparty_id"]
    email = data["email"]
    password = data["password"]
    org_name = data.get("org_name", "")
    contact_person = data.get("contact_person")
    
    # Validate
    if not thirdparty_id.replace("_", "").replace("-", "").isalnum():
        return jsonify({"error": "thirdparty_id must be alphanumeric"}), 400
    if len(password) < 8:
        return jsonify({"error": "Password must be at least 8 characters"}), 400

    pwd_hash, salt = hash_password(password)

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        # Check if already exists
        cur.execute("SELECT thirdparty_id FROM thirdparty_users WHERE thirdparty_id = %s OR email = %s", (thirdparty_id, email))
        if cur.fetchone():
            return jsonify({"error": "Third-party account already exists"}), 409

        # Create thirdparty account
        cur.execute(
            "INSERT INTO thirdparty_users (thirdparty_id, email, org_name, contact_person, password_hash, password_salt) VALUES (%s, %s, %s, %s, %s, %s)",
            (thirdparty_id, email, org_name, contact_person, pwd_hash, salt),
        )
        conn.commit()
        write_audit("THIRDPARTY_REGISTER", thirdparty_id, "THIRDPARTY", thirdparty_id, details={"email": email, "org_name": org_name})
        return jsonify({
            "thirdparty_id": thirdparty_id,
            "email": email,
            "org_name": org_name,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "message": "Third-party account created."
        }), 201
    except Exception as exc:
        conn.rollback()
        logger.error("register_thirdparty failed: %s", exc)
        return jsonify({"error": str(exc)}), 409
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/login", methods=["POST"])
def login_any_type():
    """Login endpoint that works for any user type (citizen, officer, storage_admin, pki_admin, thirdparty). Specify user_type parameter."""
    data = request.get_json(force=True)
    required = ["user_id", "password", "user_type"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    user_id = data["user_id"]
    password = data["password"]
    user_type = data["user_type"]  # 'citizen', 'officer', 'storage_admin', 'pki_admin', 'thirdparty'

    # Map user_type to table and id_column
    table_map = {
        "citizen": ("citizens", "citizen_id"),
        "officer": ("officers", "officer_id"),
        "storage_admin": ("storage_admins", "admin_id"),
        "pki_admin": ("pki_admins", "admin_id"),
        "thirdparty": ("thirdparty_users", "thirdparty_id"),
    }
    
    if user_type not in table_map:
        return jsonify({"error": "Invalid user_type. Must be: citizen, officer, storage_admin, pki_admin, thirdparty"}), 400
    
    table_name, id_col = table_map[user_type]

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(f"SELECT {id_col}, password_hash, password_salt FROM {table_name} WHERE {id_col} = %s", (user_id,))
        user = cur.fetchone()
        
        if not user or not user["password_hash"]:
            write_audit("LOGIN_FAIL", user_id, user_type.upper(), user_id, status="FAILURE", error_message="not found or no password")
            return jsonify({"error": "Invalid credentials"}), 401

        if not verify_password(password, user["password_hash"], user["password_salt"]):
            write_audit("LOGIN_FAIL", user_id, user_type.upper(), user_id, status="FAILURE", error_message="password mismatch")
            return jsonify({"error": "Invalid credentials"}), 401

        # Update last_login
        cur.execute(f"UPDATE {table_name} SET last_login = NOW() WHERE {id_col} = %s", (user_id,))

        # Generate session token
        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        cur.execute(
            """
            INSERT INTO sessions (session_id, user_id, user_type, expires_at)
            VALUES (%s, %s, %s, %s)
            """,
            (session_id, user_id, user_type, expires_at),
        )
        conn.commit()
        write_audit("LOGIN_SUCCESS", user_id, user_type.upper(), user_id)
        return jsonify({
            "user_id": user_id,
            "user_type": user_type,
            "session_id": session_id,
            "token": session_id,
            "expires_in": 3600,
            "created_at": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as exc:
        logger.error("login_any_type failed: %s", exc)
        return jsonify({"error": "Login failed"}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officers/login", methods=["POST"])
def officer_login():
    """Dedicated officer login endpoint. Body: {"officer_id", "password"} """
    data = request.get_json(force=True) or {}
    required = ["officer_id", "password"]
    missing = [f for f in required if not data.get(f)]
    if missing:
        return jsonify({"error": f"Missing field: {missing[0]}"}), 400

    officer_id = data.get("officer_id")
    password = data.get("password")

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT officer_id, password_hash, password_salt FROM officers WHERE officer_id = %s", (officer_id,))
        user = cur.fetchone()

        if not user or not user.get("password_hash"):
            write_audit("LOGIN_FAIL", officer_id, "OFFICER", officer_id, status="FAILURE", error_message="not found or no password")
            return jsonify({"error": "Invalid credentials"}), 401

        if not verify_password(password, user["password_hash"], user["password_salt"]):
            write_audit("LOGIN_FAIL", officer_id, "OFFICER", officer_id, status="FAILURE", error_message="password mismatch")
            return jsonify({"error": "Invalid credentials"}), 401

        cur.execute("UPDATE officers SET last_login = NOW() WHERE officer_id = %s", (officer_id,))

        session_id = str(uuid.uuid4())
        expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
        cur.execute(
            "INSERT INTO sessions (session_id, user_id, user_type, expires_at) VALUES (%s, %s, %s, %s)",
            (session_id, officer_id, "officer", expires_at),
        )
        conn.commit()
        write_audit("LOGIN_SUCCESS", officer_id, "OFFICER", officer_id)
        return jsonify({
            "user_id": officer_id,
            "user_type": "officer",
            "session_id": session_id,
            "token": session_id,
            "expires_in": 3600,
            "created_at": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as exc:
        logger.error("officer_login failed: %s", exc)
        return jsonify({"error": "Login failed"}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/qr-register", methods=["GET"])
def qr_register():
    """
    Generate QR token for user registration flow
    Mobile app receives this token and shows account creation form
    After user fills in (user_id, email, password), app POSTs to /api/storage/register
    """
    try:
        reg_token = str(uuid.uuid4())
        
        # Store registration token in Redis or temp table with TTL
        # For now, return the token directly
        
        reg_data = {
            "reg_token": reg_token,
            "action": "register",
            "fields": ["user_id", "email", "name", "password"],
            "role": "CITIZEN",
            "expires_in": 300,
            "message": "Scan QR to create account",
            "endpoint": "/api/storage/register"
        }
        
        import json as json_lib
        import base64
        
        # Encode as JSON then base64 for QR
        reg_json = json_lib.dumps(reg_data)
        qr_payload_b64 = base64.b64encode(reg_json.encode()).decode()
        
        write_audit("REGISTER_QR_GENERATED", "system", "REGISTRATION", reg_token)
        return jsonify({
            "reg_token": reg_token,
            "qr_payload": qr_payload_b64,
            "action": "register",
            "role": "CITIZEN",
            "expires_in": 300
        }), 200
    except Exception as exc:
        logger.error("qr_register failed: %s", exc)
        return jsonify({"error": "Failed to generate registration QR"}), 500


@app.route("/api/storage/citizens", methods=["POST"])
def create_citizen():
    """Create new citizen account (admin/officer use)"""
    data = request.get_json(force=True)
    required = ["citizen_id", "name", "email"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing: {missing[0]}"}), 400

    citizen_id = data["citizen_id"]
    password = data.get("password")
    region_code = data.get("region_code")
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        pwd_hash, salt = (hash_password(password) if password else (None, None))
        cur.execute(
            "INSERT INTO citizens (citizen_id, name, email, password_hash, password_salt, region_code) VALUES (%s, %s, %s, %s, %s, %s)",
            (citizen_id, data["name"], data["email"], pwd_hash, salt, region_code),
        )
        conn.commit()
        write_audit("CREATE_CITIZEN", "system", "CITIZEN", citizen_id, details={"email": data["email"]})
        return jsonify({"citizen_id": citizen_id, "created_at": datetime.now(timezone.utc).isoformat()}), 201
    except Exception as exc:
        conn.rollback()
        logger.error("create_citizen failed: %s", exc)
        return jsonify({"error": str(exc)}), 409
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officers", methods=["POST"])
@require_auth
@require_user_type("officer")
def create_officer():
    """Create new officer account from the officer portal only."""
    data = request.get_json(force=True)
    required = ["officer_id", "name", "email"]
    missing = [field for field in required if not data.get(field)]
    if missing:
        return jsonify({"error": f"Missing: {missing[0]}"}), 400

    officer_id = data["officer_id"]
    password = data.get("password")
    region_code = data.get("region_code") or data.get("department")
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        pwd_hash, salt = (hash_password(password) if password else (None, None))
        cur.execute(
            "INSERT INTO officers (officer_id, name, email, password_hash, password_salt, department, region_code) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (officer_id, data["name"], data["email"], pwd_hash, salt, data.get("department", ""), region_code),
        )
        conn.commit()
        write_audit("CREATE_OFFICER", "system", "OFFICER", officer_id, details={"email": data["email"]})
        return jsonify({"officer_id": officer_id, "created_at": datetime.now(timezone.utc).isoformat()}), 201
    except Exception as exc:
        conn.rollback()
        logger.error("create_officer failed: %s", exc)
        return jsonify({"error": str(exc)}), 409
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/users", methods=["POST"])
@require_auth
def create_user_legacy():
    """DEPRECATED: Legacy endpoint. Use /api/storage/{citizens|officers|...} instead"""
    return jsonify({"error": "Use specific endpoints: /api/storage/citizens, /api/storage/officers, etc."}), 410


@app.route("/api/storage/officers/<officer_id>", methods=["GET"])
def get_officer(officer_id):
    """Retrieve officer profile and keys"""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT officer_id, email, name, department, created_at FROM officers WHERE officer_id = %s",
            (officer_id,),
        )
        officer = cur.fetchone()
        if not officer:
            return jsonify({"error": "Officer not found"}), 404

        cur.execute(
            "SELECT key_id, key_type, is_current, created_at, expires_at FROM officer_keys WHERE officer_id = %s ORDER BY created_at DESC",
            (officer_id,),
        )
        keys = cur.fetchall()
        return jsonify({"officer": dict(officer), "keys": [dict(k) for k in keys]}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officer-cert-requests", methods=["GET"])
@require_auth
@require_user_type("pki_admin")
def list_officer_cert_requests():
    """PKI admins can list pending certificate requests for officers."""
    limit = min(int(request.args.get("limit", 100)), 500)
    offset = int(request.args.get("offset", 0))
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT request_id, officer_id, common_name, organization, country, st, l, ou, status, cert_id, created_at, reviewed_at, reviewed_by FROM officer_cert_requests ORDER BY created_at DESC LIMIT %s OFFSET %s", (limit, offset))
        rows = cur.fetchall()
        return jsonify({"requests": [dict(r) for r in rows], "count": len(rows)}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officer-cert-requests/<request_id>/approve", methods=["POST"])
@require_auth
@require_user_type("pki_admin")
def approve_officer_cert_request(request_id):
    """Approve a certificate request: call PKI to issue cert and store it. For renewals, expire old key and mark related documents as expired."""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT * FROM officer_cert_requests WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Request not found"}), 404
        if row["status"] == 'SIGNED' or row["status"] == 'ISSUED':
            return jsonify({"request_id": request_id, "status": row["status"]}), 200

        # Check if this is a renewal request
        metadata_raw = row.get("metadata", {})
        if isinstance(metadata_raw, str):
            metadata = json.loads(metadata_raw) if metadata_raw else {}
        else:
            metadata = metadata_raw or {}
        is_renewal = metadata.get("renewal", False)
        old_key_id = metadata.get("current_key_id")

        # Call PKI service to issue certificate
        payload = {
            "officer_id": row["officer_id"],
            "common_name": row.get("common_name") or row.get("ou") or row.get("officer_id"),
            "organization": row.get("organization") or 'OFFICER',
            "country": row.get("country") or 'VN',
            "st": row.get("st"),
            "l": row.get("l"),
            "ou": row.get("ou"),
            "purpose": 'officer_identity',
            "public_key_pem": row.get("public_key_pem"),
            "allow_reissue": True,
        }
        try:
            cert_response = requests.post(f"{DOC_SERVICE_URL}/api/pki/issue-certificate", json=payload, headers={"Content-Type": "application/json"}, timeout=15)
            cert_data = cert_response.json() if cert_response.content else {}
            if cert_response.status_code not in [200, 201]:
                raise RuntimeError(cert_data.get("error") or "PKI issuance failed")
        except Exception as exc:
            logger.error("PKI issuance failed: %s", exc)
            return jsonify({"error": "PKI issuance failed", "detail": str(exc)}), 502

        cert_id = cert_data.get("cert_id")
        cert_pem = cert_data.get("certificate")
        not_after = cert_data.get("not_after")
        if not cert_id or not cert_pem:
            return jsonify({"error": "PKI response missing certificate data"}), 502

        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode("utf-8"))
        cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
        thumbprint = hashlib.sha256(cert_der).hexdigest()

        # For renewals: deactivate old certificate and mark documents as expired
        if is_renewal:
            # Mark old certificate as inactive
            cur.execute(
                "UPDATE officer_certificates SET is_active = FALSE, revoked_at = NOW() WHERE officer_id = %s AND is_active = TRUE",
                (row["officer_id"],)
            )
            
            # Mark old key as not current
            if old_key_id:
                cur.execute(
                    "UPDATE officer_keys SET is_current = FALSE, expires_at = NOW() WHERE key_id = %s",
                    (old_key_id,)
                )
            
            # Mark documents signed with old key as "expired" (hết hiệu lực)
            cur.execute(
                """
                UPDATE documents 
                SET status = 'expired'
                WHERE signed_by = %s AND status = 'signed'
                """,
                (row["officer_id"],)
            )

        # Mark new key as current for renewal
        if is_renewal:
            cur.execute(
                "UPDATE officer_keys SET is_current = FALSE WHERE officer_id = %s AND is_current = TRUE",
                (row["officer_id"],)
            )
            key_id = f"key-{row['officer_id']}-{uuid.uuid4().hex[:8]}"
            cur.execute(
                """
                INSERT INTO officer_keys (key_id, officer_id, public_key_pem, key_type, is_current, created_at, expires_at, key_version)
                VALUES (%s, %s, %s, %s, TRUE, NOW(), NOW() + INTERVAL '365 days', 
                    (SELECT COALESCE(MAX(key_version), 0) + 1 FROM officer_keys WHERE officer_id = %s))
                """,
                (key_id, row["officer_id"], row.get("public_key_pem"), "ML-DSA-44", row["officer_id"])
            )

        # Store/update certificate
        cur.execute(
            """
            INSERT INTO officer_certificates (cert_id, officer_id, cert_pem, thumbprint, is_active, created_at, expires_at) 
            VALUES (%s, %s, %s, %s, TRUE, NOW(), %s) 
            ON CONFLICT (cert_id) DO UPDATE SET 
                officer_id = EXCLUDED.officer_id, 
                cert_pem = EXCLUDED.cert_pem, 
                thumbprint = EXCLUDED.thumbprint, 
                is_active = TRUE, 
                created_at = NOW(), 
                expires_at = EXCLUDED.expires_at
            """,
            (cert_id, row["officer_id"], cert_pem, thumbprint, not_after)
        )

        # Update request
        cur.execute("UPDATE officer_cert_requests SET status = %s, cert_id = %s, reviewed_at = NOW(), reviewed_by = %s WHERE request_id = %s", ('ISSUED', cert_id, getattr(g, 'current_user_id', 'pki_admin'), request_id))
        conn.commit()
        
        audit_details = {"cert_id": cert_id, "officer_id": row["officer_id"]}
        if is_renewal:
            audit_details["renewal"] = True
            audit_details["expired_documents"] = "marked as expired"
        write_audit("CERT_ISSUED", getattr(g, 'current_user_id', 'pki_admin'), "CERT_REQUEST", request_id, details=audit_details)

        return jsonify({"request_id": request_id, "cert_id": cert_id, "officer_id": row["officer_id"], "certificate": cert_pem, "renewal": is_renewal}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("approve_officer_cert_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officer-cert-requests/<request_id>/deny", methods=["POST"])
@require_auth
@require_user_type("pki_admin")
def deny_officer_cert_request(request_id):
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT request_id, officer_id, status FROM officer_cert_requests WHERE request_id = %s", (request_id,))
        row = cur.fetchone()
        if not row:
            return jsonify({"error": "Request not found"}), 404
        if row["status"] != 'PENDING':
            return jsonify({"error": "Request not in pending state"}), 400
        cur.execute("UPDATE officer_cert_requests SET status = %s, reviewed_at = NOW(), reviewed_by = %s WHERE request_id = %s", ('DENIED', getattr(g, 'current_user_id', 'pki_admin'), request_id))
        conn.commit()
        write_audit("CERT_REQUEST_DENIED", getattr(g, 'current_user_id', 'pki_admin'), "CERT_REQUEST", request_id, details={"officer_id": row["officer_id"]})
        return jsonify({"request_id": request_id, "status": 'DENIED'}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("deny_officer_cert_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officer-cert-requests/renew", methods=["POST"])
@require_auth
@require_user_type("officer")
def request_cert_renewal():
    """Officer requests certificate renewal with a new public key."""
    data = request.get_json(force=True)
    officer_id = g.current_user_id
    public_key_pem = data.get("public_key_pem", "").strip()
    reason = data.get("reason") or "officer_initiated_renewal"
    
    if not public_key_pem:
        return jsonify({"error": "Missing public_key_pem"}), 400
    if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
        return jsonify({"error": "Invalid public key PEM format"}), 400

    is_valid_key, validation_error = _validate_ml_dsa_public_key(public_key_pem)
    if not is_valid_key:
        return jsonify({"error": validation_error}), 400

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Verify officer exists and get current info
        cur.execute("SELECT officer_id, name, email FROM officers WHERE officer_id = %s", (officer_id,))
        officer = cur.fetchone()
        if not officer:
            return jsonify({"error": "Officer not found"}), 404

        # Get officer's current key info for subject
        cur.execute("SELECT key_id FROM officer_keys WHERE officer_id = %s AND is_current = TRUE", (officer_id,))
        current_key = cur.fetchone()
        
        # Get subject info from current certificate if exists
        cur.execute(
            "SELECT cert_id FROM officer_certificates WHERE officer_id = %s AND is_active = TRUE",
            (officer_id,)
        )
        current_cert = cur.fetchone()

        # Create renewal request (marked with renewal metadata)
        renewal_request_id = f"certreq-renewal-{officer_id}-{uuid.uuid4().hex[:12]}"
        subject_ou = officer.get("name") or officer.get("officer_id") or officer_id
        
        cur.execute(
            """
            INSERT INTO officer_cert_requests 
            (request_id, officer_id, public_key_pem, common_name, organization, country, st, l, ou, status, metadata)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                renewal_request_id, 
                officer_id, 
                public_key_pem, 
                subject_ou,
                'OFFICER', 
                'VN', 
                'HCM',  # get from session/db if needed
                'Q12', 
                subject_ou,
                'PENDING',
                json.dumps({"renewal": True, "reason": reason, "current_key_id": current_key.get("key_id") if current_key else None})
            )
        )
        conn.commit()
        write_audit("CERT_RENEWAL_REQUEST", officer_id, "CERT_REQUEST", renewal_request_id, details={"reason": reason})
        
        return jsonify({
            "request_id": renewal_request_id,
            "officer_id": officer_id,
            "reason": reason,
            "status": "PENDING",
            "message": "Renewal request submitted. Waiting for PKI admin approval."
        }), 201
    except Exception as exc:
        conn.rollback()
        logger.error("request_cert_renewal failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/users/<user_id>", methods=["GET"])
@require_auth
def get_user_legacy(user_id):
    """DEPRECATED: Use /api/storage/officers/{officer_id} or specific endpoints"""
    return jsonify({"error": "Use /api/storage/officers/{officer_id}"}), 410


@app.route("/api/storage/officers", methods=["GET"])
def list_officers():
    """List all officers"""
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT officer_id, email, name, department, created_at FROM officers ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (limit, offset),
        )
        rows = cur.fetchall()
        return jsonify({"officers": [dict(row) for row in rows], "count": len(rows)}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officers/<officer_id>", methods=["DELETE"])
@require_auth
@require_user_type("storage_admin")
def delete_officer(officer_id):
    """Delete an officer and cascade related data. Storage admins only."""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT officer_id FROM officers WHERE officer_id = %s", (officer_id,))
        if not cur.fetchone():
            return jsonify({"error": "Officer not found"}), 404

        cur.execute("DELETE FROM officers WHERE officer_id = %s", (officer_id,))
        conn.commit()
        write_audit("DELETE_OFFICER", getattr(g, 'current_user_id', 'system'), "OFFICER", officer_id)
        return jsonify({"message": "Officer deleted", "officer_id": officer_id}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("delete_officer failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/thirdparty-users", methods=["GET"])
@require_auth
@require_user_type("storage_admin")
def list_thirdparty_users():
    """List all third-party accounts. Storage admins only."""
    limit = min(int(request.args.get("limit", 50)), 200)
    offset = int(request.args.get("offset", 0))

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT thirdparty_id, email, org_name, contact_person, created_at FROM thirdparty_users ORDER BY created_at DESC LIMIT %s OFFSET %s",
            (limit, offset),
        )
        rows = cur.fetchall()
        return jsonify({"thirdparty_users": [dict(row) for row in rows], "count": len(rows)}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/thirdparty-users/<thirdparty_id>", methods=["DELETE"])
@require_auth
@require_user_type("storage_admin")
def delete_thirdparty_user(thirdparty_id):
    """Delete a third-party account. Requests cascade via FK constraints."""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor()
    try:
        cur.execute("SELECT thirdparty_id FROM thirdparty_users WHERE thirdparty_id = %s", (thirdparty_id,))
        if not cur.fetchone():
            return jsonify({"error": "Third-party not found"}), 404

        cur.execute("DELETE FROM thirdparty_users WHERE thirdparty_id = %s", (thirdparty_id,))
        conn.commit()
        write_audit("DELETE_THIRDPARTY", getattr(g, 'current_user_id', 'system'), "THIRDPARTY", thirdparty_id)
        return jsonify({"message": "Third-party deleted", "thirdparty_id": thirdparty_id}), 200
    except Exception as exc:
        conn.rollback()
        logger.error("delete_thirdparty_user failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/users", methods=["GET"])
@require_auth
def list_users_legacy():
    """DEPRECATED: Use /api/storage/officers or specific user type endpoints"""
    return jsonify({"error": "Use /api/storage/officers or specific endpoints"}), 410


@app.route("/api/storage/officers/<officer_id>/certificates", methods=["GET"])
@require_auth
def get_officer_certificates(officer_id):
    """Get all certificates for an officer (active and revoked). Shows certificate status."""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT cert_id, officer_id, cert_pem, thumbprint, is_active, revoked_at, created_at, expires_at
            FROM officer_certificates
            WHERE officer_id = %s
            ORDER BY is_active DESC, created_at DESC
            """,
            (officer_id,)
        )
        certs = cur.fetchall()
        result = []
        for cert in certs:
            result.append({
                "cert_id": cert.get("cert_id"),
                "officer_id": cert.get("officer_id"),
                "thumbprint": cert.get("thumbprint"),
                "is_active": cert.get("is_active"),
                "status": "active" if cert.get("is_active") else "revoked",
                "created_at": cert.get("created_at"),
                "expires_at": cert.get("expires_at"),
                "revoked_at": cert.get("revoked_at"),
                "cert_pem": cert.get("cert_pem")
            })
        return jsonify({"officer_id": officer_id, "certificates": result, "count": len(result)}), 200
    except Exception as exc:
        logger.error("get_officer_certificates failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officers/<officer_id>/keys", methods=["POST"])
@require_auth
@require_user_type("pki_admin")
def create_officer_key(officer_id):
    """Issue or reissue the current officer key. PKI admins only."""
    data = request.get_json(force=True)
    public_key_pem = data.get("public_key_pem")
    key_type = data.get("key_type", "ML-DSA")
    request_id = data.get("request_id")
    expires_at_value = data.get("expires_at")
    
    if not public_key_pem:
        return jsonify({"error": "Missing public_key_pem"}), 400
    if key_type.strip().upper() not in ALLOWED_OFFICER_KEY_ALGORITHMS:
        return jsonify({"error": "Only ML-DSA officer keys are supported"}), 400

    is_valid_key, validation_error = _validate_ml_dsa_public_key(public_key_pem)
    if not is_valid_key:
        return jsonify({"error": validation_error}), 400
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT officer_id, region_code FROM officers WHERE officer_id = %s", (officer_id,))
        officer = cur.fetchone()
        if not officer:
            return jsonify({"error": "Officer not found"}), 404

        cur.execute(
            "SELECT key_id FROM officer_keys WHERE officer_id = %s AND is_current = TRUE ORDER BY created_at DESC LIMIT 1",
            (officer_id,),
        )
        previous_key = cur.fetchone()

        key_id = f"key-{officer_id}-{uuid.uuid4().hex[:8]}"
        cur.execute("SELECT MAX(key_version) AS max_version FROM officer_keys WHERE officer_id = %s", (officer_id,))
        version_row = cur.fetchone()
        key_version = int(version_row["max_version"]) + 1 if version_row and version_row.get("max_version") else 1

        if expires_at_value:
            expires_at = datetime.fromisoformat(expires_at_value)
        else:
            expires_at = datetime.now(timezone.utc) + timedelta(days=365)

        if request_id:
            cur.execute(
                """
                SELECT request_id, status
                FROM officer_key_requests
                WHERE request_id = %s AND officer_id = %s
                """,
                (request_id, officer_id),
            )
            key_request = cur.fetchone()
            if not key_request:
                return jsonify({"error": "Officer key request not found"}), 404
            if key_request.get("status") != "pending":
                return jsonify({"error": "Officer key request is not pending"}), 409

        cur.execute(
            "UPDATE officer_keys SET is_current = FALSE, rotated_at = NOW() WHERE officer_id = %s AND is_current = TRUE",
            (officer_id,),
        )
        cur.execute(
            """
            INSERT INTO officer_keys (key_id, officer_id, public_key_pem, key_type, is_current, created_at, expires_at, key_version)
            VALUES (%s, %s, %s, %s, %s, NOW(), %s, %s)
            """,
            (key_id, officer_id, public_key_pem, key_type, True, expires_at, key_version),
        )
        if request_id:
            cur.execute(
                """
                UPDATE officer_key_requests
                SET status = 'approved', resolved_at = NOW(), resolved_by = %s, old_key_id = %s, new_key_id = %s
                WHERE request_id = %s AND officer_id = %s
                """,
                (g.current_user_id, previous_key["key_id"] if previous_key else None, key_id, request_id, officer_id),
            )
        conn.commit()
        write_audit(
            "ISSUE_KEY",
            g.current_user_id,
            "OFFICER_KEY",
            key_id,
            details={"officer_id": officer_id, "request_id": request_id, "region_code": officer.get("region_code")},
        )
        return jsonify({"key_id": key_id, "officer_id": officer_id, "key_version": key_version, "created_at": datetime.now(timezone.utc).isoformat()}), 201
    except Exception as exc:
        conn.rollback()
        logger.error("create_officer_key failed: %s", exc)
        return jsonify({"error": str(exc)}), 409
    finally:
        cur.close()
        conn.close()

@app.route("/api/storage/officers/<officer_id>/certificates", methods=["POST"])
@require_auth
@require_user_type("pki_admin")
def register_officer_certificate(officer_id):
    """Register an issued officer certificate. Enforces 1-certificate-per-officer."""
    data = request.get_json(force=True)
    cert_id = data.get("cert_id")
    cert_pem = data.get("certificate")
    expires_at = data.get("not_after")
    
    if not cert_id or not cert_pem or not expires_at:
        return jsonify({"error": "Missing cert_id, certificate, or not_after"}), 400
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Check if officer exists
        cur.execute("SELECT officer_id FROM officers WHERE officer_id = %s", (officer_id,))
        if not cur.fetchone():
            return jsonify({"error": "Officer not found"}), 404
        
        # Check if officer already has an active certificate
        cur.execute(
            "SELECT cert_id FROM officer_certificates WHERE officer_id = %s AND is_active = TRUE",
            (officer_id,)
        )
        existing = cur.fetchone()
        if existing:
            return jsonify({
                "error": "Officer already has an active certificate",
                "officer_id": officer_id,
                "existing_cert_id": existing.get("cert_id")
            }), 409
        
        # Revoke any previous certificates
        cur.execute(
            """
            UPDATE officer_certificates
            SET is_active = FALSE, revoked_at = NOW()
            WHERE officer_id = %s AND is_active = TRUE
            """,
            (officer_id,)
        )
        
        # Calculate certificate thumbprint (SHA256 of DER)
        import hashlib
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        cert_obj = x509.load_pem_x509_certificate(cert_pem.encode('utf-8'))
        cert_der = cert_obj.public_bytes(serialization.Encoding.DER)
        thumbprint = hashlib.sha256(cert_der).hexdigest()
        
        # Register new certificate
        cur.execute(
            """
            INSERT INTO officer_certificates (cert_id, officer_id, cert_pem, thumbprint, is_active, created_at, expires_at)
            VALUES (%s, %s, %s, %s, TRUE, NOW(), %s)
            ON CONFLICT (cert_id) DO UPDATE SET
                officer_id = EXCLUDED.officer_id,
                cert_pem = EXCLUDED.cert_pem,
                thumbprint = EXCLUDED.thumbprint,
                is_active = TRUE,
                created_at = NOW(),
                expires_at = EXCLUDED.expires_at
            """,
            (cert_id, officer_id, cert_pem, thumbprint, expires_at)
        )
        
        conn.commit()
        write_audit(
            "REGISTER_CERTIFICATE",
            g.current_user_id,
            "OFFICER_CERTIFICATE",
            cert_id,
            details={"officer_id": officer_id, "thumbprint": thumbprint}
        )
        
        return jsonify({
            "cert_id": cert_id,
            "officer_id": officer_id,
            "thumbprint": thumbprint,
            "registered_at": datetime.now(timezone.utc).isoformat()
        }), 201
    except Exception as exc:
        conn.rollback()
        logger.error("register_officer_certificate failed: %s", exc)
        return jsonify({"error": str(exc)}), 409
    finally:
        cur.close()
        conn.close()

@app.route("/api/storage/officers/<officer_id>/register-key", methods=["POST"])
@require_auth
@require_user_type("officer")
def register_officer_public_key(officer_id):
    """Officer registers an ML-DSA public key to request certificate issuance."""
    if g.current_user_id != officer_id:
        return jsonify({"error": "Forbidden"}), 403
    
    data = request.get_json(force=True) or {}
    public_key_pem = data.get("public_key_pem", "").strip()
    key_algorithm = data.get("key_algorithm", "ML-DSA-44").strip()
    
    if not public_key_pem:
        return jsonify({"error": "public_key_pem is required"}), 400
    if not public_key_pem.startswith("-----BEGIN PUBLIC KEY-----"):
        return jsonify({"error": "Invalid PEM format"}), 400
    if key_algorithm.upper() not in ALLOWED_OFFICER_KEY_ALGORITHMS:
        return jsonify({"error": "Only ML-DSA officer keys are supported"}), 400

    is_valid_key, validation_error = _validate_ml_dsa_public_key(public_key_pem)
    if not is_valid_key:
        return jsonify({"error": validation_error}), 400
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Verify officer exists
        cur.execute("SELECT officer_id, email FROM officers WHERE officer_id = %s", (officer_id,))
        officer = cur.fetchone()
        if not officer:
            return jsonify({"error": "Officer not found"}), 404
        
        # Check if officer already has a pending key registration or active certificate
        cur.execute(
            "SELECT key_id FROM officer_keys WHERE officer_id = %s AND is_current = TRUE",
            (officer_id,)
        )
        if cur.fetchone():
            return jsonify({
                "error": "Officer already has an active certificate",
                "message": "Request key rotation if you need a new certificate"
            }), 409
        
        # Store the public key
        key_id = f"key-{officer_id}-{uuid.uuid4().hex[:8]}"
        cur.execute(
            """
            INSERT INTO officer_keys (key_id, officer_id, key_type, public_key, is_current, created_at)
            VALUES (%s, %s, %s, %s, FALSE, NOW())
            """,
            (key_id, officer_id, key_algorithm, public_key_pem)
        )
        
        conn.commit()
        write_audit("REGISTER_PUBLIC_KEY", g.current_user_id, "OFFICER_KEY", key_id, 
                   details={"officer_id": officer_id, "key_algorithm": key_algorithm})
        
        return jsonify({
            "key_id": key_id,
            "officer_id": officer_id,
            "key_algorithm": key_algorithm,
            "registered_at": datetime.now(timezone.utc).isoformat(),
            "next_step": "Request certificate from PKI admin or submit via /api/pki/issue-certificate with officer_id"
        }), 201
    except Exception as exc:
        conn.rollback()
        logger.error("register_officer_public_key failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/users/<user_id>/keys", methods=["POST"])
@require_auth
def rotate_user_key(user_id):
    """DEPRECATED: officer keys are managed through /api/storage/officers/<officer_id>/register-key and PKI issuance."""
    return jsonify({"error": "Use /api/storage/officers/<officer_id>/register-key to register public key"}), 410


@app.route("/api/storage/officers/<officer_id>/key-requests", methods=["POST"])
@require_auth
@require_user_type("officer")
def request_officer_key_reissue(officer_id):
    """DEPRECATED: Use POST /api/storage/officers/<officer_id>/register-key to register public key instead."""
    if g.current_user_id != officer_id:
        return jsonify({"error": "Forbidden"}), 403
    
    return jsonify({
        "error": "Key request workflow is deprecated",
        "message": "Please use POST /api/storage/officers/{officer_id}/register-key to register your public key",
        "new_endpoint": "/api/storage/officers/<officer_id>/register-key"
    }), 410


@app.route("/api/storage/officers/<officer_id>/keys", methods=["GET"])
@require_auth
def get_officer_keys(officer_id):
    """Retrieve all keys for officer"""
    if g.current_user_type == "officer" and g.current_user_id != officer_id:
        return jsonify({"error": "Forbidden"}), 403
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT key_id, key_type, is_current, created_at, expires_at FROM officer_keys WHERE officer_id = %s ORDER BY created_at DESC",
            (officer_id,),
        )
        keys = cur.fetchall()
        return jsonify({"officer_id": officer_id, "keys": [dict(k) for k in keys]}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/internal/officers/<officer_id>/current-key", methods=["GET"])
def get_officer_current_key_internal(officer_id):
    """Internal service-to-service endpoint for the current officer public key."""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT key_id, public_key_pem, key_type, is_current, created_at, expires_at, key_version
            FROM officer_keys
            WHERE officer_id = %s AND is_current = TRUE
            ORDER BY created_at DESC
            LIMIT 1
            """,
            (officer_id,),
        )
        key = cur.fetchone()
        if not key:
            return jsonify({"error": "Current key not found"}), 404
        return jsonify({"officer_id": officer_id, "key": dict(key)}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officers/<officer_id>/key-requests", methods=["GET"])
@require_auth
def list_officer_key_requests(officer_id):
    if g.current_user_type == "officer" and g.current_user_id != officer_id:
        return jsonify({"error": "Forbidden"}), 403

    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT request_id, officer_id, requested_by, reason, status, created_at, resolved_at, resolved_by, old_key_id, new_key_id
            FROM officer_key_requests
            WHERE officer_id = %s
            ORDER BY created_at DESC
            """,
            (officer_id,),
        )
        rows = cur.fetchall()
        return jsonify({"officer_id": officer_id, "requests": [dict(row) for row in rows]}), 200
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officer-key-requests/pending", methods=["GET"])
@require_auth
@require_user_type("pki_admin")
def list_pending_key_requests():
    """DEPRECATED: Key requests are no longer used. Officers register public keys directly."""
    return jsonify({
        "status": "deprecated",
        "message": "Key request workflow has been replaced with direct public key registration",
        "new_workflow": "Officers use POST /api/storage/officers/<officer_id>/register-key to register their public key",
        "then_request_certificate": "PKI admin issues certificate via POST /api/pki/issue-certificate with officer_id and public_key_pem"
    }), 410


@app.route("/api/storage/admin/overview", methods=["GET"])
@require_auth
@require_user_type("storage_admin")
def get_admin_overview():
    """Storage admin dashboard overview - see all accounts, requests, keys"""
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Get all officers with their current key status
        cur.execute("""
            SELECT 
                o.officer_id, o.name, o.email, o.region_code, o.department, o.created_at,
                (SELECT COUNT(*) FROM officer_keys WHERE officer_id=o.officer_id AND is_current=TRUE) as current_key_count,
                (SELECT COUNT(*) FROM officer_key_requests WHERE officer_id=o.officer_id AND status='pending') as pending_requests
            FROM officers o
            ORDER BY o.created_at DESC
        """)
        officers = [dict(row) for row in cur.fetchall()]
        
        # Get all pending key requests with officer details
        cur.execute("""
            SELECT 
                r.request_id, r.officer_id, r.reason, r.status, r.created_at, r.resolved_at,
                o.name, o.email, o.region_code
            FROM officer_key_requests r
            JOIN officers o ON r.officer_id = o.officer_id
            WHERE r.status IN ('pending', 'approved')
            ORDER BY r.created_at DESC
        """)
        pending_requests = [dict(row) for row in cur.fetchall()]
        
        # Get all current keys
        cur.execute("""
            SELECT 
                k.key_id, k.officer_id, k.key_version, k.is_current, k.created_at, k.expires_at,
                o.name, o.email
            FROM officer_keys k
            JOIN officers o ON k.officer_id = o.officer_id
            WHERE k.is_current = TRUE
            ORDER BY k.created_at DESC
        """)
        current_keys = [dict(row) for row in cur.fetchall()]
        
        # Get all citizens (count only)
        cur.execute("SELECT COUNT(*) as count FROM citizens")
        citizen_count = cur.fetchone()["count"]
        
        # Get all thirdparties (count only)
        cur.execute("SELECT COUNT(*) as count FROM thirdparties")
        thirdparty_count = cur.fetchone()["count"]
        
        write_audit("VIEW_ADMIN_OVERVIEW", g.current_user_id, "ADMIN_ACCESS", "dashboard",
                   details={"officers_count": len(officers), "pending_requests_count": len(pending_requests)})
        
        return jsonify({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "viewed_by": g.current_user_id,
            "summary": {
                "total_officers": len(officers),
                "officers_with_pending_requests": sum(1 for o in officers if o["pending_requests"] > 0),
                "officers_with_current_keys": sum(1 for o in officers if o["current_key_count"] > 0),
                "total_pending_requests": len(pending_requests),
                "total_current_keys": len(current_keys),
                "total_citizens": citizen_count,
                "total_thirdparties": thirdparty_count
            },
            "officers": officers,
            "pending_requests": pending_requests,
            "current_keys": current_keys
        }), 200
    except Exception as exc:
        logger.error("get_admin_overview failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/officer-key-requests/<request_id>/approve", methods=["POST"])
@require_auth
@require_user_type("pki_admin")
def approve_key_request(request_id):
    """PKI admin approves a key request and auto-generates a key pair"""
    data = request.get_json(force=True) or {}
    key_type = data.get("key_type", "ML-DSA")
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        # Get the request details
        cur.execute(
            """
            SELECT request_id, officer_id, status
            FROM officer_key_requests
            WHERE request_id = %s
            """,
            (request_id,)
        )
        key_req = cur.fetchone()
        if not key_req:
            return jsonify({"error": "Key request not found"}), 404
        
        if key_req["status"] != "pending":
            return jsonify({"error": f"Request is {key_req['status']}, cannot approve"}), 409
        
        officer_id = key_req["officer_id"]
        
        # Mark old keys as non-current
        cur.execute(
            "UPDATE officer_keys SET is_current = FALSE, rotated_at = NOW() WHERE officer_id = %s AND is_current = TRUE",
            (officer_id,)
        )
        
        # Generate new key ID and version
        key_id = f"key-{officer_id}-{uuid.uuid4().hex[:8]}"
        cur.execute("SELECT MAX(key_version) AS max_version FROM officer_keys WHERE officer_id = %s", (officer_id,))
        version_row = cur.fetchone()
        key_version = int(version_row["max_version"]) + 1 if version_row and version_row.get("max_version") else 1
        
        # Generate a temporary public key (in production, officer would provide this after local keygen)
        # For now, we'll return instructions for the PKI admin to complete the process
        expires_at = datetime.now(timezone.utc) + timedelta(days=365)
        
        # Update request status to approved (pending public key submission)
        cur.execute(
            """
            UPDATE officer_key_requests
            SET status = 'approved', resolved_at = NOW(), resolved_by = %s
            WHERE request_id = %s AND officer_id = %s
            """,
            (g.current_user_id, request_id, officer_id)
        )
        conn.commit()
        
        write_audit("APPROVE_KEY_REQUEST", g.current_user_id, "OFFICER_KEY", request_id,
                   details={"officer_id": officer_id, "key_version": key_version})
        
        return jsonify({
            "request_id": request_id,
            "officer_id": officer_id,
            "status": "approved",
            "key_version": key_version,
            "next_step": "Officer must generate key pair locally and submit public key",
            "submit_key_url": f"/api/storage/officers/{officer_id}/keys",
            "approved_at": datetime.now(timezone.utc).isoformat(),
            "approved_by": g.current_user_id
        }), 200
    except Exception as exc:
        conn.rollback()
        logger.error("approve_key_request failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/users/<user_id>/keys", methods=["GET"])
@require_auth
def get_user_keys_legacy(user_id):
    """DEPRECATED: Use /api/storage/officers/{officer_id}/keys"""
    return jsonify({"error": "Use /api/storage/officers/{officer_id}/keys"}), 410


@app.route("/api/storage/officers/<officer_id>/keys/<key_id>", methods=["GET"])
@require_auth
def get_officer_key_public(officer_id, key_id):
    """Retrieve officer's specific public key in PEM format"""
    if g.current_user_type == "officer" and g.current_user_id != officer_id:
        return jsonify({"error": "Forbidden"}), 403
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            "SELECT public_key_pem, key_type, is_current, created_at FROM officer_keys WHERE key_id = %s AND officer_id = %s",
            (key_id, officer_id),
        )
        key = cur.fetchone()
        if not key:
            return jsonify({"error": "Key not found"}), 404

        return Response(key["public_key_pem"], status=200, mimetype="application/octet-stream")
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/users/<user_id>/keys/<key_id>", methods=["GET"])
@require_auth
def get_user_key_public_legacy(user_id, key_id):
    """DEPRECATED: Use /api/storage/officers/{officer_id}/keys/{key_id}"""
    return jsonify({"error": "Use /api/storage/officers/{officer_id}/keys/{key_id}"}), 410


@app.route("/api/storage/document-qr", methods=["POST"])
def store_document_qr():
    """Store document QR metadata in database"""
    try:
        ensure_schema()
        data = request.get_json(force=True)
        qr_id = data.get("qr_id")
        document_id = data.get("document_id")
        document_type = data.get("document_type", "certificate")
        key_b64 = data.get("key_b64")
        encrypted_data = data.get("encrypted_data")
        metadata = data.get("metadata", {})
        created_by = data.get("created_by", "system")

        if not all([qr_id, document_id, key_b64, encrypted_data]):
            return jsonify({"error": "Missing required fields"}), 400

        conn = get_db_connection()
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO document_qr (qr_id, document_id, document_type, key_b64, encrypted_data, metadata, created_by)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (qr_id, document_id, document_type, key_b64, encrypted_data, json.dumps(metadata), created_by)
            )
            conn.commit()
            logger.info(f"Document QR stored: {qr_id} for doc {document_id}")
            return jsonify({"qr_id": qr_id, "document_id": document_id}), 201
        except Exception as e:
            conn.rollback()
            logger.error(f"Failed to store document QR: {e}")
            return jsonify({"error": str(e)}), 500
        finally:
            cur.close()
            conn.close()
    except Exception as e:
        logger.error(f"Store document QR error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/storage/document-qr/<qr_id>", methods=["GET"])
def get_document_by_qr(qr_id):
    """Retrieve document metadata by QR ID"""
    try:
        ensure_schema()
        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            cur.execute(
                """
                UPDATE document_qr SET accessed_count = accessed_count + 1, last_accessed_at = NOW()
                WHERE qr_id = %s
                """,
                (qr_id,)
            )
            conn.commit()

            cur.execute(
                """
                SELECT qr_id, document_id, document_type, key_b64, encrypted_data, metadata, created_at, created_by, accessed_count
                FROM document_qr WHERE qr_id = %s
                """,
                (qr_id,)
            )
            doc = cur.fetchone()
            if not doc:
                return jsonify({"error": "QR not found"}), 404

            return jsonify(dict(doc)), 200
        finally:
            cur.close()
            conn.close()
    except Exception as e:
        logger.error(f"Get document by QR error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/storage/document-qr", methods=["GET"])
def list_document_qrs():
    """List all document QRs (with optional filtering)"""
    try:
        ensure_schema()
        cert_type = request.args.get("document_type")
        limit = min(int(request.args.get("limit", "100")), 500)

        conn = get_db_connection()
        cur = conn.cursor(cursor_factory=RealDictCursor)
        try:
            if cert_type:
                cur.execute(
                    """
                    SELECT qr_id, document_id, document_type, created_at, accessed_count
                    FROM document_qr WHERE document_type = %s ORDER BY created_at DESC LIMIT %s
                    """,
                    (cert_type, limit)
                )
            else:
                cur.execute(
                    """
                    SELECT qr_id, document_id, document_type, created_at, accessed_count
                    FROM document_qr ORDER BY created_at DESC LIMIT %s
                    """,
                    (limit,)
                )
            qrs = cur.fetchall()
            return jsonify({"qrs": [dict(q) for q in qrs]}), 200
        finally:
            cur.close()
            conn.close()
    except Exception as e:
        logger.error(f"List document QRs error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/api/storage/pki/officer-keys-export", methods=["GET"])
@require_auth
@require_user_type("pki_admin")
def export_all_officer_keys():
    """
    Bulk export of all officer public keys for PKI verification and audit.
    Returns a JSON with all officers and their current public keys in PEM format.
    PKI admins only.
    """
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute(
            """
            SELECT 
                o.officer_id, 
                o.email, 
                o.name, 
                o.region_code,
                ok.key_id,
                ok.public_key_pem,
                ok.key_type,
                ok.is_current,
                ok.created_at,
                ok.expires_at,
                ok.key_version
            FROM officers o
            LEFT JOIN officer_keys ok ON o.officer_id = ok.officer_id
            ORDER BY o.officer_id, ok.created_at DESC
            """
        )
        rows = cur.fetchall()
        
        # Group by officer
        officers_map = {}
        for row in rows:
            officer_id = row['officer_id']
            if officer_id not in officers_map:
                officers_map[officer_id] = {
                    "officer_id": officer_id,
                    "email": row['email'],
                    "name": row['name'],
                    "region_code": row['region_code'],
                    "keys": []
                }
            
            if row['key_id']:
                officers_map[officer_id]['keys'].append({
                    "key_id": row['key_id'],
                    "public_key_pem": row['public_key_pem'],
                    "key_type": row['key_type'],
                    "is_current": row['is_current'],
                    "created_at": row['created_at'].isoformat() if row['created_at'] else None,
                    "expires_at": row['expires_at'].isoformat() if row['expires_at'] else None,
                    "key_version": row['key_version']
                })
        
        write_audit("EXPORT_KEYS", g.current_user_id, "PKI_EXPORT", "all_officer_keys", details={"officer_count": len(officers_map)})
        return jsonify({
            "exported_at": datetime.now(timezone.utc).isoformat(),
            "exported_by": g.current_user_id,
            "officer_count": len(officers_map),
            "officers": list(officers_map.values())
        }), 200
    except Exception as exc:
        logger.error("export_all_officer_keys failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/pki-admins/<admin_id>/change-password", methods=["POST"])
def change_pki_admin_password(admin_id):
    """Change PKI admin password"""
    data = request.get_json(force=True)
    
    if not data.get("current_password") or not data.get("new_password"):
        return jsonify({"error": "Missing current_password or new_password"}), 400
    
    current_password = data["current_password"]
    new_password = data["new_password"]
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT admin_id, password_hash, password_salt FROM pki_admins WHERE admin_id = %s", (admin_id,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({"error": "Admin not found"}), 404
        
        if not verify_password(current_password, user["password_hash"], user["password_salt"]):
            write_audit("CHANGE_PASSWORD_FAIL", admin_id, "PKI_ADMIN", admin_id, status="FAILURE", error_message="wrong current password")
            return jsonify({"error": "Current password is incorrect"}), 401
        
        new_hash, new_salt = hash_password(new_password)
        cur.execute(
            "UPDATE pki_admins SET password_hash = %s, password_salt = %s WHERE admin_id = %s",
            (new_hash, new_salt, admin_id),
        )
        conn.commit()
        write_audit("CHANGE_PASSWORD_SUCCESS", admin_id, "PKI_ADMIN", admin_id)
        return jsonify({
            "admin_id": admin_id,
            "message": "Password changed successfully",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as exc:
        conn.rollback()
        logger.error("change_pki_admin_password failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


@app.route("/api/storage/storage-admins/<admin_id>/change-password", methods=["POST"])
def change_storage_admin_password(admin_id):
    """Change Storage admin password"""
    data = request.get_json(force=True)
    
    if not data.get("current_password") or not data.get("new_password"):
        return jsonify({"error": "Missing current_password or new_password"}), 400
    
    current_password = data["current_password"]
    new_password = data["new_password"]
    
    ensure_schema()
    conn = get_db_connection()
    cur = conn.cursor(cursor_factory=RealDictCursor)
    try:
        cur.execute("SELECT admin_id, password_hash, password_salt FROM storage_admins WHERE admin_id = %s", (admin_id,))
        user = cur.fetchone()
        
        if not user:
            return jsonify({"error": "Admin not found"}), 404
        
        if not verify_password(current_password, user["password_hash"], user["password_salt"]):
            write_audit("CHANGE_PASSWORD_FAIL", admin_id, "STORAGE_ADMIN", admin_id, status="FAILURE", error_message="wrong current password")
            return jsonify({"error": "Current password is incorrect"}), 401
        
        new_hash, new_salt = hash_password(new_password)
        cur.execute(
            "UPDATE storage_admins SET password_hash = %s, password_salt = %s WHERE admin_id = %s",
            (new_hash, new_salt, admin_id),
        )
        conn.commit()
        write_audit("CHANGE_PASSWORD_SUCCESS", admin_id, "STORAGE_ADMIN", admin_id)
        return jsonify({
            "admin_id": admin_id,
            "message": "Password changed successfully",
            "updated_at": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as exc:
        conn.rollback()
        logger.error("change_storage_admin_password failed: %s", exc)
        return jsonify({"error": str(exc)}), 500
    finally:
        cur.close()
        conn.close()


if __name__ == "__main__":
    app.run(host=SERVICE_LISTEN, port=SERVICE_PORT, debug=False)
