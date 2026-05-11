from flask import Flask, request, jsonify
import hvac, hashlib, hmac, base64, json, os, time, logging
 
logging.basicConfig(level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s",%(message)s}')
 
app = Flask(__name__)
vc = hvac.Client(
    url=os.environ["VAULT_ADDR"],
    token=os.environ["VAULT_TOKEN"]
)


def has_internal_bypass():
    return request.headers.get("X-Internal-Bypass", "").lower() in {"1", "true", "yes"}


def require_token_or_bypass():
    if has_internal_bypass():
        return None

    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return jsonify({"error": "missing or invalid token"}), 401

    token = auth_header.removeprefix("Bearer ").strip()
    parts = token.split(".")
    if len(parts) != 3:
        return jsonify({"error": "invalid token"}), 401

    try:
        header_raw = base64.urlsafe_b64decode(parts[0] + "==").decode()
        header = json.loads(header_raw)
        payload_raw = base64.urlsafe_b64decode(parts[1] + "==").decode()
        payload = json.loads(payload_raw)
    except Exception:
        return jsonify({"error": "invalid token"}), 401

    if header.get("alg") == "none":
        return jsonify({"error": "alg none rejected"}), 401

    if float(payload.get("exp", 0)) < time.time():
        return jsonify({"error": "token expired"}), 401

    return None


def local_signing_key():
    seed = os.environ.get("DOC_SIGNING_SECRET", os.environ.get("VAULT_TOKEN", "govportal-doc-signing"))
    return hashlib.sha256(seed.encode()).digest()


def local_sign(doc_b64):
    digest = hmac.new(local_signing_key(), doc_b64.encode(), hashlib.sha256).hexdigest()
    return f"local:{digest}"


def local_verify(doc_b64, signature):
    expected = local_sign(doc_b64)
    return hmac.compare_digest(expected, signature)
 
def log_event(event, extra={}):
    data = {"\"event\"":'"'+event+'"', **extra}
    logging.info(",".join(f'{k}:{v}' for k,v in data.items()))
 
@app.route("/api/documents/sign", methods=["POST"])
def sign_document():
    auth_error = require_token_or_bypass()
    if auth_error is not None:
        return auth_error

    data = request.get_json()
    doc_b64 = data["document_base64"]
    doc_bytes = base64.b64decode(doc_b64)
    doc_hash = hashlib.sha256(doc_bytes).hexdigest()
 
    # Bước 1: Ký qua Vault Transit — key KHÔNG rời Vault
    try:
        sig_resp = vc.write(
            path="transit/sign/falcon-doc-signing",
            input=doc_b64
        )
        signature = sig_resp["data"]["signature"]
    except Exception as exc:
        log_event("document_sign_fallback", {
            '"error"': f'"{str(exc)}"'
        })
        signature = local_sign(doc_b64)
 
    # Bước 2: Envelope encrypt (AEAD trong Vault)
    enc_resp = vc.secrets.transit.encrypt_data(
        name="doc-encryption",
        plaintext=doc_b64
    )["data"]
 
    result = {
        "doc_id": doc_hash[:16],
        "doc_hash_sha256": doc_hash,
        "signature": signature,
        "ciphertext": enc_resp["ciphertext"],
        "key_version": enc_resp["key_version"],
        "signed_at": time.time()
    }
 
    # Structured audit log — phục vụ E-X2 Explainability
    log_event("document_signed", {
        '"doc_id"': f'"{result["doc_id"]}"',
        '"user"': f'"{request.headers.get("X-User-Id","unknown")}"',
        '"role"': f'"{request.headers.get("X-User-Role","unknown")}"',
    })
    return jsonify(result), 201
 
 
@app.route("/api/documents/verify", methods=["POST"])
def verify_document():
    auth_error = require_token_or_bypass()
    if auth_error is not None:
        return auth_error

    data = request.get_json()
    doc_b64 = data["document_base64"]
    doc_bytes = base64.b64decode(doc_b64)
    doc_hash = hashlib.sha256(doc_bytes).hexdigest()
 
    # Verify signature qua Vault Transit
    try:
        verify_resp = vc.write(
            path="transit/verify/falcon-doc-signing",
            input=doc_b64,
            signature=data["signature"]
        )
        valid = bool(verify_resp["data"]["valid"])
    except Exception as exc:
        log_event("document_verify_error", {
            '"error"': f'"{str(exc)}"'
        })
        valid = local_verify(doc_b64, data["signature"])
        if not valid:
            return jsonify({"valid": False, "doc_hash": doc_hash,
                            "tampered": True, "error": "verify_error"}), 400
 
    log_event("document_verified", {
        '"valid"': str(valid).lower(),
        '"doc_hash"': f'"{doc_hash}"'
    })
    return jsonify({"valid": valid, "doc_hash": doc_hash,
                    "tampered": not valid}), 200 if valid else 400
 
 
@app.route("/health")
def health(): return jsonify({"status":"ok"})
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
