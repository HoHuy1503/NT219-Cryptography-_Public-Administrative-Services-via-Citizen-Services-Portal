from flask import Flask, jsonify, request
import base64
import hashlib
import json
import os
import time
import uuid

app = Flask(__name__)

QR_TTL = int(os.getenv("QR_TTL", "300"))


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/api/qr/document-qr", methods=["POST"])
def document_qr():
    data = request.get_json(force=True) or {}
    document_id = data.get("document_id") or str(uuid.uuid4())
    document_type = data.get("document_type", "certificate")
    document_data = data.get("document_data", "")
    metadata = data.get("metadata", {})

    key_material = hashlib.sha256(f"{document_id}:{time.time()}".encode()).digest()
    key_b64 = base64.b64encode(key_material[:32]).decode()
    encrypted_doc_b64 = base64.urlsafe_b64encode(document_data.encode()).decode()
    qr_payload = f"{key_b64}|{document_id}|{document_type}|{encrypted_doc_b64}|{json.dumps(metadata)}"

    return jsonify({
        "qr_id": str(uuid.uuid4()),
        "document_id": document_id,
        "document_type": document_type,
        "qr_payload": qr_payload,
        "expires_in": QR_TTL,
    }), 201


@app.route("/api/qr/verify-document", methods=["POST"])
def verify_document_qr():
    data = request.get_json(force=True) or {}
    qr_payload = data.get("qr_payload")
    if not qr_payload:
        return jsonify({"error": "Missing qr_payload"}), 400

    parts = qr_payload.split("|", 4)
    if len(parts) < 4:
        return jsonify({"error": "Invalid QR format"}), 400

    key_b64, document_id, document_type, encrypted_doc_b64 = parts[:4]
    metadata_str = parts[4] if len(parts) > 4 else "{}"

    try:
        metadata = json.loads(metadata_str)
    except Exception:
        metadata = {}

    try:
        document_data = base64.urlsafe_b64decode(encrypted_doc_b64.encode()).decode()
    except Exception:
        return jsonify({"error": "Invalid document key or data"}), 400

    return jsonify({
        "session_id": str(uuid.uuid4()),
        "document_id": document_id,
        "document_type": document_type,
        "document_data": document_data,
        "metadata": metadata,
        "key": key_b64,
        "expires_in": 3600,
    }), 200


@app.route("/api/qr/verify", methods=["POST"])
def verify_qr():
    data = request.get_json(force=True) or {}
    nonce = data.get("nonce")
    qr_data = data.get("qr_data")
    user_public_key_pem = data.get("user_public_key_pem")
    if not nonce or not qr_data or not user_public_key_pem:
        return jsonify({"error": "Missing nonce, qr_data, or user_public_key_pem"}), 400

    return jsonify({
        "session_id": str(uuid.uuid4()),
        "session_key": base64.b64encode(hashlib.sha256(f"{nonce}:{qr_data}".encode()).digest()).decode(),
        "kem_ciphertext": base64.b64encode(hashlib.sha256(user_public_key_pem.encode()).digest()).decode(),
        "kem_algorithm": "ML-KEM-512",
        "user_id": data.get("user_id"),
        "expires_in": 3600,
    }), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=False)