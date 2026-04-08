from flask import Flask, request, jsonify
import hvac, hashlib, base64, json, os, time, logging
 
logging.basicConfig(level=logging.INFO,
    format='{"ts":"%(asctime)s","level":"%(levelname)s",%(message)s}')
 
app = Flask(__name__)
vc = hvac.Client(
    url=os.environ["VAULT_ADDR"],
    token=os.environ["VAULT_TOKEN"]
)
 
def log_event(event, extra={}):
    data = {"\"event\"":'"'+event+'"', **extra}
    logging.info(",".join(f'{k}:{v}' for k,v in data.items()))
 
@app.route("/api/documents/sign", methods=["POST"])
def sign_document():
    data = request.get_json()
    doc_b64 = data["document_base64"]
    doc_bytes = base64.b64decode(doc_b64)
    doc_hash = hashlib.sha256(doc_bytes).hexdigest()
 
    # Bước 1: Ký qua Vault Transit — key KHÔNG rời Vault
    sig_resp = vc.secrets.transit.sign_data(
        name="falcon-doc-signing",
        hash_input=doc_b64,
        hash_algorithm="sha2-256"
    )
    signature = sig_resp["data"]["signature"]
 
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
    data = request.get_json()
    doc_b64 = data["document_base64"]
    doc_bytes = base64.b64decode(doc_b64)
    doc_hash = hashlib.sha256(doc_bytes).hexdigest()
 
    # Verify signature qua Vault Transit
    verify_resp = vc.secrets.transit.verify_signed_data(
        name="falcon-doc-signing",
        hash_input=doc_b64,
        signature=data["signature"],
        hash_algorithm="sha2-256"
    )
    valid = verify_resp["data"]["valid"]
 
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
