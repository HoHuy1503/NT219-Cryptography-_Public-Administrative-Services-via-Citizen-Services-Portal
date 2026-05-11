# DEPLOY/D1/qr-service/app.py
import redis, json, uuid, time, base64, os, logging
from flask import Flask, request, jsonify
from cryptography.fernet import Fernet
 
logging.basicConfig(level=logging.INFO)
app = Flask(__name__)
r = redis.Redis(host=os.environ.get("REDIS_HOST","redis"),
                port=6379, decode_responses=True)
 
# Trong production: lấy key từ Vault/KMS. Dev có thể truyền QR_FERNET_KEY để
# tái lập demo, nếu không sẽ generate mới mỗi lần start.
QR_KEY = os.environ.get("QR_FERNET_KEY")
if QR_KEY:
    QR_KEY = QR_KEY.encode()
else:
    QR_KEY = Fernet.generate_key()

fernet = Fernet(QR_KEY)
QR_TTL = 300  # 5 phút
 
 
@app.route("/api/qr/generate", methods=["POST"])
def generate_qr():
    user_id = request.get_json()["user_id"]
    nonce = str(uuid.uuid4())  # Nonce ngẫu nhiên — single-use (I7)
 
    payload = json.dumps({
        "user_id": user_id,
        "nonce": nonce,
        "iat": time.time(),
        "exp": time.time() + QR_TTL
    })
 
    # Mã hóa payload (ChaCha20-Poly1305 trong production)
    encrypted = fernet.encrypt(payload.encode())
    qr_data = base64.urlsafe_b64encode(encrypted).decode()
 
    # Lưu nonce vào Redis: chưa dùng → TTL = 5 phút
    r.setex(f"qr_pending:{nonce}", QR_TTL, user_id)
    logging.info(json.dumps({"event":"qr_generated",
                              "user_id":user_id,"nonce":nonce[:8]}))
    return jsonify({"nonce": nonce, "qr_data": qr_data,
                    "expires_in": QR_TTL}), 201
 
 
@app.route("/api/qr/verify", methods=["POST"])
def verify_qr():
    qr_data = request.get_json().get("qr_data","")
    try:
        encrypted = base64.urlsafe_b64decode(qr_data)
        payload = json.loads(fernet.decrypt(encrypted))
    except Exception:
        return jsonify({"error": "Invalid QR data"}), 400
 
    # Kiểm tra TTL
    if time.time() > payload["exp"]:
        return jsonify({"error": "QR expired"}), 401
 
    nonce = payload["nonce"]
 
    # ── I7: SINGLE-USE NONCE CHECK ────────────────────────
    if r.exists(f"qr_used:{nonce}"):
        logging.warning(json.dumps({"event":"qr_replay_detected",
                                    "nonce":nonce[:8],
                                    "invariant":"I7"}))
        return jsonify({
            "error": "QR already used — replay attack detected",
            "invariant": "I7",
            "nonce": nonce[:8]+"..."
        }), 401
 
    # Đánh dấu đã dùng (giữ thêm TTL giây để chống race condition)
    r.setex(f"qr_used:{nonce}", QR_TTL, "used")
    r.delete(f"qr_pending:{nonce}")
 
    logging.info(json.dumps({"event":"qr_verified_ok",
                              "user_id":payload["user_id"],
                              "nonce":nonce[:8]}))
    return jsonify({
        "valid": True,
        "user_id": payload["user_id"],
        "message": "QR verified — issue short-lived token"
    }), 200
 
 
@app.route("/health")
def health(): return jsonify({"status":"ok"})
 
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002)
