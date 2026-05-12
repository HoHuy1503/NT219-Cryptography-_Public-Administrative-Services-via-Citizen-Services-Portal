#!/usr/bin/env python3
import json
import os
import sys
import time
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

def main() -> int:

    script_dir = Path(__file__).parent.absolute()

    base_dir = script_dir.parent

    key_file_path = base_dir / "key" / "key.bin"
    qr_file_path = base_dir / "qr_encoded" / "qr_code.enc"

    if not key_file_path.exists():
        print(f"[ERROR] Không tìm thấy file key: {key_file_path}")
        return 2
    if not qr_file_path.exists():
        print(f"[ERROR] Không tìm thấy file mã hóa: {qr_file_path}")
        return 2

    try:

        with open(key_file_path, "rb") as f:
            raw_key_data = f.read()

        iv = raw_key_data[-16:]
        key = raw_key_data[:-16]

        with open(qr_file_path, "rb") as f:
            encrypted_data = f.read()

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_raw = cipher.decrypt(encrypted_data)
        decrypted_text = unpad(decrypted_raw, AES.block_size).decode('utf-8')
        
        payload = json.loads(decrypted_text)

        now = time.time()
        exp = float(payload.get("exp", 0))
        expired = now > exp

        result = {
            "status": "SUCCESS",
            "valid": not expired,
            "expired": expired,
            "user_id": payload.get("user_id"),
            "iat": payload.get("iat"),
            "exp": exp,
            "details": {
                "key_used": key_file_path.name,
                "file_decrypted": qr_file_path.name,
                "key_length": len(key)
            }
        }
        
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return 0 if not expired else 1

    except Exception as e:
        print(json.dumps({
            "status": "ERROR",
            "message": f"Không thể verify. Lỗi: {str(e)}"
        }, indent=2))
        return 1

if __name__ == "__main__":
    sys.exit(main())