#!/usr/bin/env python3
"""Offline QR payload verifier for D1 demo.

The qr-service payload is Fernet-encrypted. Provide the same Fernet key used by
qr-service via --key or QR_FERNET_KEY environment variable.
"""

import argparse
import base64
import json
import os
import sys
import time

from cryptography.fernet import Fernet, InvalidToken


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify encrypted QR payload offline")
    parser.add_argument("--qr", required=True, help="QR payload string (base64url of Fernet token)")
    parser.add_argument(
        "--key",
        default=os.environ.get("QR_FERNET_KEY", ""),
        help="Fernet key used by qr-service (or set QR_FERNET_KEY)",
    )
    args = parser.parse_args()

    if not args.key:
        print("[ERROR] Missing Fernet key. Use --key or QR_FERNET_KEY.")
        return 2

    try:
        fernet = Fernet(args.key.encode())
    except Exception:
        print("[ERROR] Invalid Fernet key format.")
        return 2

    try:
        encrypted = base64.urlsafe_b64decode(args.qr.encode())
        payload = json.loads(fernet.decrypt(encrypted).decode())
    except (InvalidToken, ValueError, json.JSONDecodeError):
        print("[INVALID] QR payload cannot be decrypted/parsed.")
        return 1

    now = time.time()
    expired = now > float(payload.get("exp", 0))

    result = {
        "valid": not expired,
        "expired": expired,
        "user_id": payload.get("user_id"),
        "nonce": payload.get("nonce"),
        "iat": payload.get("iat"),
        "exp": payload.get("exp"),
    }
    print(json.dumps(result, ensure_ascii=True, indent=2))
    return 0 if not expired else 1


if __name__ == "__main__":
    sys.exit(main())
