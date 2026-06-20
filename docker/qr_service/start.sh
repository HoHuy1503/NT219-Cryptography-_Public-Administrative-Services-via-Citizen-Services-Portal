#!/bin/sh
set -e
echo "Starting qr_service mTLS front-end..."
nginx -c /etc/nginx/nginx-internal.conf
echo "Starting qr_service app..."
exec python3 app.py
