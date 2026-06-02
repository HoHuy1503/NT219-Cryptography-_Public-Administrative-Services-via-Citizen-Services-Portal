#!/bin/sh
set -e
echo "Starting storage_service mTLS front-end..."
nginx -c /etc/nginx/nginx-internal.conf
echo "Starting storage_service app..."
exec python3 app.py
