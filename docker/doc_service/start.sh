#!/bin/sh
set -e
echo "Starting doc_service mTLS front-end..."
nginx -c /etc/nginx/nginx-internal.conf
echo "Starting doc_service app..."
exec python3 app.py
