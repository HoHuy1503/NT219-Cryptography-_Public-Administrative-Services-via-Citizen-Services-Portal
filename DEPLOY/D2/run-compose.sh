#!/bin/sh
set -e
ROOT_DIR=$(cd "$(dirname "$0")" && pwd)
echo "Bringing up compose stack (builds images)."
cd "$ROOT_DIR"
docker compose up -d --build
echo "Services starting. Use 'docker compose ps' to check status." 
