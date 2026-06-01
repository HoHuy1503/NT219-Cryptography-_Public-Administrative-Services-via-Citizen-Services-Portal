#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "🚀 Starting GovPortal Multi-Role Systems"
echo ""

# Check if Python is available
if ! command -v python3 &> /dev/null; then
    echo "❌ Python3 is required but not installed"
    exit 1
fi

# Start portal server
python3 start_portals.py
