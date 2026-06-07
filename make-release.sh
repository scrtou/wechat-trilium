#!/usr/bin/env bash
set -Eeuo pipefail
OUT="${1:-wechat-trilium-bridge.tar.gz}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
tar \
  --exclude='./.env' \
  --exclude='./.venv' \
  --exclude='./__pycache__' \
  --exclude='./*.pyc' \
  --exclude='./wechat-trilium-bridge.tar.gz' \
  -czf "$OUT" \
  app.py requirements.txt install.sh .env.example wechat-trilium.service.example 2>/dev/null || \
tar \
  --exclude='.env' \
  --exclude='.venv' \
  --exclude='__pycache__' \
  --exclude='*.pyc' \
  -czf "$OUT" \
  app.py requirements.txt install.sh .env.example wechat-trilium.service.example

echo "Created: $(realpath "$OUT" 2>/dev/null || printf '%s' "$OUT")"
