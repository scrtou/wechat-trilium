#!/usr/bin/env bash
set -Eeuo pipefail

SERVICE_NAME="${SERVICE_NAME:-wechat-trilium}"
APP_DIR="${APP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)}"
ENV_FILE="$APP_DIR/.env"
ENV_EXAMPLE="$APP_DIR/.env.example"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
NONINTERACTIVE="${INSTALL_NONINTERACTIVE:-0}"
USE_EXISTING_ENV="${INSTALL_USE_EXISTING_ENV:-0}"

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  cat <<'EOF_HELP'
Usage:
  ./install.sh
  ./install.sh --use-existing-env
Environment overrides:
  SERVICE_NAME=wechat-trilium APP_DIR=/path/to/wechat ./install.sh
  INSTALL_NONINTERACTIVE=1 TRILIUM_ETAPI_TOKEN=xxx ./install.sh
  INSTALL_USE_EXISTING_ENV=1 ./install.sh

The script installs Python dependencies, writes .env, creates a systemd service,
enables it and starts it.
EOF_HELP
  exit 0
fi
while [[ $# -gt 0 ]]; do
  case "$1" in
    --use-existing-env|--no-config)
      USE_EXISTING_ENV=1
      shift
      ;;
    --non-interactive)
      NONINTERACTIVE=1
      shift
      ;;
    *)
      printf '\033[1;31m[error]\033[0m unknown argument: %s\n' "$1" >&2
      exit 1
      ;;
  esac
done
if [[ "$(id -u)" -eq 0 ]]; then
  SUDO=""
  RUN_USER="${RUN_USER:-${SUDO_USER:-root}}"
else
  SUDO="sudo"
  RUN_USER="${RUN_USER:-$(id -un)}"
fi
RUN_GROUP="${RUN_GROUP:-$(id -gn "$RUN_USER" 2>/dev/null || id -gn)}"

log() { printf '\033[1;32m[install]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*"; }
err() { printf '\033[1;31m[error]\033[0m %s\n' "$*" >&2; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || { err "缺少命令：$1"; exit 1; }
}
run_as_root() {
  if [[ -n "$SUDO" ]]; then
    need_cmd sudo
    sudo "$@"
  else
    "$@"
  fi
}

get_env_value() {
  local key="$1" file="${2:-$ENV_FILE}"
  [[ -f "$file" ]] || return 0
  grep -E "^${key}=" "$file" | tail -n 1 | sed "s/^${key}=//" || true
}

random_token() {
  python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(24))
PY
}
prompt_value() {
  local key="$1" label="$2" default_value="$3" secret="${4:-0}"
  local current="${!key:-}"
  if [[ -z "$current" ]]; then
    current="$(get_env_value "$key")"
  fi
  if [[ -z "$current" ]]; then
    current="$default_value"
  fi

  if [[ "$NONINTERACTIVE" == "1" ]]; then
    printf '%s' "$current"
    return
  fi
  local input=""
  if [[ "$secret" == "1" ]]; then
    if [[ -n "$current" && "$current" != put-your-* && "$current" != change-me-* ]]; then
