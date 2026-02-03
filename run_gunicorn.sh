#!/bin/bash

set -euo pipefail

usage() {
  cat << 'EOF'
Usage: ./run_gunicorn.sh [--user USER]

Options:
  -u, --user USER   Run gunicorn as a non-privileged user (uses sudo -u)
  -h, --help        Show this help

Environment overrides:
  GUNICORN_WORKERS   Number of workers (default: 4)
  GUNICORN_TIMEOUT   Worker timeout seconds (default: 120)
  GUNICORN_BIND      Bind address (default: 0.0.0.0:8000)
  GUNICORN_LOG_DIR   Log directory (default: ./logs)
EOF
}

RUN_AS_USER=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    -u|--user)
      RUN_AS_USER="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      usage
      exit 1
      ;;
  esac
done

if [[ "$(id -u)" -eq 0 && -z "$RUN_AS_USER" ]]; then
  echo "[WARN] Running as root is discouraged for security reasons."
  echo "       Use --user <non-privileged-user> to drop privileges."
fi

if [[ -n "$RUN_AS_USER" ]]; then
  if ! id -u "$RUN_AS_USER" >/dev/null 2>&1; then
    echo "[ERROR] User '$RUN_AS_USER' does not exist."
    exit 1
  fi
fi

if [[ ! -d "venv" ]]; then
  echo "[ERROR] venv not found. Create it first: python3 -m venv venv"
  exit 1
fi

# Activate venv
# shellcheck disable=SC1091
source venv/bin/activate

if ! command -v gunicorn >/dev/null 2>&1; then
  echo "[ERROR] gunicorn not found in venv. Install with: pip install gunicorn"
  exit 1
fi

LOG_DIR="${GUNICORN_LOG_DIR:-./logs}"
SESSION_DIR="./flask_session"

mkdir -p "$LOG_DIR" "$SESSION_DIR"

check_writable() {
  local dir="$1"
  if [[ -n "$RUN_AS_USER" ]]; then
    if ! sudo -u "$RUN_AS_USER" test -w "$dir"; then
      echo "[ERROR] Directory not writable for user '$RUN_AS_USER': $dir"
      exit 1
    fi
  else
    if [[ ! -w "$dir" ]]; then
      echo "[ERROR] Directory not writable: $dir"
      exit 1
    fi
  fi
}

check_writable "$LOG_DIR"
check_writable "$SESSION_DIR"

BIND="${GUNICORN_BIND:-0.0.0.0:8000}"
WORKERS="${GUNICORN_WORKERS:-4}"
TIMEOUT="${GUNICORN_TIMEOUT:-120}"

ACCESS_LOG="$LOG_DIR/access.log"
ERROR_LOG="$LOG_DIR/error.log"

CMD=(gunicorn --workers "$WORKERS" \
     --bind "$BIND" \
     --timeout "$TIMEOUT" \
     --access-logfile "$ACCESS_LOG" \
     --error-logfile "$ERROR_LOG" \
     fuco:app)

if [[ -n "$RUN_AS_USER" ]]; then
  echo "[INFO] Starting gunicorn as user '$RUN_AS_USER'..."
  sudo -u "$RUN_AS_USER" "${CMD[@]}"
else
  echo "[INFO] Starting gunicorn..."
  "${CMD[@]}"
fi
