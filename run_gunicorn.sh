#!/bin/bash

set -euo pipefail

usage() {
  cat << 'EOF'
Usage: ./run_gunicorn.sh [--user USER]

Options:
  -u, --user USER   Run gunicorn as a non-privileged user (uses sudo -u)
  -h, --help        Show this help

Environment overrides:
  GUNICORN_WORKERS   Number of workers (default: 5)
  GUNICORN_WORKER_CLASS Worker class (default: gthread)
  GUNICORN_THREADS   Threads per worker (default: 3)
  GUNICORN_TIMEOUT   Worker timeout seconds (default: 240)
  GUNICORN_GRACEFUL_TIMEOUT Graceful timeout seconds (default: 30)
  GUNICORN_KEEPALIVE Keep-alive seconds (default: 5)
  GUNICORN_MAX_REQUESTS Recycle worker after N requests (default: 1000)
  GUNICORN_MAX_REQUESTS_JITTER Random jitter added to max-requests (default: 100)
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
    --user=*)
      RUN_AS_USER="${1#*=}"
      shift
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

VENV_DIR=""
if [[ -d "venv" ]]; then
  VENV_DIR="venv"
elif [[ -d "vevn" ]]; then
  # Compatibility fallback for environments created with a typo.
  VENV_DIR="vevn"
else
  echo "[ERROR] Neither 'venv' nor 'vevn' was found. Create it first: python3 -m venv venv"
  exit 1
fi

GUNICORN_BIN="$VENV_DIR/bin/gunicorn"
if [[ ! -x "$GUNICORN_BIN" ]]; then
  echo "[ERROR] gunicorn not found in $VENV_DIR. Install with: $VENV_DIR/bin/pip install gunicorn"
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
WORKERS="${GUNICORN_WORKERS:-5}"
WORKER_CLASS="${GUNICORN_WORKER_CLASS:-gthread}"
THREADS="${GUNICORN_THREADS:-3}"
TIMEOUT="${GUNICORN_TIMEOUT:-240}"
GRACEFUL_TIMEOUT="${GUNICORN_GRACEFUL_TIMEOUT:-30}"
KEEPALIVE="${GUNICORN_KEEPALIVE:-5}"
MAX_REQUESTS="${GUNICORN_MAX_REQUESTS:-1000}"
MAX_REQUESTS_JITTER="${GUNICORN_MAX_REQUESTS_JITTER:-100}"

ACCESS_LOG="$LOG_DIR/access.log"
ERROR_LOG="$LOG_DIR/error.log"

CMD=("$GUNICORN_BIN" --workers "$WORKERS" \
  --worker-class "$WORKER_CLASS" \
  --threads "$THREADS" \
     --bind "$BIND" \
     --timeout "$TIMEOUT" \
  --graceful-timeout "$GRACEFUL_TIMEOUT" \
  --keep-alive "$KEEPALIVE" \
  --max-requests "$MAX_REQUESTS" \
  --max-requests-jitter "$MAX_REQUESTS_JITTER" \
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
