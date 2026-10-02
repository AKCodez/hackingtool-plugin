#!/usr/bin/env sh
# ht.sh — Python-free entrypoint for the pentest skill scripts.
#
# Runs the ht_*.py orchestration scripts using the host's Python when a real
# interpreter is present. When it isn't (common on Windows: no Python, or only
# the Microsoft Store stub), it bootstraps them inside a lightweight container
# that has both Python and the Docker CLI, with the host Docker socket mounted —
# so tool containers are still launched by the host daemon.
#
# Usage:
#   sh ht.sh preflight
#   sh ht.sh run <tool_id> [--args "..."] [--command "..."] [...]
#   sh ht.sh search --q nmap        # any ht_<name>.py, called by <name>
#
# Output is the underlying script's stdout verbatim (JSON). Diagnostics go to
# stderr so callers can still parse stdout as JSON.

set -eu

SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
PLUGIN_ROOT=$(dirname -- "$SCRIPT_DIR")

if [ "$#" -lt 1 ]; then
    echo "usage: sh ht.sh <preflight|run|search|env|...> [args...]" >&2
    exit 2
fi

CMD=$1
shift
TARGET="$SCRIPT_DIR/ht_${CMD}.py"
if [ ! -f "$TARGET" ]; then
    echo "no such script: ht_${CMD}.py (in $SCRIPT_DIR)" >&2
    exit 2
fi

log() { echo "ht.sh: $*" >&2; }

# ── Host OS (used to tell the containerized detector the real host) ────────────
detect_host() {
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux)                      # could be real Linux or WSL; both are "linux"
            echo linux ;;
        Darwin)
            echo macos ;;
        MINGW*|MSYS*|CYGWIN*|Windows_NT)
            echo windows ;;
        *)
            echo unknown ;;
    esac
}
HOST=$(detect_host)

# ── Find a *real* host Python (reject the Windows Store execution-alias stub) ──
find_python() {
    for cand in python3 python; do
        if command -v "$cand" >/dev/null 2>&1; then
            # The stub exits non-zero and prints nothing on stdout for this.
            if ver=$("$cand" -c 'import sys;print(sys.version_info[0])' 2>/dev/null) \
               && [ "$ver" = "3" ]; then
                echo "$cand"
                return 0
            fi
        fi
    done
    return 1
}

# ── Is the host Docker daemon reachable? ──────────────────────────────────────
docker_ready() {
    command -v docker >/dev/null 2>&1 || return 1
    v=$(docker version --format '{{.Server.Version}}' 2>/dev/null) || return 1
    [ -n "$v" ]
}

# Fast path: a genuine host Python runs the script directly.
if PY=$(find_python); then
    log "using host Python ($PY), backend auto-detected natively"
    exec "$PY" "$TARGET" "$@"
fi

log "no host Python found; attempting Docker bootstrap"

if ! docker_ready; then
    # Emit a structured, honest blocked verdict rather than a shell error so the
    # skill can surface it. Mirrors ht_preflight's shape for the common case.
    cat <<EOF
{
  "verdict": "blocked",
  "env": {"host": "$HOST", "docker": false, "preferred_backend": "fallback"},
  "recommendations": [
    {"priority": "critical",
     "action": "Install Python 3 OR start Docker Desktop",
     "why": "No host Python interpreter and no reachable Docker daemon, so neither the orchestration scripts nor the tool containers can run."}
  ],
  "summary_for_user": "Blocked — no host Python and Docker is not running. Start Docker Desktop (or install Python 3) and re-run."
}
EOF
    exit 0
fi

# ── Docker bootstrap ──────────────────────────────────────────────────────────
# A tiny image with Python + the Docker CLI, built once and cached. The Docker
# socket is mounted so ht_run.py's inner `docker run` reaches the host daemon.
BOOTSTRAP_IMAGE="ht-bootstrap:latest"
if ! docker image inspect "$BOOTSTRAP_IMAGE" >/dev/null 2>&1; then
    log "building $BOOTSTRAP_IMAGE (one-time, ~10s)"
    printf 'FROM docker:cli\nRUN apk add --no-cache python3\n' \
        | docker build -q -t "$BOOTSTRAP_IMAGE" - >&2
fi

# Host-native paths for volume mounts. On Git Bash, cygpath yields C:\... form
# that Docker Desktop understands; elsewhere the POSIX path is already correct.
if command -v cygpath >/dev/null 2>&1; then
    ROOT_MOUNT=$(cygpath -w "$PLUGIN_ROOT")
    HOST_CWD=$(cygpath -w "$PWD")
    SOCK="//var/run/docker.sock"
else
    ROOT_MOUNT="$PLUGIN_ROOT"
    HOST_CWD="$PWD"
    SOCK="/var/run/docker.sock"
fi

# Don't let MSYS rewrite the container-side paths (/opt, the socket target).
export MSYS_NO_PATHCONV=1

log "backend=docker (bootstrapped); host=$HOST"
exec docker run --rm -i \
    -v "$ROOT_MOUNT":/opt/ht \
    -v "$SOCK":/var/run/docker.sock \
    -e "HT_FORCE_HOST=$HOST" \
    -e HT_FORCE_DOCKER=1 \
    -e "HT_HOST_CWD=$HOST_CWD" \
    "$BOOTSTRAP_IMAGE" \
    python3 "/opt/ht/scripts/ht_${CMD}.py" "$@"
