#!/usr/bin/env bash
# Обёртка для CI: создаёт WORKDIR, вызывает scanner.py, гарантирует cleanup.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
WORKDIR="${CONTAINER_SCAN_WORKDIR:-}"

usage() {
  echo "Usage: $0 IMAGE[:TAG] [--report PATH]" >&2
  exit 2
}

if [[ $# -lt 1 ]]; then
  usage
fi

IMAGE="$1"
shift

if [[ -z "${CONTAINER_ENGINE:-}" ]]; then
  if command -v podman >/dev/null 2>&1; then
    export CONTAINER_ENGINE=podman
  elif command -v docker >/dev/null 2>&1; then
    export CONTAINER_ENGINE=docker
  else
    echo "ERROR: neither podman nor docker found in PATH" >&2
    exit 2
  fi
fi

if ! command -v "$CONTAINER_ENGINE" >/dev/null 2>&1; then
  echo "ERROR: CONTAINER_ENGINE=$CONTAINER_ENGINE not found in PATH" >&2
  exit 2
fi

if ! command -v python3 >/dev/null 2>&1; then
  echo "ERROR: python3 not found in PATH" >&2
  exit 2
fi

if [[ -z "$WORKDIR" ]]; then
  WORKDIR="$(mktemp -d /tmp/container-scan-XXXXXX)"
  export CONTAINER_SCAN_WORKDIR="$WORKDIR"
  cleanup() {
    rm -rf "$WORKDIR"
  }
  trap cleanup EXIT
fi

exec python3 "$SCRIPT_DIR/scanner.py" "$IMAGE" --workdir "$WORKDIR" "$@"
