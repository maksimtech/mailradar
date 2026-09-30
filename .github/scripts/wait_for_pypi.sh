#!/usr/bin/env bash
# Wait until <package>==<version> can be downloaded from PyPI.
# Uses pip itself, so it checks exactly what `pip install` in the Dockerfile needs.
# Usage: wait_for_pypi.sh <package> <version> [attempts=30] [interval_seconds=20]
set -uo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <package> <version> [attempts] [interval_seconds]" >&2
    exit 2
fi

PACKAGE="$1"
VERSION="$2"
ATTEMPTS="${3:-30}"
INTERVAL="${4:-20}"
DEST="$(mktemp -d)"
trap 'rm -rf "$DEST"' EXIT

for attempt in $(seq 1 "$ATTEMPTS"); do
    if pip download --no-deps --no-cache-dir --disable-pip-version-check --quiet --dest "$DEST" "${PACKAGE}==${VERSION}"; then
        echo "${PACKAGE}==${VERSION} available on PyPI (attempt ${attempt}/${ATTEMPTS})"
        exit 0
    fi
    echo "${PACKAGE}==${VERSION} not yet available (attempt ${attempt}/${ATTEMPTS})"
    if [ "$attempt" -lt "$ATTEMPTS" ]; then
        sleep "$INTERVAL"
    fi
done

echo "${PACKAGE}==${VERSION} still not available on PyPI after ${ATTEMPTS} attempts" >&2
exit 1
