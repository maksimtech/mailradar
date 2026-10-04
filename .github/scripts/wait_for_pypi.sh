#!/usr/bin/env bash
# Wait until <package>==<version> can be downloaded from PyPI.
# Uses pip itself, so it checks exactly what `pip install` in the Dockerfile needs.
# Usage: wait_for_pypi.sh <package> <version> [attempts=30] [interval_seconds=20] [grace_seconds=45]
set -uo pipefail

if [ $# -lt 2 ]; then
    echo "Usage: $0 <package> <version> [attempts] [interval_seconds]" >&2
    exit 2
fi

PACKAGE="$1"
VERSION="$2"
ATTEMPTS="${3:-30}"
INTERVAL="${4:-20}"
# Allowed for the index to agree with itself once the file is reachable from here.
#
# Not the `sleep 60` that stood in this step before polling and lost the race
# twice: that was a guess about how long publishing takes, made before knowing
# anything. This waits for the fact first. The margin exists because the runner and
# the build container ask different edges — measured on apkradar 2026.42 on
# 2026-10-03, where the poll succeeded at 16:31:21 and the build still failed with
# "No matching distribution found" at 16:31:36.
#
# It narrows the window; it does not close it. What closes it is not asking the
# index during the build at all, as exeradar's Dockerfile does.
GRACE="${5:-45}"
DEST="$(mktemp -d)"
trap 'rm -rf "$DEST"' EXIT

for attempt in $(seq 1 "$ATTEMPTS"); do
    if pip download --no-deps --no-cache-dir --disable-pip-version-check --quiet --dest "$DEST" "${PACKAGE}==${VERSION}"; then
        echo "${PACKAGE}==${VERSION} available on PyPI (attempt ${attempt}/${ATTEMPTS})"
        if [ "$GRACE" -gt 0 ]; then
            echo "waiting ${GRACE}s for the index to agree with itself"
            sleep "$GRACE"
        fi
        exit 0
    fi
    echo "${PACKAGE}==${VERSION} not yet available (attempt ${attempt}/${ATTEMPTS})"
    if [ "$attempt" -lt "$ATTEMPTS" ]; then
        sleep "$INTERVAL"
    fi
done

echo "${PACKAGE}==${VERSION} still not available on PyPI after ${ATTEMPTS} attempts" >&2
exit 1
