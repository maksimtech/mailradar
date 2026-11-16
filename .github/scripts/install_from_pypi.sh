#!/usr/bin/env bash
# Install <package>==<version> from PyPI into <venv>, asking again while the index catches up.
# Usage: install_from_pypi.sh <venv> <package> <version> [attempts=10] [interval_seconds=30]
#
# wait_for_pypi.sh answers "has the index got it?" for one request. The install that
# follows is another request, and another request can be answered by a cache that has
# not caught up: on apkradar 2026.48, on 2026-11-16, the wait saw the version at
# 15:04:30 and the install three seconds later, on the same runner, was told "from
# versions: ... 2026.47". releaseradar had lost the same way on v2026.2 and v2026.4,
# the second time with a 45 s grace in place. A margin narrows that; asking again
# until the install itself succeeds answers the question the check is asking.
#
# The price: a wheel that is genuinely broken fails after attempts x interval (five
# minutes by default) instead of at once. pip's last error is in the log above the
# verdict either way.
set -uo pipefail

if [ $# -lt 3 ]; then
    echo "Usage: $0 <venv> <package> <version> [attempts] [interval_seconds]" >&2
    exit 2
fi

VENV="$1"
PACKAGE="$2"
VERSION="$3"
ATTEMPTS="${4:-10}"
INTERVAL="${5:-30}"

for attempt in $(seq 1 "$ATTEMPTS"); do
    if "${VENV}/bin/pip" install --no-cache-dir --disable-pip-version-check \
            --only-binary :all: "${PACKAGE}==${VERSION}"; then
        echo "${PACKAGE}==${VERSION} installed from PyPI (attempt ${attempt}/${ATTEMPTS})"
        exit 0
    fi
    echo "${PACKAGE}==${VERSION} not installable yet (attempt ${attempt}/${ATTEMPTS})"
    if [ "$attempt" -lt "$ATTEMPTS" ]; then
        sleep "$INTERVAL"
    fi
done

echo "${PACKAGE}==${VERSION} still not installable from PyPI after ${ATTEMPTS} attempts" >&2
exit 1
