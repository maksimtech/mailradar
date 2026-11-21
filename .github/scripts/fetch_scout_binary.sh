#!/usr/bin/env bash
# Put Docker Scout's binary where docker/scout-action looks first, fetched with the job's token.
# Usage: fetch_scout_binary.sh <action commit> <release tag>     (GH_TOKEN in the environment)
#
# docker/scout-action downloads its ~190 MB binary from api.github.com without
# authentication (`tc.downloadTool(asset.url, binary, undefined, ...)`), on the
# 60-an-hour budget of the runner's address, which GitHub-hosted runners share; when
# it is spent the step fails with "Unexpected HTTP response: 403" before scanning
# anything (docker/scout-action#116). The action uses `dist/<name>` next to its
# index.js when it is already there, so this puts it there first, with the token.
#
# Two checks, and a failed one stops the job: the tag must be the commit the
# workflow pins, so the binary is the one that action version runs; and the file
# must have the SHA-256 GitHub publishes for it. Where the runner keeps actions is
# not documented: when the directory is not there, or the download itself fails,
# this says so and leaves the download to the action, as before.
# tests/test_scout_binary.py
set -uo pipefail

if [ $# -ne 2 ]; then
    echo "Usage: $0 <action commit> <release tag>" >&2
    exit 2
fi

COMMIT="$1"
TAG="$2"
NAME="docker-scout-action_linux_amd64"
ACTIONS="${SCOUT_ACTIONS_DIR:-$(dirname "${RUNNER_WORKSPACE:-.}")/_actions}"
DIST="$ACTIONS/docker/scout-action/$COMMIT/dist"
BINARY="$DIST/$NAME"

if [ ! -d "$ACTIONS/docker/scout-action/$COMMIT" ]; then
    echo "::warning::docker/scout-action@$COMMIT is not under $ACTIONS; the action will download its binary itself"
    exit 0
fi

tagged=$(gh api "repos/docker/scout-action/commits/$TAG" --jq .sha)
if [ "$tagged" != "$COMMIT" ]; then
    echo "::error::docker/scout-action $TAG is commit ${tagged:-unknown}, the workflow pins $COMMIT"
    exit 1
fi

mkdir -p "$DIST"
expected=$(gh api "repos/docker/scout-action/releases/tags/$TAG" \
    --jq ".assets[] | select(.name == \"$NAME\") | .digest")
if [ -z "$expected" ] || ! gh release download "$TAG" --repo docker/scout-action \
        --pattern "$NAME" --dir "$DIST" --clobber; then
    rm -f "$BINARY"
    echo "::warning::could not fetch $NAME $TAG with the job's token; the action will download it itself"
    exit 0
fi

# From stdin: given a path with a backslash, sha256sum prefixes its line with one.
actual="sha256:$(sha256sum < "$BINARY" | cut -d ' ' -f 1)"
if [ "$actual" != "$expected" ]; then
    rm -f "$BINARY"
    echo "::error::$NAME $TAG has $actual, the release publishes $expected"
    exit 1
fi

chmod +x "$BINARY"
echo "$NAME $TAG in place for docker/scout-action@$COMMIT ($actual)"
