#!/bin/bash
set -euo pipefail

INIT_FILE="mailradar/__init__.py"

fail() {
    echo "❌ $*" >&2
    exit 1
}

if [ $# -lt 1 ] || [ -z "$1" ]; then
    echo "❌ Usage: ./release.sh <version>" >&2
    echo "   Example: ./release.sh 2026.09.3" >&2
    exit 1
fi

VERSION="$1"
TAG="v${VERSION}"

# CalVer, Apple style: YYYY.count[.fix]. The tag is v<VERSION> and has to match
# __init__.py; publish.yml checks that.
#
# This read YYYY.MM.N until 2026-09-30 and would have refused the version that is
# in this repository — 2026.41 has no month in it, and the five Radar moved to the
# generation-and-count scheme on 2026-09-29. So the documented release path was
# broken by the release before last, and the way that was noticed is that v2026.41
# went out by hand. patchradar's scripts/bump_version.py had the same defect, found
# the same week.
#
# A leading zero is refused rather than tolerated: 2026.09.5 is the old shape, and
# it sorts *below* 2026.10 under PEP 440, so publishing it would be a downgrade
# PyPI never lets anybody take back.
if ! [[ "$VERSION" =~ ^[0-9]{4}\.([1-9][0-9]*)(\.([1-9][0-9]*))?$ ]]; then
    fail "Invalid version: ${VERSION} (expected YYYY.count[.fix], e.g. 2026.42 or 2026.42.1)"
fi

# Three segments with a middle of twelve or less is the old YYYY.MM.N form, and
# nothing can tell the two apart by looking: the count is past forty for every
# Radar, so a middle segment that could be a month is refused rather than guessed.
if [ -n "${BASH_REMATCH[2]}" ] && [ "${BASH_REMATCH[1]}" -le 12 ]; then
    fail "Ambiguous version: ${VERSION} — a middle segment of ${BASH_REMATCH[1]} reads as a month, not a count"
fi

echo "🚀 Releasing MailRadar ${TAG}"

BRANCH=$(git rev-parse --abbrev-ref HEAD)
[ "$BRANCH" = "main" ] || fail "Not on main (current branch: ${BRANCH})"

[ -z "$(git status --porcelain)" ] || fail "Working tree not clean — commit your changes first"

git fetch --quiet --tags origin main
[ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
    || fail "local main is not aligned with origin/main — pull or push before releasing"

if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null \
    || [ -n "$(git ls-remote --tags origin "refs/tags/${TAG}")" ]; then
    fail "Tag ${TAG} already exists"
fi

OLD_VERSION=$(python3 - "$INIT_FILE" <<'EOF'
import re, sys
print(re.search(r'__version__ = "(.+?)"', open(sys.argv[1]).read()).group(1))
EOF
)
[ "$OLD_VERSION" != "$VERSION" ] || fail "${VERSION} is already the current version"

echo "📝 Version bump: ${OLD_VERSION} → ${VERSION}"
python3 - "$INIT_FILE" "$VERSION" <<'EOF'
import re, sys
path, version = sys.argv[1], sys.argv[2]
text = open(path).read()
new, count = re.subn(r'__version__ = ".+?"', f'__version__ = "{version}"', text, count=1)
assert count == 1, "__version__ not found"
open(path, "w").write(new)
EOF

git add "$INIT_FILE"
git commit -m "chore: bump version to ${VERSION}"
git tag -a "$TAG" -m "MailRadar ${VERSION}"

echo "📤 Pushing main + tag ${TAG}..."
# Atomic: either both arrive or neither does
git push --atomic origin main "$TAG"

echo "✅ Done! GitHub Actions takes it from here"
echo "   → Release: github.com/maksimtech/mailradar/releases"
echo "   → PyPI:    pypi.org/project/mailradar"
echo "   → Docker:  hub.docker.com/r/maksimtech/mailradar"
