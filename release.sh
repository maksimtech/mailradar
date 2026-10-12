#!/bin/bash
set -euo pipefail

INIT_FILE="mailradar/__init__.py"
NAME="MailRadar"
REPO="maksimtech/mailradar"

fail() {
    echo "❌ $*" >&2
    exit 1
}

usage() {
    echo "❌ Usage: ./release.sh <version>        bump on a release branch, PR, auto-merge, tag" >&2
    echo "          ./release.sh --tag <version>  tag main once the bump is merged" >&2
    echo "   Example: ./release.sh 2026.45" >&2
    exit 1
}

# main takes changes through pull requests only, the owner included: since
# 2026-10-12 the rulesets have no bypass, because a cloud session had pushed
# straight to main with the owner's account and left it red. So the version bump
# goes on a release branch and through a pull request like any other change, and
# the tag is made on the commit GitHub merged. Until then this script committed
# the bump on main and pushed main and the tag together.
#
# Two modes. `./release.sh <version>` checks, bumps, runs the suite, commits on
# release/v<version>, pushes that branch and nothing else; with `gh` on PATH it
# opens the pull request with auto-merge, waits for GitHub to merge it, and tags.
# `./release.sh --tag <version>` is the last step alone, for when the wait was cut
# short or the pull request was merged by hand.
MODE="release"
if [ "${1:-}" = "--tag" ]; then
    MODE="tag"
    shift
fi
[ $# -ge 1 ] && [ -n "$1" ] || usage

VERSION="$1"
TAG="v${VERSION}"
BRANCH_NAME="release/${TAG}"

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

current_version() {
    python3 - "$INIT_FILE" <<'EOF'
import re, sys
print(re.search(r'__version__ = "(.+?)"', open(sys.argv[1]).read()).group(1))
EOF
}

on_clean_main_aligned() {
    local branch
    branch=$(git rev-parse --abbrev-ref HEAD)
    [ "$branch" = "main" ] || fail "Not on main (current branch: ${branch})"
    [ -z "$(git status --porcelain)" ] || fail "Working tree not clean — commit your changes first"
    git fetch --quiet --tags origin main
    [ "$(git rev-parse HEAD)" = "$(git rev-parse origin/main)" ] \
        || fail "local main is not aligned with origin/main — pull or push before releasing"
}

refuse_existing_tag() {
    if git rev-parse -q --verify "refs/tags/${TAG}" >/dev/null \
        || [ -n "$(git ls-remote --tags origin "refs/tags/${TAG}")" ]; then
        fail "Tag ${TAG} already exists"
    fi
}

# The last step: main has to carry the version already, which is what a merged
# release pull request leaves there. Only the tag is pushed. It is made before
# anything is pushed, so a tag that cannot be made — on 2026-10-03 a signed tag
# without a message — leaves the remote untouched.
tag_main() {
    on_clean_main_aligned
    refuse_existing_tag
    [ "$(current_version)" = "$VERSION" ] \
        || fail "main carries $(current_version), not ${VERSION} — merge the release pull request first"
    git tag -a "$TAG" -m "${NAME} ${VERSION}"
    echo "📤 Pushing tag ${TAG}..."
    git push origin "$TAG"
    echo "✅ Tagged ${TAG}: GitHub Actions takes it from here"
    echo "   → Release: github.com/${REPO}/releases"
    echo "   → PyPI:    pypi.org/project/mailradar"
    echo "   → Docker:  hub.docker.com/r/${REPO}"
}

if [ "$MODE" = "tag" ]; then
    echo "🏷️  Tagging ${NAME} ${TAG}"
    tag_main
    exit 0
fi

echo "🚀 Releasing ${NAME} ${TAG}"
on_clean_main_aligned
refuse_existing_tag

if git rev-parse -q --verify "refs/heads/${BRANCH_NAME}" >/dev/null \
    || [ -n "$(git ls-remote --heads origin "refs/heads/${BRANCH_NAME}")" ]; then
    fail "Branch ${BRANCH_NAME} already exists — a release of ${VERSION} is already under way"
fi

OLD_VERSION=$(current_version)
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

# The suite, after the bump and before the commit. The version is written above,
# so a run before the release cannot see what the bump breaks: twice — apkradar
# 2026.42 and 2026.43 — the README's stated version failed in CI, on main, with
# the tag already pushed.
#
# Before the commit on purpose. A refusal here leaves the version file modified
# and nothing else touched, which is what somebody needs to see; a gate after the
# commit would have to undo one, and undoing is worse than not doing.
if [ -d tests ]; then
    echo "🧪 Suite, with the new version in place..."
    python3 -m pytest -q || {
        echo
        fail "the suite fails with ${VERSION} in place — nothing was committed, \
tagged or pushed. ${INIT_FILE} is left modified so you can see what broke; \
\`git checkout ${INIT_FILE}\` undoes the bump."
    }
else
    echo "🧪 No tests/ directory — nothing to run"
fi

git switch --quiet -c "$BRANCH_NAME"
git add "$INIT_FILE"
git commit -m "chore: bump version to ${VERSION}"
echo "📤 Pushing ${BRANCH_NAME} (main is not touched)..."
git push --quiet -u origin "$BRANCH_NAME"
git switch --quiet main

next_steps() {
    echo "   Merge the pull request from ${BRANCH_NAME}, then:  ./release.sh --tag ${VERSION}"
}

# GitHub is asked only when origin is this repository on GitHub and gh is there
# to ask it; otherwise the branch is pushed and the rest is left to whoever runs
# this, with the next step spelled out.
if ! command -v gh >/dev/null 2>&1 || [[ "$(git remote get-url origin)" != *"github.com"*"${REPO}"* ]]; then
    echo "ℹ️  No pull request opened: gh is missing or origin is not github.com/${REPO}."
    next_steps
    exit 0
fi

PR_URL=$(gh pr create --repo "$REPO" --base main --head "$BRANCH_NAME" \
    --title "chore: bump version to ${VERSION}" \
    --body "Version bump for ${NAME} ${VERSION}, made by release.sh. When it is merged the script tags the merge commit ${TAG}, which publishes the release.") \
    || { echo "❌ ${BRANCH_NAME} is pushed but the pull request could not be opened." >&2; next_steps >&2; exit 1; }
echo "🔀 ${PR_URL}"
gh pr merge "$PR_URL" --auto --squash --delete-branch --subject "chore: bump version to ${VERSION}" \
    || { echo "❌ auto-merge could not be enabled on ${PR_URL}." >&2; next_steps >&2; exit 1; }

# Waits for GitHub to merge it once the required checks pass. RELEASE_WAIT_MINUTES
# bounds the wait; when it runs out nothing is lost, the tag step just runs later.
deadline=$(( SECONDS + 60 * ${RELEASE_WAIT_MINUTES:-60} ))
while :; do
    state=$(gh pr view "$PR_URL" --json state --jq .state)
    case "$state" in
        MERGED) break ;;
        CLOSED) fail "${PR_URL} was closed without being merged — nothing was tagged" ;;
    esac
    if [ "$SECONDS" -ge "$deadline" ]; then
        echo "⏳ ${PR_URL} is not merged yet; it will be once the checks pass."
        next_steps
        exit 0
    fi
    sleep 20
done

echo "✅ Merged. Tagging the merge commit..."
git pull --quiet --ff-only origin main
git branch --quiet -D "$BRANCH_NAME" 2>/dev/null || true
git push --quiet origin --delete "$BRANCH_NAME" 2>/dev/null || true
tag_main
