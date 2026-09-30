#!/bin/sh
# What the image actually contains, printed rather than taken from a scanner.
#
# This exists because Docker Desktop cannot be installed on the machine this is
# developed on — Windows 10 IoT Enterprise LTSC 2021 is build 19044 and Docker
# requires 19045, a build that edition never receives. The image can therefore
# only be examined from inside a CI job, which is a better place for it anyway: a
# Linux runner is what the image actually runs on.
#
# This Dockerfile already removes pip, setuptools and wheel after installing
# mailradar, so the first thing below is a check that the removal held. That is
# worth checking rather than assuming: the install line and the removal are in the
# same `RUN`, and a future edit that splits them would leave the tooling behind
# without changing anything a reader would notice.
#
# The second is which perl is installed. SECURITY-EXCEPTIONS.toml says only
# `perl-base` — Essential, which dpkg itself depends on — and cites a measurement
# taken inside patchradar's image rather than this one. Docker Scout names the
# *source* package for CVE-2026-82560, and Debian's `perl` source produces both
# `perl-base` and the removable `perl`; which is here decides whether the finding
# is ours to close or only ours to record.
#
# Run by .github/workflows/docker-build-check.yml, which builds and publishes
# nothing:
#     docker run --rm -i --entrypoint sh mailradar:build-check - < inspect.sh
#
# It reports and does not judge: a red step here would be a broken diagnostic, and
# what matters is whether the numbers and the record agree.
set -eu

echo "── build tooling, which the Dockerfile removes ──"
for pkg in pip setuptools wheel; do
    if version=$(python -c "import importlib.metadata as m, sys; sys.stdout.write(m.version('$pkg'))" 2>/dev/null); then
        echo "  <- $pkg $version IS STILL PRESENT, so the removal did not hold"
    else
        echo "  $pkg absent, as intended"
    fi
done

echo
echo "── anything left under pip/_vendor ──"
find / -path '*/pip/_vendor*' -name 'bom.cdx.json' 2>/dev/null | sed 's/^/  /' || true
echo "  (nothing above means the vendored path Scout reports is gone)"

echo
echo "── perl packages installed ──"
# Only the versioned lines are real installs. `perl`, `perl-modules` and the
# `perlapi-*` entries come back with no version when they are virtual packages
# that perl-base provides.
dpkg-query -W -f '  ${Package} ${Version} essential=${Essential} priority=${Priority}\n' \
    'perl*' 'libperl*' 2>/dev/null || echo "  none"

echo
echo "── the other packages the record names ──"
# Patterns, not exact names: Debian trixie's 64-bit time_t transition renamed a
# number of libraries with a `t64` suffix, and an exact name that no longer exists
# comes back looking like "not installed" rather than "I asked the wrong question".
# That happened once, on cookieradar's libcups2, on 2026-09-30.
for pattern in 'zlib1g*' 'libattr1*' 'libacl1*'; do
    found=$(dpkg-query -W -f '  ${Package} ${Version} priority=${Priority}\n' "$pattern" 2>/dev/null || true)
    if [ -n "$found" ]; then
        echo "$found"
    else
        echo "  $pattern matched nothing installed"
    fi
done

echo
echo "── size of the installed set ──"
printf '  %s packages\n' "$(dpkg-query -f '.\n' -W | wc -l)"
