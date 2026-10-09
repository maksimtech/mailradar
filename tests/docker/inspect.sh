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
# The sections that measure report and do not judge: a red step there would be a
# broken diagnostic, and what matters is whether the numbers and the record agree.
# The last section, on gpg, does judge — it holds a decision, and says why there.
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

# ── gpg without dirmngr ──
#
# Everything above reports. This section judges, because it holds a decision rather
# than a measurement: the Dockerfile installs `gpg gpg-agent` and not the `gnupg`
# metapackage, which pulls in dirmngr → libldap2 → libsasl2-2, and cyrus-sasl2
# carries CVE-2026-107161 (high, no fix in trixie; Docker Scout alert #66). Nothing
# in mailradar needs dirmngr: sender.py calls gpg for --import, --encrypt and
# --clearsign, with the public key already fetched over HTTP by mailradar.gpg.
# Putting `gnupg` back would be a one-word edit that reopens the finding without
# anything else in the build changing, so the image is asked directly.
#
# Then the three calls sender.py makes are run for real, offline, on a key made
# here: an image with gpg but without gpg-agent, or with an agent that cannot be
# started, would pass the package check and fail the user.
echo
echo "── gpg without dirmngr ──"
failed=0
for pkg in libsasl2-2 dirmngr gnupg; do
    if dpkg-query -W -f '${Status}\n' "$pkg" 2>/dev/null | grep -q '^install ok installed$'; then
        echo "  <- $pkg IS INSTALLED, and should not be"
        failed=1
    else
        echo "  $pkg absent, as intended"
    fi
done
for pkg in gpg gpg-agent; do
    if dpkg-query -W -f '${Status}\n' "$pkg" 2>/dev/null | grep -q '^install ok installed$'; then
        echo "  $pkg $(dpkg-query -W -f '${Version}' "$pkg") present"
    else
        echo "  <- $pkg IS MISSING, and sender.py needs it"
        failed=1
    fi
done

# The flow of sender.py, without a network: a key generated in one homedir, exported,
# imported into an empty one, used to encrypt with --trust-model always (a key just
# fetched is not trusted), then clearsign through the loopback pinentry.
keys=$(mktemp -d /tmp/mr-keys.XXXXXX)
ring=$(mktemp -d /tmp/mr-ring.XXXXXX)
gpg_flow() {
    gpg --batch --homedir "$keys" --passphrase 'probe' --pinentry-mode loopback \
        --quick-gen-key 'Probe <probe@example.invalid>' default default never \
        || { echo "  <- key generation failed"; return 1; }
    gpg --batch --homedir "$keys" --armor --export probe@example.invalid > "$keys/pub.asc" \
        || { echo "  <- export failed"; return 1; }
    gpg --batch --yes --homedir "$ring" --import < "$keys/pub.asc" \
        || { echo "  <- import into an empty homedir failed"; return 1; }
    printf 'report\n' | gpg --batch --yes --homedir "$ring" --trust-model always --armor \
        --encrypt --recipient probe@example.invalid > "$ring/msg.asc" \
        || { echo "  <- encrypt failed"; return 1; }
    grep -q 'BEGIN PGP MESSAGE' "$ring/msg.asc" || { echo "  <- encrypt produced no PGP message"; return 1; }
    printf 'probe\nreport\n' | gpg --batch --yes --armor --homedir "$keys" --clearsign \
        --local-user probe@example.invalid --passphrase-fd 0 --pinentry-mode loopback > "$keys/signed.asc" \
        || { echo "  <- clearsign failed"; return 1; }
    grep -q 'BEGIN PGP SIGNED MESSAGE' "$keys/signed.asc" || { echo "  <- clearsign produced no signed message"; return 1; }
    gpg --batch --homedir "$keys" --verify "$keys/signed.asc" \
        || { echo "  <- the clearsigned message does not verify"; return 1; }
    return 0
}
if gpg_flow > "$ring/flow.log" 2>&1; then
    echo "  generate, export, import, encrypt, clearsign, verify: all ok"
else
    echo "  <- the gpg flow sender.py relies on FAILED:"
    sed 's/^/     /' "$ring/flow.log"
    failed=1
fi
gpgconf --homedir "$keys" --kill all 2>/dev/null || true
gpgconf --homedir "$ring" --kill all 2>/dev/null || true
rm -rf "$keys" "$ring"

if [ "$failed" -ne 0 ]; then
    echo "  gpg section: FAILED"
    exit 1
fi
echo "  gpg section: ok"
