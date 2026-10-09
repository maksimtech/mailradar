"""What the image is allowed to install, and from where.

docker.yml pushes maksimtech/mailradar:latest to Docker Hub, and there is no smoke test
between the build and the push: it builds and pushes. A bad `:latest` is what everyone
pulling the image gets, and the weekly rebuild means `latest` moves without a release, so
the parts that are easy to get quietly wrong are pinned here.

Static checks on the Dockerfile's text. They need no Docker daemon, which is the point —
Docker Desktop does not install on the machine this was written on — and what they cannot
tell you is whether the image builds. docker-build-check.yml does that, on every push and
pull request as of the change these cases came with.
"""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile"


def dockerfile() -> str:
    return DOCKERFILE.read_text(encoding="utf-8")


def test_the_source_can_be_either_the_checkout_or_the_index():
    """Two branches, because the release wants this tag's code and somebody reproducing
    an older image wants what was published then."""
    text = dockerfile()

    assert "MAILRADAR_SOURCE" in text
    assert "local)" in text and "pypi)" in text


def test_a_plain_build_uses_the_working_tree():
    """`docker build .` has to say something about the code in front of whoever ran it.
    With a PyPI default it said 2026.9.2 for ever, and it did: that was the default here
    while the project was at 2026.42."""
    assert re.search(r"ARG\s+MAILRADAR_SOURCE=local", dockerfile())


def test_a_pypi_build_has_to_say_which_version():
    """The stale default is the trap, not the missing one: nothing about
    `ARG MAILRADAR_VERSION=2026.9.2` looked wrong while it rebuilt September."""
    assert not re.search(r"ARG\s+MAILRADAR_VERSION=\S", dockerfile()), (
        "a default version here rebuilds an old release by accident"
    )


def test_wheels_are_asked_for_first_on_both_branches():
    """Asked for, not required — and the difference is deliberate.

    The image is built for amd64 and arm64, so a dependency without an aarch64 wheel
    would be compiled under QEMU: tens of minutes or an out-of-memory, in a release. So
    both branches try `--only-binary :all:` first.

    Both also retry without it. That retry is older than the switch and was kept as it
    was: why it is needed is not recorded anywhere, and removing it would make this build
    stricter than it has ever been for a reason that cannot be checked without a Docker
    daemon. This case holds the attempt, which is what is actually true here — it does
    not claim a guarantee the Dockerfile does not give.
    """
    text = dockerfile()

    for branch in ("local)", "pypi)"):
        start = text.index(branch)
        end = text.index(";;", start)
        assert "--only-binary :all:" in text[start:end], branch

    assert "pip wheel --no-deps" in text, (
        "the local branch has a source tree to build before it can install a wheel"
    )


def test_the_licence_label_is_the_one_the_standard_names():
    """`org.opencontainers.image.licenses` is the key, plural. The singular is read by
    nothing, so a tool asking the image what it is licensed under gets no answer — while
    the label looks right in the file, which is why it survived."""
    text = dockerfile()

    assert 'org.opencontainers.image.licenses="MIT"' in text
    assert "org.opencontainers.image.license=" not in text


def _apt_get_installs() -> list[list[str]]:
    """Every `apt-get install` in the Dockerfile, as the list of packages it names.

    Line continuations are joined first, then each RUN is split on `&&`, so a package on
    a continued line and an option between `install` and the first name both land where
    they should. Options are anything starting with `-`; `--no-install-recommends` is one
    of them and is deliberately not counted as a package.
    """
    joined = re.sub(r"\\r?\n", " ", dockerfile())
    installs = []
    for line in joined.splitlines():
        if not line.startswith("RUN "):
            continue
        for command in line[len("RUN "):].split("&&"):
            words = command.split()
            if words[:2] != ["apt-get", "install"]:
                continue
            installs.append([w for w in words[2:] if not w.startswith("-")])
    return installs


def test_gpg_and_gpg_agent_are_installed_and_the_gnupg_metapackage_is_not():
    """`gnupg` is a metapackage. It pulls in `dirmngr`, which depends on `libldap2`, which
    depends on `libsasl2-2` — and cyrus-sasl2 carries CVE-2026-107161, high, with no fix in
    trixie (Docker Scout alert #66, 2026-10-09). None of that is used: `sender.py` runs
    gpg for `--import`, `--encrypt --trust-model always` and `--clearsign`, and the keys
    reach it over HTTP from `mailradar.gpg`, never through gpg's own keyserver or WKD
    code, which is what dirmngr is for. `gpg` and `gpg-agent` cover those three calls on
    their own, and measured in python:3.12-slim-trixie the pair brings 9 packages where
    the metapackage brings 21.

    Exactly these two, not "at least": whatever is added here is added to the attack
    surface of an image that is pulled as `latest`, and should have to say why.
    """
    installs = _apt_get_installs()

    assert len(installs) == 1, installs
    assert set(installs[0]) == {"gpg", "gpg-agent"}, installs[0]
