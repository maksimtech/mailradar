FROM python:3.12-slim-trixie

# Metadata OCI
LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="MailRadar"
LABEL org.opencontainers.image.description="Email security posture analyzer — DMARC, SPF, DKIM, BIMI, VMC & GPG audit tool"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/mailradar"
# `licenses`, plural: that is the key the standard names, and the singular
# is read by nothing.
LABEL org.opencontainers.image.licenses="MIT"

# System packages, upgraded at build time: a Debian fix reaches the image
# through a rebuild and nobody has to chase it.
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends gnupg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Python environment
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Where the package comes from:
#   local (default, CI) → the code in this repository
#   pypi                → mailradar==MAILRADAR_VERSION from the index
#
# The default is local because a build with no arguments has to say something about the
# code in front of whoever ran it. With a PyPI default it said 2026.9.2 for ever, which
# is what stood here while this project was at 2026.42 — and nothing about it looked
# wrong.
ARG MAILRADAR_SOURCE=local
ARG MAILRADAR_VERSION=

# Upgrade pip: the copy in the base image has known CVEs.
RUN pip install --no-cache-dir --root-user-action=ignore -U pip

COPY pyproject.toml README.md LICENSE /app/build/
COPY mailradar/ /app/build/mailradar/

# `--only-binary :all:` first on both branches, so nothing is compiled while building
# this image if it can be helped: it is built for amd64 and arm64, and a dependency
# without an aarch64 wheel would be compiled under QEMU — tens of minutes or an
# out-of-memory, in a release.
#
# The retry without that flag is older than this change and is kept as it was. Why it
# is needed is not recorded, and removing it would make this build stricter than it has
# ever been for a reason that cannot be checked without a Docker daemon.
RUN case "${MAILRADAR_SOURCE}" in \
        local) pip wheel --no-deps --no-cache-dir --wheel-dir /app/wheel /app/build && \
               { pip install --no-cache-dir --root-user-action=ignore --only-binary :all: /app/wheel/*.whl || \
                 pip install --no-cache-dir --root-user-action=ignore /app/wheel/*.whl ; } ;; \
        pypi) test -n "${MAILRADAR_VERSION}" || { echo "MAILRADAR_VERSION is required with MAILRADAR_SOURCE=pypi" >&2; exit 1; } && \
              { pip install --no-cache-dir --root-user-action=ignore --only-binary :all: "mailradar==${MAILRADAR_VERSION}" || \
                pip install --no-cache-dir --root-user-action=ignore "mailradar==${MAILRADAR_VERSION}" ; } ;; \
        *) echo "MAILRADAR_SOURCE must be 'local' or 'pypi'" >&2; exit 1 ;; \
    esac && \
    rm -rf /app/build /app/wheel

# Remove pip: the runtime does not need it, and the packages vendored inside it
# carry CVEs that no pin of ours can reach — they are copies under pip's own
# path, not dependencies of this project.
RUN pip uninstall pip -y --root-user-action=ignore

# A non-root user to run as
RUN useradd -m -u 1000 mailradar && \
    mkdir -p /home/mailradar/.mailradar && \
    chown -R mailradar:mailradar /home/mailradar

USER mailradar
WORKDIR /home/mailradar

# Volume per report generati
VOLUME ["/home/mailradar/.mailradar"]

# Entrypoint CLI
ENTRYPOINT ["mailradar"]
CMD ["--help"]
