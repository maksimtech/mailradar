FROM python:3.12-slim-trixie

# Metadata OCI
LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="MailRadar"
LABEL org.opencontainers.image.description="Email security posture analyzer — DMARC, SPF, DKIM, BIMI, VMC & GPG audit tool"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/mailradar"
LABEL org.opencontainers.image.license="MIT"

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

# The MailRadar version to install. Overridden by docker.yml, which passes the
# version being released; the default is only for a local build.
ARG MAILRADAR_VERSION=2026.9.2

# Upgrade pip: the copy in the base image has known CVEs.
RUN pip install --no-cache-dir --root-user-action=ignore -U pip

# Install mailradar from PyPI
RUN pip install --no-cache-dir --root-user-action=ignore --only-binary :all: \
    "mailradar==${MAILRADAR_VERSION}" || \
    pip install --no-cache-dir --root-user-action=ignore \
    "mailradar==${MAILRADAR_VERSION}"

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
