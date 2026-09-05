FROM python:3.12-slim-bookworm

# Metadata OCI
LABEL maintainer="maksimtech <github@maksimtech.com>"
LABEL org.opencontainers.image.title="MailRadar"
LABEL org.opencontainers.image.description="Email security posture analyzer — DMARC, SPF, DKIM, BIMI, VMC & GPG audit tool"
LABEL org.opencontainers.image.source="https://github.com/maksimtech/mailradar"
LABEL org.opencontainers.image.license="MIT"

# Aggiorna pacchetti di sistema per fix vulnerabilità
RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get install -y --no-install-recommends gnupg && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Ambiente Python
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Versione MailRadar da installare
ARG MAILRADAR_VERSION=2026.9.2

# Installa mailradar da PyPI
RUN pip install --no-cache-dir --root-user-action=ignore --only-binary :all: \
    "mailradar==${MAILRADAR_VERSION}" || \
    pip install --no-cache-dir --root-user-action=ignore \
    "mailradar==${MAILRADAR_VERSION}"

# Crea utente non-root per sicurezza
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
