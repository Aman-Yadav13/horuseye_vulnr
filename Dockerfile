FROM golang:1.24-alpine AS builder

ENV GOBIN=/go/bin GOPATH=/go

WORKDIR /src

RUN apk add --no-cache git ca-certificates

RUN set -eux; \
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest; \
    go install -v github.com/zricethezav/gitleaks/v8@latest; \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

RUN git clone --depth 1 https://github.com/trufflesecurity/trufflehog.git . \
    && go build -o /go/bin/trufflehog .

FROM python:3.12-slim

WORKDIR /app

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
    git \
    perl \
    curl \
    iputils-ping \
    sqlmap \
    lynis \
    ruby \
    ruby-dev \
    build-essential \
    wget \
    yara \
    ; \
    git clone --depth 1 https://github.com/sullo/nikto.git /opt/nikto; \
    git clone --depth 1 https://github.com/Yara-Rules/rules.git /opt/yara-rules; \
    gem install wpscan; wpscan --update || true; \
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin; \
    apt-get remove -y --purge git ruby-dev build-essential; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /go/bin/nuclei /usr/local/bin/
COPY --from=builder /go/bin/gitleaks /usr/local/bin/
COPY --from=builder /go/bin/httpx /usr/local/bin/
COPY --from=builder /go/bin/trufflehog /usr/local/bin/

RUN nuclei -update-templates || true

COPY requirements.txt .

RUN python -m pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8081

CMD ["python", "main.py"]
