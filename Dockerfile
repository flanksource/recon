# syntax=docker/dockerfile:1

FROM node:22-bookworm-slim AS web

RUN npm install --global pnpm@10
WORKDIR /src/app

COPY app/package.json app/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile

COPY app/ ./
RUN pnpm build

FROM golang:1.26.1-bookworm AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY embed.go ./
COPY cmd/ cmd/
COPY internal/ internal/
COPY app/reports/ app/reports/
COPY --from=web /src/app/dist/ app/dist/

RUN CGO_ENABLED=0 go build -trimpath -o /out/reconctl ./cmd/reconctl

FROM node:22-bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates chromium curl fonts-liberation git jq libpcap0.8 \
        python3 python3-venv tini unzip xz-utils \
    && rm -rf /var/lib/apt/lists/*

ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=true \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    PATH=/opt/recon/bin:/opt/cinc-auditor/bin:$PATH

# deps has no Omnitruck manager, so CINC needs its native package installer.
RUN <<'SH'
set -eu

case "$(dpkg --print-architecture)" in
    amd64) arch=x86_64 ;;
    arm64) arch=aarch64 ;;
    *) echo 'Unsupported CINC Auditor architecture' >&2; exit 1 ;;
esac

curl --fail --show-error --silent --retry 3 --proto '=https' \
    -H 'Accept: application/json' \
    "https://omnitruck.cinc.sh/stable/cinc-auditor/metadata?v=7.2.1&p=debian&pv=12&m=$arch" \
    -o /tmp/cinc.json
test "$(jq -er .version /tmp/cinc.json)" = 7.2.1

curl --fail --show-error --silent --location --retry 3 --proto '=https' --proto-redir '=https' \
    "$(jq -er .url /tmp/cinc.json)" -o /tmp/cinc.deb
printf '%s  /tmp/cinc.deb\n' "$(jq -er .sha256 /tmp/cinc.json)" | sha256sum --check --strict

dpkg -i /tmp/cinc.deb
cinc-auditor version
rm /tmp/cinc.json /tmp/cinc.deb
SH

RUN npm install --global pnpm@10 @flanksource/facet-cli@0.1.71 \
    && npm cache clean --force

RUN python3 -m venv /opt/prowler \
    && /opt/prowler/bin/pip install --no-cache-dir \
        'git+https://github.com/prowler-cloud/prowler.git@ba564af4f46fd7c4908d34798687eda36b88398c' \
    && ln -s /opt/prowler/bin/prowler /usr/local/bin/prowler

COPY --from=build /out/reconctl /usr/local/bin/reconctl
RUN reconctl --bin-dir /opt/recon/bin engine install

RUN mkdir -p /data \
    && chown 1000:1000 /data

USER 1000:1000
ENV HOME=/home/node
WORKDIR /data

RUN reconctl engine templates update \
    && reconctl --data-dir /data/postgres db url > /dev/null \
    && rm -rf /data/postgres/data /data/postgres/runtime

EXPOSE 8280
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/tini", "--", "reconctl", "--data-dir", "/data/postgres"]
CMD ["serve", "--host", "0.0.0.0"]
