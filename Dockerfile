# Stage 1: build frontend
FROM node:22-alpine AS frontend
WORKDIR /app
COPY web/package*.json ./
RUN npm ci
COPY web/ ./
RUN npm run build

# Stage 2: build daemon
FROM rust:1.90-slim-bookworm AS builder
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev libzmq3-dev cmake git ca-certificates gcc g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Cache dependency compilation separately from source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir src && echo 'fn main(){}' > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 libzmq5 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/marketd /usr/local/bin/marketd
COPY --from=frontend /app/dist /usr/share/marketd/web

ENV MARKETD_LISTEN_ADDR=0.0.0.0:3005
ENV MARKETD_HEALTHCHECK_PORT=3005
ENV MARKETD_STATIC_DIR=/usr/share/marketd/web
EXPOSE 3005

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${MARKETD_HEALTHCHECK_PORT}/api/health" || exit 1

ENTRYPOINT ["marketd"]
