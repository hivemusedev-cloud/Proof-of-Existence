# PoE testnet node — container image (used by testnet/RAILWAY.md,
# works on any Docker host).
#
# Two stages: build the release binary with the Rust toolchain,
# then run it on a slim Debian with just curl (for the optional
# bundle download in the entrypoint) and CA certificates.
#
# The node keeps ALL of its state in one directory (identity keys,
# store, finality snapshots, epoch bundles). Mount a volume at
# /data or the node re-identifies and re-syncs on every restart.

FROM rust:bookworm AS builder
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      protobuf-compiler cmake pkg-config libssl-dev clang \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY . .
RUN cargo build --release --locked -p poe-node \
 && cp target/release/poe-node /usr/local/bin/poe-node

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends curl ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /usr/local/bin/poe-node /usr/local/bin/poe-node
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
VOLUME ["/data"]
EXPOSE 41001/tcp
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
