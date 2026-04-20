ARG BUILDER_IMAGE=builder_cache

############################################################
# Cache image with all the deps
FROM rust:1.95-trixie AS builder_cache

# hadolint ignore=DL3008
RUN rustup component add rustfmt clippy \
    && apt-get update \
    && apt-get install -y --no-install-recommends cmake libclang-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . ./


RUN cargo fmt --all -- --check --color=always || (echo "Use cargo fmt to format your code"; exit 1)
RUN cargo clippy --all -- -D warnings || (echo "Solve your clippy warnings to succeed"; exit 1)

#RUN cargo test --all --all-features
#RUN just test "tcp://localhost:2375" || (echo "Test are failing"; exit 1)

#ENV RUSTFLAGS="-C link-arg=-Wl,--compress-debug-sections=zlib -C force-frame-pointers=yes"
RUN cargo build --tests
#RUN cargo build --release --all-features


############################################################
# Builder for production image
FROM ${BUILDER_IMAGE} AS builder_release

WORKDIR /build
COPY . ./

ARG BIN_TARGET=--bins
ARG PROFILE=release
# Build with QUIC and jemalloc by default.
# Override at build time: --build-arg FEATURES=jemalloc (excludes QUIC) or --build-arg FEATURES=jemalloc,quic
ARG FEATURES="jemalloc,quic"

#ENV RUSTFLAGS="-C link-arg=-Wl,--compress-debug-sections=zlib -C force-frame-pointers=yes"
RUN cargo build --features=${FEATURES} --profile=${PROFILE} ${BIN_TARGET}


############################################################
# Final image
FROM debian:trixie-slim AS final-image

# hadolint ignore=DL3008
RUN useradd -ms /bin/bash app && \
        apt-get update && \
        apt-get -y upgrade && \
        apt-get install -y --no-install-recommends ca-certificates dumb-init && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists

WORKDIR /home/app

ARG PROFILE=release
COPY --from=builder_release  /build/target/${PROFILE}/velox velox

ENV RUST_LOG="INFO"
# Set SERVER_PROTOCOL=ws when a reverse proxy (e.g. Caddy, nginx) handles TLS.
ENV SERVER_PROTOCOL="wss"
ENV SERVER_LISTEN="[::]"
ENV SERVER_PORT="8080"
# QUIC transport (requires the binary to have been built with --features quic).
# Set QUIC_BIND to a bind address to enable the QUIC listener, e.g. [::]:8443
# Leave empty (default) to disable QUIC.
ENV QUIC_BIND=""
# Bind IP for reverse tunnel listeners. Default [::] (all interfaces) so
# reverse-proxied containers (Caddy) can reach the tunnel ports.
# Set to empty to disable the override (uses whatever the client requests).
ENV VELOX_REVERSE_TUNNEL_BIND="[::]"
# Extra CLI flags forwarded verbatim to `velox server …`.
# Example: --restrict-to google.com:443 --restrict-config /etc/velox/restrictions.yaml
ENV VELOX_EXTRA_ARGS=""
EXPOSE 8080
# QUIC/UDP port - only used when QUIC_BIND is set
EXPOSE 8443/udp

USER app

ENTRYPOINT ["/usr/bin/dumb-init", "-v", "--"]
# Conditionally append --quic-bind and --reverse-tunnel-bind when their env vars are non-empty.
CMD ["/bin/sh", "-c", "exec /home/app/velox server ${SERVER_PROTOCOL}://${SERVER_LISTEN}:${SERVER_PORT} ${QUIC_BIND:+--quic-bind $QUIC_BIND} ${VELOX_REVERSE_TUNNEL_BIND:+--reverse-tunnel-bind $VELOX_REVERSE_TUNNEL_BIND} ${VELOX_EXTRA_ARGS}"]
