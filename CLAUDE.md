# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

`wstunnel` tunnels TCP/UDP/Unix/Stdio traffic over WebSocket or HTTP/2 to bypass firewalls/proxies. It is a Rust rewrite of the original Haskell tool (v7.0.0+ is not wire-compatible with previous versions). Single static binary, supports forward and reverse tunnels, static and dynamic (SOCKS5 / HTTP proxy / Linux tproxy).

## Workspace layout

Cargo workspace with two members:

- `wstunnel/` — the library crate (`wstunnel`). Contains all protocol, tunnel, and transport logic. Exposes `run_client`, `run_server`, `create_client`, and the `Client` / `Server` config structs. The `clap` feature (optional) derives CLI args onto these config structs.
- `wstunnel-cli/` — the binary crate (`wstunnel`). Thin `main.rs` that parses args with clap, sets up tracing, raises the fd limit, and delegates to the library. Optional `jemalloc` feature for release builds.

Crypto provider is selectable at build time:
- `aws-lc-rs` (default) — required for ECH support (`--tls-ech-enable`).
- `ring` — used for some cross-compile targets (armv6/v7, i686-freebsd, etc.).
- `aws-lc-rs-bindgen` — for targets where vendored aws-lc-rs needs bindgen (e.g. i686-musl).

See `.github/workflows/release.yaml` for the per-target feature combination.

## Build, test, lint

Common commands (via `just` or `mise run`, both wrap cargo):

```bash
cargo build --package wstunnel-cli           # debug build of the CLI
cargo build --package wstunnel-cli --release # release build
cargo build --features=jemalloc --release    # production build (as used by Docker/release)

just test          # cargo nextest run --all-features (REQUIRES Docker — uses testcontainers)
just fmt           # cargo fmt --all + taplo fmt
just linter_fix    # cargo clippy --fix --all-features --locked --allow-dirty
just bump_deps     # cargo upgrade --recursive + cargo update --recursive
```

Tests use `nextest` + `testcontainers` + `serial_test`. Integration tests in `wstunnel/src/test_integrations.rs` bind `127.0.0.1:9998/9999` and are `#[serial]` — running them in parallel will collide. To run one test:

```bash
cargo nextest run --all-features -p wstunnel test_tcp_tunnel
```

`rustfmt.toml` sets `max_width = 120`; `taplo.toml` formats TOML. CI (`Dockerfile`, `release.yaml`) enforces `cargo fmt --check` and `cargo clippy -D warnings` — run `just fmt` / `just linter_fix` before committing.

Version bumps are driven by `just make_release $VERSION` (edits both `Cargo.toml`s, tags, pushes, triggers Docker release).

## Architecture — big picture

The whole tool is two CLI verbs (`client` / `server`) sharing one transport layer. Every tunnel, forward or reverse, is: **Listener → WsClient → (WS or H2) transport → WsServer → Connector**.

### Entry points

- `wstunnel-cli/src/main.rs` — parses `Commands::Client(Client) | Commands::Server(Server)` and calls `run_client` / `run_server` from the library.
- `wstunnel/src/lib.rs` — `run_client` builds TLS config + DNS resolver + `WsClientConfig`, constructs a `WsClient`, and spawns one future per `-L` / `-R` argument. `run_server` builds `WsServerConfig` + `RestrictionsRules` and calls `WsServer::serve`.

### Config (`wstunnel/src/config.rs`)

Single 900+ line file defining the `Client` and `Server` clap structs plus all the URL-style parsers (`tcp://…`, `socks5://…`, `tproxy+udp://…`, `unix://…`, `stdio://…`). Parsers live in a `parsers` submodule and do the heavy lifting of mapping CLI URLs to `LocalProtocol` variants.

### Core tunnel types

`wstunnel/src/tunnel/mod.rs`:
- `LocalProtocol` — the enum of all supported protocols (Tcp, Udp, Stdio, Socks5, TProxyTcp, TProxyUdp, HttpProxy, Unix, and their `Reverse*` counterparts). Travels inside a JWT from client → server to describe what tunnel to open.
- `RemoteAddr` — `{ protocol, host, port }` describing the far end.

### Client side (`wstunnel/src/tunnel/client/`)

- `WsClient` holds a `bb8::Pool<WsConnection>` of idle transport connections (see `--connection-min-idle`). Pool max size 1000, max lifetime 30s.
- `run_tunnel(listener)` — for forward tunnels. Accept local connection → get a pooled ws/h2 connection → spawn two `propagate_*` futures.
- `run_reverse_tunnel(remote, connector)` — for reverse. Exponential-backoff reconnect loop; server tells client where to connect back via a `COOKIE` header containing a JWT.

### Server side (`wstunnel/src/tunnel/server/`)

- `WsServer::serve` binds one `TcpListener`, optionally wraps each accepted stream with `tokio_rustls::TlsAcceptor` (ALPN picks `h2` vs `http/1.1`), then dispatches to one of:
  - `handler_websocket::ws_server_upgrade` — for WS upgrade requests.
  - `handler_http2::http_server_upgrade` — for HTTP/2 CONNECT-like requests.
  - Auto-detect path when no TLS (used to pick WS or H2 based on `hyper_util::server::conn::auto`).
- `handle_tunnel_request` validates the JWT, matches against `RestrictionsRules`, and then `exec_tunnel` creates the outbound connector (TCP/UDP) **or** spawns a reverse listener.
- `reverse_tunnel.rs` keeps a global `LazyLock<ReverseTunnelServer<_>>` per reverse-protocol so multiple clients requesting the same reverse port share one listener.

### Transport (`wstunnel/src/tunnel/transport/`)

- `websocket.rs` / `http2.rs` — two implementations of the `TunnelRead`/`TunnelWrite` traits from `io.rs`.
- `jwt.rs` — HMAC-HS256 JWT carried in the `Sec-Websocket-Protocol` (WS) or `Authorization` (H2) header. **Signature verification is disabled** (`insecure_disable_signature_validation`); the JWT is just a structured envelope, auth is done via `--http-upgrade-path-prefix` and/or mTLS / basic auth.
- `io.rs` — `propagate_local_to_remote` / `propagate_remote_to_local` pump bytes between the local socket and the transport; also handles ws pings.
- `types.rs` — `TransportScheme` (`Ws`/`Wss`/`Http`/`Https`) and `TransportAddr`.

### Listeners & Connectors

- `tunnel/listeners/` — one file per input protocol that implements the `TunnelListener` trait (a `Stream` of accepted `(io, RemoteAddr)`). Includes `tproxy.rs` (Linux only) and `unix_sock.rs` (Unix only).
- `tunnel/connectors/` — `TunnelConnector` trait for outbound connections (TCP, UDP, SOCKS5). TCP is the only connector that supports `connect_with_http_proxy`.

### Protocols (`wstunnel/src/protocols/`)

Low-level networking primitives, **not** tunnel logic:
- `tcp.rs`, `udp.rs`, `unix_sock.rs` — socket construction, SO_MARK, PROXY protocol v2 emission.
- `tls.rs` — rustls wiring, cert loading, SNI/ECH, CN extraction (used for mTLS path-prefix routing).
- `dns.rs` — Hickory resolver, supports `dns://`, `dns+https://`, `dns+tls://`, `system://`.
- `socks5.rs`, `http_proxy.rs`, `stdio.rs` — server-side implementations of these protocols.

### Restrictions (`wstunnel/src/restrictions/`)

Server-side allowlist. Either built inline from `--restrict-to` + `--restrict-http-upgrade-path-prefix` flags, or loaded from YAML via `--restrict-config` (auto-reloaded on change by `config_reloader.rs`). Each incoming tunnel is matched against rules (`PathPrefix`, `Authorization`, `Any`) and then checked against `Tunnel` / `ReverseTunnel` allow entries (protocol, port range, host regex, CIDR, unix_path, `port_mapping` for reverse). See `restrictions.yaml` for the full schema with examples.

### Hot reload

- `tunnel/tls_reloader.rs` — watches TLS cert/key/CA paths via `notify`, swaps the acceptor/connector under an `arc_swap::ArcSwap` / `RwLock` without dropping connections.
- `restrictions/config_reloader.rs` — same pattern for the YAML restriction file.

### Executor abstraction

`wstunnel/src/executor.rs` — `TokioExecutor` / `TokioExecutorRef` traits with a `DefaultTokioExecutor`. Lets the library be embedded in a host that wants to supply its own spawn function.

## Things that commonly trip people up

- `--nb-worker-threads` does nothing; set the `TOKIO_WORKER_THREADS` env var (documented in the clap help).
- `stdio://` tunnels redirect logs to stderr (see `main.rs`) because stdin/stdout is the tunnel data.
- When the client uses mTLS and no explicit `--http-upgrade-path-prefix`, the prefix is auto-set to the client cert's CN (see `lib.rs::create_client`). The server must have a matching restriction.
- HTTP/2 transport does not survive a reverse proxy that buffers requests or downgrades to HTTP/1 (Cloudflare, default nginx). Use websocket unless you control the path end-to-end.
- UDP tunnels default to a 30s idle timeout — set `?timeout_sec=0` on the URL to disable (needed for WireGuard).
- Integration tests and many protocol tests are `#[serial]` + bind fixed ports; don't parallelize.
- Embedded self-signed cert (`embedded_certificate.rs`) is identical across all users → fingerprintable. Production setups should supply their own cert via `--tls-certificate`.
