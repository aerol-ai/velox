# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project

`wstunnel` tunnels TCP/UDP/Unix/Stdio traffic over WebSocket, HTTP/2, or QUIC to bypass firewalls/proxies. It is a Rust rewrite of the original Haskell tool (v7.0.0+ is not wire-compatible with previous versions). Single static binary, supports forward and reverse tunnels, static and dynamic (SOCKS5 / HTTP proxy / Linux tproxy).

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
cargo build --features=quic --package wstunnel-cli    # build with QUIC support

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

The whole tool is two CLI verbs (`client` / `server`) sharing one transport layer. Every tunnel, forward or reverse, is: **Listener → WsClient → (WS, H2, or QUIC) transport → WsServer → Connector**.

### Entry points

- `wstunnel-cli/src/main.rs` — parses `Commands::Client(Client) | Commands::Server(Server)` and calls `run_client` / `run_server` from the library.
- `wstunnel/src/lib.rs` — `run_client` builds TLS config + DNS resolver + `WsClientConfig`, constructs a `WsClient`, and spawns one future per `-L` / `-R` argument. `run_server` builds `WsServerConfig` + `RestrictionsRules` and calls `WsServer::serve`.

### Config (`wstunnel/src/config.rs`)

Single 900+ line file defining the `Client` and `Server` clap structs plus all the URL-style parsers (`tcp://…`, `socks5://…`, `tproxy+udp://…`, `unix://…`, `stdio://…`). Parsers live in a `parsers` submodule and do the heavy lifting of mapping CLI URLs to `LocalProtocol` variants.

QUIC flags are gated by `#[cfg(feature = "quic")]`:
- **Client**: `--quic-0rtt`, `--quic-keep-alive`, `--quic-max-idle-timeout`, `--quic-max-streams`, `--quic-datagram-buffer-size`.
- **Server**: `--quic-bind 0.0.0.0:PORT`, `--quic-0rtt`, `--quic-keep-alive`, `--quic-max-idle-timeout`, `--quic-max-streams`, `--quic-datagram-buffer-size`, `--quic-disable-migration`.

### Core tunnel types

`wstunnel/src/tunnel/mod.rs`:
- `LocalProtocol` — the enum of all supported protocols (Tcp, Udp, Stdio, Socks5, TProxyTcp, TProxyUdp, HttpProxy, Unix, and their `Reverse*` counterparts). Travels inside a JWT from client → server to describe what tunnel to open.
- `RemoteAddr` — `{ protocol, host, port }` describing the far end.

### Client side (`wstunnel/src/tunnel/client/`)

- `WsClient` holds a `bb8::Pool<WsConnection>` of idle transport connections (see `--connection-min-idle`). Pool max size 1000, max lifetime 30s. **For QUIC, the pool is bypassed** (forced to 0) and a single `QuicClientState` is held in `quic_state: Arc<Mutex<Option<QuicClientState>>>`.
- `l4_transport_stream.rs` — `TransportStream` enum-dispatches `AsyncRead + AsyncWrite` over plain TCP, client TLS, and server TLS with optional pre-buffered bytes.
- `run_tunnel(listener)` — for forward tunnels. Accept local connection → get transport (pooled ws/h2, or open a new QUIC bi-stream) → spawn two `propagate_*` futures.
- `run_reverse_tunnel(remote, connector)` — for reverse. Exponential-backoff reconnect loop; server tells client where to connect back via a `COOKIE` (WS/H2) or `cookie` field in the QUIC response header containing a JWT.

### Server side (`wstunnel/src/tunnel/server/`)

- `WsServer::serve` binds one `TcpListener`, optionally wraps each accepted stream with `tokio_rustls::TlsAcceptor` (ALPN picks `h2` vs `http/1.1`), then dispatches to one of:
  - `handler_websocket::ws_server_upgrade` — for WS upgrade requests.
  - `handler_http2::http_server_upgrade` — for HTTP/2 CONNECT-like requests.
  - Auto-detect path when no TLS (used to pick WS or H2 based on `hyper_util::server::conn::auto`).
- If `--quic-bind` is set, `create_quic_endpoint` binds a separate UDP socket and a sibling task runs `handler_quic::quic_server_serve` — accepting one `quinn::Connection` per client, each multiplexing tunnels as independent bi-streams. TLS reloads propagate via `endpoint.set_server_config`.
- `handle_tunnel_request` (WS/H2) and `handle_quic_stream` (QUIC) both validate the JWT, match against `RestrictionsRules`, and call `exec_tunnel` to open the outbound connector or reverse listener.
- `reverse_tunnel.rs` keeps a global `LazyLock<ReverseTunnelServer<_>>` per reverse-protocol so multiple clients requesting the same reverse port share one listener.

### Transport (`wstunnel/src/tunnel/transport/`)

- `websocket.rs` / `http2.rs` — `TunnelRead`/`TunnelWrite` impls for WS and H2.
- `quic.rs` — QUIC transport (behind `#[cfg(feature = "quic")]`):
  - `QuicStreamTunnelRead` / `QuicStreamTunnelWrite` — stream-based reliable tunnel.
  - `QuicDatagramTunnelRead` / `QuicDatagramTunnelWrite` — DATAGRAM-based UDP tunnel; multiplexed by `QuicDatagramHub` using a `HashMap<u32 flow_id, mpsc::Sender<Bytes>>`.
  - `QuicTunnelRead` / `QuicTunnelWrite` — enum dispatch over the two above.
  - `QuicClientState` — holds the live `quinn::Endpoint` + `quinn::Connection` + `Arc<QuicDatagramHub>`.
  - Wire preamble: `"WSTUNNEL/1\n"` (11 bytes) + length-prefixed fields (u16 BE).
  - ALPN: `b"wstunnel"`.
- `jwt.rs` — HMAC-HS256 JWT carried in the `Sec-Websocket-Protocol` (WS) or `Authorization` (H2) header, or in the `jwt` field of the QUIC request header. **Signature verification is disabled** (`insecure_disable_signature_validation`); auth is done via path prefix / mTLS / restrictions.
- `io.rs` — `propagate_local_to_remote` / `propagate_remote_to_local` pump bytes between the local socket and the transport; also handles WS pings. `MAX_PACKET_LENGTH` = 64 KiB.
- `types.rs` — `TransportScheme` (`Ws`/`Wss`/`Http`/`Https`/`Quic`) and `TransportAddr`.

### Listeners & Connectors

- `tunnel/listeners/` — one file per input protocol that implements the `TunnelListener` trait (a `Stream` of accepted `(io, RemoteAddr)`). Includes `tproxy.rs` (Linux only) and `unix_sock.rs` (Unix only).
- `tunnel/connectors/` — `TunnelConnector` trait for outbound connections (TCP, UDP, SOCKS5). TCP is the only connector that supports `connect_with_http_proxy`.

### Protocols (`wstunnel/src/protocols/`)

Low-level networking primitives, **not** tunnel logic:
- `tcp.rs`, `udp.rs`, `unix_sock.rs` — socket construction, SO_MARK, PROXY protocol v2 emission.
- `tls.rs` — rustls wiring, cert loading, SNI/ECH, CN extraction (used for mTLS path-prefix routing and QUIC mTLS CN extraction via `connection.peer_identity()`).
- `dns.rs` — Hickory resolver, supports `dns://`, `dns+https://`, `dns+tls://`, `system://`.
- `socks5.rs`, `http_proxy.rs`, `stdio.rs` — server-side implementations of these protocols.

### Restrictions (`wstunnel/src/restrictions/`)

Server-side allowlist. Either built inline from `--restrict-to` + `--restrict-http-upgrade-path-prefix` flags, or loaded from YAML via `--restrict-config` (auto-reloaded on change by `config_reloader.rs`). Each incoming tunnel is matched against rules (`PathPrefix`, `Authorization`, `Any`) and then checked against `Tunnel` / `ReverseTunnel` allow entries (protocol, port range, host regex, CIDR, unix_path, `port_mapping` for reverse). See `restrictions.yaml` for the full schema with examples. **Restrictions apply equally to QUIC tunnels** — same `validate_tunnel` + `exec_tunnel` path.

### Hot reload

- `tunnel/tls_reloader.rs` — watches TLS cert/key/CA paths via `notify`, swaps the acceptor/connector under an `arc_swap::ArcSwap` / `RwLock` without dropping connections. For QUIC, `should_reload_certificate_quic()` triggers `endpoint.set_server_config(new_cfg)`.
- `restrictions/config_reloader.rs` — same pattern for the YAML restriction file.

### Executor abstraction

`wstunnel/src/executor.rs` — `TokioExecutor` / `TokioExecutorRef` traits with a `DefaultTokioExecutor`. Lets the library be embedded in a host that wants to supply its own spawn function.

## Things that commonly trip people up

- `--nb-worker-threads` does nothing; set the `TOKIO_WORKER_THREADS` env var (documented in the clap help).
- `stdio://` tunnels redirect logs to stderr (see `main.rs`) because stdin/stdout is the tunnel data.
- When the client uses mTLS and no explicit `--http-upgrade-path-prefix`, the prefix is auto-set to the client cert's CN (see `lib.rs::create_client`). The server must have a matching restriction. This works for QUIC too — CN is extracted from `connection.peer_identity()`.
- HTTP/2 transport does not survive a reverse proxy that buffers requests or downgrades to HTTP/1 (Cloudflare, default nginx). Use websocket or QUIC unless you control the path end-to-end.
- UDP tunnels default to a 30s idle timeout — set `?timeout_sec=0` on the URL to disable (needed for WireGuard).
- Integration tests and many protocol tests are `#[serial]` + bind fixed ports; don't parallelize.
- Embedded self-signed cert (`embedded_certificate.rs`) is identical across all users → fingerprintable. Production setups should supply their own cert via `--tls-certificate`.
- QUIC requires TLS; there is no cleartext QUIC. The server must have a cert (`--tls-certificate` / embedded default) and the QUIC bind port is separate from the TCP port (`--quic-bind`).
- For QUIC, `--connection-min-idle` is silently forced to 0 because the connection pool is not used; reuse is inherent in the single-connection model.
- QUIC DATAGRAM frames are used for UDP tunnels automatically when `transport_mode == Datagram`. The `flow_id` in the stream header registers a channel in `QuicDatagramHub`; subsequent UDP packets travel outside the stream.
