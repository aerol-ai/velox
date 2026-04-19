# velox architecture

End-to-end reference for how the CLI and the server work, and a catalogue of the use cases currently covered.

---

## 1. 10,000-foot view

```
 Local app                Client (velox client)              Server (velox server)            Remote target
 ─────────                ───────────────────────────           ────────────────────────            ─────────────
   TCP / UDP / Unix   ─►  Listener  ──►  WsClient pool     ──►  TLS acceptor ──► WS/H2 upgrade ──►  Connector ──► TCP / UDP / SOCKS5 / Unix
   Stdio / SOCKS5         (per -L arg)   JWT-in-upgrade          Restriction check  │                (per tunnel request)
   HTTP proxy / TProxy                   WS or HTTP/2            JWT parse          ▼
                                         transport                                 Reverse listener  (for -R tunnels)

                                         ─── OR ───

                          quic_state ──► QUIC endpoint ──►  QUIC endpoint ──► bi-stream per tunnel ──►  Connector ──► TCP / UDP / SOCKS5
   UDP flows                             (single shared         JWT-in-stream                             QUIC DATAGRAM for UDP tunnels
                                         connection)            Restriction check
                                         QUIC DATAGRAM          per-conn datagram hub
```

Every tunnel, forward or reverse, is the same assembly line:

1. **A listener accepts a local connection.**
2. **`WsClient` gets (or creates) a transport connection** to the server - pooled WS/H2 connections via `bb8::Pool<WsConnection>`, or a shared QUIC connection via `quic_state` (one per client, multiplexed as bi-streams).
3. **A JWT envelope** describes "I want a tunnel of kind X to host:port Y" and travels in the WS upgrade / H2 request headers (WS/H2) or as a length-prefixed binary frame on the first bytes of a QUIC bi-stream.
4. **Server validates** (upgrade path, mTLS, restrictions YAML) and either opens an outbound connection (forward) or binds a new listener (reverse).
5. **Two `propagate_*` tasks** shuffle bytes in both directions until one side closes. UDP tunnels over QUIC use QUIC DATAGRAM frames (RFC 9221) via the `QuicDatagramHub` flow multiplexer instead of a reliable stream.

---

## 2. The CLI

### 2.1 Binary: `velox-cli/src/main.rs`

- `#[tokio::main] async fn main()` parses `Velox { commands: Client | Server }` via clap (`derive` + `env`).
- Bumps soft fd limit to hard via `fdlimit::raise_fd_limit()`.
- Configures `tracing_subscriber` from `RUST_LOG` / `--log-lvl`. Forces `h2::codec=off` unless the user overrides.
- If any `-L` is `stdio://…`, logs go to **stderr** (stdout is tunnel data).
- Dispatches to `velox::run_client(args, DefaultTokioExecutor)` or `velox::run_server(args, …)`.

### 2.2 Clap config: `velox/src/config.rs`

- `Client` and `Server` are `#[derive(clap::Args)]` on the `clap` feature (enabled from `velox-cli`).
- Custom parsers (`parsers::parse_tunnel_arg`, `parse_reverse_tunnel_arg`, `parse_duration_sec`, `parse_sni_override`, etc.) convert URL-style flags into typed values:
  - `tcp://BIND:PORT:HOST:PORT[?proxy_protocol]`
  - `udp://…?timeout_sec=N`
  - `socks5://BIND:PORT[?login=&password=]`
  - `http://BIND:PORT[?login=&password=]`
  - `tproxy+tcp://BIND:PORT` / `tproxy+udp://BIND:PORT[?timeout_sec=]` (Linux only)
  - `stdio://HOST:PORT`
  - `unix:///path:HOST:PORT[?proxy_protocol]`
- Each `-L` / `-R` becomes a `LocalToRemote { local_protocol, local, remote }`.
- `Client` carries: transport URL, TLS (cert/key/verify/SNI/ECH), mTLS, DNS resolvers, HTTP-proxy credentials, connection pool sizing, backoff, custom headers, upgrade path prefix, upgrade credentials, `websocket-ping-frequency`, `websocket-mask-frame`, `socket-so-mark`.
- `Server` carries: bind URL, TLS (server cert, client CA for mTLS), restriction file, `restrict-to`, `restrict-http-upgrade-path-prefix`, ping frequency, DNS resolvers, HTTP proxy (used when the server needs to phone out through one).

### 2.3 Subcommands

Two verbs only:
- `velox client <ws[s]|http[s]|quic://server> [-L ...]... [-R ...]... [options]`
- `velox server <ws[s]://bind> [--quic-bind addr:port] [options]`

There is no `--config` top-level file; configuration is purely flags + environment (`HTTP_PROXY`, `NO_COLOR`, `RUST_LOG`, `TOKIO_WORKER_THREADS`, `VELOX_HTTP_PROXY_LOGIN`/`PASSWORD`, `VELOX_HTTP_UPGRADE_PATH_PREFIX`, `VELOX_RESTRICT_HTTP_UPGRADE_PATH_PREFIX`).

---

## 3. Client runtime (`velox/src/lib.rs::run_client` + `tunnel/client/`)

### 3.1 Bootstrap - `create_client`

1. Load mTLS cert/key if supplied. If present and no explicit `--http-upgrade-path-prefix`, **derive the prefix from the cert's CN** (this is how the server routes "which client is this" via TLS - see `protocols/tls.rs::cn_from_certificate`).
2. Build an HTTP proxy URL from `-p` / `HTTP_PROXY` + login/password.
3. Build a `DnsResolver` (`protocols/dns.rs`) from `--dns-resolver` URLs. Default is the system resolver; alternates are UDP, DoH, DoT, or `system://`.
4. If the remote scheme is `wss://` / `https://`, build a `tls::tls_connector`. Handles: ALPN per scheme, SNI override/disable, ECH config fetched via DNS, mTLS cert.
5. Compute the `Host:` header (honors the user-supplied one from `-H Host: …` if given, else `host[:port]` of the remote).
6. Instantiate `WsClient::new(config, connection_min_idle, connection_retry_max_backoff, reverse_tunnel_connection_retry_max_backoff, executor)`. This constructs a `bb8::Pool<WsConnection>` with `max_size=1000`, `max_lifetime=30s`.

### 3.2 Spawning tunnels - `create_client_tunnels`

Iterates `remote_to_local` (reverse) and `local_to_remote` (forward). For each tunnel:

| Kind       | Forward (`-L`)                                                                                                                           | Reverse (`-R`)                                                                                             |
|------------|-------------------------------------------------------------------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|
| TCP        | `TcpTunnelListener` → `run_tunnel`                                                                                                        | `TcpTunnelConnector` → `run_reverse_tunnel`                                                                |
| UDP        | `UdpTunnelListener` (with per-flow state, idle timeout) → `run_tunnel`                                                                    | `UdpTunnelConnector` → `run_reverse_tunnel`                                                                |
| SOCKS5     | `Socks5TunnelListener` (negotiates SOCKS5 locally, builds remote addr dynamically) → `run_tunnel`                                         | `Socks5TunnelConnector`                                                                                    |
| HTTP proxy | `HttpProxyTunnelListener` (CONNECT + absolute-URI GET, basic auth) → `run_tunnel`                                                         | `TcpTunnelConnector` (the remote side of a reverse-http-proxy is just "dial this ip:port")                 |
| Stdio      | `new_stdio_listener` - single-shot tunnel, exits on close or SIGINT                                                                       | n/a                                                                                                        |
| Unix       | `UnixTunnelListener` (Unix only)                                                                                                          | `TcpTunnelConnector` (reverse-unix: server binds a unix socket, client dials the tcp target)               |
| TProxy TCP | `TproxyTcpTunnelListener` (Linux only; needs `CAP_NET_ADMIN`)                                                                             | n/a                                                                                                        |
| TProxy UDP | `new_tproxy_udp` (Linux only)                                                                                                             | n/a                                                                                                        |

### 3.3 Forward tunnel (`WsClient::run_tunnel`)

Loop:
- `listener.next().await` → `(local_stream, remote_addr)`.
- Open `uuid = Uuid::now_v7()`, attach a tracing span `tunnel{id, remote}`.
- `connect_to_server(request_id, remote_addr, local_stream)` picks the transport based on scheme:
  - `ws/wss` → `transport::websocket::connect` (HTTP/1.1 + Upgrade).
  - `http/https` → `transport::http2::connect` (HTTP/2 request with streaming body).
- `propagate_local_to_remote` and `propagate_remote_to_local` are spawned - each is its own tokio task.

### 3.4 Reverse tunnel (`WsClient::run_reverse_tunnel`)

The client keeps one long-lived transport connection per `-R` arg:
- Connect to server; server hands back a JWT in the `COOKIE` response header telling the client the final `RemoteAddr` (useful for dynamic reverse tunnels where the server knows the port mapping).
- `connector.connect(&remote)` dials the target on the **client's** side.
- The same `propagate_*` pair pumps bytes.
- Any transport error triggers an **exponential backoff** (`Duration::from_secs(1)` → `*2` up to `--reverse-tunnel-connection-retry-max-backoff`).

### 3.5 Connection pool (`tunnel/client/cnx_pool.rs`)

`bb8::ManageConnection` impl on `WsConnection`. Opens a new transport connection on demand, honors `--connection-min-idle` to pre-warm the pool, respects `socket_so_mark`, timeouts, DNS resolver, TLS config. Connections older than 30s are reaped.

When the transport scheme is `quic://`, the pool is bypassed: `connection_min_idle` is forced to 0 and `WsClient::quic_state` holds the live `QuicClientState` (QUIC endpoint + connection + datagram hub) instead. New tunnels call `transport/quic.rs::connect` which reuses or re-establishes the shared QUIC connection and opens a new bi-directional stream.

### 3.6 L4 transport stream (`tunnel/client/l4_transport_stream.rs`)

`TransportStream` is an enum-dispatched `AsyncRead + AsyncWrite` over plain TCP, client-side TLS, and server-side TLS. Wraps each half with an optional pre-buffered `Bytes` (for bytes already read during TLS negotiation).

### 3.7 TLS reload (`tunnel/tls_reloader.rs`)

Watches `tls_certificate_path` / `tls_key_path` / `tls_client_ca_certs_path` using `notify`. When a change is detected, rebuilds the rustls config and swaps it behind an `Arc<RwLock<…>>` - existing connections keep their old config; new ones pick up the new cert/CA.

---

## 4. Server runtime (`velox/src/lib.rs::run_server_impl` + `tunnel/server/`)

### 4.1 Bootstrap

1. If bind scheme is `wss://`, load TLS:
   - Cert/key from `--tls-certificate`/`--tls-private-key`, else fall back to `embedded_certificate::TLS_CERTIFICATE` (a self-signed pair baked into the binary - **publicly known, fingerprintable**).
   - Optional `--tls-client-ca-certs` enables **mTLS**; client certs are verified against the CA.
2. Build `RestrictionsRules`:
   - If `--restrict-config <file.yaml>` is given, parse YAML and watch for changes.
   - Otherwise, synthesize from `--restrict-to host:port` pairs and `--restrict-http-upgrade-path-prefix` prefixes (the latter acts as a shared secret).
   - If neither is given, allow everything.
3. Build `DnsResolver`, `http_proxy`, `WsServerConfig`, spawn `WsServer::serve`.

### 4.2 Accept loop (`server.rs::serve`)

- Binds one `TcpListener`. Configures socket (SO_MARK, nodelay) via `protocols::tcp::configure_socket`.
- For each accepted connection:
  - **With TLS** - `TlsAcceptor::accept`, sniff `alpn_protocol()`:
    - `h2` → `hyper::server::conn::http2` + `http_server_upgrade` service.
    - else → `http1::Builder` + `ws_server_upgrade` service.
    - If the client presented a cert, `cn_from_certificate` is extracted and passed down as the **required path prefix for that connection**. This is how mTLS CN → restriction routing works.
  - **No TLS** - `hyper_util::server::conn::auto::Builder` auto-detects HTTP/1.1 vs HTTP/2; for H/1 the request is then inspected for `Upgrade: websocket`. If neither upgrade is possible, it rejects with 400.
- Each connection runs in its own tokio task, inside a `cnx{peer=…}` tracing span.
- **QUIC** - if `--quic-bind` is set, `create_quic_endpoint` binds a separate UDP socket using `quinn::Endpoint::server`. A sibling task (`quic_server_serve`) runs the accept loop, handling one `quinn::Connection` per client, each carrying many tunnels as independent bi-streams. The same `RestrictionsRules` and `exec_tunnel` path is reused. TLS cert reloads are propagated via `endpoint.set_server_config`.

### 4.3 Per-request handling - `handle_tunnel_request`

1. Extract `X-Forwarded-For` (so logs/restrictions see the real IP when behind a proxy).
2. Extract the path prefix from the URI (e.g. `/v1/…` → `"v1"`).
3. If the TLS handshake produced a CN-based restricted path, enforce it.
4. Extract the JWT from `Sec-WebSocket-Protocol` (WS) or `Authorization` (H/2), prefix `authorization.bearer.`.
   - JWT uses HS256 but **signature validation is disabled** - it is purely a structured envelope (see `transport/jwt.rs::JWT_DECODE`). Real auth comes from path prefix / mTLS / restriction YAML's `Authorization` matcher.
5. Parse JWT claims → `RemoteAddr { protocol: LocalProtocol, host, port }`.
6. `validate_tunnel(remote, path_prefix, auth_header, restrictions)` walks the rules:
   - Match step - every `MatchConfig` in the rule must match (`PathPrefix` regex, `Authorization` regex, or `Any`).
   - Allow step - at least one `AllowConfig::Tunnel | ReverseTunnel` entry must admit the destination (protocol ∈ allowed, port ∈ allowed ranges, host matches regex, IP in CIDR, for reverse: unix_path match + optional port_mapping rewrite).
7. `exec_tunnel` opens the outbound side:
   - **Forward TCP** - `TcpTunnelConnector`, optionally through `http_proxy`, optionally emits PROXY protocol v2 to the target.
   - **Forward UDP** - `UdpTunnelConnector`, per-flow timeout.
   - **Reverse TCP/UDP/SOCKS5/HTTP-Proxy/Unix** - shared `ReverseTunnelServer<L>` keeps one listener per (bind, protocol) so multiple clients asking for the same reverse port reuse it. Idle timeout is `--remote-to-local-server-idle-timeout`.
8. Returned streams are adapted to `Pin<Box<dyn AsyncRead + Send>>` / `AsyncWrite`, and `ws_server_upgrade` / `http_server_upgrade` splice them to the WS/H2 framing via `transport::io::propagate_*`.

### 4.4 Reverse tunnel server (`tunnel/server/reverse_tunnel.rs`)

- `ReverseTunnelServer<L: TunnelListener>` is a `LazyLock`-ed singleton per reverse protocol (one per `LocalProtocol::Reverse*`).
- First request binds the requested (host, port) locally; subsequent requests for the same address get the existing listener.
- Accepted local connections are matched to a waiting client (the client that initiated the reverse tunnel).
- `port_mapping` from restrictions can rewrite the public port (e.g. client asks `-R tcp://10001:…`, server actually binds 8080).

### 4.5 Restrictions YAML (`restrictions/types.rs`)

```
restrictions:
  - name: "…"
    match:                     # all must match (AND)
      - !PathPrefix "regex"
      - !Authorization "regex"
      - !Any
    allow:                     # at least one must allow (OR)
      - !Tunnel        { protocol, port, host, cidr }
      - !ReverseTunnel { protocol, port, port_mapping, cidr, unix_path }
```

Reloaded automatically via `notify` watcher in `config_reloader.rs`. Default when no file and no flags → blanket allow.

---

## 5. Transport layer (`tunnel/transport/`)

### 5.1 `TunnelRead` / `TunnelWrite` (`io.rs`)

Abstracts over WS and H/2. Two pump functions:

- `propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency)` - copies local→ws, injects periodic pings, signals `close_tx` on EOF.
- `propagate_remote_to_local(local_tx, ws_rx, close_rx)` - copies ws→local, exits on `close_rx` or remote close.

`MAX_PACKET_LENGTH` = 64 KiB framed packets.

### 5.2 WebSocket (`websocket.rs`)

- Client: HTTP/1.1 Upgrade, uses `fastwebsockets` with SIMD masking. Emits:
  - `Upgrade: websocket`, `Connection: upgrade`, `Sec-WebSocket-Version: 13`, random `Sec-WebSocket-Key`.
  - `Sec-WebSocket-Protocol: v1,authorization.bearer.<JWT>` for tunnel config.
  - Optional `--http-upgrade-credentials USER[:PASS]` → `Authorization: Basic …`.
  - Custom headers from `-H` or `--http-headers-file`.
  - Path is `/<http_upgrade_path_prefix>/events`.
- Server: reuses `fastwebsockets::upgrade::upgrade`, inspects `Sec-WebSocket-Protocol` for the JWT.
- `--websocket-mask-frame` is off by default - mask only if a middlebox mangles unmasked frames.
- Keepalive: configurable WS pings every `--websocket-ping-frequency-sec` (default 30s). `in_flight_ping` counter catches a dead server.

### 5.3 HTTP/2 (`http2.rs`)

- Client: `hyper::Client` with ALPN `h2`, sends a long-lived POST with streaming body.
- Server: `hyper::server::conn::http2` upgrades the request, consumes the streaming body as the "up" direction and the response body as the "down" direction.
- Caveats documented in `config.rs` clap help: any reverse proxy that buffers request bodies or downgrades to HTTP/1 breaks this transport.

### 5.4 QUIC (`quic.rs`) - requires `--features quic`

Built on `quinn` (pure-Rust QUIC over `tokio`). Uses a **single long-lived QUIC connection** per client, held in `WsClient::quic_state` (`Arc<Mutex<Option<QuicClientState>>>`). Each tunnel runs as an independent bi-directional QUIC stream, eliminating TCP head-of-line blocking.

**Wire format per bi-stream (client → server header):**
```
[preamble: "VELOX/1\n" (11 bytes)]
[u16 BE path_prefix_len][path_prefix]
[u16 BE jwt_len][jwt]
[u16 BE auth_len][authorization]      // empty = absent
[u8 num_headers]
{ [u16 BE name_len][name][u16 BE val_len][value] } × num_headers
[u8 transport_mode]                   // 0 = stream, 1 = QUIC DATAGRAM
[u32 BE flow_id]                      // non-zero only for datagram tunnels
<then raw tunneled bytes for stream mode>
```

**Server → client response header:**
```
[preamble: "VELOX/1\n" (11 bytes)]
[u8 status]                           // 0 = OK, 1 = bad request, 2 = forbidden, 3 = internal error
[u16 BE reason_len][reason]
[u16 BE cookie_len][cookie]           // JWT for dynamic reverse tunnels
```

**UDP tunnels** use QUIC DATAGRAM frames (RFC 9221) instead of streams. Each UDP flow gets a `flow_id` (u32). The `QuicDatagramHub` per connection demultiplexes incoming datagrams by flow_id using a `HashMap<u32, mpsc::Sender<Bytes>>` protected by a `parking_lot::Mutex`. Wire: `u32 BE flow_id || payload`.

**ALPN**: `velox` (constant `QUIC_ALPN`).

**mTLS over QUIC**: `extract_restrict_path_prefix` reads the CN from `connection.peer_identity()` (same logic as TLS).

**Key config fields** (gated by `#[cfg(feature = "quic")]`):
- Client: `quic_0rtt`, `quic_keep_alive`, `quic_max_idle_timeout`, `quic_max_streams`, `quic_datagram_buffer_size`.
- Server: `quic_bind`, plus all the above plus `quic_disable_migration`.

### 5.5 JWT (`jwt.rs`)

```rust
struct JwtTunnelConfig { id: String, p: LocalProtocol, r: String, rp: u16 }
```

Encoded `HS256` with a process-unique key (nanos since UNIX epoch), **decoded without verifying signature**. Reverse-tunnel responses from server → client use a different JWT in the `COOKIE` response header to tell the client the chosen remote address.

---

## 6. Shared helpers

### 6.1 `protocols/` (low-level networking)

- **tcp.rs** - `connect`, `run_server`, SO_MARK, Nagle off, optional PROXY-protocol v2 header.
- **udp.rs** - peer-muxing `Stream` for UDP server, per-peer writer, idle timeout.
- **unix_sock.rs** - AF_UNIX stream listener (Unix only).
- **tls.rs** - rustls connector/acceptor factories, cert/key PEM loading, CN extraction, ECH config lookup via DNS (requires `aws-lc-rs` feature).
- **dns.rs** - Hickory resolver factory from a list of resolver URLs; handles DoH/DoT through the same HTTP proxy if any.
- **socks5.rs** - server-side SOCKS5 handshake (via `fast-socks5`), returns the requested `RemoteAddr`.
- **http_proxy.rs** - server-side HTTP proxy (CONNECT + absolute-URI GET), basic auth.
- **stdio.rs** - wraps stdin/stdout (with a special code path on Windows using `crossterm` + `tokio-util`).

### 6.2 `somark.rs`

Thin wrapper around Linux `SO_MARK` setsockopt. No-op on non-Linux.

### 6.3 `embedded_certificate.rs`

A compile-time-embedded self-signed certificate + key used when the server is launched with `wss://` but no `--tls-certificate`. Shared across all users → fingerprintable.

### 6.4 `executor.rs`

Trait-based executor abstraction so the library can be driven by a custom spawn function instead of `tokio::spawn`. Default is `DefaultTokioExecutor`.

---

## 7. Feature flags

| Feature              | Effect                                                                                   |
|----------------------|------------------------------------------------------------------------------------------|
| `aws-lc-rs` (default)| rustls + rcgen + jsonwebtoken backed by AWS-LC. Required for ECH.                        |
| `ring`               | Alternative crypto backend. Needed on some musl / Android / freebsd cross targets.       |
| `aws-lc-rs-bindgen`  | Forces aws-lc-rs to use bindgen (for targets without prebuilt bindings).                 |
| `clap` (velox lib)| Derives CLI args on `Client` / `Server`. Always on when built from `velox-cli`.       |
| `quic`               | Enables QUIC transport via `quinn`. Adds `--features quic` to CLI; `quic://` URL scheme. |
| `jemalloc` (cli)     | Swaps the global allocator to `tikv-jemallocator`. Used in release/Docker builds.        |

---

## 8. Use cases currently covered

Drawn from the README, CLI help, `config.rs`, `restrictions.yaml`, and the module layout.

### 8.1 Forward tunnels (`-L`)

1. **TCP forward** - `tcp://BIND:PORT:HOST:PORT`. Port-forward any TCP protocol through the WS/H2 tunnel.
2. **TCP forward with PROXY-protocol v2** - `tcp://…?proxy_protocol` so the target sees the real client IP.
3. **UDP forward** - `udp://BIND:PORT:HOST:PORT[?timeout_sec=N]`. Tunnels any UDP protocol; idle timeout configurable (needed for WireGuard: `timeout_sec=0`).
4. **SOCKS5 proxy** - `socks5://BIND:PORT[?login=&password=]`. Any SOCKS5-aware client can browse through it (browsers, curl, proxychains).
5. **HTTP CONNECT proxy** - `http://BIND:PORT[?login=&password=]`. Same as SOCKS5 but via HTTP proxy protocol.
6. **Transparent proxy TCP (Linux)** - `tproxy+tcp://BIND:PORT`. Redirect arbitrary TCP via iptables TPROXY or tools like `cproxy`.
7. **Transparent proxy UDP (Linux)** - `tproxy+udp://BIND:PORT[?timeout_sec=]`. Same for UDP.
8. **Stdio forward** - `stdio://HOST:PORT`. One-shot pipe over stdin/stdout; ideal for `ssh -o ProxyCommand="velox client … -L stdio://%h:%p …"`.
9. **Unix socket forward** - `unix:///path/to.sock:HOST:PORT[?proxy_protocol]` (Unix only).

### 8.2 Reverse tunnels (`-R`)

10. **Reverse TCP** - `tcp://BIND:PORT:HOST:PORT`. Server listens, client dials locally. Useful for exposing a laptop-local service behind NAT.
11. **Reverse UDP** - `udp://…`. Reverse equivalent for UDP.
12. **Reverse SOCKS5** - `socks5://…[?login=&password=]`. Clients on the server's network get a SOCKS5 egress that tunnels back to the velox-client's machine.
13. **Reverse HTTP proxy** - `http://…[?login=&password=]`. Same, as HTTP CONNECT.
14. **Reverse Unix socket** - `unix://BIND_SOCKET:HOST:PORT`. Server creates a unix socket, bytes end up on the client side connecting to HOST:PORT.
15. **Reverse tunnels with port mapping** - `port_mapping` in `restrictions.yaml` rewrites the server-side bind port (e.g. client requests port 10001, server actually binds 8080).

### 8.3 Transport options

16. **WebSocket transport** - `ws://` (cleartext) or `wss://` (TLS). Recommended path; works with most reverse proxies.
17. **HTTP/2 transport** - `http://` / `https://`. For when WS is blocked. Requires direct exposure - most reverse proxies break it.
18. **QUIC transport** - `quic://` (always TLS). Requires `--features quic`. Single QUIC connection per client; each tunnel is an independent bi-stream. UDP tunnels use QUIC DATAGRAM frames. Enables 0-RTT, connection migration, and eliminates TCP HoL blocking.
19. **Via HTTP proxy** - `-p http://user:pass@host:port`. Client tunnels out through a corporate proxy first. Server can also be configured with the same (for reverse-tunnel back-connections).

### 8.4 TLS / authentication

19. **TLS with embedded self-signed cert** - zero-config `wss://` server.
20. **TLS with custom cert/key** - `--tls-certificate` + `--tls-private-key`, hot-reloaded on change.
21. **mTLS (client-cert auth)** - server sets `--tls-client-ca-certs`. Client presents `--tls-certificate` + `--tls-private-key`. Client CN auto-becomes the upgrade path prefix so restrictions can route per-client. Documented in `docs/using_mtls.md`.
22. **SNI override / disable** - `--tls-sni-override domain` or `--tls-sni-disable` for stealth / CDN routing.
23. **Encrypted ClientHello (ECH)** - `--tls-ech-enable` (needs `aws-lc-rs`). ECH config fetched from DNS at startup.
24. **Cert verification** - `--tls-verify-certificate` (off by default; defaults to trust-anything to keep the embedded self-signed cert usable).

### 8.5 Upgrade-path-prefix auth

25. **Shared-secret path prefix** - `--http-upgrade-path-prefix SECRET` on client, `--restrict-http-upgrade-path-prefix SECRET` on server. Acts as a bearer secret at the URL level.
26. **Multiple prefixes** - server accepts multiple `--restrict-http-upgrade-path-prefix` values.

### 8.6 HTTP-level auth and customization

27. **HTTP Basic upgrade credentials** - `--http-upgrade-credentials user:pass`.
28. **Custom HTTP headers** - `-H "Name: value"` or `--http-headers-file path` (re-read every connection, live-editable).
29. **Custom Host header** - supplying `-H "Host: …"` overrides the automatic one (useful behind CDNs).

### 8.7 Restrictions (server-side policy)

30. **Simple destination allowlist** - repeated `--restrict-to host:port`.
31. **YAML restrictions file** - `--restrict-config file.yaml`, hot-reloaded. Supports:
    - Path-prefix regex match, Authorization regex match, or `!Any`.
    - Per-protocol/port-range/host-regex/CIDR allow rules for forward tunnels.
    - Per-protocol/port-range/CIDR/unix-path-regex + `port_mapping` rules for reverse tunnels.
32. **X-Forwarded-For handling** - server picks up the client IP from `X-Forwarded-For` when behind a trusted reverse proxy (applied before CIDR restriction checks).

### 8.8 DNS

33. **Custom DNS resolvers** - `--dns-resolver dns://1.1.1.1`, `dns+https://…?sni=…`, `dns+tls://…?sni=…`, or `system://`. Multiple can be stacked.
34. **Prefer-IPv4** knob for DNS resolution on client and server.

### 8.9 Performance / connection pool

35. **Warm connection pool** - `--connection-min-idle N`. Pre-opens N TLS sessions so new tunnels skip the TCP + TLS handshake. Critical for browser/SOCKS5 workloads. Not used for QUIC (pool forced to 0; connection reuse is inherent).
36. **Configurable retry backoff** - `--connection-retry-max-backoff` (forward) and `--reverse-tunnel-connection-retry-max-backoff`.
37. **WebSocket ping keepalive** - `--websocket-ping-frequency-sec`, on by default (30s).
38. **SO_MARK** - `--socket-so-mark N` (Linux) for policy routing / excluding tunnel traffic from VPNs.

### 8.10 Platform / deployment

39. **Standalone static binaries** - musl x86_64, x86, aarch64, armv7hf, armv6, Android aarch64/armv7, FreeBSD x86/x86_64 (see `.github/workflows/release.yaml`).
40. **Docker image** - `ghcr.io/aerol-ai/velox:latest`. Entry point runs `velox server ${SERVER_PROTOCOL}://${SERVER_LISTEN}:${SERVER_PORT}`.
41. **jemalloc build** - `--features=jemalloc` for better allocator behavior on server workloads.
42. **Windows support** - stdio uses `crossterm` shim; tproxy/unix/SO_MARK disabled.
43. **Raspberry Pi (armv7)** - supported as a first-class target; was a reason for the Haskell → Rust rewrite.

### 8.11 Observability

44. **Structured tracing** - `tracing` + `tracing-subscriber`, `RUST_LOG`/`--log-lvl`, per-connection and per-tunnel spans with `peer`, `id`, `remote`, `forwarded_for` fields. QUIC tunnels emit the same `tunnel{id,remote}` span shape.
45. **`--no-color`** / `NO_COLOR` env support.

### 8.12 Library embedding

46. **`velox` as a Rust library** - `run_client`, `run_server`, `create_client` are `pub`; `WsClient`, `WsServer`, `WsClientConfig`, `WsServerConfig`, `LocalProtocol`, `TlsClientConfig` are re-exported. Custom executor via `TokioExecutor` trait lets embedders control task spawning.

### 8.13 QUIC-specific tuning

47. **QUIC 0-RTT** - `--quic-0rtt` on both client and server. Client resumes with a cached ticket; server accepts early data. Off by default.
48. **QUIC keepalive** - `--quic-keep-alive SECS` (QUIC PING at transport level). Supersedes WS application-level pings for QUIC connections.
49. **QUIC idle timeout** - `--quic-max-idle-timeout SECS`. QUIC connections are closed after this many seconds of silence.
50. **QUIC stream budget** - `--quic-max-streams N` (default 1024). Per-connection concurrency cap.
51. **QUIC datagram buffer** - `--quic-datagram-buffer-size BYTES` (default 1 MiB). Capacity of the datagram send/receive buffer.
52. **Disable connection migration** - `--quic-disable-migration`. Escape hatch if middleboxes are confused by CID changes.
53. **Separate QUIC bind** - server uses `--quic-bind 0.0.0.0:PORT` to accept QUIC connections on a dedicated UDP port while the main TCP listener stays on its own port.
