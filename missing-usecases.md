# Missing / not-yet-covered use cases

Observations about gaps in velox's feature set today (v10.5.2). Each entry names what is missing, what the current workaround is, and a rough sketch of where an implementation would live. Items are ordered by apparent user value, not by implementation cost.

---

## Authentication & authorization

### 1. Real JWT signature verification
**Today:** `velox/src/tunnel/transport/jwt.rs` creates a per-process HMAC key and then calls `validation.insecure_disable_signature_validation()` on decode. The JWT is a structured envelope, not an auth token. Anyone who reaches the server can mint any claims they want.
**Workaround:** `--http-upgrade-path-prefix` (shared secret in the URL) or mTLS.
**Gap:** no built-in HMAC-secret or RSA/EC-based client auth. A `--jwt-secret`/`--jwt-public-key` pair on both sides would close the loop.

### 2. Per-client identity beyond mTLS CN
**Today:** if mTLS is configured, the client cert's CN is auto-used as the upgrade path prefix. Anything richer (multiple SANs, custom OIDs, organizational unit-based policy) has no first-class support.
**Gap:** restriction matchers over the full peer-certificate subject / SANs / fingerprint, not just CN.

### 3. Auth backends
**Today:** basic auth via `--http-upgrade-credentials`, regex over `Authorization:` header in restrictions YAML.
**Gap:** OAuth2/OIDC bearer validation, IP-allowlist files, integration with an external auth service (e.g. forward-auth HTTP hook before accepting the upgrade).

### 4. Rate limiting / connection quotas
**Today:** no per-client or per-IP rate limit, no max-connections-per-client, no total-bytes quota. A single client can exhaust the `bb8::Pool::max_size=1000`.
**Gap:** a token-bucket in `tunnel/server/handler_*` keyed on mTLS CN / JWT claim / peer IP.

---

## Observability

### 5. Metrics (Prometheus / OpenTelemetry)
**Today:** only `tracing` logs. No counters for tunnels opened/closed, bytes in/out, reconnects, rejected restrictions, pool hit/miss.
**Gap:** an optional `/metrics` endpoint on the server and a library feature to expose a `MetricsRecorder` trait. Straight addition next to `WsServer::serve`.

### 6. Access logs / audit log
**Today:** `info!` lines for accepted and rejected tunnels. No structured per-tunnel record with bytes transferred, duration, close reason.
**Gap:** a JSON access-log writer (`--access-log path`) emitting one record per tunnel on close.

### 7. Health / readiness endpoint
**Today:** server exposes only the upgrade path. Operators behind a load balancer must TCP-probe.
**Gap:** a lightweight `GET /healthz` response on non-upgrade requests.

---

## Config & operations

### 8. Config file for the CLI
**Today:** `velox` only takes flags and env vars; `restrictions.yaml` is the only config file. Heavy invocations (many `-L`/`-R`, TLS, headers file) become unwieldy shell commands.
**Gap:** `--config velox.yaml` parsing `Client`/`Server` into one file. Most of the plumbing is there because `Client`/`Server` already derive `Debug` + are `Clone` - add `Deserialize`.

### 9. Systemd / graceful shutdown
**Today:** `main.rs` handles `ctrl_c` only in the stdio path. The server's accept loop is `loop {}`-no SIGTERM handler, no drain, no "finish in-flight tunnels then exit".
**Gap:** wire `tokio::signal` into `run_server_impl` + emit a drained signal.

### 10. Reverse-tunnel listener listing / admin API
**Today:** the set of currently-bound reverse listeners and in-flight tunnels is only observable via logs. `ReverseTunnelServer<L>` keeps them in a `LazyLock<…>` singleton.
**Gap:** a local admin socket (unix domain) that dumps the state - useful for scripted cleanup.

### 11. Dynamic tunnel add/remove
**Today:** tunnels are set at start time; the only way to add or remove one is to restart the client.
**Gap:** control-plane socket to `add-tunnel -L …` / `remove-tunnel -L …` at runtime.

---

## Transport and protocol coverage

### 12. QUIC / HTTP/3 transport
**Today:** `TransportScheme` supports `Ws`, `Wss`, `Http`, `Https` only. HTTP/2 is the fallback when WS is blocked, but has the reverse-proxy buffering problem documented in `config.rs`.
**Gap:** a `quic://` or `h3://` transport. Would add `transport/quic.rs` alongside `websocket.rs` / `http2.rs`.

### 13. Raw-TCP obfuscated transport
**Today:** WS and H/2 only.
**Gap:** a `tcp://` transport for when the velox server can be exposed directly and the HTTP framing overhead is pure loss.

### 14. Multiplexing over one TCP connection
**Today:** each tunnel opens its own HTTP upgrade (or reuses a pooled idle WS). There is no per-connection mux - pooling helps throughput but wastes a TCP+TLS handshake every time the pool is cold.
**Gap:** sub-stream multiplexing (yamux/smux) so one transport connection carries many logical tunnels.

### 15. ICMP / raw-IP tunneling
**Today:** only TCP/UDP/Unix/Stdio. No way to tunnel ICMP (ping), GRE, or raw IP packets.
**Gap:** a tun/tap-device listener (Linux/macOS) feeding arbitrary L3 packets across the tunnel. Much larger scope - practically a new product.

### 16. IPv6 happy-eyeballs
**Today:** `DnsResolver::new_from_urls` takes a `prefer_ipv4` flag and resolves one family first. No RFC 8305-style parallel attempts.
**Gap:** `protocols/tcp.rs::connect` could race A/AAAA.

---

## Forward-tunnel features

### 17. Dynamic SOCKS5 over UDP (`UDP ASSOCIATE`)
**Today:** `Socks5TunnelListener` / `fast-socks5` usage supports CONNECT. UDP ASSOCIATE is not advertised.
**Gap:** tools like DNS-over-SOCKS5 or games cannot use reverse/forward SOCKS5 for UDP.

### 18. HTTP proxy - non-CONNECT support
**Today:** the HTTP proxy listener handles CONNECT + absolute-URI GET. Many legacy clients send other methods (POST with absolute URI, keep-alive reuse, CONNECT-Piggyback).
**Gap:** proper HTTP-proxy compliance beyond the common path.

### 19. SOCKS4 / SOCKS4a
**Today:** SOCKS5 only.
**Gap:** some embedded devices only speak SOCKS4a.

### 20. Static DNS-over-tunnel helper
**Today:** `--dns-resolver` configures resolution **locally**, but there is no mode where the client forwards all DNS to the server (SOCKS5 clients with `Proxy DNS` get that for free, but plain `-L tcp://…` flows don't).
**Gap:** `-L dns://LOCAL_PORT` that relays queries to the server's resolver.

---

## Reverse-tunnel features

### 21. Reverse-tunnel authentication tokens
**Today:** whichever client connects first to the server with `-R tcp://:PORT:…` wins the port until it drops. Any other client that knows the upgrade path can also request the same port.
**Gap:** a claim token (`--reverse-tunnel-id`) tying the bound port to a specific client identity, enforced by restrictions.

### 22. Reverse HTTP with vhosts
**Today:** `ReverseHttpProxy` is a reverse HTTP-CONNECT proxy, not an HTTP vhost router. You can't say "requests to `foo.example.com` go to client A, `bar.example.com` to client B".
**Gap:** a new reverse mode that parses the `Host:` header and routes by hostname - would turn velox into an ngrok-style named-host exposer.

### 23. TLS-terminated reverse tunnels
**Today:** reverse tunnels expose raw TCP on the server. If you want TLS on the public side, put a reverse proxy in front.
**Gap:** `-R tls+tcp://…` where the server terminates TLS with its own cert and the plaintext travels through the tunnel.

### 24. UDP reverse tunnels with multiple concurrent senders
**Today:** `UdpTunnelListener` muxes by `(src_ip, src_port)`. Under heavy fan-in this may keep state around past the idle `timeout_sec`.
**Gap:** explicit per-peer eviction strategy / bounded HashMap size; a metric/log line when state overflows.

---

## TLS / crypto

### 25. ECH for the server (publish keys)
**Today:** `--tls-ech-enable` is client-side only (fetch ECH config via DNS). The server cannot **publish** an ECH config or decrypt ECH-encrypted ClientHellos.
**Gap:** server-side ECH requires rustls ECH-server support + a way to load keys.

### 26. OCSP stapling / certificate transparency
**Today:** the server just serves the cert file. No OCSP stapling, no CT pre-certificates.
**Gap:** optional stapling for Let's Encrypt deployments.

### 27. Post-quantum key exchange
**Today:** rustls defaults only. aws-lc-rs does expose Kyber hybrids but velox doesn't opt into the hybrid suites.
**Gap:** an explicit `--tls-kx` knob.

---

## Linux-only features parity

### 28. TPROXY on BSD / macOS
**Today:** `TProxyTcp` / `TProxyUdp` are `#[cfg(target_os = "linux")]` only.
**Gap:** pf divert / ipfw fwd on BSDs, pfctl on macOS.

### 29. SO_MARK equivalents on other OSes
**Today:** `--socket-so-mark` is Linux only.
**Gap:** `SO_INCOMING_NAPI_ID` on some, `SO_USER_COOKIE` on FreeBSD, no-op elsewhere but with a clearer warning.

### 30. Windows service integration
**Today:** Windows build works but there is no service wrapper, no firewall profile, no installer.
**Gap:** documentation + optional MSI build.

---

## Restriction engine

### 31. Deny-list rules
**Today:** restrictions are allow-only. You can express "allow only this" but not "allow everything except `169.254.0.0/16`".
**Gap:** add a `deny:` section alongside `allow:`, evaluated first.

### 32. Time-of-day / rate-based rules
**Today:** match → allow, nothing more.
**Gap:** `match: - !TimeWindow "MON..FRI 09:00-18:00"` or `!RateLimit {…}`.

### 33. Geo-IP restrictions
**Today:** CIDR only.
**Gap:** optional MaxMind GeoIP lookup so rules can say `!Country DE`.

---

## Developer / ecosystem

### 34. Stable public library API
**Today:** `velox` is published as a path dep only (see `velox-cli/Cargo.toml`). `LocalProtocol` is `pub` but many supporting types (`TransportAddr`, `Socks5TunnelListener`, etc.) are `pub` inside private modules - subject to change at any release.
**Gap:** publish `velox` on crates.io with a documented surface.

### 35. Language bindings
**Today:** Rust library only.
**Gap:** a thin C ABI (`velox-sys`) would unlock iOS/Android embedding and browser extensions - mobile is already a target in CI via Android builds.

### 36. `#[tokio::test]`-friendly test harness
**Today:** integration tests bind fixed `127.0.0.1:9998/9999` and are `#[serial]`. Running a subset or parallelizing requires careful test selection.
**Gap:** port-0 binding in the fixtures; emit the chosen port to the test. Would let nextest run them in parallel.

### 37. Benchmarks under CI
**Today:** a screenshot in the README shows benchmark numbers but there is no `benches/` crate, no reproducible harness.
**Gap:** a criterion-based bench comparing ws vs h/2, pool hot vs cold, TLS vs plain.

---

## Documentation / UX

### 38. Diagnostic "doctor" subcommand
**Today:** troubleshooting a broken setup means reading tracing logs and knowing the JWT+path-prefix+restriction flow.
**Gap:** `velox doctor --server wss://…` that does a dry-run connect and prints why it would be rejected.

### 39. Restriction-file validator
**Today:** parse errors surface at first connection or at startup, but there is no `velox validate-config restrictions.yaml`.
**Gap:** a subcommand that parses and prints the effective ruleset.

### 40. Machine-readable CLI help
**Today:** clap help is prose with URL examples. There is no JSON schema for the `-L`/`-R` URI format.
**Gap:** a `--emit-schema` flag producing a JSON schema - useful for GUI frontends.
