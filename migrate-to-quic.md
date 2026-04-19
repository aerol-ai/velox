# Migrating wstunnel to QUIC

Plan for adding QUIC as a first-class transport alongside WebSocket and HTTP/2, plus the use cases that open up once QUIC is in the picture.

---

## 1. Why QUIC at all

wstunnel today carries tunnel bytes over `ws://`, `wss://`, `http://`, or `https://` (see `wstunnel/src/tunnel/transport/{websocket,http2}.rs`). Those transports share three structural limits:

- **TCP head-of-line blocking** — one lost packet on the underlying TCP stream stalls every tunnel sharing that connection, so wstunnel avoids multiplexing and keeps a `bb8::Pool<WsConnection>` of parallel TCP sockets (`wstunnel/src/tunnel/client/cnx_pool.rs`) instead.
- **No connection migration** — a phone switching from Wi-Fi to LTE tears down every active tunnel; the client has to reconnect each pooled socket and re-do TCP + TLS handshakes.
- **Sequential handshakes** — every new transport connection pays one TCP RTT plus one full TLS handshake. The pool pre-warms this, but cold starts still cost 2–3 RTTs.

QUIC (RFC 9000–9002) addresses all three at once: UDP-native, built-in TLS 1.3, multi-stream without HoL, 0-RTT resumption, and CID-based connection migration. HTTP/3 is just "HTTP over QUIC"; we can either use HTTP/3 (to look like normal web traffic) or raw QUIC streams (for the tightest wire format).

---

## 2. Goals and non-goals

### Goals
- A new transport scheme `quic://` / `quics://` (cleartext QUIC is not really a thing since QUIC mandates TLS — `quic://` stays as an alias for `quics://` and keeps the URL structure symmetric).
- Parity with the existing WS/H2 transports for every `LocalProtocol`, forward and reverse.
- Single long-lived QUIC connection per client carrying many tunnels over independent streams, replacing the `bb8::Pool<WsConnection>` for this transport.
- Connection migration preserved across NAT rebind / network switch.
- 0-RTT resumption for reconnects.
- QUIC DATAGRAM frames (RFC 9221) used as the wire for UDP tunnels to avoid reliable-stream overhead.
- Coexistence: a single server process can accept WS, H2, **and** QUIC simultaneously on the same host, chosen by the client URL.

### Non-goals (initial release)
- Replacing WS / H2. Those stay because they remain the compatibility path through HTTP-only firewalls and reverse proxies.
- HTTP/3 server/client with full `:method CONNECT` semantics. We'll ride raw QUIC bi-streams first; HTTP/3 framing can be layered on later if a use case demands it (see §9).
- MASQUE (CONNECT-UDP / CONNECT-IP). Valuable long-term but out of scope here.

---

## 3. Library choice

Three mature Rust QUIC stacks:

| Library        | Pros                                                           | Cons                                                              |
|----------------|----------------------------------------------------------------|-------------------------------------------------------------------|
| **`quinn`**    | Built on rustls (matches our existing crypto layer), pure Rust, large ecosystem, supports datagrams + 0-RTT + migration. | Single-threaded per-connection tasks; some tuning needed for high fan-in. |
| `quiche`       | C library with Rust bindings; used by Cloudflare.              | Adds a C build dep, doesn't use our rustls config, awkward async. |
| `s2n-quic`     | AWS-backed, async-first, integrates cleanly with tokio.        | Uses s2n-tls (adds a second TLS stack alongside rustls).          |

**Pick `quinn`.** It reuses the rustls `ClientConfig` / `ServerConfig` we already build in `protocols/tls.rs`, it already has `aws-lc-rs` and `ring` feature parity with the rest of the tree, and it supports everything in §2 goals out of the box.

Dependencies to add to `wstunnel/Cargo.toml`:

```toml
quinn = { version = "0.11", default-features = false, features = ["runtime-tokio", "rustls"] }
quinn-proto = "0.11"           # for DATAGRAM + 0-RTT config
```

---

## 4. Wire protocol

We keep the existing JWT envelope + `LocalProtocol` enum. What changes is the framing underneath.

### 4.1 Control stream
- On connect, the client opens **bi-stream 0** as the control stream.
- Sends a fixed header: `"WSTUNNEL/1 QUIC\n"` + length-prefixed JSON block containing the client's preferred options (same things that today ride in HTTP headers: upgrade path prefix, custom headers, basic auth).
- Server replies with `OK` or an error code — mirroring today's HTTP status behavior so restrictions can reject early.

### 4.2 Per-tunnel streams
For each tunnel request, client opens a new **bi-directional stream**:

```
uvarint(stream_kind=1)           // 1 = reliable tunnel, 2 = datagram-bound tunnel
uvarint(len)
bytes(len) = JWT(JwtTunnelConfig)   // existing envelope, see transport/jwt.rs
<then raw tunneled bytes flow>
```

The server parses the JWT, runs the current `validate_tunnel` path, and if accepted begins splicing bytes to the connector.

### 4.3 UDP tunnels over DATAGRAM
For `LocalProtocol::Udp { .. }` (and reverse), we bind each UDP flow to a 32-bit `flow_id` sent once on the control stream, then use QUIC DATAGRAMs:

```
datagram = uvarint(flow_id) || udp_payload
```

This avoids the per-packet reliable-stream framing that today's WS/H2 transport imposes on UDP — a major latency win for DNS, WireGuard, QUIC-over-QUIC (gaming).

### 4.4 Reverse tunnels
Same as today: the server opens a *new* bi-stream **to the client** (QUIC is symmetric) when it accepts a connection on the reverse-listener port. The control stream carries the reverse-tunnel registration; each inbound connection is one server-initiated stream.

---

## 5. Module layout

New files:

```
wstunnel/src/tunnel/transport/
    quic.rs          # Connect / accept + stream framing
    quic_datagram.rs # DATAGRAM flow multiplexer for UDP tunnels
```

Modified files:

```
wstunnel/src/tunnel/transport/types.rs    # Add TransportScheme::Quic
wstunnel/src/tunnel/transport/mod.rs      # Export quic::connect / accept
wstunnel/src/tunnel/client/client.rs      # Branch in connect_to_server on Quic scheme
wstunnel/src/tunnel/client/cnx_pool.rs    # Bypass pool for QUIC (single connection)
wstunnel/src/tunnel/server/server.rs      # Second accept task for QUIC endpoint
wstunnel/src/tunnel/server/handler_quic.rs  # New handler analogous to handler_websocket
wstunnel/src/config.rs                    # Parser for quic://, CLI flags
wstunnel/src/protocols/tls.rs             # Build quinn rustls config from existing tls_connector
```

### 5.1 Config surface

New CLI flags (all on both `Client` and `Server`):

- `--quic-max-streams N` (default 1024) — per-connection stream budget.
- `--quic-keep-alive SECS` (default 15) — QUIC-level PING.
- `--quic-initial-mtu BYTES` (default 1200) — PMTU floor.
- `--quic-0rtt` — enable 0-RTT on the client; the server always advertises.
- `--quic-congestion {cubic,bbr,newreno}` (default `bbr`).
- `--quic-disable-migration` — escape hatch if migration causes middlebox issues.

Server also gets `--quic-max-idle-timeout SECS` and `--quic-max-datagram-frame-size BYTES`.

### 5.2 Scheme recognition

`TransportScheme` becomes:

```rust
pub enum TransportScheme { Ws, Wss, Http, Https, Quic }
```

Parser in `config.rs` accepts both `quic://host:port` and `quics://host:port` as the same thing (QUIC is always encrypted).

---

## 6. Implementation phases

### Phase 0 — groundwork (½ week)
- Add `quinn` dep behind a `quic` cargo feature. Default off initially; enable in release after phase 4.
- Extend `TransportScheme` and URL parser. All existing code paths reject `Quic` with a clear error until phase 1 wires it up.
- Add a minimal `protocols/quic.rs` helper that takes a `tls::ClientConfig` / `ServerConfig` and produces `quinn::ClientConfig` / `ServerConfig`. Reuses `aws-lc-rs` or `ring` based on workspace features.

### Phase 1 — forward TCP over QUIC (1 week)
- Implement `transport/quic.rs::connect` and `accept` using one bi-stream per tunnel.
- Wire `WsClient::connect_to_server` and `handler_quic::quic_server_serve` together.
- Integration test alongside `test_tcp_tunnel` in `test_integrations.rs`.
- Ship behind `--features quic` in the CLI.

### Phase 2 — UDP datagrams (½ week)
- Implement `transport/quic_datagram.rs`: flow-id multiplexer + `TunnelWrite`/`TunnelRead` impls that target `Connection::send_datagram` / `read_datagram`.
- Add `stream_kind=2` negotiation on the control stream for UDP tunnels.
- Extend `test_udp_tunnel` with a QUIC variant.

### Phase 3 — reverse tunnels (1 week)
- Server-initiated streams: when the `ReverseTunnelServer` gets a local connection, it calls `connection.open_bi()` on the relevant client's QUIC connection and writes a reverse-tunnel header.
- Match today's `jwt_token_to_tunnel` cookie-in-response mechanism for dynamic reverse tunnels.

### Phase 4 — 0-RTT, migration, keepalive polish (½ week)
- Enable `TransportConfig::max_idle_timeout`, `keep_alive_interval`.
- Build a resumption token store (in-memory) on the client so reconnects use 0-RTT.
- Verify migration with a test that binds client to one local port, mid-tunnel triggers a local UDP socket rebind, and checks bytes continue to flow.
- Add metrics hooks (see phase 6).

### Phase 5 — server coexistence (½ week)
- `WsServer::serve` currently owns one `TcpListener`. Add a sibling `QuicListener` spawned only when `--quic-listen` is set (or when the bind URL scheme is `quic://`).
- Same `RestrictionsRules` code path; unify the JWT → `exec_tunnel` flow so WS/H2/QUIC all end up in the same server side handler.

### Phase 6 — observability + docs (½ week)
- Tracing spans for `quic{cid=…, peer=…}`, per-stream spans matching today's `tunnel{id,remote}`.
- README update, CHANGELOG entry, `docs/using_quic.md` mirroring `using_mtls.md`.
- Benchmark the pool hot/cold + lossy-link case against WS and H/2.

### Phase 7 — hardening (ongoing)
- Fuzz the wire framing (length-prefix + varint parsing).
- Load test with 10k concurrent tunnels on one connection.
- Eval `HTTP/3` compatibility mode — see §9.

Total: ~4 weeks of focused work to "good enough to ship opt-in", another ~2 weeks before flipping the feature on by default.

---

## 7. Backward compatibility

- WS and H/2 transports remain unchanged. No user is forced to migrate.
- `LocalProtocol`, `JwtTunnelConfig`, and `RestrictionsRules` are reused verbatim — so `restrictions.yaml` works for QUIC tunnels with zero changes.
- The CLI keeps the same `-L`/`-R` grammar; only the server URL scheme distinguishes the transport.
- Servers can accept WS, H/2, and QUIC all at once. Operators pick the mix they want.

---

## 8. Testing

- New fixture `server_quic` alongside `server_no_tls` in `test_integrations.rs`.
- Matrix test that runs `test_tcp_tunnel` / `test_udp_tunnel` / reverse variants against each of { WS, WSS, H2, Quic }.
- A loss/delay test: `tc netem loss 5% delay 50ms` on loopback, measure throughput. Existing WS baseline must not regress; QUIC must win.
- A migration test: socket rebind mid-transfer (cleaner than trying to simulate mobile handover in CI).
- A 0-RTT test: first connect caches a ticket, second connect asserts on `ZeroRttAccepted`.

---

## 9. Open questions / follow-ups

- **HTTP/3 compatibility mode.** Some environments only allow "HTTPS-looking" traffic. Wrapping wstunnel's streams in HTTP/3 `CONNECT` would let it live behind an ALB / Cloudflare that speaks H/3. Defer until there's a concrete ask.
- **MASQUE (CONNECT-UDP, CONNECT-IP).** Would replace `LocalProtocol::Udp` framing with a standardized one — useful if a MASQUE-speaking proxy sits in front.
- **Unreliable-reverse-tunnel fairness.** DATAGRAM frames share one congestion controller; a chatty UDP tunnel can starve others. Consider per-flow pacing.
- **Key rotation.** QUIC supports key updates every N packets; quinn handles this automatically, but we should document the behavior.

---

## 10. Use cases unlocked by QUIC migration

Concrete scenarios that either become possible or get materially better once the QUIC transport lands. Ordered by practical impact.

1. **Mobile / roaming clients keep tunnels alive across Wi-Fi ↔ LTE switches** — QUIC's connection ID survives NAT rebinding and IP changes, so SSH, WireGuard, and SOCKS5 sessions don't drop when the phone leaves the house.

2. **Instant reconnect after suspend / resume** — 0-RTT resumption means laptops coming out of sleep re-establish all tunnels in a single round-trip instead of re-handshaking TLS.

3. **Thousands of tunnels over one connection** — stream multiplexing replaces the current `bb8` pool (max 1000 TCP sockets) with a single QUIC connection carrying arbitrarily many streams. Big win for SOCKS5 browsing where a page loads dozens of connections.

4. **No TCP head-of-line blocking between tunnels** — a lost packet on one tunnel no longer stalls every other tunnel sharing the same transport, the way they do on WS today.

5. **Low-latency UDP tunneling** — DATAGRAM frames carry WireGuard / DNS / QUIC-over-QUIC packets without the reliable-stream queue. Today's `udp://` tunnel framing adds buffering latency that DATAGRAM removes entirely.

6. **Better throughput on lossy / high-latency links** — BBR congestion control + QUIC's packet-level retransmit recover from loss faster than TCP; users on satellite, cellular, or transoceanic paths see measurable improvement.

7. **Faster cold-start for one-shot tunnels** — `stdio://` + SSH ProxyCommand usage becomes ~1 RTT cheaper because TCP handshake goes away, replaced by QUIC's combined crypto/transport handshake.

8. **Tunnels through UDP-only networks** — some ISPs / mobile carriers rate-limit or block long-lived TCP connections but leave UDP alone. QUIC slides through.

9. **Resilience to middlebox connection-killing** — corporate firewalls that kill idle TCP after 5 minutes don't reset UDP flows the same way; QUIC's per-path keepalive is also lighter than TCP keepalives.

10. **Client-side NAT rebinding tolerated** — today's reverse tunnels break when the client's NAT picks a new external port; QUIC's path validation keeps the connection valid on the new 4-tuple.

11. **Graceful degradation on packet reordering** — mobile networks that reorder packets aggressively cause TCP throughput collapse; QUIC handles reorders in its own framing without retransmit storms.

12. **Per-tunnel flow control** — QUIC stream flow control means a slow receiver on tunnel A doesn't backpressure tunnel B. Today a stuck WS connection stalls everything on it.

13. **Symmetric server ↔ client streams for reverse tunnels** — QUIC makes server-initiated streams a first-class concept, removing the cookie-JWT dance currently needed to bootstrap dynamic reverse tunnels.

14. **Built-in encryption without a separate TLS layer** — eliminates the "do I use `ws://` or `wss://`" question; QUIC is always encrypted. Simplifies deployment docs and removes the fingerprintable-embedded-cert footgun for plaintext mode.

15. **Reduced tail latency on bursty workloads** — stream-level congestion isolation keeps a big file transfer on one stream from blowing out interactive SSH latency on another.

16. **Server preferred-address failover** — QUIC lets the server advertise a backup address mid-connection; clients migrate to it transparently. Useful for blue/green deploys of a wstunnel server without dropping tunnels.

17. **Reconnection without re-auth** — resumption tickets carry the mTLS / JWT context, so post-suspend reconnects skip cert validation and restriction-matching work on the server hot path.

18. **Gaming / voice-over-SOCKS5 viability** — today's SOCKS5 over WS adds 40–80 ms of queueing on a congested link; QUIC DATAGRAM brings this down to underlying network latency.

19. **Cheap periodic wakeups** — IoT devices that tunnel telemetry every N minutes avoid paying a full TCP + TLS handshake per wakeup thanks to 0-RTT; battery win.

20. **Firewall bypass without HTTP cosplay** — environments that flag HTTP/1.1 WebSocket upgrade patterns or HTTP/2 request smuggling can be traversed with QUIC, which looks like ordinary HTTPS UDP traffic (or plain QUIC on port 443). Pairs naturally with the existing `--tls-sni-override` stealth knobs.
