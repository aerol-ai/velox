# Docker Compose + Caddy Setup

Deploy a **velox** tunnel server on any Linux VM in under 5 minutes. Caddy handles
automatic TLS certificate issuance (Let's Encrypt / ZeroSSL) so you don't need to
manage certificates manually.

This stack supports **two independent transport protocols**:

| Transport | Port | TLS | Notes |
|-----------|------|-----|-------|
| **WebSocket / HTTP2** | TCP 443 | Caddy (auto-TLS) | Works through most proxies and CDNs |
| **QUIC** | UDP 8443 | velox (auto-TLS) | Lowest latency, native UDP tunnels, no proxy |

> QUIC is a separate UDP listener - Caddy cannot proxy UDP. The QUIC port is exposed
> **directly** from the velox container. Both transports can run simultaneously.

## Prerequisites

| Tool | Minimum version |
|---|---|
| Docker Engine | 24+ |
| Docker Compose plugin | v2 |
| A public domain/subdomain pointing at your server | - |

> **Local development** works too - set `VELOX_DOMAIN=localhost` and Caddy will
> issue a locally-trusted certificate via its built-in CA (no domain required).

---

## 1. Clone & configure

```bash
git clone https://github.com/aerol-ai/velox.git
cd velox

# Create your environment file from the template
cp .env.example .env
```

Edit `.env`:

```
VELOX_DOMAIN=tunnel.example.com   # your domain
RUST_LOG=INFO                     # log verbosity
QUIC_PORT=8443                    # UDP port for QUIC (leave as-is or change)
QUIC_BIND=[::]:8443               # bind address passed to velox --quic-bind
VELOX_EXTRA_ARGS=                 # optional extra velox server flags (see below)
```

Make sure ports **80**, **443** (TCP), and **8443** (UDP) are open in your firewall:

```bash
# Example with ufw
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 8443/udp   # QUIC
```

---

## 2. Start the stack

```bash
docker compose up -d
```

Caddy will obtain a TLS certificate automatically on first start. Check logs:

```bash
docker compose logs -f caddy   # watch for "certificate obtained successfully"
docker compose logs -f velox   # watch for velox INFO startup lines
```

---

## 3. Connect from a client

Replace `tunnel.example.com` with your `VELOX_DOMAIN`.

### WebSocket (works everywhere, through proxies and CDNs)

```bash
# SOCKS5 proxy
velox client -L socks5://127.0.0.1:1080 --connection-min-idle 5 \
  wss://tunnel.example.com

# Forward a specific TCP port
velox client -L tcp://2222:internal-host:22 wss://tunnel.example.com

# SSH ProxyCommand
ssh -o ProxyCommand="velox client --log-lvl=off \
  -L stdio://%h:%p wss://tunnel.example.com" my-server
```

### QUIC (lowest latency, native UDP tunnels)

Requires the velox binary to be built with `--features quic` (the Docker image includes this).
QUIC uses the UDP port directly - no Caddy in the path.

```bash
# SOCKS5 proxy via QUIC
velox client -L socks5://127.0.0.1:1080 quic://tunnel.example.com:8443

# Forward a TCP port via QUIC
velox client -L tcp://5432:db.internal:5432 quic://tunnel.example.com:8443

# WireGuard via QUIC DATAGRAM frames (zero idle timeout)
velox client -L 'udp://51820:localhost:51820?timeout_sec=0' quic://tunnel.example.com:8443
```

> **QUIC tip:** QUIC multiplexes all tunnels over a single UDP connection. You get
> lower latency and no head-of-line blocking compared to WebSocket.

### DNS-over-Velox / WireGuard via WebSocket

```bash
# Forward WireGuard UDP (disable idle timeout with timeout_sec=0)
velox client -L 'udp://51820:localhost:51820?timeout_sec=0' \
  wss://tunnel.example.com
```

---

## 4. Restrict which destinations are allowed (optional)

### Via environment variable

```
VELOX_EXTRA_ARGS=--restrict-to google.com:443 --restrict-to localhost:22
```

### Via restrictions.yaml

Uncomment the volume mount in `docker-compose.yml`:

```yaml
volumes:
  - ./restrictions.yaml:/home/app/restrictions.yaml:ro
```

Then set:

```
VELOX_EXTRA_ARGS=--restrict-config /home/app/restrictions.yaml
```

See the root `restrictions.yaml` for the full schema with examples.

---

## 5. Updating

```bash
docker compose pull        # pull latest images
docker compose up -d       # recreate containers
docker compose image prune # clean up old layers
```

---

## 6. Troubleshooting

| Symptom | Fix |
|---|---|
| Caddy stays in a retry loop | Check that port 80/443 are open and DNS points to this server |
| `Connection refused` on port 8080 | velox is not healthy yet; run `docker compose ps` |
| Client connects but tunnels fail | Enable restrictions and check velox logs |
| `VELOX_DOMAIN must be set` error | Copy `.env.example` to `.env` and set the variable |
| QUIC connection times out | Check UDP port 8443 is open (`ufw allow 8443/udp`) |
| QUIC: `feature not compiled in` | The binary lacks `--features quic`; use the official Docker image |

---

## Architecture overview

```
Client (velox CLI)
      │
      ├── WSS (port 443, TCP) ────► Caddy (auto-TLS) ─► velox:8080 (ws://)
      │
      └── QUIC (port 8443, UDP) ──► velox:8443/udp (TLS by velox)
                                     │
                                     ▼
                                Destination host:port
```

Caddy terminates TLS for WebSocket; velox handles TLS directly for QUIC.
Nothing TCP is exposed to the public internet except via Caddy.
