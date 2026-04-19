# Kubernetes / Helm Setup

Deploy a **velox** tunnel server on Kubernetes using the official Helm chart.
The chart supports **two transport protocols**:

| Transport | Kubernetes exposure | TLS |
|-----------|---------------------|-----|
| **WebSocket / HTTP2** | Ingress (TCP 443) | cert-manager / ingress controller |
| **QUIC** | Dedicated LoadBalancer / NodePort (UDP) | velox handles TLS directly |

> QUIC is UDP-based. Ingress controllers cannot proxy UDP, so the QUIC port is
> exposed via a separate Kubernetes Service of type `LoadBalancer` or `NodePort`.
> Both transports can run simultaneously.

## Prerequisites

| Tool | Minimum version |
|---|---|
| Kubernetes cluster | 1.25+ |
| Helm | 3.12+ |
| kubectl (configured) | — |
| Ingress controller | nginx-ingress recommended |
| cert-manager (optional) | 1.13+ for automatic TLS |

---

## 1. Add / pull the Helm chart

### From GHCR (OCI registry)

```bash
helm pull oci://ghcr.io/aerol-ai/charts/velox --version 0.1.0
```

### From source

```bash
git clone https://github.com/aerol-ai/velox.git
cd velox/helm
```

---

## 2. Minimal install (no TLS, for testing)

```bash
helm upgrade --install velox oci://ghcr.io/aerol-ai/charts/velox \
  --namespace velox --create-namespace
```

Forward the port to test locally:

```bash
kubectl port-forward -n velox svc/velox 8080:8080
velox client -L socks5://127.0.0.1:1080 ws://127.0.0.1:8080
```

---

## 3. Production install with ingress + TLS (WebSocket) + QUIC

Create a `my-values.yaml`:

```yaml
# WebSocket / HTTP2 via ingress + cert-manager
ingress:
  enabled: true
  className: nginx
  annotations:
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-connect-timeout: "60"
  hosts:
    - host: tunnel.example.com
      paths:
        - path: /
          pathType: Prefix
  tls:
    - secretName: velox-tls
      hosts:
        - tunnel.example.com

# QUIC transport — separate UDP LoadBalancer service
velox:
  logLevel: INFO
  quic:
    enabled: true
    port: 8443
    serviceType: LoadBalancer   # or NodePort for on-prem
    # Optional tuning:
    # keepAlive: "15s"
    # maxIdleTimeout: "60s"
    # maxStreams: 1024

resources:
  requests:
    cpu: 50m
    memory: 64Mi
  limits:
    memory: 256Mi
```

Install:

```bash
helm upgrade --install velox oci://ghcr.io/aerol-ai/charts/velox \
  --namespace velox --create-namespace \
  --values my-values.yaml
```

Get the QUIC external IP (LoadBalancer):

```bash
kubectl get svc -n velox velox-quic --watch
# Once EXTERNAL-IP is assigned:
export QUIC_IP=$(kubectl get svc -n velox velox-quic \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')
```

---

## 4. Connect from a client

### WebSocket (via ingress)

```bash
velox client -L socks5://127.0.0.1:1080 --connection-min-idle 5 \
  wss://tunnel.example.com
```

### QUIC (direct UDP to LoadBalancer IP)

Requires the velox binary to be built with `--features quic` (the Docker image includes this).

```bash
# Substitute the QUIC external IP/hostname from the LoadBalancer service
export QUIC_IP=$(kubectl get svc -n velox velox-quic \
  -o jsonpath='{.status.loadBalancer.ingress[0].ip}')

# SOCKS5 proxy via QUIC
velox client -L socks5://127.0.0.1:1080 quic://${QUIC_IP}:8443

# Forward a TCP port via QUIC
velox client -L tcp://5432:db.internal:5432 quic://${QUIC_IP}:8443

# WireGuard via QUIC DATAGRAM frames (zero idle timeout)
velox client -L 'udp://51820:localhost:51820?timeout_sec=0' quic://${QUIC_IP}:8443
```

> **QUIC tip:** QUIC multiplexes all tunnels over a single UDP connection with no
> head-of-line blocking. UDP tunnels use native QUIC DATAGRAM frames for the
> lowest possible latency — ideal for WireGuard, DNS, and VoIP workloads.

### Forward a TCP port (WebSocket)

```bash
velox client -L tcp://2222:db.internal:5432 wss://tunnel.example.com
psql -h 127.0.0.1 -p 2222 -U postgres mydb
```

### SSH ProxyCommand

```bash
ssh -o ProxyCommand="velox client --log-lvl=off \
  -L stdio://%h:%p wss://tunnel.example.com" user@my-server
```

---

## 5. Using a restrictions config

Enable a restrictions ConfigMap in `my-values.yaml`:

```yaml
velox:
  restrictConfig:
    enabled: true
    content: |
      tunnels:
        - allow:
            - protocol: "^tcp$"
              port:
                - start: 22
                  end: 22
              host: ".*\\.internal$"
```

See the root `restrictions.yaml` for full schema documentation.

---

## 6. QUIC-only deployment (no ingress)

If you only need QUIC (e.g. WireGuard gateway):

```yaml
velox:
  quic:
    enabled: true
    port: 8443
    serviceType: LoadBalancer

# No ingress needed
ingress:
  enabled: false

# velox still needs TLS certs for QUIC.
# The embedded self-signed cert works for testing.
# For production, mount real certs via VELOX_EXTRA_ARGS:
velox:
  extraArgs:
    - "--tls-certificate"
    - "/certs/tls.crt"
    - "--tls-private-key"
    - "/certs/tls.key"
```

---

## 7. Enable the path-prefix secret

Protect your server so only clients that know the prefix can connect:

```yaml
velox:
  httpUpgradePathPrefix: "my-secret-path"
```

Clients must pass:

```bash
velox client -P my-secret-path -L socks5://127.0.0.1:1080 wss://tunnel.example.com
```

---

## 8. Autoscaling

```yaml
autoscaling:
  enabled: true
  minReplicas: 1
  maxReplicas: 5
  targetCPUUtilizationPercentage: 70
```

---

## 9. Upgrading

```bash
helm upgrade velox oci://ghcr.io/aerol-ai/charts/velox \
  --namespace velox --values my-values.yaml
```

## 10. Uninstalling

```bash
helm uninstall velox --namespace velox
kubectl delete namespace velox
```

---

## Architecture overview

```
Client (velox CLI)
      │
      ├── WSS (TCP 443) ──► Ingress (cert-manager TLS) ─► velox-svc:8080 (ClusterIP)
      │                                                        │
      └── QUIC (UDP 8443) ─► velox-quic svc (LoadBalancer/NP) ─┘
                                                               │
                                                        velox Pod
                                                               │
                                                        Destination
```

The ingress terminates TLS and forwards plain WebSocket traffic to the velox
Service on the internal cluster network. QUIC bypasses the ingress entirely via
a dedicated UDP service.

---

## 10. Troubleshooting

| Symptom | Fix |
|---|---|
| Pod in `CrashLoopBackOff` | `kubectl logs -n velox deploy/velox` |
| `502 Bad Gateway` from ingress | Check readiness probe; increase probe `initialDelaySeconds` |
| TLS cert not issued | Verify cert-manager is running and ClusterIssuer is ready |
| WebSocket connection drops | Add nginx timeout annotations (see step 3) |
| Clients connect but tunnels fail | Check `velox.restrictTo` or `velox.restrictConfig` |
| QUIC external IP pending | Cloud LB quota; try `serviceType: NodePort` instead |
| QUIC connection refused | Check node firewall / security group for UDP 8443 |
| QUIC: `feature not compiled in` | Docker image must be built with `--features quic` (official image includes it) |
