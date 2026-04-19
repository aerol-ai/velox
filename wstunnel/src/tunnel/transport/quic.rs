//! QUIC transport for wstunnel.
//!
//! Wire format on each bi-directional stream:
//!
//! Client → Server (first bytes after `open_bi`):
//! ```text
//! [preamble: b"WSTUNNEL/1\n" (11 bytes)]
//! [u16 BE path_prefix_len][path_prefix: utf-8]
//! [u16 BE jwt_len][jwt: utf-8]
//! [u16 BE auth_len][authorization: utf-8]      // empty = no Authorization header
//! [u8 num_headers]
//! { [u16 BE name_len][name][u16 BE val_len][value] } x num_headers
//! <then raw tunneled bytes>
//! ```
//!
//! Server → Client (first bytes once the request is validated):
//! ```text
//! [preamble: b"WSTUNNEL/1\n" (11 bytes)]
//! [u8 status]                                  // 0 = OK, non-zero = error
//! [u16 BE reason_len][reason: utf-8]
//! [u16 BE cookie_len][cookie: utf-8]           // JWT cookie for dynamic reverse tunnels
//! <then raw tunneled bytes>
//! ```

use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use anyhow::{Context, anyhow};
use bytes::BytesMut;
use hyper::header::{COOKIE, HeaderValue};
use hyper::http::response::Parts;
use hyper::{Response, StatusCode, Version};
use quinn::{RecvStream, SendStream};
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Notify;
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::{debug, info};
use uuid::Uuid;

const PREAMBLE: &[u8; 11] = b"WSTUNNEL/1\n";
const MAX_PATH_PREFIX_LEN: usize = 4096;
const MAX_JWT_LEN: usize = 16 * 1024;
const MAX_AUTH_LEN: usize = 8 * 1024;
const MAX_REASON_LEN: usize = 4096;
const MAX_HEADER_NAME_LEN: usize = 1024;
const MAX_HEADER_VALUE_LEN: usize = 8 * 1024;
const MAX_HEADERS: u8 = 64;

pub const STATUS_OK: u8 = 0;
pub const STATUS_BAD_REQUEST: u8 = 1;
pub const STATUS_FORBIDDEN: u8 = 2;
pub const STATUS_INTERNAL_ERROR: u8 = 3;

const QUIC_KEEP_ALIVE: Duration = Duration::from_secs(15);
const QUIC_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const QUIC_MAX_BIDI_STREAMS: u32 = 1024;
pub const QUIC_ALPN: &[u8] = b"wstunnel";

// ============================================================================
// Wire format
// ============================================================================

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicRequestHeader {
    pub path_prefix: String,
    pub jwt: String,
    pub authorization: Option<String>,
    pub headers: Vec<(String, String)>,
}

impl QuicRequestHeader {
    pub async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(PREAMBLE).await?;
        write_u16_prefixed(w, self.path_prefix.as_bytes()).await?;
        write_u16_prefixed(w, self.jwt.as_bytes()).await?;
        write_u16_prefixed(w, self.authorization.as_deref().unwrap_or("").as_bytes()).await?;
        let n = self.headers.len().min(MAX_HEADERS as usize) as u8;
        w.write_u8(n).await?;
        for (name, val) in self.headers.iter().take(n as usize) {
            write_u16_prefixed(w, name.as_bytes()).await?;
            write_u16_prefixed(w, val.as_bytes()).await?;
        }
        Ok(())
    }

    pub async fn read<R: AsyncReadExt + Unpin>(r: &mut R) -> anyhow::Result<Self> {
        let mut preamble = [0u8; PREAMBLE.len()];
        r.read_exact(&mut preamble).await.context("reading QUIC preamble")?;
        if &preamble != PREAMBLE {
            return Err(anyhow!("invalid QUIC preamble: got {preamble:?}"));
        }
        let path_prefix = read_u16_prefixed_string(r, MAX_PATH_PREFIX_LEN, "path_prefix").await?;
        let jwt = read_u16_prefixed_string(r, MAX_JWT_LEN, "jwt").await?;
        let auth = read_u16_prefixed_string(r, MAX_AUTH_LEN, "authorization").await?;
        let authorization = if auth.is_empty() { None } else { Some(auth) };

        let num_headers = r.read_u8().await.context("reading num_headers")?;
        if num_headers > MAX_HEADERS {
            return Err(anyhow!("too many headers: {num_headers}"));
        }
        let mut headers = Vec::with_capacity(num_headers as usize);
        for _ in 0..num_headers {
            let name = read_u16_prefixed_string(r, MAX_HEADER_NAME_LEN, "header name").await?;
            let value = read_u16_prefixed_string(r, MAX_HEADER_VALUE_LEN, "header value").await?;
            headers.push((name, value));
        }
        Ok(Self {
            path_prefix,
            jwt,
            authorization,
            headers,
        })
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicResponseHeader {
    pub status: u8,
    pub reason: String,
    pub cookie: String,
}

impl QuicResponseHeader {
    pub fn ok(cookie: String) -> Self {
        Self {
            status: STATUS_OK,
            reason: String::new(),
            cookie,
        }
    }

    pub fn err(status: u8, reason: impl Into<String>) -> Self {
        Self {
            status,
            reason: reason.into(),
            cookie: String::new(),
        }
    }

    pub async fn write<W: AsyncWrite + Unpin>(&self, w: &mut W) -> io::Result<()> {
        w.write_all(PREAMBLE).await?;
        w.write_u8(self.status).await?;
        write_u16_prefixed(w, self.reason.as_bytes()).await?;
        write_u16_prefixed(w, self.cookie.as_bytes()).await?;
        Ok(())
    }

    pub async fn read<R: AsyncReadExt + Unpin>(r: &mut R) -> anyhow::Result<Self> {
        let mut preamble = [0u8; PREAMBLE.len()];
        r.read_exact(&mut preamble)
            .await
            .context("reading QUIC response preamble")?;
        if &preamble != PREAMBLE {
            return Err(anyhow!("invalid QUIC response preamble: got {preamble:?}"));
        }
        let status = r.read_u8().await.context("reading status")?;
        let reason = read_u16_prefixed_string(r, MAX_REASON_LEN, "reason").await?;
        let cookie = read_u16_prefixed_string(r, MAX_JWT_LEN, "cookie").await?;
        Ok(Self { status, reason, cookie })
    }
}

async fn write_u16_prefixed<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> io::Result<()> {
    let len = u16::try_from(data.len())
        .map_err(|_| io::Error::new(ErrorKind::InvalidInput, "field too large for u16 length prefix"))?;
    w.write_all(&len.to_be_bytes()).await?;
    w.write_all(data).await?;
    Ok(())
}

async fn read_u16_prefixed_string<R: AsyncReadExt + Unpin>(
    r: &mut R,
    max: usize,
    what: &'static str,
) -> anyhow::Result<String> {
    let len = r.read_u16().await.with_context(|| format!("reading {what} length"))? as usize;
    if len > max {
        return Err(anyhow!("{what} too large: {len} > {max}"));
    }
    let mut buf = vec![0u8; len];
    if len > 0 {
        r.read_exact(&mut buf)
            .await
            .with_context(|| format!("reading {what} bytes"))?;
    }
    String::from_utf8(buf).map_err(|e| anyhow!("invalid utf-8 in {what}: {e}"))
}

// ============================================================================
// TunnelRead / TunnelWrite implementations
// ============================================================================

pub struct QuicTunnelWrite {
    inner: SendStream,
    buf: BytesMut,
    notify: Arc<Notify>,
}

impl QuicTunnelWrite {
    pub fn new(send: SendStream) -> Self {
        Self {
            inner: send,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
            notify: Arc::new(Notify::new()),
        }
    }
}

impl TunnelWrite for QuicTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let data = self.buf.split().freeze();
        self.inner
            .write_all(&data)
            .await
            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;
        if self.buf.capacity() < MAX_PACKET_LENGTH {
            self.buf.reserve(MAX_PACKET_LENGTH);
        }
        Ok(())
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        // QUIC keep-alive is configured at the connection level via TransportConfig::keep_alive_interval.
        // Application-level pings are unnecessary.
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        self.inner
            .finish()
            .map_err(|err| io::Error::new(ErrorKind::BrokenPipe, err))
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        self.notify.clone()
    }

    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

pub struct QuicTunnelRead {
    inner: RecvStream,
}

impl QuicTunnelRead {
    pub fn new(recv: RecvStream) -> Self {
        Self { inner: recv }
    }
}

impl TunnelRead for QuicTunnelRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        let mut buf = vec![0u8; MAX_PACKET_LENGTH];
        match self.inner.read(&mut buf).await {
            Ok(Some(n)) => {
                writer
                    .write_all(&buf[..n])
                    .await
                    .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))?;
                Ok(())
            }
            Ok(None) => Err(io::Error::new(ErrorKind::BrokenPipe, "QUIC stream finished")),
            Err(err) => Err(io::Error::new(ErrorKind::ConnectionAborted, err)),
        }
    }
}

// ============================================================================
// Client: persistent endpoint + connection per WsClient
// ============================================================================

pub struct QuicClientState {
    /// Kept alive so the endpoint driver task isn't dropped.
    pub _endpoint: quinn::Endpoint,
    pub connection: quinn::Connection,
}

/// Build a `quinn::TransportConfig` with sensible defaults for tunnel workloads.
pub fn build_transport_config() -> anyhow::Result<Arc<quinn::TransportConfig>> {
    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(Some(QUIC_KEEP_ALIVE));
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(QUIC_IDLE_TIMEOUT).map_err(|e| anyhow!("invalid idle timeout: {e}"))?,
    ));
    transport.max_concurrent_bidi_streams(QUIC_MAX_BIDI_STREAMS.into());
    Ok(Arc::new(transport))
}

fn build_quinn_client_config(client: &WsClient<impl crate::TokioExecutorRef>) -> anyhow::Result<quinn::ClientConfig> {
    let tls_cfg = client
        .config
        .remote_addr
        .tls()
        .ok_or_else(|| anyhow!("QUIC transport requires TLS configuration"))?;

    let mut rustls_config = (**tls_cfg.tls_connector().config()).clone();
    rustls_config.alpn_protocols = vec![QUIC_ALPN.to_vec()];

    let quinn_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| anyhow!("Failed to build QUIC client crypto: {e}"))?;

    let mut quinn_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
    quinn_config.transport_config(build_transport_config()?);
    Ok(quinn_config)
}

async fn resolve_server(client: &WsClient<impl crate::TokioExecutorRef>) -> anyhow::Result<SocketAddr> {
    let host = client.config.remote_addr.host();
    let port = client.config.remote_addr.port();
    let host_str = host.to_string();
    let addrs = client
        .config
        .dns_resolver
        .lookup_host(&host_str, port)
        .await
        .with_context(|| format!("cannot resolve {host_str}:{port}"))?;
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("DNS returned no address for {host_str}:{port}"))
}

fn client_bind_for(target: SocketAddr) -> SocketAddr {
    match target {
        SocketAddr::V4(_) => SocketAddr::new(Ipv4Addr::UNSPECIFIED.into(), 0),
        SocketAddr::V6(_) => SocketAddr::new(Ipv6Addr::UNSPECIFIED.into(), 0),
    }
}

fn sni_for(client: &WsClient<impl crate::TokioExecutorRef>, fallback: &str) -> String {
    match client.config.tls_server_name() {
        ServerName::DnsName(dns) => dns.as_ref().to_string(),
        // For IP literals we hand the IP back to quinn as a string; quinn re-parses into ServerName
        // and either matches an IP-SAN cert or fails the handshake. We deliberately do *not* use
        // Debug formatting (which produces "Ipv4(...)") here.
        ServerName::IpAddress(_) => fallback.to_string(),
        _ => fallback.to_string(),
    }
}

async fn establish_new_connection(
    client: &WsClient<impl crate::TokioExecutorRef>,
) -> anyhow::Result<QuicClientState> {
    let server_addr = resolve_server(client).await?;
    let bind = client_bind_for(server_addr);
    let quinn_client_cfg = build_quinn_client_config(client)?;

    let mut endpoint =
        quinn::Endpoint::client(bind).with_context(|| format!("failed to bind QUIC client endpoint on {bind}"))?;
    endpoint.set_default_client_config(quinn_client_cfg);

    let host_str = client.config.remote_addr.host().to_string();
    let sni = sni_for(client, &host_str);

    info!("Opening QUIC connection to {server_addr} (SNI: {sni})");
    let connection = endpoint
        .connect(server_addr, &sni)
        .with_context(|| format!("failed to start QUIC connection to {server_addr}"))?
        .await
        .with_context(|| format!("QUIC handshake failed with {server_addr}"))?;
    info!("QUIC connection established with {server_addr}");
    Ok(QuicClientState {
        _endpoint: endpoint,
        connection,
    })
}

/// Returns a live `quinn::Connection` for this client, opening a new one if necessary.
/// Connections are reused across all tunnels of the same `WsClient` so multiple `-L`/`-R`
/// tunnels share a single QUIC handshake + datagram stream.
pub async fn get_or_create_connection(
    client: &WsClient<impl crate::TokioExecutorRef>,
) -> anyhow::Result<quinn::Connection> {
    let mut guard = client.quic_state.lock().await;
    if let Some(state) = guard.as_ref()
        && state.connection.close_reason().is_none()
    {
        return Ok(state.connection.clone());
    }
    if let Some(state) = guard.as_ref() {
        debug!(
            "existing QUIC connection closed ({:?}), reconnecting",
            state.connection.close_reason()
        );
    }
    let state = establish_new_connection(client).await?;
    let connection = state.connection.clone();
    *guard = Some(state);
    Ok(connection)
}

async fn invalidate_connection(client: &WsClient<impl crate::TokioExecutorRef>) {
    let mut guard = client.quic_state.lock().await;
    *guard = None;
}

// ============================================================================
// Client: public connect entrypoint
// ============================================================================

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(QuicTunnelRead, QuicTunnelWrite, Parts)> {
    // Acquire (or open) the shared QUIC connection.
    let connection = match get_or_create_connection(client).await {
        Ok(c) => c,
        Err(err) => {
            invalidate_connection(client).await;
            return Err(err);
        }
    };

    // Open a new bi-directional stream for this tunnel. If it fails the connection is dead;
    // clear the cached state so the next call re-handshakes.
    let (mut send, mut recv) = match connection.open_bi().await {
        Ok(s) => s,
        Err(err) => {
            invalidate_connection(client).await;
            return Err(anyhow!("failed to open QUIC bi-stream: {err}"));
        }
    };

    let cfg = &client.config;
    let jwt_token = tunnel_to_jwt_token(request_id, dest_addr);

    let authorization = cfg
        .http_upgrade_credentials
        .as_ref()
        .and_then(|hv| hv.to_str().ok().map(ToOwned::to_owned));

    let mut headers: Vec<(String, String)> = cfg
        .http_headers
        .iter()
        .filter_map(|(n, v)| v.to_str().ok().map(|v| (n.to_string(), v.to_string())))
        .collect();
    if let Ok(host_val) = cfg.http_header_host.to_str() {
        headers.push(("host".to_string(), host_val.to_string()));
    }

    let header = QuicRequestHeader {
        path_prefix: cfg.http_upgrade_path_prefix.clone(),
        jwt: jwt_token,
        authorization,
        headers,
    };

    if let Err(err) = header.write(&mut send).await {
        invalidate_connection(client).await;
        return Err(anyhow!("failed to write QUIC request header: {err}"));
    }

    let response = match QuicResponseHeader::read(&mut recv).await {
        Ok(r) => r,
        Err(err) => {
            invalidate_connection(client).await;
            return Err(anyhow!("failed to read QUIC response header: {err}"));
        }
    };

    if response.status != STATUS_OK {
        return Err(anyhow!(
            "QUIC server rejected tunnel (status={}): {}",
            response.status,
            if response.reason.is_empty() {
                "<no reason>".to_string()
            } else {
                response.reason
            }
        ));
    }

    // Build a synthetic HTTP-style response for compatibility with the existing
    // WS/H2 call sites. Inject the COOKIE header so reverse-dynamic tunnels can
    // parse the server's chosen RemoteAddr.
    let mut builder = Response::builder().status(StatusCode::OK).version(Version::HTTP_3);
    if !response.cookie.is_empty()
        && let Ok(cookie_val) = HeaderValue::from_str(&response.cookie)
        && let Some(headers_mut) = builder.headers_mut()
    {
        headers_mut.insert(COOKIE, cookie_val);
    }
    let http_response = builder.body(()).unwrap();
    let (parts, _) = http_response.into_parts();

    Ok((QuicTunnelRead::new(recv), QuicTunnelWrite::new(send), parts))
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use tokio::io::duplex;

    #[tokio::test]
    async fn request_header_roundtrip() {
        let original = QuicRequestHeader {
            path_prefix: "v1".into(),
            jwt: "header.payload.signature".into(),
            authorization: Some("Basic dXNlcjpwYXNz".into()),
            headers: vec![
                ("Host".into(), "example.com".into()),
                ("X-Custom".into(), "value".into()),
            ],
        };

        let (mut a, mut b) = duplex(8192);
        original.write(&mut a).await.unwrap();
        a.shutdown().await.unwrap();
        let parsed = QuicRequestHeader::read(&mut b).await.unwrap();
        assert_eq!(parsed, original);
    }

    #[tokio::test]
    async fn request_header_no_auth_no_headers() {
        let original = QuicRequestHeader {
            path_prefix: "v1".into(),
            jwt: "j".into(),
            authorization: None,
            headers: vec![],
        };
        let (mut a, mut b) = duplex(1024);
        original.write(&mut a).await.unwrap();
        a.shutdown().await.unwrap();
        let parsed = QuicRequestHeader::read(&mut b).await.unwrap();
        assert_eq!(parsed, original);
    }

    #[tokio::test]
    async fn response_header_ok_with_cookie() {
        let original = QuicResponseHeader::ok("cookie.jwt".into());
        let (mut a, mut b) = duplex(1024);
        original.write(&mut a).await.unwrap();
        a.shutdown().await.unwrap();
        let parsed = QuicResponseHeader::read(&mut b).await.unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.status, STATUS_OK);
    }

    #[tokio::test]
    async fn response_header_error() {
        let original = QuicResponseHeader::err(STATUS_FORBIDDEN, "denied by restriction");
        let (mut a, mut b) = duplex(1024);
        original.write(&mut a).await.unwrap();
        a.shutdown().await.unwrap();
        let parsed = QuicResponseHeader::read(&mut b).await.unwrap();
        assert_eq!(parsed, original);
        assert_eq!(parsed.status, STATUS_FORBIDDEN);
    }

    #[tokio::test]
    async fn rejects_bad_preamble() {
        let mut bad = Cursor::new(b"NOTAPREAMBLE0\x00".to_vec());
        let err = QuicRequestHeader::read(&mut bad).await.err().unwrap();
        assert!(format!("{err}").contains("preamble"));
    }
}
