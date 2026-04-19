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
//! [u8 transport_mode]                           // 0 = reliable stream, 1 = datagram
//! [u32 BE flow_id]                              // non-zero only for datagram tunnels
//! <then raw tunneled bytes on the stream, if transport_mode == 0>
//! ```
//!
//! Server → Client (first bytes once the request is validated):
//! ```text
//! [preamble: b"WSTUNNEL/1\n" (11 bytes)]
//! [u8 status]                                  // 0 = OK, non-zero = error
//! [u16 BE reason_len][reason: utf-8]
//! [u16 BE cookie_len][cookie: utf-8]           // JWT cookie for dynamic reverse tunnels
//! <then raw tunneled bytes on the stream, if transport_mode == 0>
//! ```

use super::io::{MAX_PACKET_LENGTH, TunnelRead, TunnelWrite};
use crate::tunnel::LocalProtocol;
use crate::tunnel::RemoteAddr;
use crate::tunnel::client::WsClient;
use crate::tunnel::transport::jwt::tunnel_to_jwt_token;
use anyhow::{Context, anyhow, ensure};
use bytes::{BufMut, Bytes, BytesMut};
use futures_util::FutureExt;
use hyper::header::{COOKIE, HeaderValue};
use hyper::http::response::Parts;
use hyper::{Response, StatusCode, Version};
use parking_lot::Mutex;
use quinn::{RecvStream, SendStream};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Weak};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio_rustls::rustls::pki_types::ServerName;
use tracing::{debug, info, warn};
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

const QUIC_DATAGRAM_CHANNEL_SIZE: usize = 64;
const QUIC_DATAGRAM_FLOW_PREFIX_LEN: usize = 4;
pub const QUIC_ALPN: &[u8] = b"wstunnel";

// ============================================================================
// Wire format
// ============================================================================

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum QuicTransportMode {
    #[default]
    Stream = 0,
    Datagram = 1,
}

impl QuicTransportMode {
    fn from_protocol(protocol: &LocalProtocol) -> Self {
        match protocol {
            LocalProtocol::Udp { .. } | LocalProtocol::ReverseUdp { .. } => Self::Datagram,
            _ => Self::Stream,
        }
    }

    fn from_u8(mode: u8) -> anyhow::Result<Self> {
        match mode {
            0 => Ok(Self::Stream),
            1 => Ok(Self::Datagram),
            _ => Err(anyhow!("invalid QUIC transport mode: {mode}")),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct QuicRequestHeader {
    pub path_prefix: String,
    pub jwt: String,
    pub authorization: Option<String>,
    pub headers: Vec<(String, String)>,
    pub transport_mode: QuicTransportMode,
    pub flow_id: u32,
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
        w.write_u8(self.transport_mode as u8).await?;
        w.write_u32(self.flow_id).await?;
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
        let transport_mode = QuicTransportMode::from_u8(r.read_u8().await.context("reading transport mode")?)?;
        let flow_id = r.read_u32().await.context("reading flow id")?;
        Ok(Self {
            path_prefix,
            jwt,
            authorization,
            headers,
            transport_mode,
            flow_id,
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

pub struct QuicStreamTunnelWrite {
    inner: SendStream,
    buf: BytesMut,
    notify: Arc<Notify>,
}

impl QuicStreamTunnelWrite {
    pub fn new(send: SendStream) -> Self {
        Self {
            inner: send,
            buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
            notify: Arc::new(Notify::new()),
        }
    }
}

impl TunnelWrite for QuicStreamTunnelWrite {
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

pub struct QuicStreamTunnelRead {
    inner: RecvStream,
}

impl QuicStreamTunnelRead {
    pub fn new(recv: RecvStream) -> Self {
        Self { inner: recv }
    }
}

impl TunnelRead for QuicStreamTunnelRead {
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

pub(crate) struct QuicDatagramHub {
    connection: quinn::Connection,
    flows: Mutex<HashMap<u32, mpsc::Sender<Bytes>>>,
    next_flow_id: AtomicU32,
}

impl QuicDatagramHub {
    pub(crate) fn new(connection: quinn::Connection) -> Arc<Self> {
        Arc::new(Self {
            connection,
            flows: Mutex::new(HashMap::new()),
            next_flow_id: AtomicU32::new(1),
        })
    }

    fn allocate_flow_id(&self) -> u32 {
        self.next_flow_id.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) fn register_flow(
        self: &Arc<Self>,
        flow_id: u32,
    ) -> anyhow::Result<(QuicDatagramTunnelRead, QuicDatagramTunnelWrite)> {
        if flow_id == 0 {
            return Err(anyhow!("flow id 0 is reserved for stream-based QUIC tunnels"));
        }

        let (tx, rx) = mpsc::channel(QUIC_DATAGRAM_CHANNEL_SIZE);
        let previous = self.flows.lock().insert(flow_id, tx);
        if previous.is_some() {
            return Err(anyhow!("datagram flow id {flow_id} is already registered"));
        }

        let registration = Arc::new(QuicDatagramFlowRegistration {
            flow_id,
            hub: Arc::downgrade(self),
        });
        Ok((
            QuicDatagramTunnelRead {
                inner: rx,
                _registration: registration.clone(),
            },
            QuicDatagramTunnelWrite {
                connection: self.connection.clone(),
                flow_id,
                buf: BytesMut::with_capacity(MAX_PACKET_LENGTH),
                notify: Arc::new(Notify::new()),
                _registration: registration,
            },
        ))
    }

    fn unregister_flow(&self, flow_id: u32) {
        self.flows.lock().remove(&flow_id);
    }

    pub(crate) async fn run(self: Arc<Self>) {
        loop {
            let datagram = match self.connection.read_datagram().await {
                Ok(datagram) => datagram,
                Err(err) => {
                    debug!("Stopping QUIC datagram router: {err}");
                    break;
                }
            };

            let Some((flow_id, payload)) = decode_datagram(datagram) else {
                warn!("Dropping malformed QUIC datagram shorter than flow prefix");
                continue;
            };

            let sender = self.flows.lock().get(&flow_id).cloned();
            let Some(sender) = sender else {
                debug!("Dropping QUIC datagram for unknown flow {flow_id}");
                continue;
            };

            if sender.try_send(payload).is_err() {
                debug!("Dropping QUIC datagram for backpressured flow {flow_id}");
            }
        }

        self.flows.lock().clear();
    }
}

struct QuicDatagramFlowRegistration {
    flow_id: u32,
    hub: Weak<QuicDatagramHub>,
}

impl Drop for QuicDatagramFlowRegistration {
    fn drop(&mut self) {
        if let Some(hub) = self.hub.upgrade() {
            hub.unregister_flow(self.flow_id);
        }
    }
}

pub struct QuicDatagramTunnelWrite {
    connection: quinn::Connection,
    flow_id: u32,
    buf: BytesMut,
    notify: Arc<Notify>,
    _registration: Arc<QuicDatagramFlowRegistration>,
}

impl TunnelWrite for QuicDatagramTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        &mut self.buf
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        if self.buf.is_empty() {
            return Ok(());
        }

        let payload = self.buf.split().freeze();
        self.connection
            .send_datagram_wait(encode_datagram(self.flow_id, payload))
            .await
            .map_err(map_datagram_write_error)?;
        if self.buf.capacity() < MAX_PACKET_LENGTH {
            self.buf.reserve(MAX_PACKET_LENGTH);
        }
        Ok(())
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        Ok(())
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        self.notify.clone()
    }

    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        std::future::ready(Ok(()))
    }
}

pub struct QuicDatagramTunnelRead {
    inner: mpsc::Receiver<Bytes>,
    _registration: Arc<QuicDatagramFlowRegistration>,
}

impl TunnelRead for QuicDatagramTunnelRead {
    async fn copy(&mut self, mut writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        let data = match self.inner.recv().await {
            Some(data) => data,
            None => return Err(io::Error::new(ErrorKind::BrokenPipe, "QUIC datagram flow finished")),
        };
        writer
            .write_all(data.as_ref())
            .await
            .map_err(|err| io::Error::new(ErrorKind::ConnectionAborted, err))
    }
}

pub enum QuicTunnelWrite {
    Stream(QuicStreamTunnelWrite),
    Datagram(QuicDatagramTunnelWrite),
}

impl TunnelWrite for QuicTunnelWrite {
    fn buf_mut(&mut self) -> &mut BytesMut {
        match self {
            Self::Stream(stream) => stream.buf_mut(),
            Self::Datagram(datagram) => datagram.buf_mut(),
        }
    }

    async fn write(&mut self) -> Result<(), io::Error> {
        match self {
            Self::Stream(stream) => stream.write().await,
            Self::Datagram(datagram) => datagram.write().await,
        }
    }

    async fn ping(&mut self) -> Result<(), io::Error> {
        match self {
            Self::Stream(stream) => stream.ping().await,
            Self::Datagram(datagram) => datagram.ping().await,
        }
    }

    async fn close(&mut self) -> Result<(), io::Error> {
        match self {
            Self::Stream(stream) => stream.close().await,
            Self::Datagram(datagram) => datagram.close().await,
        }
    }

    fn pending_operations_notify(&mut self) -> Arc<Notify> {
        match self {
            Self::Stream(stream) => stream.pending_operations_notify(),
            Self::Datagram(datagram) => datagram.pending_operations_notify(),
        }
    }

    fn handle_pending_operations(&mut self) -> impl Future<Output = Result<(), io::Error>> + Send {
        match self {
            Self::Stream(stream) => stream.handle_pending_operations().left_future(),
            Self::Datagram(datagram) => datagram.handle_pending_operations().right_future(),
        }
    }
}

pub enum QuicTunnelRead {
    Stream(QuicStreamTunnelRead),
    Datagram(QuicDatagramTunnelRead),
}

impl TunnelRead for QuicTunnelRead {
    async fn copy(&mut self, writer: impl AsyncWrite + Unpin + Send) -> Result<(), io::Error> {
        match self {
            Self::Stream(stream) => stream.copy(writer).await,
            Self::Datagram(datagram) => datagram.copy(writer).await,
        }
    }
}

fn encode_datagram(flow_id: u32, payload: Bytes) -> Bytes {
    let mut data = BytesMut::with_capacity(QUIC_DATAGRAM_FLOW_PREFIX_LEN + payload.len());
    data.put_u32(flow_id);
    data.extend_from_slice(payload.as_ref());
    data.freeze()
}

fn decode_datagram(datagram: Bytes) -> Option<(u32, Bytes)> {
    if datagram.len() < QUIC_DATAGRAM_FLOW_PREFIX_LEN {
        return None;
    }
    let flow_id = u32::from_be_bytes(datagram[..QUIC_DATAGRAM_FLOW_PREFIX_LEN].try_into().ok()?);
    Some((flow_id, datagram.slice(QUIC_DATAGRAM_FLOW_PREFIX_LEN..)))
}

fn map_datagram_write_error(err: quinn::SendDatagramError) -> io::Error {
    io::Error::new(ErrorKind::ConnectionAborted, err)
}

// ============================================================================
// Client: persistent endpoint + connection per WsClient
// ============================================================================

pub struct QuicClientState {
    /// Kept alive so the endpoint driver task isn't dropped.
    pub(crate) _endpoint: quinn::Endpoint,
    pub(crate) connection: quinn::Connection,
    pub(crate) datagram_hub: Arc<QuicDatagramHub>,
}

/// Build a `quinn::TransportConfig` from the explicit wstunnel QUIC settings.
pub fn build_transport_config(
    keep_alive_interval: Option<Duration>,
    max_idle_timeout: Option<Duration>,
    max_concurrent_bidi_streams: u32,
    datagram_buffer_size: usize,
) -> anyhow::Result<Arc<quinn::TransportConfig>> {
    ensure!(max_concurrent_bidi_streams > 0, "QUIC max streams must be greater than zero");
    ensure!(datagram_buffer_size > 0, "QUIC datagram buffer size must be greater than zero");

    let mut transport = quinn::TransportConfig::default();
    transport.keep_alive_interval(keep_alive_interval);
    transport.max_idle_timeout(match max_idle_timeout {
        Some(timeout) => Some(quinn::IdleTimeout::try_from(timeout).map_err(|e| anyhow!("invalid idle timeout: {e}"))?),
        None => None,
    });
    transport.max_concurrent_bidi_streams(max_concurrent_bidi_streams.into());
    transport.datagram_receive_buffer_size(Some(datagram_buffer_size));
    transport.datagram_send_buffer_size(datagram_buffer_size);
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
    rustls_config.enable_early_data = client.config.quic_0rtt;

    let quinn_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(rustls_config)
        .map_err(|e| anyhow!("Failed to build QUIC client crypto: {e}"))?;

    let mut quinn_config = quinn::ClientConfig::new(Arc::new(quinn_crypto));
    quinn_config.transport_config(build_transport_config(
        client.config.quic_keep_alive,
        client.config.quic_max_idle_timeout,
        client.config.quic_max_streams,
        client.config.quic_datagram_buffer_size,
    )?);
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

async fn establish_new_connection(client: &WsClient<impl crate::TokioExecutorRef>) -> anyhow::Result<QuicClientState> {
    let server_addr = resolve_server(client).await?;
    let bind = client_bind_for(server_addr);
    let quinn_client_cfg = build_quinn_client_config(client)?;

    let mut endpoint =
        quinn::Endpoint::client(bind).with_context(|| format!("failed to bind QUIC client endpoint on {bind}"))?;
    endpoint.set_default_client_config(quinn_client_cfg);

    let host_str = client.config.remote_addr.host().to_string();
    let sni = sni_for(client, &host_str);

    info!("Opening QUIC connection to {server_addr} (SNI: {sni})");
    let connecting = endpoint
        .connect(server_addr, &sni)
        .with_context(|| format!("failed to start QUIC connection to {server_addr}"))?;
    let connection = if client.config.quic_0rtt {
        match connecting.into_0rtt() {
            Ok((connection, accepted)) => {
                info!("Attempting QUIC 0-RTT with {server_addr}");
                client.executor.clone().spawn(async move {
                    if accepted.await {
                        info!("QUIC 0-RTT accepted by {server_addr}");
                    } else {
                        info!("QUIC 0-RTT rejected by {server_addr}");
                    }
                });
                connection
            }
            Err(connecting) => {
                debug!("QUIC 0-RTT not available yet for {server_addr}, continuing with 1-RTT");
                connecting
                    .await
                    .with_context(|| format!("QUIC handshake failed with {server_addr}"))?
            }
        }
    } else {
        connecting
            .await
            .with_context(|| format!("QUIC handshake failed with {server_addr}"))?
    };
    let datagram_hub = QuicDatagramHub::new(connection.clone());
    client.executor.clone().spawn(datagram_hub.clone().run());
    info!("QUIC connection established with {server_addr}");
    Ok(QuicClientState {
        _endpoint: endpoint,
        connection,
        datagram_hub,
    })
}

/// Returns a live `quinn::Connection` for this client, opening a new one if necessary.
/// Connections are reused across all tunnels of the same `WsClient` so multiple `-L`/`-R`
/// tunnels share a single QUIC handshake + datagram stream.
async fn get_or_create_connection(
    client: &WsClient<impl crate::TokioExecutorRef>,
) -> anyhow::Result<(quinn::Connection, Arc<QuicDatagramHub>)> {
    let mut guard = client.quic_state.lock().await;
    if let Some(state) = guard.as_ref()
        && state.connection.close_reason().is_none()
    {
        return Ok((state.connection.clone(), state.datagram_hub.clone()));
    }
    if let Some(state) = guard.as_ref() {
        debug!(
            "existing QUIC connection closed ({:?}), reconnecting",
            state.connection.close_reason()
        );
    }
    let state = establish_new_connection(client).await?;
    let connection = state.connection.clone();
    let datagram_hub = state.datagram_hub.clone();
    *guard = Some(state);
    Ok((connection, datagram_hub))
}

async fn invalidate_connection(client: &WsClient<impl crate::TokioExecutorRef>) {
    let mut guard = client.quic_state.lock().await;
    *guard = None;
}

fn is_zero_rtt_rejected(err: &anyhow::Error) -> bool {
    err.chain().any(|cause| cause.to_string().contains("0-RTT rejected"))
}

// ============================================================================
// Client: public connect entrypoint
// ============================================================================

pub async fn connect(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(QuicTunnelRead, QuicTunnelWrite, Parts)> {
    match connect_once(request_id, client, dest_addr).await {
        Ok(result) => Ok(result),
        Err(err) if client.config.quic_0rtt && is_zero_rtt_rejected(&err) => {
            info!("Retrying QUIC tunnel after 0-RTT rejection");
            invalidate_connection(client).await;
            connect_once(request_id, client, dest_addr).await
        }
        Err(err) => Err(err),
    }
}

async fn connect_once(
    request_id: Uuid,
    client: &WsClient<impl crate::TokioExecutorRef>,
    dest_addr: &RemoteAddr,
) -> anyhow::Result<(QuicTunnelRead, QuicTunnelWrite, Parts)> {
    // Acquire (or open) the shared QUIC connection.
    let (connection, datagram_hub) = match get_or_create_connection(client).await {
        Ok(state) => state,
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
    let transport_mode = QuicTransportMode::from_protocol(&dest_addr.protocol);
    let datagram_flow = match transport_mode {
        QuicTransportMode::Stream => None,
        QuicTransportMode::Datagram => {
            if connection.max_datagram_size().is_none() {
                invalidate_connection(client).await;
                return Err(anyhow!("QUIC peer does not support DATAGRAM frames"));
            }
            let flow_id = datagram_hub.allocate_flow_id();
            Some((flow_id, datagram_hub.register_flow(flow_id)?))
        }
    };

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
        transport_mode,
        flow_id: datagram_flow.as_ref().map(|(flow_id, _)| *flow_id).unwrap_or_default(),
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

    if let Some((_flow_id, (rx, tx))) = datagram_flow {
        let _ = send.finish();
        drop(recv);
        Ok((QuicTunnelRead::Datagram(rx), QuicTunnelWrite::Datagram(tx), parts))
    } else {
        Ok((
            QuicTunnelRead::Stream(QuicStreamTunnelRead::new(recv)),
            QuicTunnelWrite::Stream(QuicStreamTunnelWrite::new(send)),
            parts,
        ))
    }
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
            transport_mode: QuicTransportMode::Datagram,
            flow_id: 7,
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
            transport_mode: QuicTransportMode::Stream,
            flow_id: 0,
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

    #[test]
    fn datagram_roundtrip() {
        let payload = Bytes::from_static(b"hello");
        let datagram = encode_datagram(42, payload.clone());
        let (flow_id, restored_payload) = decode_datagram(datagram).unwrap();
        assert_eq!(flow_id, 42);
        assert_eq!(restored_payload, payload);
    }
}
