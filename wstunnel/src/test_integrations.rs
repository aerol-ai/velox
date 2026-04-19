#[cfg(feature = "quic")]
use crate::embedded_certificate;
use crate::executor::DefaultTokioExecutor;
use crate::protocols;
use crate::protocols::dns::DnsResolver;
#[cfg(feature = "quic")]
use crate::protocols::tls;
use crate::restrictions::types;
use crate::restrictions::types::{AllowConfig, MatchConfig, RestrictionConfig, RestrictionsRules};
use crate::somark::SoMark;
#[cfg(feature = "quic")]
use crate::tunnel::LocalProtocol;
#[cfg(feature = "quic")]
use crate::tunnel::RemoteAddr;
#[cfg(feature = "quic")]
use crate::tunnel::client::TlsClientConfig;
use crate::tunnel::client::{WsClient, WsClientConfig};
#[cfg(feature = "quic")]
use crate::tunnel::connectors::UdpTunnelConnector;
use crate::tunnel::listeners::{TcpTunnelListener, UdpTunnelListener};
#[cfg(feature = "quic")]
use crate::tunnel::server::TlsServerConfig;
use crate::tunnel::server::{WsServer, WsServerConfig};
use crate::tunnel::transport::{TransportAddr, TransportScheme};
use bytes::BytesMut;
use futures_util::StreamExt;
use hyper::http::HeaderValue;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
#[cfg(feature = "quic")]
use parking_lot::{Mutex, RwLock};
#[cfg(feature = "quic")]
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair, KeyUsagePurpose,
};
use regex::Regex;
use rstest::{fixture, rstest};
use scopeguard::defer;
use serial_test::serial;
use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
#[cfg(feature = "quic")]
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::pin;
#[cfg(feature = "quic")]
use tokio_rustls::rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use url::Host;
#[cfg(feature = "quic")]
use uuid::Uuid;

#[fixture]
fn dns_resolver() -> DnsResolver {
    DnsResolver::new_from_urls(&[], None, SoMark::new(None), true).expect("Cannot create DNS resolver")
}

#[fixture]
fn server_no_tls(dns_resolver: DnsResolver) -> WsServer {
    let server_config = WsServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: "127.0.0.1:8080".parse().unwrap(),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: None,
        dns_resolver,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        #[cfg(feature = "quic")]
        quic_bind: None,
        #[cfg(feature = "quic")]
        quic_0rtt: false,
        #[cfg(feature = "quic")]
        quic_keep_alive: Some(Duration::from_secs(15)),
        #[cfg(feature = "quic")]
        quic_max_idle_timeout: Some(Duration::from_secs(60)),
        #[cfg(feature = "quic")]
        quic_max_streams: 1024,
        #[cfg(feature = "quic")]
        quic_datagram_buffer_size: 1024 * 1024,
        #[cfg(feature = "quic")]
        quic_disable_migration: false,
    };
    WsServer::new(server_config, DefaultTokioExecutor::default())
}

#[fixture]
async fn client_ws(dns_resolver: DnsResolver) -> WsClient {
    let client_config = WsClientConfig {
        remote_addr: TransportAddr::new(TransportScheme::Ws, Host::Ipv4("127.0.0.1".parse().unwrap()), 8080, None)
            .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_static("127.0.0.1:8080"),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        #[cfg(feature = "quic")]
        quic_0rtt: false,
        #[cfg(feature = "quic")]
        quic_keep_alive: Some(Duration::from_secs(15)),
        #[cfg(feature = "quic")]
        quic_max_idle_timeout: Some(Duration::from_secs(60)),
        #[cfg(feature = "quic")]
        quic_max_streams: 1024,
        #[cfg(feature = "quic")]
        quic_datagram_buffer_size: 1024 * 1024,
    };

    WsClient::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

#[fixture]
fn no_restrictions() -> RestrictionsRules {
    pub fn default_host() -> Regex {
        Regex::new("^.*$").unwrap()
    }

    pub fn default_cidr() -> Vec<IpNet> {
        vec![IpNet::V4(Ipv4Net::default()), IpNet::V6(Ipv6Net::default())]
    }

    let tunnels = types::AllowConfig::Tunnel(types::AllowTunnelConfig {
        protocol: vec![],
        port: vec![],
        host: default_host(),
        cidr: default_cidr(),
    });
    let reverse_tunnel = AllowConfig::ReverseTunnel(types::AllowReverseTunnelConfig {
        protocol: vec![],
        port: vec![],
        port_mapping: Default::default(),
        cidr: default_cidr(),
        unix_path: default_host(),
    });

    RestrictionsRules {
        restrictions: vec![RestrictionConfig {
            name: "".to_string(),
            r#match: vec![MatchConfig::Any],
            allow: vec![tunnels, reverse_tunnel],
        }],
    }
}

const TUNNEL_LISTEN: (SocketAddr, Host) = (
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9998)),
    Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
);
const ENDPOINT_LISTEN: (SocketAddr, Host) = (
    SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9999)),
    Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
);

#[cfg(feature = "quic")]
const QUIC_SERVER_TCP_BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 18080));
#[cfg(feature = "quic")]
const QUIC_SERVER_UDP_BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 18443));
#[cfg(feature = "quic")]
const QUIC_REVERSE_UDP_BIND: SocketAddr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 19998));

#[cfg(feature = "quic")]
fn server_quic(dns_resolver: DnsResolver, tls: TlsServerConfig) -> WsServer {
    let server_config = WsServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: QUIC_SERVER_TCP_BIND,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: Some(tls),
        dns_resolver,
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        quic_bind: Some(QUIC_SERVER_UDP_BIND),
        quic_0rtt: false,
        quic_keep_alive: Some(Duration::from_secs(15)),
        quic_max_idle_timeout: Some(Duration::from_secs(60)),
        quic_max_streams: 1024,
        quic_datagram_buffer_size: 1024 * 1024,
        quic_disable_migration: false,
    };
    WsServer::new(server_config, DefaultTokioExecutor::default())
}

#[cfg(feature = "quic")]
fn quic_server_tls(client_ca_certificates: Option<Vec<CertificateDer<'static>>>) -> TlsServerConfig {
    let (tls_certificate, tls_key) = &*embedded_certificate::TLS_CERTIFICATE;
    TlsServerConfig {
        tls_certificate: Mutex::new(tls_certificate.clone()),
        tls_key: Mutex::new(tls_key.clone_key()),
        tls_client_ca_certificates: client_ca_certificates.map(Mutex::new),
        tls_certificate_path: None,
        tls_key_path: None,
        tls_client_ca_certs_path: None,
    }
}

#[cfg(feature = "quic")]
async fn client_quic(
    dns_resolver: DnsResolver,
    connection_min_idle: u32,
    path_prefix: &str,
    client_certificate: Option<Vec<CertificateDer<'static>>>,
    client_key: Option<PrivateKeyDer<'static>>,
) -> WsClient {
    let tls_connector = tls::tls_connector(
        false,
        TransportScheme::Quic.alpn_protocols(),
        true,
        None,
        client_certificate,
        client_key,
    )
    .unwrap();

    let client_config = WsClientConfig {
        remote_addr: TransportAddr::new(
            TransportScheme::Quic,
            Host::Ipv4("127.0.0.1".parse().unwrap()),
            QUIC_SERVER_UDP_BIND.port(),
            Some(TlsClientConfig {
                tls_sni_disabled: false,
                tls_sni_override: None,
                tls_verify_certificate: false,
                tls_connector: Arc::new(RwLock::new(tls_connector)),
                tls_certificate_path: None,
                tls_key_path: None,
            }),
        )
        .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: path_prefix.to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_static("127.0.0.1:18443"),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        quic_0rtt: false,
        quic_keep_alive: Some(Duration::from_secs(15)),
        quic_max_idle_timeout: Some(Duration::from_secs(60)),
        quic_max_streams: 1024,
        quic_datagram_buffer_size: 1024 * 1024,
    };

    WsClient::new(
        client_config,
        connection_min_idle,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

/// QUIC client variant pointed at an arbitrary local port. Used by tests that put a UDP
/// relay (lossy or otherwise) between the client and the real QUIC server.
#[cfg(feature = "quic")]
async fn client_quic_at_port(dns_resolver: DnsResolver, target_port: u16) -> WsClient {
    let tls_connector = tls::tls_connector(false, TransportScheme::Quic.alpn_protocols(), true, None, None, None)
        .unwrap();

    let client_config = WsClientConfig {
        remote_addr: TransportAddr::new(
            TransportScheme::Quic,
            Host::Ipv4("127.0.0.1".parse().unwrap()),
            target_port,
            Some(TlsClientConfig {
                tls_sni_disabled: false,
                tls_sni_override: None,
                tls_verify_certificate: false,
                tls_connector: Arc::new(RwLock::new(tls_connector)),
                tls_certificate_path: None,
                tls_key_path: None,
            }),
        )
        .unwrap(),
        socket_so_mark: SoMark::new(None),
        http_upgrade_path_prefix: "wstunnel".to_string(),
        http_upgrade_credentials: None,
        http_headers: HashMap::new(),
        http_headers_file: None,
        http_header_host: HeaderValue::from_static("127.0.0.1"),
        timeout_connect: Duration::from_secs(10),
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        websocket_mask_frame: false,
        dns_resolver,
        http_proxy: None,
        quic_0rtt: false,
        quic_keep_alive: Some(Duration::from_secs(15)),
        quic_max_idle_timeout: Some(Duration::from_secs(60)),
        quic_max_streams: 1024,
        quic_datagram_buffer_size: 1024 * 1024,
    };

    WsClient::new(
        client_config,
        1,
        Duration::from_secs(1),
        Duration::from_secs(1),
        DefaultTokioExecutor::default(),
    )
    .await
    .unwrap()
}

/// Tiny xorshift64* PRNG for the lossy relay. We deliberately avoid pulling in the `rand`
/// crate just for tests, and a deterministic-but-shifting source is fine here — we only
/// need an unbiased "drop this packet?" decision.
#[cfg(feature = "quic")]
fn pseudo_rand_pct() -> u32 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEED: AtomicU64 = AtomicU64::new(0xcafe_babe_dead_beef);
    let mut x = SEED.load(Ordering::Relaxed);
    if x == 0 {
        x = 0xdead_beef_cafe_babe;
    }
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    SEED.store(x, Ordering::Relaxed);
    (x % 100) as u32
}

/// Spawn a single-client lossy UDP relay. Forwards packets between the client and `target`,
/// dropping `drop_pct` percent of packets in each direction. Returns the relay's bind
/// address for the QUIC client to point at. Replaces `tc netem` from the migration plan
/// (which is Linux+root-only, can't run portably in CI).
#[cfg(feature = "quic")]
async fn spawn_lossy_udp_relay(target: SocketAddr, drop_pct: u32) -> SocketAddr {
    use tokio::net::UdpSocket;
    let down = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let up = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    up.connect(target).await.unwrap();
    let bound = down.local_addr().unwrap();

    let last_client: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));

    // client -> upstream
    {
        let down = down.clone();
        let up = up.clone();
        let last_client = last_client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (n, peer) = match down.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                *last_client.lock() = Some(peer);
                if pseudo_rand_pct() < drop_pct {
                    continue;
                }
                let _ = up.send(&buf[..n]).await;
            }
        });
    }
    // upstream -> client
    {
        let down = down.clone();
        let up = up.clone();
        let last_client = last_client.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_535];
            loop {
                let n = match up.recv(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if pseudo_rand_pct() < drop_pct {
                    continue;
                }
                let dest = *last_client.lock();
                if let Some(dest) = dest {
                    let _ = down.send_to(&buf[..n], dest).await;
                }
            }
        });
    }
    bound
}

#[cfg(feature = "quic")]
fn build_client_mtls_material(
    common_name: &str,
) -> (
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    Vec<CertificateDer<'static>>,
) {
    let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "wstunnel-quic-test-ca");
    ca_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    ca_params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(KeyUsagePurpose::CrlSign);
    let ca_key = KeyPair::generate().unwrap();
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_issuer = Issuer::new(ca_params, ca_key);

    let mut client_params = CertificateParams::new(Vec::new()).unwrap();
    client_params.distinguished_name.push(DnType::CommonName, common_name);
    client_params.use_authority_key_identifier_extension = true;
    client_params.key_usages.push(KeyUsagePurpose::DigitalSignature);
    client_params
        .extended_key_usages
        .push(ExtendedKeyUsagePurpose::ClientAuth);
    let client_key = KeyPair::generate().unwrap();
    let client_cert = client_params.signed_by(&client_key, &ca_issuer).unwrap();

    (
        vec![client_cert.der().clone()],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(client_key.serialized_der().to_vec())),
        vec![ca_cert.der().clone()],
    )
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel(
    #[future] client_ws: WsClient,
    server_no_tls: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions, tokio_util::sync::CancellationToken::new()));
    defer! { server_h.abort(); };

    let client_ws = client_ws.await;

    let server = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1, ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel(
    #[future] client_ws: WsClient,
    server_no_tls: WsServer,
    no_restrictions: RestrictionsRules,
    dns_resolver: DnsResolver,
) {
    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions, tokio_util::sync::CancellationToken::new()));
    defer! { server_h.abort(); };

    let client_ws = client_ws.await;

    let server = UdpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1, ENDPOINT_LISTEN.0.port()), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_ws.run_tunnel(server).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(ENDPOINT_LISTEN.0, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut client = protocols::udp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        Duration::from_secs(10),
        SoMark::new(None),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    pin!(udp_listener);
    let dd = udp_listener.next().await.unwrap().unwrap();
    pin!(dd);
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.writer().write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[cfg(feature = "quic")]
#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_quic(no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let server_h = tokio::spawn(server_quic(dns_resolver.clone(), quic_server_tls(None)).serve(no_restrictions, tokio_util::sync::CancellationToken::new()));
    defer! { server_h.abort(); };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let client_quic = client_quic(dns_resolver.clone(), 1, "wstunnel", None, None).await;

    let server = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1.clone(), ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_quic.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let mut client = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    let mut dd = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[cfg(feature = "quic")]
#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_udp_tunnel_quic(no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let server_h = tokio::spawn(server_quic(dns_resolver.clone(), quic_server_tls(None)).serve(no_restrictions, tokio_util::sync::CancellationToken::new()));
    defer! { server_h.abort(); };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let client_quic = client_quic(dns_resolver.clone(), 1, "wstunnel", None, None).await;

    let server = UdpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1.clone(), ENDPOINT_LISTEN.0.port()), None)
        .await
        .unwrap();
    tokio::spawn(async move {
        client_quic.run_tunnel(server).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(ENDPOINT_LISTEN.0, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut client = protocols::udp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        Duration::from_secs(10),
        SoMark::new(None),
        &dns_resolver,
    )
    .await
    .unwrap();

    client.write_all(b"Hello").await.unwrap();
    pin!(udp_listener);
    let dd = udp_listener.next().await.unwrap().unwrap();
    pin!(dd);
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.writer().write_all(b"world!").await.unwrap();
    client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[cfg(feature = "quic")]
#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_reverse_udp_tunnel_quic(no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let server_h = tokio::spawn(server_quic(dns_resolver.clone(), quic_server_tls(None)).serve(no_restrictions, tokio_util::sync::CancellationToken::new()));
    defer! { server_h.abort(); };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let client_quic = client_quic(dns_resolver.clone(), 1, "wstunnel", None, None).await;

    let reverse_remote = RemoteAddr {
        protocol: LocalProtocol::ReverseUdp { timeout: None },
        host: Host::Ipv4("127.0.0.1".parse().unwrap()),
        port: QUIC_REVERSE_UDP_BIND.port(),
    };
    let connector_dns_resolver = dns_resolver.clone();
    tokio::spawn(async move {
        let connector = UdpTunnelConnector::new(
            &ENDPOINT_LISTEN.1,
            ENDPOINT_LISTEN.0.port(),
            SoMark::new(None),
            Duration::from_secs(10),
            &connector_dns_resolver,
        );
        client_quic.run_reverse_tunnel(reverse_remote, connector).await.unwrap();
    });

    let udp_listener = protocols::udp::run_server(ENDPOINT_LISTEN.0, None, |_| Ok(()), |s| Ok(s.clone()))
        .await
        .unwrap();
    let mut reverse_client = protocols::udp::connect(
        &Host::Ipv4("127.0.0.1".parse().unwrap()),
        QUIC_REVERSE_UDP_BIND.port(),
        Duration::from_secs(10),
        SoMark::new(None),
        &dns_resolver,
    )
    .await
    .unwrap();

    let mut reverse_sender = reverse_client.clone();
    let sender_task = tokio::spawn(async move {
        loop {
            let _ = reverse_sender.write_all(b"Hello").await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });
    pin!(udp_listener);
    let dd = udp_listener.next().await.unwrap().unwrap();
    sender_task.abort();
    pin!(dd);
    let mut buf = BytesMut::new();
    dd.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");
    buf.clear();

    dd.writer().write_all(b"world!").await.unwrap();
    reverse_client.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"world!");
}

#[cfg(feature = "quic")]
#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_quic_mtls_rejects_wrong_path_prefix(no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let (client_certificate, client_key, client_ca_certificates) = build_client_mtls_material("expected-quic-cn");
    let server_h = tokio::spawn(
        server_quic(dns_resolver.clone(), quic_server_tls(Some(client_ca_certificates))).serve(no_restrictions, tokio_util::sync::CancellationToken::new()),
    );
    defer! { server_h.abort(); };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let client_quic = client_quic(dns_resolver, 0, "wrong-prefix", Some(client_certificate), Some(client_key)).await;

    let _endpoint_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let remote_addr = RemoteAddr {
        protocol: LocalProtocol::Tcp { proxy_protocol: false },
        host: ENDPOINT_LISTEN.1.clone(),
        port: ENDPOINT_LISTEN.0.port(),
    };

    let err = match crate::tunnel::transport::quic::connect(Uuid::now_v7(), &client_quic, &remote_addr).await {
        Ok(_) => panic!("QUIC tunnel unexpectedly succeeded with the wrong mTLS path prefix"),
        Err(err) => err,
    };
    assert!(format!("{err:#}").contains("bad upgrade path"));
}

//#[rstest]
//#[timeout(Duration::from_secs(10))]
//#[tokio::test]
//async fn test_socks5_tunnel(
//    #[future] client_ws: WsClient,
//    server_no_tls: WsServer,
//    no_restrictions: RestrictionsRules,
//    dns_resolver: DnsResolver,
//) {
//    let server_h = tokio::spawn(server_no_tls.serve(no_restrictions, tokio_util::sync::CancellationToken::new()));
//    defer! { server_h.abort(); };
//
//    let client_ws = client_ws.await;
//
//    let server = Socks5TunnelListener::new(TUNNEL_LISTEN.0, None, None).await.unwrap();
//    tokio::spawn(async move { client_ws.run_tunnel(server).await.unwrap(); });
//
//    let socks5_listener = protocols::socks5::run_server(ENDPOINT_LISTEN.0, None, None).await.unwrap();
//    let mut client = protocols::tcp::connect(&TUNNEL_LISTEN.1, TUNNEL_LISTEN.0.port(), None, Duration::from_secs(10), &dns_resolver).await.unwrap();
//
//    client.write_all(b"Hello").await.unwrap();
//    pin!(socks5_listener);
//    let (dd, _) = socks5_listener.next().await.unwrap().unwrap();
//    let (mut read, mut write) = dd.into_split();
//    let mut buf = BytesMut::new();
//    read.read_buf(&mut buf).await.unwrap();
//    assert_eq!(&buf[..5], b"Hello");
//    buf.clear();
//
//    write.write_all(b"world!").await.unwrap();
//    client.read_buf(&mut buf).await.unwrap();
//    assert_eq!(&buf[..6], b"world!");
//}

#[cfg(feature = "quic")]
#[rstest]
#[timeout(Duration::from_secs(10))]
#[tokio::test]
#[serial]
async fn test_tcp_tunnel_quic_0rtt(no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let server_config = WsServerConfig {
        socket_so_mark: SoMark::new(None),
        bind: QUIC_SERVER_TCP_BIND,
        websocket_ping_frequency: Some(Duration::from_secs(10)),
        timeout_connect: Duration::from_secs(10),
        websocket_mask_frame: false,
        tls: Some(quic_server_tls(None)),
        dns_resolver: dns_resolver.clone(),
        restriction_config: None,
        http_proxy: None,
        remote_server_idle_timeout: Duration::from_secs(30),
        quic_bind: Some(QUIC_SERVER_UDP_BIND),
        quic_0rtt: true,
        quic_keep_alive: Some(Duration::from_secs(15)),
        quic_max_idle_timeout: Some(Duration::from_secs(60)),
        quic_max_streams: 1024,
        quic_datagram_buffer_size: 1024 * 1024,
        quic_disable_migration: false,
    };
    let srv_conf = WsServer::new(server_config, DefaultTokioExecutor::default());
    let server_h = tokio::spawn(srv_conf.serve(no_restrictions, tokio_util::sync::CancellationToken::new()));
    defer! { server_h.abort(); };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut client_quic = client_quic(dns_resolver.clone(), 1, "wstunnel", None, None).await;
    let mut c_cfg = (*client_quic.config).clone();
    c_cfg.quic_0rtt = true;
    client_quic.config = Arc::new(c_cfg);

    let server_1 = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1.clone(), ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    let client_quic_1 = client_quic.clone();
    tokio::spawn(async move {
        client_quic_1.run_tunnel(server_1).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let mut client_sock_1 = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client_sock_1.write_all(b"Hello").await.unwrap();
    let mut dd_1 = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    dd_1.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..5], b"Hello");

    // give a little time for ticket to arrive
    tokio::time::sleep(Duration::from_millis(200)).await;

    // drop connection state to form a new connection next
    client_quic.quic_state.lock().await.take();

    let server_2 = TcpTunnelListener::new(
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 9997)),
        (ENDPOINT_LISTEN.1.clone(), ENDPOINT_LISTEN.0.port()),
        false,
    )
    .await
    .unwrap();
    let client_quic_2 = client_quic.clone();
    tokio::spawn(async move {
        client_quic_2.run_tunnel(server_2).await.unwrap();
    });

    let mut client_sock_2 = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        9997,
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    client_sock_2.write_all(b"Hello 2").await.unwrap();
    let mut dd_2 = tcp_listener.next().await.unwrap().unwrap();
    buf.clear();
    dd_2.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..7], b"Hello 2");

    tokio::time::sleep(Duration::from_millis(100)).await;

    let accepted = client_quic
        .quic_state
        .lock()
        .await
        .as_ref()
        .unwrap()
        .zero_rtt_accepted
        .load(std::sync::atomic::Ordering::SeqCst);
    assert!(accepted, "Expected 0-RTT to be accepted on the second connection");
}

/// Connection migration: rebind the client's QUIC endpoint to a different local UDP port
/// mid-tunnel and verify the open bi-stream survives. QUIC's connection ID + path
/// validation should keep bytes flowing despite the 4-tuple change. This is the CI-friendly
/// equivalent of a real Wi-Fi → LTE handover.
#[cfg(feature = "quic")]
#[rstest]
#[timeout(Duration::from_secs(15))]
#[tokio::test]
#[serial]
async fn test_quic_connection_migration(no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let server_h = tokio::spawn(
        server_quic(dns_resolver.clone(), quic_server_tls(None))
            .serve(no_restrictions, tokio_util::sync::CancellationToken::new()),
    );
    defer! { server_h.abort(); };

    tokio::time::sleep(Duration::from_millis(100)).await;
    let client_quic = client_quic(dns_resolver.clone(), 1, "wstunnel", None, None).await;

    let server = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1.clone(), ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    let client_runner = client_quic.clone();
    tokio::spawn(async move {
        client_runner.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let mut client_sock = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    // Establish the QUIC connection + bi-stream by exchanging some bytes first.
    client_sock.write_all(b"before").await.unwrap();
    let mut server_sock = tcp_listener.next().await.unwrap().unwrap();
    let mut buf = BytesMut::new();
    server_sock.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"before");
    buf.clear();

    server_sock.write_all(b"reply1").await.unwrap();
    client_sock.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..6], b"reply1");
    buf.clear();

    // Rebind the client QUIC endpoint to a new local UDP port. The 4-tuple changes; QUIC's
    // CID + path validation should keep the open bi-stream alive.
    {
        let state_guard = client_quic.quic_state.lock().await;
        let state = state_guard
            .as_ref()
            .expect("QUIC client state should exist after the first exchange");
        let new_socket = std::net::UdpSocket::bind("127.0.0.1:0")
            .expect("failed to bind replacement UDP socket for migration test");
        state
            ._endpoint
            .rebind(new_socket)
            .expect("quinn endpoint rebind failed");
    }

    // Sending client→server first triggers path validation; the server learns the new
    // 4-tuple and migrates. Then verify both directions still work.
    client_sock.write_all(b"after-migration").await.unwrap();
    server_sock.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..15], b"after-migration");
    buf.clear();

    server_sock.write_all(b"post-reply").await.unwrap();
    client_sock.read_buf(&mut buf).await.unwrap();
    assert_eq!(&buf[..10], b"post-reply");
}

/// Lossy-link test: put a UDP relay between client and server that drops 5% of packets in
/// each direction and verify a moderate payload still round-trips intact through a QUIC
/// tunnel. Validates that QUIC's per-packet retransmit machinery compensates for loss
/// without wstunnel framing getting in the way.
#[cfg(feature = "quic")]
#[rstest]
#[timeout(Duration::from_secs(20))]
#[tokio::test]
#[serial]
async fn test_quic_tunnel_survives_packet_loss(no_restrictions: RestrictionsRules, dns_resolver: DnsResolver) {
    let server_h = tokio::spawn(
        server_quic(dns_resolver.clone(), quic_server_tls(None))
            .serve(no_restrictions, tokio_util::sync::CancellationToken::new()),
    );
    defer! { server_h.abort(); };

    tokio::time::sleep(Duration::from_millis(100)).await;

    let relay_addr = spawn_lossy_udp_relay(QUIC_SERVER_UDP_BIND, 5).await;
    let client_quic = client_quic_at_port(dns_resolver.clone(), relay_addr.port()).await;

    let server = TcpTunnelListener::new(TUNNEL_LISTEN.0, (ENDPOINT_LISTEN.1.clone(), ENDPOINT_LISTEN.0.port()), false)
        .await
        .unwrap();
    let client_runner = client_quic.clone();
    tokio::spawn(async move {
        client_runner.run_tunnel(server).await.unwrap();
    });

    let mut tcp_listener = protocols::tcp::run_server(ENDPOINT_LISTEN.0, false).await.unwrap();
    let mut client_sock = protocols::tcp::connect(
        &TUNNEL_LISTEN.1,
        TUNNEL_LISTEN.0.port(),
        SoMark::new(None),
        Duration::from_secs(10),
        &dns_resolver,
    )
    .await
    .unwrap();

    let payload: Vec<u8> = (0u32..16 * 1024).map(|i| (i % 251) as u8).collect();
    let send_payload = payload.clone();
    let writer_task = tokio::spawn(async move {
        client_sock.write_all(&send_payload).await.unwrap();
        client_sock.flush().await.unwrap();
        client_sock
    });

    let mut server_sock = tcp_listener.next().await.unwrap().unwrap();
    let mut received = Vec::with_capacity(payload.len());
    while received.len() < payload.len() {
        let mut chunk = [0u8; 4096];
        let n = server_sock.read(&mut chunk).await.unwrap();
        assert!(n > 0, "TCP stream closed before all bytes were received");
        received.extend_from_slice(&chunk[..n]);
    }
    assert_eq!(received, payload, "payload corrupted under packet loss");
    let _ = writer_task.await.unwrap();
}
