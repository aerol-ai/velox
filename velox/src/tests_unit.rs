/// Comprehensive unit tests for velox core modules.
/// These tests don't require Docker, network, or external services.
///
/// Test coverage areas:
///   1. LocalProtocol enum methods (is_reverse_tunnel, is_dynamic_reverse_tunnel)
///   2. RemoteAddr / to_host_port / try_to_sock_addr
///   3. JWT encoding/decoding round-trips
///   4. JwtTunnelConfig → RemoteAddr conversion
///   5. TransportScheme parsing, display, ALPN
///   6. Restriction rules construction & matching
///   7. AllowTunnelConfig / AllowReverseTunnelConfig validation
///   8. RestrictionConfig filter logic (PathPrefix, Authorization, Any)
///   9. Config parsers (tunnel_arg, reverse_tunnel_arg, duration, http_headers, credentials, server_url)
///  10. Server utils (extract_path_prefix, inject_cookie, find_mapped_port)
///  11. SoMark construction
///  12. Embedded certificate generation
///  13. Protocol type conversions (LocalProtocol → TunnelConfigProtocol / ReverseTunnelConfigProtocol)
///  14. Edge cases and error paths
#[cfg(test)]
mod tests {
    // ──────────────────────────────────────────────────────────────────────
    // Imports
    // ──────────────────────────────────────────────────────────────────────
    use crate::restrictions::types::{
        AllowConfig, AllowReverseTunnelConfig, AllowTunnelConfig, MatchConfig, RestrictionConfig, RestrictionsRules,
        ReverseTunnelConfigProtocol, TunnelConfigProtocol, default_cidr, default_host,
    };
    use crate::tunnel::transport::{JwtTunnelConfig, jwt_token_to_tunnel, tunnel_to_jwt_token};
    use crate::tunnel::transport::TransportScheme;
    use crate::tunnel::{LocalProtocol, RemoteAddr, to_host_port, try_to_sock_addr};
    use ipnet::IpNet;
    use regex::Regex;
    use std::collections::HashMap;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
    use std::path::PathBuf;
    use std::time::Duration;
    use url::Host;
    use uuid::Uuid;

    fn ensure_crypto_provider() {
        use std::sync::Once;
        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let _ = tokio_rustls::rustls::crypto::aws_lc_rs::default_provider().install_default();
            let _ = jsonwebtoken::crypto::aws_lc::DEFAULT_PROVIDER.install_default();
        });
    }

    // ======================================================================
    //  1. LocalProtocol — is_reverse_tunnel
    // ======================================================================

    #[test]
    fn test_tcp_is_not_reverse() {
        let p = LocalProtocol::Tcp { proxy_protocol: false };
        assert!(!p.is_reverse_tunnel());
    }

    #[test]
    fn test_udp_is_not_reverse() {
        let p = LocalProtocol::Udp { timeout: None };
        assert!(!p.is_reverse_tunnel());
    }

    #[test]
    fn test_stdio_is_not_reverse() {
        let p = LocalProtocol::Stdio { proxy_protocol: false };
        assert!(!p.is_reverse_tunnel());
    }

    #[test]
    fn test_socks5_is_not_reverse() {
        let p = LocalProtocol::Socks5 {
            timeout: None,
            credentials: None,
        };
        assert!(!p.is_reverse_tunnel());
    }

    #[test]
    fn test_http_proxy_is_not_reverse() {
        let p = LocalProtocol::HttpProxy {
            timeout: None,
            credentials: None,
            proxy_protocol: false,
        };
        assert!(!p.is_reverse_tunnel());
    }

    #[test]
    fn test_tproxy_tcp_is_not_reverse() {
        assert!(!LocalProtocol::TProxyTcp.is_reverse_tunnel());
    }

    #[test]
    fn test_tproxy_udp_is_not_reverse() {
        let p = LocalProtocol::TProxyUdp { timeout: None };
        assert!(!p.is_reverse_tunnel());
    }

    #[test]
    fn test_unix_is_not_reverse() {
        let p = LocalProtocol::Unix {
            path: PathBuf::from("/tmp/sock"),
            proxy_protocol: false,
        };
        assert!(!p.is_reverse_tunnel());
    }

    #[test]
    fn test_reverse_tcp_is_reverse() {
        assert!(LocalProtocol::ReverseTcp.is_reverse_tunnel());
    }

    #[test]
    fn test_reverse_udp_is_reverse() {
        let p = LocalProtocol::ReverseUdp {
            timeout: Some(Duration::from_secs(30)),
        };
        assert!(p.is_reverse_tunnel());
    }

    #[test]
    fn test_reverse_socks5_is_reverse() {
        let p = LocalProtocol::ReverseSocks5 {
            timeout: None,
            credentials: None,
        };
        assert!(p.is_reverse_tunnel());
    }

    #[test]
    fn test_reverse_http_proxy_is_reverse() {
        let p = LocalProtocol::ReverseHttpProxy {
            timeout: None,
            credentials: None,
        };
        assert!(p.is_reverse_tunnel());
    }

    #[test]
    fn test_reverse_unix_is_reverse() {
        let p = LocalProtocol::ReverseUnix {
            path: PathBuf::from("/tmp/sock"),
        };
        assert!(p.is_reverse_tunnel());
    }

    // ======================================================================
    //  2. LocalProtocol — is_dynamic_reverse_tunnel
    // ======================================================================

    #[test]
    fn test_reverse_socks5_is_dynamic_reverse() {
        let p = LocalProtocol::ReverseSocks5 {
            timeout: None,
            credentials: None,
        };
        assert!(p.is_dynamic_reverse_tunnel());
    }

    #[test]
    fn test_reverse_http_proxy_is_dynamic_reverse() {
        let p = LocalProtocol::ReverseHttpProxy {
            timeout: None,
            credentials: None,
        };
        assert!(p.is_dynamic_reverse_tunnel());
    }

    #[test]
    fn test_reverse_tcp_is_not_dynamic_reverse() {
        assert!(!LocalProtocol::ReverseTcp.is_dynamic_reverse_tunnel());
    }

    #[test]
    fn test_reverse_udp_is_not_dynamic_reverse() {
        let p = LocalProtocol::ReverseUdp { timeout: None };
        assert!(!p.is_dynamic_reverse_tunnel());
    }

    #[test]
    fn test_reverse_unix_is_not_dynamic_reverse() {
        let p = LocalProtocol::ReverseUnix {
            path: PathBuf::from("/tmp/x"),
        };
        assert!(!p.is_dynamic_reverse_tunnel());
    }

    #[test]
    fn test_tcp_is_not_dynamic_reverse() {
        let p = LocalProtocol::Tcp { proxy_protocol: false };
        assert!(!p.is_dynamic_reverse_tunnel());
    }

    // ======================================================================
    //  3. to_host_port / try_to_sock_addr
    // ======================================================================

    #[test]
    fn test_to_host_port_ipv4() {
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 8080));
        let (host, port) = to_host_port(addr);
        assert_eq!(host, Host::<String>::Ipv4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(port, 8080);
    }

    #[test]
    fn test_to_host_port_ipv6() {
        let addr = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0));
        let (host, port) = to_host_port(addr);
        assert_eq!(host, Host::<String>::Ipv6(Ipv6Addr::LOCALHOST));
        assert_eq!(port, 443);
    }

    #[test]
    fn test_try_to_sock_addr_ipv4() {
        let result = try_to_sock_addr((Host::Ipv4(Ipv4Addr::LOCALHOST), 80));
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 80))
        );
    }

    #[test]
    fn test_try_to_sock_addr_ipv6() {
        let result = try_to_sock_addr((Host::Ipv6(Ipv6Addr::LOCALHOST), 443));
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 443, 0, 0))
        );
    }

    #[test]
    fn test_try_to_sock_addr_domain_fails() {
        let result = try_to_sock_addr((Host::Domain("example.com".into()), 443));
        assert!(result.is_err());
    }

    // ======================================================================
    //  4. JWT round-trip (encode → decode)
    // ======================================================================

    #[test]
    fn test_jwt_round_trip_tcp() {
        ensure_crypto_provider();
        let id = Uuid::now_v7();
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("example.com".into()),
            port: 443,
        };
        let token = tunnel_to_jwt_token(id, &remote);
        assert!(!token.is_empty());

        let decoded = jwt_token_to_tunnel(&token).unwrap();
        assert_eq!(decoded.claims.rp, 443);
        assert_eq!(decoded.claims.r, "example.com");
        assert_eq!(decoded.claims.id, id.to_string());
    }

    #[test]
    fn test_jwt_round_trip_udp() {
        ensure_crypto_provider();
        let id = Uuid::now_v7();
        let remote = RemoteAddr {
            protocol: LocalProtocol::Udp {
                timeout: Some(Duration::from_secs(30)),
            },
            host: Host::Ipv4(Ipv4Addr::new(1, 1, 1, 1)),
            port: 53,
        };
        let token = tunnel_to_jwt_token(id, &remote);
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        assert_eq!(decoded.claims.rp, 53);
        assert_eq!(decoded.claims.r, "1.1.1.1");
    }

    #[test]
    fn test_jwt_round_trip_reverse_tcp() {
        ensure_crypto_provider();
        let id = Uuid::now_v7();
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 9999,
        };
        let token = tunnel_to_jwt_token(id, &remote);
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        assert_eq!(decoded.claims.rp, 9999);
    }

    #[test]
    fn test_jwt_round_trip_reverse_udp() {
        ensure_crypto_provider();
        let id = Uuid::now_v7();
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUdp {
                timeout: Some(Duration::from_secs(10)),
            },
            host: Host::Ipv6(Ipv6Addr::LOCALHOST),
            port: 5353,
        };
        let token = tunnel_to_jwt_token(id, &remote);
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        assert_eq!(decoded.claims.rp, 5353);
        assert_eq!(decoded.claims.r, "[::1]");
    }

    #[test]
    fn test_jwt_invalid_token_fails() {
        ensure_crypto_provider();
        let result = jwt_token_to_tunnel("not-a-valid-jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_empty_token_fails() {
        ensure_crypto_provider();
        let result = jwt_token_to_tunnel("");
        assert!(result.is_err());
    }

    // ======================================================================
    //  5. JwtTunnelConfig → RemoteAddr conversion
    // ======================================================================

    #[test]
    fn test_jwt_config_to_remote_addr_domain() {
        let cfg = JwtTunnelConfig {
            id: Uuid::nil().to_string(),
            p: LocalProtocol::Tcp { proxy_protocol: false },
            r: "google.com".to_string(),
            rp: 443,
        };
        let remote: RemoteAddr = cfg.try_into().unwrap();
        assert_eq!(remote.host, Host::<String>::Domain("google.com".into()));
        assert_eq!(remote.port, 443);
    }

    #[test]
    fn test_jwt_config_to_remote_addr_ipv4() {
        let cfg = JwtTunnelConfig {
            id: Uuid::nil().to_string(),
            p: LocalProtocol::ReverseTcp,
            r: "192.168.1.1".to_string(),
            rp: 8080,
        };
        let remote: RemoteAddr = cfg.try_into().unwrap();
        assert_eq!(remote.host, Host::<String>::Ipv4(Ipv4Addr::new(192, 168, 1, 1)));
        assert_eq!(remote.port, 8080);
    }

    #[test]
    fn test_jwt_config_to_remote_addr_ipv6() {
        let cfg = JwtTunnelConfig {
            id: Uuid::nil().to_string(),
            p: LocalProtocol::Udp { timeout: None },
            r: "[::1]".to_string(),
            rp: 53,
        };
        let remote: RemoteAddr = cfg.try_into().unwrap();
        assert_eq!(remote.host, Host::<String>::Ipv6(Ipv6Addr::LOCALHOST));
    }

    #[test]
    fn test_jwt_config_invalid_host_fails() {
        let cfg = JwtTunnelConfig {
            id: Uuid::nil().to_string(),
            p: LocalProtocol::Tcp { proxy_protocol: false },
            r: "[invalid".to_string(),
            rp: 80,
        };
        let result: Result<RemoteAddr, _> = cfg.try_into();
        assert!(result.is_err());
    }

    // ======================================================================
    //  6. TransportScheme — FromStr / Display / to_str / alpn
    // ======================================================================

    #[test]
    fn test_transport_scheme_from_str_ws() {
        let s: TransportScheme = "ws".parse().unwrap();
        assert_eq!(s.to_str(), "ws");
    }

    #[test]
    fn test_transport_scheme_from_str_wss() {
        let s: TransportScheme = "wss".parse().unwrap();
        assert_eq!(s.to_str(), "wss");
    }

    #[test]
    fn test_transport_scheme_from_str_http() {
        let s: TransportScheme = "http".parse().unwrap();
        assert_eq!(s.to_str(), "http");
    }

    #[test]
    fn test_transport_scheme_from_str_https() {
        let s: TransportScheme = "https".parse().unwrap();
        assert_eq!(s.to_str(), "https");
    }

    #[test]
    fn test_transport_scheme_from_str_invalid() {
        let result: Result<TransportScheme, ()> = "ftp".parse();
        assert!(result.is_err());
    }

    #[test]
    fn test_transport_scheme_display() {
        let s = TransportScheme::Https;
        assert_eq!(format!("{s}"), "https");
    }

    #[test]
    fn test_transport_scheme_alpn_ws_empty() {
        assert!(TransportScheme::Ws.alpn_protocols().is_empty());
    }

    #[test]
    fn test_transport_scheme_alpn_wss_http11() {
        let alpn = TransportScheme::Wss.alpn_protocols();
        assert_eq!(alpn, vec![b"http/1.1".to_vec()]);
    }

    #[test]
    fn test_transport_scheme_alpn_http_empty() {
        assert!(TransportScheme::Http.alpn_protocols().is_empty());
    }

    #[test]
    fn test_transport_scheme_alpn_https_h2() {
        let alpn = TransportScheme::Https.alpn_protocols();
        assert_eq!(alpn, vec![b"h2".to_vec()]);
    }

    // ======================================================================
    //  7. Restriction rules — from_path_prefix
    // ======================================================================

    #[test]
    fn test_restrictions_empty_prefix_empty_restrict() {
        let rules = RestrictionsRules::from_path_prefix(&[], &[]).unwrap();
        assert_eq!(rules.restrictions.len(), 1);
        assert_eq!(rules.restrictions[0].name, "Allow All");
        // Should have both Tunnel and ReverseTunnel allow entries
        assert_eq!(rules.restrictions[0].allow.len(), 2);
    }

    #[test]
    fn test_restrictions_multiple_path_prefixes() {
        let prefixes = vec!["/a".to_string(), "/b".to_string(), "/c".to_string()];
        let rules = RestrictionsRules::from_path_prefix(&prefixes, &[]).unwrap();
        assert_eq!(rules.restrictions.len(), 3);
        assert_eq!(rules.restrictions[0].name, "Allow path prefix /a");
        assert_eq!(rules.restrictions[1].name, "Allow path prefix /b");
        assert_eq!(rules.restrictions[2].name, "Allow path prefix /c");
    }

    #[test]
    fn test_restrictions_with_ipv6_restrict_to() {
        let restrict_to = vec![("::1".to_string(), 53)];
        let rules = RestrictionsRules::from_path_prefix(&[], &restrict_to).unwrap();
        assert_eq!(rules.restrictions.len(), 1);
        if let AllowConfig::Tunnel(cfg) = &rules.restrictions[0].allow[0] {
            assert_eq!(cfg.cidr.len(), 1);
            assert_eq!(cfg.cidr[0], IpNet::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 128).unwrap());
        } else {
            panic!("Expected Tunnel config");
        }
    }

    #[test]
    fn test_restrictions_multiple_restrict_to() {
        let restrict_to = vec![
            ("example.com".to_string(), 443),
            ("10.0.0.1".to_string(), 80),
        ];
        let rules = RestrictionsRules::from_path_prefix(&[], &restrict_to).unwrap();
        assert_eq!(rules.restrictions[0].allow.len(), 2);
    }

    // ======================================================================
    //  8. AllowTunnelConfig — is_allowed
    // ======================================================================

    #[test]
    fn test_tunnel_allowed_with_empty_filters() {
        let config = AllowTunnelConfig {
            protocol: vec![],
            port: vec![],
            host: default_host(),
            cidr: default_cidr(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::new(8, 8, 8, 8)),
            port: 443,
        };
        assert!(AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_tunnel_blocked_wrong_protocol() {
        let config = AllowTunnelConfig {
            protocol: vec![TunnelConfigProtocol::Udp],
            port: vec![],
            host: default_host(),
            cidr: default_cidr(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 80,
        };
        assert!(!AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_tunnel_allowed_correct_port_range() {
        let config = AllowTunnelConfig {
            protocol: vec![],
            port: vec![80..=90],
            host: default_host(),
            cidr: default_cidr(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 85,
        };
        assert!(AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_tunnel_blocked_port_out_of_range() {
        let config = AllowTunnelConfig {
            protocol: vec![],
            port: vec![80..=90],
            host: default_host(),
            cidr: default_cidr(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 91,
        };
        assert!(!AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_tunnel_blocked_reverse_protocol() {
        let config = AllowTunnelConfig {
            protocol: vec![],
            port: vec![],
            host: default_host(),
            cidr: default_cidr(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 80,
        };
        assert!(!AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_tunnel_allowed_domain_host_match() {
        let config = AllowTunnelConfig {
            protocol: vec![],
            port: vec![],
            host: Regex::new(r"^.*\.example\.com$").unwrap(),
            cidr: vec![],
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("sub.example.com".into()),
            port: 443,
        };
        assert!(AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_tunnel_blocked_domain_host_no_match() {
        let config = AllowTunnelConfig {
            protocol: vec![],
            port: vec![],
            host: Regex::new(r"^example\.com$").unwrap(),
            cidr: vec![],
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("other.com".into()),
            port: 443,
        };
        assert!(!AllowConfig::from(config).is_allowed(&remote));
    }

    // ======================================================================
    //  9. AllowReverseTunnelConfig — is_allowed
    // ======================================================================

    #[test]
    fn test_reverse_tunnel_allowed_empty_filters() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![],
            port: vec![],
            cidr: default_cidr(),
            port_mapping: HashMap::new(),
            unix_path: default_host(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 8080,
        };
        assert!(AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_reverse_tunnel_blocked_non_reverse_protocol() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![],
            port: vec![],
            cidr: default_cidr(),
            port_mapping: HashMap::new(),
            unix_path: default_host(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 80,
        };
        assert!(!AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_reverse_tunnel_blocked_domain_host() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![],
            port: vec![],
            cidr: default_cidr(),
            port_mapping: HashMap::new(),
            unix_path: default_host(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseTcp,
            host: Host::Domain("example.com".into()),
            port: 80,
        };
        assert!(!AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_reverse_unix_tunnel_allowed_path_match() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![],
            port: vec![],
            cidr: vec![],
            port_mapping: HashMap::new(),
            unix_path: Regex::new(r"^/var/run/.*\.sock$").unwrap(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix {
                path: PathBuf::from("/var/run/app.sock"),
            },
            host: Host::Domain("ignored".into()),
            port: 0,
        };
        assert!(AllowConfig::from(config).is_allowed(&remote));
    }

    #[test]
    fn test_reverse_unix_tunnel_blocked_path_no_match() {
        let config = AllowReverseTunnelConfig {
            protocol: vec![],
            port: vec![],
            cidr: vec![],
            port_mapping: HashMap::new(),
            unix_path: Regex::new(r"^/var/run/.*\.sock$").unwrap(),
        };
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix {
                path: PathBuf::from("/tmp/evil.sock"),
            },
            host: Host::Domain("ignored".into()),
            port: 0,
        };
        assert!(!AllowConfig::from(config).is_allowed(&remote));
    }

    // ======================================================================
    // 10. RestrictionConfig filter
    // ======================================================================

    #[test]
    fn test_restriction_filter_any_always_matches() {
        let cfg = RestrictionConfig {
            name: "test".into(),
            r#match: vec![MatchConfig::Any],
            allow: vec![],
        };
        assert!(cfg.filter("anything", None));
        assert!(cfg.filter("anything", Some("bearer xyz")));
    }

    #[test]
    fn test_restriction_filter_path_prefix_matches() {
        let cfg = RestrictionConfig {
            name: "test".into(),
            r#match: vec![MatchConfig::PathPrefix(Regex::new(r"^/v1$").unwrap())],
            allow: vec![],
        };
        assert!(cfg.filter("/v1", None));
        assert!(!cfg.filter("/v2", None));
    }

    #[test]
    fn test_restriction_filter_authorization_matches() {
        let cfg = RestrictionConfig {
            name: "test".into(),
            r#match: vec![MatchConfig::Authorization(Regex::new(r"^Bearer secret$").unwrap())],
            allow: vec![],
        };
        assert!(cfg.filter("anything", Some("Bearer secret")));
        assert!(!cfg.filter("anything", Some("Bearer wrong")));
        assert!(!cfg.filter("anything", None));
    }

    #[test]
    fn test_restriction_filter_combined_requires_all() {
        let cfg = RestrictionConfig {
            name: "test".into(),
            r#match: vec![
                MatchConfig::PathPrefix(Regex::new(r"^/v1$").unwrap()),
                MatchConfig::Authorization(Regex::new(r"^Bearer token$").unwrap()),
            ],
            allow: vec![],
        };
        // both must match
        assert!(cfg.filter("/v1", Some("Bearer token")));
        // only path matches
        assert!(!cfg.filter("/v1", Some("Bearer wrong")));
        // only auth matches
        assert!(!cfg.filter("/v2", Some("Bearer token")));
    }

    // ======================================================================
    // 11. validate_tunnel (full integration of restrictions)
    // ======================================================================

    fn make_restrictions() -> RestrictionsRules {
        RestrictionsRules {
            restrictions: vec![
                RestrictionConfig {
                    name: "web-only".into(),
                    r#match: vec![MatchConfig::PathPrefix(Regex::new(r"^/web$").unwrap())],
                    allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                        protocol: vec![TunnelConfigProtocol::Tcp],
                        port: vec![80..=80, 443..=443],
                        host: Regex::new(r".*").unwrap(),
                        cidr: default_cidr(),
                    })],
                },
                RestrictionConfig {
                    name: "catch-all".into(),
                    r#match: vec![MatchConfig::Any],
                    allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                        protocol: vec![],
                        port: vec![],
                        host: Regex::new(r"^internal\.local$").unwrap(),
                        cidr: vec![],
                    })],
                },
            ],
        }
    }

    #[test]
    fn test_validate_tunnel_matches_first_rule() {
        let rules = make_restrictions();
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 443,
        };
        let matched = crate::tunnel::server::utils::validate_tunnel(&remote, "/web", None, &rules);
        assert_eq!(matched.unwrap().name, "web-only");
    }

    #[test]
    fn test_validate_tunnel_falls_through_to_catch_all() {
        let rules = make_restrictions();
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("internal.local".into()),
            port: 9999,
        };
        let matched = crate::tunnel::server::utils::validate_tunnel(&remote, "/other", None, &rules);
        assert_eq!(matched.unwrap().name, "catch-all");
    }

    #[test]
    fn test_validate_tunnel_no_rule_matches() {
        let rules = make_restrictions();
        let remote = RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Domain("external.com".into()),
            port: 9999,
        };
        let matched = crate::tunnel::server::utils::validate_tunnel(&remote, "/other", None, &rules);
        assert!(matched.is_none());
    }

    // ======================================================================
    // 12. Protocol type conversions
    // ======================================================================

    #[test]
    fn test_tcp_to_tunnel_config_protocol() {
        let p = LocalProtocol::Tcp { proxy_protocol: true };
        assert_eq!(TunnelConfigProtocol::from(&p), TunnelConfigProtocol::Tcp);
    }

    #[test]
    fn test_udp_to_tunnel_config_protocol() {
        let p = LocalProtocol::Udp { timeout: None };
        assert_eq!(TunnelConfigProtocol::from(&p), TunnelConfigProtocol::Udp);
    }

    #[test]
    fn test_socks5_to_tunnel_config_protocol_unknown() {
        let p = LocalProtocol::Socks5 {
            timeout: None,
            credentials: None,
        };
        assert_eq!(TunnelConfigProtocol::from(&p), TunnelConfigProtocol::Unknown);
    }

    #[test]
    fn test_reverse_tcp_to_reverse_config_protocol() {
        assert_eq!(
            ReverseTunnelConfigProtocol::from(&LocalProtocol::ReverseTcp),
            ReverseTunnelConfigProtocol::Tcp
        );
    }

    #[test]
    fn test_reverse_udp_to_reverse_config_protocol() {
        let p = LocalProtocol::ReverseUdp { timeout: None };
        assert_eq!(ReverseTunnelConfigProtocol::from(&p), ReverseTunnelConfigProtocol::Udp);
    }

    #[test]
    fn test_reverse_socks5_to_reverse_config_protocol() {
        let p = LocalProtocol::ReverseSocks5 {
            timeout: None,
            credentials: None,
        };
        assert_eq!(
            ReverseTunnelConfigProtocol::from(&p),
            ReverseTunnelConfigProtocol::Socks5
        );
    }

    #[test]
    fn test_reverse_unix_to_reverse_config_protocol() {
        let p = LocalProtocol::ReverseUnix {
            path: PathBuf::from("/x"),
        };
        assert_eq!(
            ReverseTunnelConfigProtocol::from(&p),
            ReverseTunnelConfigProtocol::Unix
        );
    }

    #[test]
    fn test_reverse_http_proxy_to_reverse_config_protocol() {
        let p = LocalProtocol::ReverseHttpProxy {
            timeout: None,
            credentials: None,
        };
        assert_eq!(
            ReverseTunnelConfigProtocol::from(&p),
            ReverseTunnelConfigProtocol::HttpProxy
        );
    }

    #[test]
    fn test_tcp_to_reverse_config_protocol_unknown() {
        let p = LocalProtocol::Tcp { proxy_protocol: false };
        assert_eq!(
            ReverseTunnelConfigProtocol::from(&p),
            ReverseTunnelConfigProtocol::Unknown
        );
    }

    #[test]
    fn test_http_proxy_to_tunnel_config_protocol_unknown() {
        let p = LocalProtocol::HttpProxy {
            timeout: None,
            credentials: None,
            proxy_protocol: false,
        };
        assert_eq!(TunnelConfigProtocol::from(&p), TunnelConfigProtocol::Unknown);
    }

    // ======================================================================
    // 13. SoMark
    // ======================================================================

    #[test]
    fn test_somark_new_none() {
        let _mark = crate::somark::SoMark::new(None);
        // On non-Linux, this is a zero-size struct — just verify it constructs
    }

    #[test]
    fn test_somark_new_some() {
        let _mark = crate::somark::SoMark::new(Some(42));
    }

    // ======================================================================
    // 14. Embedded certificate
    // ======================================================================

    #[test]
    fn test_embedded_certificate_generates_valid_cert() {
        let (certs, key) = &*crate::embedded_certificate::TLS_CERTIFICATE;
        assert!(!certs.is_empty(), "Should generate at least one certificate");
        assert!(!key.secret_der().is_empty(), "Private key should not be empty");
    }

    #[test]
    fn test_embedded_certificate_single_cert() {
        let (certs, _) = &*crate::embedded_certificate::TLS_CERTIFICATE;
        assert_eq!(certs.len(), 1, "Should generate exactly one self-signed certificate");
    }

    // ======================================================================
    // 15. LocalProtocol — serialization round-trips (serde JSON)
    // ======================================================================

    #[test]
    fn test_local_protocol_serde_tcp() {
        let p = LocalProtocol::Tcp { proxy_protocol: true };
        let json = serde_json::to_string(&p).unwrap();
        let p2: LocalProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn test_local_protocol_serde_udp_with_timeout() {
        let p = LocalProtocol::Udp {
            timeout: Some(Duration::from_secs(30)),
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: LocalProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn test_local_protocol_serde_reverse_socks5() {
        let p = LocalProtocol::ReverseSocks5 {
            timeout: Some(Duration::from_secs(10)),
            credentials: Some(("admin".into(), "pass".into())),
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: LocalProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn test_local_protocol_serde_reverse_unix() {
        let p = LocalProtocol::ReverseUnix {
            path: PathBuf::from("/tmp/test.sock"),
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: LocalProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn test_local_protocol_serde_http_proxy() {
        let p = LocalProtocol::HttpProxy {
            timeout: None,
            credentials: Some(("user".into(), "pw".into())),
            proxy_protocol: true,
        };
        let json = serde_json::to_string(&p).unwrap();
        let p2: LocalProtocol = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    // ======================================================================
    // 16. Config parsers (requires feature = "clap")
    // ======================================================================

    #[cfg(feature = "clap")]
    mod parser_tests {
        use crate::config::parsers::*;
        use crate::tunnel::LocalProtocol;
        use std::time::Duration;
        use url::Host;

        // --- parse_duration_sec ---

        #[test]
        fn test_parse_duration_plain_seconds() {
            let d = parse_duration_sec("42").unwrap();
            assert_eq!(d, Duration::from_secs(42));
        }

        #[test]
        fn test_parse_duration_suffix_s() {
            let d = parse_duration_sec("10s").unwrap();
            assert_eq!(d, Duration::from_secs(10));
        }

        #[test]
        fn test_parse_duration_suffix_m() {
            let d = parse_duration_sec("2m").unwrap();
            assert_eq!(d, Duration::from_secs(120));
        }

        #[test]
        fn test_parse_duration_suffix_h() {
            let d = parse_duration_sec("1h").unwrap();
            assert_eq!(d, Duration::from_secs(3600));
        }

        #[test]
        fn test_parse_duration_invalid() {
            assert!(parse_duration_sec("abc").is_err());
        }

        #[test]
        fn test_parse_duration_zero() {
            let d = parse_duration_sec("0").unwrap();
            assert_eq!(d, Duration::from_secs(0));
        }

        // --- parse_http_headers ---

        #[test]
        fn test_parse_http_headers_valid() {
            let (name, value) = parse_http_headers("X-Custom: my-value").unwrap();
            assert_eq!(name.as_str(), "x-custom");
            assert_eq!(value.to_str().unwrap(), "my-value");
        }

        #[test]
        fn test_parse_http_headers_no_colon_fails() {
            assert!(parse_http_headers("no-colon-here").is_err());
        }

        // --- parse_http_credentials ---

        #[test]
        fn test_parse_http_credentials_valid() {
            let header = parse_http_credentials("admin:password").unwrap();
            let val = header.to_str().unwrap();
            assert!(val.starts_with("Basic "));
        }

        // --- parse_server_url ---

        #[test]
        fn test_parse_server_url_wss() {
            let url = parse_server_url("wss://example.com:443").unwrap();
            assert_eq!(url.scheme(), "wss");
            assert_eq!(url.host_str(), Some("example.com"));
        }

        #[test]
        fn test_parse_server_url_invalid_scheme() {
            assert!(parse_server_url("ftp://example.com").is_err());
        }

        #[test]
        fn test_parse_server_url_no_host() {
            assert!(parse_server_url("ws://").is_err());
        }

        // --- parse_tunnel_arg ---

        #[test]
        fn test_parse_tunnel_arg_tcp_simple() {
            let lt = parse_tunnel_arg("tcp://8080:localhost:80").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::Tcp { proxy_protocol: false }));
            assert_eq!(lt.local.port(), 8080);
            assert_eq!(lt.remote.1, 80);
        }

        #[test]
        fn test_parse_tunnel_arg_tcp_proxy_protocol() {
            let lt = parse_tunnel_arg("tcp://8080:localhost:80?proxy_protocol").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::Tcp { proxy_protocol: true }));
        }

        #[test]
        fn test_parse_tunnel_arg_udp_with_timeout() {
            let lt = parse_tunnel_arg("udp://5353:1.1.1.1:53?timeout_sec=60").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::Udp { timeout: Some(d) } if d == Duration::from_secs(60)));
        }

        #[test]
        fn test_parse_tunnel_arg_udp_timeout_zero_means_none() {
            let lt = parse_tunnel_arg("udp://5353:1.1.1.1:53?timeout_sec=0").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::Udp { timeout: None }));
        }

        #[test]
        fn test_parse_tunnel_arg_stdio() {
            let lt = parse_tunnel_arg("stdio://google.com:443").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::Stdio { proxy_protocol: false }));
            assert_eq!(lt.remote.0, Host::<String>::Domain("google.com".to_string()));
        }

        #[test]
        fn test_parse_tunnel_arg_socks5() {
            let lt = parse_tunnel_arg("socks5://127.0.0.1:1080").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::Socks5 { .. }));
        }

        #[test]
        fn test_parse_tunnel_arg_http_proxy() {
            let lt = parse_tunnel_arg("http://127.0.0.1:3128").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::HttpProxy { .. }));
        }

        #[test]
        fn test_parse_tunnel_arg_invalid_protocol_fails() {
            assert!(parse_tunnel_arg("ftp://127.0.0.1:21:host:21").is_err());
        }

        #[test]
        fn test_parse_tunnel_arg_no_protocol_fails() {
            assert!(parse_tunnel_arg("127.0.0.1:80:host:80").is_err());
        }

        // --- parse_reverse_tunnel_arg ---

        #[test]
        fn test_parse_reverse_tunnel_tcp() {
            let lt = parse_reverse_tunnel_arg("tcp://8080:localhost:80").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::ReverseTcp));
        }

        #[test]
        fn test_parse_reverse_tunnel_udp() {
            let lt = parse_reverse_tunnel_arg("udp://5353:1.1.1.1:53?timeout_sec=10").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::ReverseUdp { .. }));
        }

        #[test]
        fn test_parse_reverse_tunnel_socks5() {
            let lt = parse_reverse_tunnel_arg("socks5://127.0.0.1:1080").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::ReverseSocks5 { .. }));
        }

        #[test]
        fn test_parse_reverse_tunnel_http() {
            let lt = parse_reverse_tunnel_arg("http://127.0.0.1:3128").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::ReverseHttpProxy { .. }));
        }

        #[test]
        fn test_parse_reverse_tunnel_unix() {
            let lt = parse_reverse_tunnel_arg("unix:///tmp/velox.sock:host:80").unwrap();
            assert!(matches!(lt.local_protocol, LocalProtocol::ReverseUnix { .. }));
        }
    }

    // ======================================================================
    // 17. Server utils — extract_path_prefix
    // ======================================================================

    #[test]
    fn test_extract_path_prefix_valid() {
        use crate::tunnel::server::utils::extract_path_prefix;
        assert_eq!(extract_path_prefix("/myprefix/events"), Ok("myprefix"));
    }

    #[test]
    fn test_extract_path_prefix_nested_path() {
        use crate::tunnel::server::utils::extract_path_prefix;
        assert_eq!(extract_path_prefix("/pfx/some/more/events"), Ok("pfx"));
    }

    #[test]
    fn test_extract_path_prefix_no_leading_slash() {
        use crate::tunnel::server::utils::{PathPrefixErr, extract_path_prefix};
        assert_eq!(extract_path_prefix("pfx/events"), Err(PathPrefixErr::BadPathPrefix));
    }

    #[test]
    fn test_extract_path_prefix_empty_string() {
        use crate::tunnel::server::utils::{PathPrefixErr, extract_path_prefix};
        assert_eq!(extract_path_prefix(""), Err(PathPrefixErr::BadPathPrefix));
    }

    #[test]
    fn test_extract_path_prefix_no_events_suffix() {
        use crate::tunnel::server::utils::{PathPrefixErr, extract_path_prefix};
        assert_eq!(
            extract_path_prefix("/pfx/something"),
            Err(PathPrefixErr::BadUpgradeRequest)
        );
    }

    // ======================================================================
    // 18. Server utils — find_mapped_port
    // ======================================================================

    #[test]
    fn test_find_mapped_port_no_mapping() {
        use crate::tunnel::server::utils::find_mapped_port;
        let restriction = RestrictionConfig {
            name: "test".into(),
            r#match: vec![MatchConfig::Any],
            allow: vec![AllowConfig::Tunnel(AllowTunnelConfig {
                protocol: vec![],
                port: vec![],
                host: default_host(),
                cidr: default_cidr(),
            })],
        };
        assert_eq!(find_mapped_port(8080, &restriction), 8080);
    }

    #[test]
    fn test_find_mapped_port_with_mapping() {
        use crate::tunnel::server::utils::find_mapped_port;
        let mut port_mapping = HashMap::new();
        port_mapping.insert(8080, 80);
        let restriction = RestrictionConfig {
            name: "test".into(),
            r#match: vec![MatchConfig::Any],
            allow: vec![AllowConfig::ReverseTunnel(AllowReverseTunnelConfig {
                protocol: vec![],
                port: vec![],
                cidr: default_cidr(),
                port_mapping,
                unix_path: default_host(),
            })],
        };
        assert_eq!(find_mapped_port(8080, &restriction), 80);
    }

    #[test]
    fn test_find_mapped_port_unmapped_port() {
        use crate::tunnel::server::utils::find_mapped_port;
        let mut port_mapping = HashMap::new();
        port_mapping.insert(8080, 80);
        let restriction = RestrictionConfig {
            name: "test".into(),
            r#match: vec![MatchConfig::Any],
            allow: vec![AllowConfig::ReverseTunnel(AllowReverseTunnelConfig {
                protocol: vec![],
                port: vec![],
                cidr: default_cidr(),
                port_mapping,
                unix_path: default_host(),
            })],
        };
        assert_eq!(find_mapped_port(9090, &restriction), 9090);
    }

    // ======================================================================
    // 19. Default helpers
    // ======================================================================

    #[test]
    fn test_default_host_matches_anything() {
        let h = default_host();
        assert!(h.is_match("anything"));
        assert!(h.is_match(""));
        assert!(h.is_match("foo.bar.baz"));
    }

    #[test]
    fn test_default_cidr_contains_all_ipv4() {
        let cidrs = default_cidr();
        assert!(cidrs.iter().any(|c| c.contains(&IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)))));
    }

    #[test]
    fn test_default_cidr_contains_all_ipv6() {
        let cidrs = default_cidr();
        assert!(cidrs.iter().any(|c| c.contains(&IpAddr::V6(Ipv6Addr::LOCALHOST))));
    }

    // ======================================================================
    // 20. Edge cases
    // ======================================================================

    #[test]
    fn test_jwt_round_trip_reverse_socks5_with_credentials() {
        ensure_crypto_provider();
        let id = Uuid::now_v7();
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseSocks5 {
                timeout: Some(Duration::from_secs(5)),
                credentials: Some(("user".into(), "pass".into())),
            },
            host: Host::Ipv4(Ipv4Addr::new(10, 0, 0, 1)),
            port: 1080,
        };
        let token = tunnel_to_jwt_token(id, &remote);
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        assert_eq!(decoded.claims.rp, 1080);
        assert_eq!(decoded.claims.r, "10.0.0.1");
        // Verify protocol is preserved through serialization
        if let LocalProtocol::ReverseSocks5 { timeout, credentials } = decoded.claims.p {
            assert_eq!(timeout, Some(Duration::from_secs(5)));
            assert_eq!(credentials, Some(("user".into(), "pass".into())));
        } else {
            panic!("Expected ReverseSocks5 protocol");
        }
    }

    #[test]
    fn test_jwt_round_trip_reverse_http_proxy() {
        ensure_crypto_provider();
        let id = Uuid::now_v7();
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseHttpProxy {
                timeout: None,
                credentials: None,
            },
            host: Host::Domain("proxy.local".into()),
            port: 3128,
        };
        let token = tunnel_to_jwt_token(id, &remote);
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        assert_eq!(decoded.claims.rp, 3128);
        assert!(matches!(decoded.claims.p, LocalProtocol::ReverseHttpProxy { .. }));
    }

    #[test]
    fn test_jwt_round_trip_reverse_unix() {
        ensure_crypto_provider();
        let id = Uuid::now_v7();
        let remote = RemoteAddr {
            protocol: LocalProtocol::ReverseUnix {
                path: PathBuf::from("/var/run/tunnel.sock"),
            },
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port: 0,
        };
        let token = tunnel_to_jwt_token(id, &remote);
        let decoded = jwt_token_to_tunnel(&token).unwrap();
        if let LocalProtocol::ReverseUnix { path } = decoded.claims.p {
            assert_eq!(path, PathBuf::from("/var/run/tunnel.sock"));
        } else {
            panic!("Expected ReverseUnix");
        }
    }

    #[test]
    fn test_to_host_port_roundtrip_ipv4() {
        let original = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 22));
        let (host, port) = to_host_port(original);
        let back = try_to_sock_addr((host, port)).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn test_to_host_port_roundtrip_ipv6() {
        let original = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
            8080,
            0,
            0,
        ));
        let (host, port) = to_host_port(original);
        let back = try_to_sock_addr((host, port)).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn test_tunnel_allowed_multiple_port_ranges() {
        let config = AllowTunnelConfig {
            protocol: vec![],
            port: vec![80..=80, 443..=443, 8000..=9000],
            host: default_host(),
            cidr: default_cidr(),
        };
        let make_remote = |port| RemoteAddr {
            protocol: LocalProtocol::Tcp { proxy_protocol: false },
            host: Host::Ipv4(Ipv4Addr::LOCALHOST),
            port,
        };
        assert!(AllowConfig::from(config.clone()).is_allowed(&make_remote(80)));
        assert!(AllowConfig::from(config.clone()).is_allowed(&make_remote(443)));
        assert!(AllowConfig::from(config.clone()).is_allowed(&make_remote(8500)));
        assert!(!AllowConfig::from(config.clone()).is_allowed(&make_remote(81)));
        assert!(!AllowConfig::from(config).is_allowed(&make_remote(7999)));
    }

    #[test]
    fn test_restrictions_special_chars_in_host_escaped() {
        let restrict_to = vec![("sub.example.com".to_string(), 443)];
        let rules = RestrictionsRules::from_path_prefix(&[], &restrict_to).unwrap();
        if let AllowConfig::Tunnel(cfg) = &rules.restrictions[0].allow[0] {
            // The dot should be escaped in the regex
            assert_eq!(cfg.host.as_str(), r"^sub\.example\.com$");
        } else {
            panic!("Expected Tunnel");
        }
    }

    #[test]
    fn test_restrictions_path_prefix_special_chars_escaped() {
        let prefixes = vec!["/my.prefix+test".to_string()];
        let rules = RestrictionsRules::from_path_prefix(&prefixes, &[]).unwrap();
        if let MatchConfig::PathPrefix(re) = &rules.restrictions[0].r#match[0] {
            assert_eq!(re.as_str(), r"^/my\.prefix\+test$");
        } else {
            panic!("Expected PathPrefix");
        }
    }
}
