use crate::executor::TokioExecutorRef;
use crate::protocols::tls;
use crate::restrictions::types::RestrictionsRules;
use crate::tunnel::RemoteAddr;
use crate::tunnel::server::WsServer;
use crate::tunnel::server::utils::validate_tunnel;
use crate::tunnel::transport;
use crate::tunnel::transport::quic::{
    QUIC_ALPN, QuicRequestHeader, QuicResponseHeader, QuicStreamTunnelRead, QuicStreamTunnelWrite, QuicTransportMode,
    QuicTunnelRead, QuicTunnelWrite, STATUS_BAD_REQUEST, STATUS_FORBIDDEN, STATUS_INTERNAL_ERROR,
};
use crate::tunnel::transport::{jwt_token_to_tunnel, tunnel_to_jwt_token};
use anyhow::anyhow;
use arc_swap::ArcSwap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::oneshot;
use tokio_rustls::rustls::pki_types::CertificateDer;
use tracing::{Instrument, Level, Span, error, info, span, warn};
use uuid::Uuid;

fn mk_quic_span() -> Span {
    span!(
        Level::INFO,
        "tunnel",
        id = tracing::field::Empty,
        remote = tracing::field::Empty,
        forwarded_for = tracing::field::Empty
    )
}

/// Build a `quinn::ServerConfig` from the current TLS state. Called both on initial bind
/// and on every cert reload.
pub(super) fn build_quic_server_config(
    server: &crate::tunnel::server::WsServerConfig,
) -> anyhow::Result<quinn::ServerConfig> {
    let tls_config = server
        .tls
        .as_ref()
        .ok_or_else(|| anyhow!("QUIC transport requires TLS configuration on the server"))?;
    let server_crypto = tls::build_server_config(tls_config, Some(vec![QUIC_ALPN.to_vec()]))?;
    let mut server_crypto = server_crypto;
    if server.quic_0rtt {
        server_crypto.max_early_data_size = u32::MAX;
    }

    let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(server_crypto)
            .map_err(|e| anyhow!("Failed to create QUIC server crypto: {e}"))?,
    ));
    server_config.transport_config(crate::tunnel::transport::quic::build_transport_config(
        server.quic_keep_alive,
        server.quic_max_idle_timeout,
        server.quic_max_streams,
        server.quic_datagram_buffer_size,
    )?);
    server_config.migration(!server.quic_disable_migration);
    Ok(server_config)
}

async fn send_err(send: &mut quinn::SendStream, status: u8, reason: impl Into<String>) {
    let response = QuicResponseHeader::err(status, reason);
    if let Err(err) = response.write(send).await {
        warn!("Failed to send QUIC error response: {err}");
    }
    let _ = send.finish();
}

fn extract_restrict_path_prefix(connection: &quinn::Connection) -> Option<String> {
    let identity = connection.peer_identity()?;
    let certificates = identity.downcast::<Vec<CertificateDer<'static>>>().ok()?;
    let leaf_certificate = tls::find_leaf_certificate(certificates.as_slice())?;
    tls::cn_from_certificate(&leaf_certificate)
}

/// Handle a single QUIC bi-directional stream:
///   1. Parse the request header (path prefix + JWT + auth + custom headers).
///   2. Validate against restrictions.
///   3. exec_tunnel to open the outbound connector or reverse listener.
///   4. Send the response header (status + cookie for dynamic reverse tunnels).
///   5. Splice bytes between QUIC stream and target.
#[allow(clippy::too_many_arguments)]
async fn handle_quic_stream(
    server: WsServer<impl TokioExecutorRef>,
    restrictions: Arc<RestrictionsRules>,
    datagram_hub: Arc<crate::tunnel::transport::quic::QuicDatagramHub>,
    restrict_path_prefix: Option<String>,
    client_addr: SocketAddr,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let header = match QuicRequestHeader::read(&mut recv).await {
        Ok(h) => h,
        Err(err) => {
            warn!("Malformed QUIC request header from {client_addr}: {err}");
            send_err(&mut send, STATUS_BAD_REQUEST, format!("malformed header: {err}")).await;
            return;
        }
    };

    if let Some(restrict_path) = restrict_path_prefix.as_deref()
        && header.path_prefix != restrict_path
    {
        warn!(
            "Client requested upgrade path '{}' does not match upgrade path restriction '{}' (mTLS, etc.)",
            header.path_prefix, restrict_path
        );
        send_err(&mut send, STATUS_BAD_REQUEST, "bad upgrade path").await;
        return;
    }

    let jwt = match jwt_token_to_tunnel(&header.jwt) {
        Ok(j) => j,
        Err(err) => {
            warn!("Invalid JWT in QUIC request from {client_addr}: {err}");
            send_err(&mut send, STATUS_BAD_REQUEST, "invalid JWT").await;
            return;
        }
    };

    Span::current().record("id", &jwt.claims.id);
    Span::current().record("remote", format!("{}:{}", jwt.claims.r, jwt.claims.rp));

    let remote = match RemoteAddr::try_from(jwt.claims) {
        Ok(r) => r,
        Err(err) => {
            warn!("Bad tunnel info in QUIC JWT from {client_addr}: {err}");
            send_err(&mut send, STATUS_BAD_REQUEST, "bad tunnel info").await;
            return;
        }
    };

    if header.transport_mode == QuicTransportMode::Datagram
        && !matches!(
            remote.protocol,
            crate::tunnel::LocalProtocol::Udp { .. } | crate::tunnel::LocalProtocol::ReverseUdp { .. }
        )
    {
        warn!("Rejecting QUIC datagram tunnel for non-UDP protocol from {client_addr}");
        send_err(
            &mut send,
            STATUS_BAD_REQUEST,
            "QUIC datagram transport is only supported for UDP tunnels",
        )
        .await;
        return;
    }

    // Authorization: prefer the dedicated field, fall back to a custom header named "authorization".
    let authorization: Option<String> = header.authorization.clone().or_else(|| {
        header
            .headers
            .iter()
            .find(|(n, _)| n.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v.clone())
    });

    let restriction = match validate_tunnel(&remote, &header.path_prefix, authorization.as_deref(), &restrictions) {
        Some(r) => r.clone(),
        None => {
            warn!("Rejecting QUIC tunnel to {remote:?} from {client_addr}: no matching restriction");
            send_err(&mut send, STATUS_FORBIDDEN, "forbidden by restrictions").await;
            return;
        }
    };

    info!("QUIC tunnel accepted due to matched restriction: {}", restriction.name);

    let req_protocol = remote.protocol.clone();
    let needs_cookie = req_protocol.is_dynamic_reverse_tunnel();

    let tunnel = match server.exec_tunnel(&restriction, remote, client_addr, shutdown).await {
        Ok(t) => t,
        Err(err) => {
            warn!("Failed to exec QUIC tunnel for {client_addr}: {err}");
            send_err(&mut send, STATUS_INTERNAL_ERROR, format!("tunnel setup failed: {err}")).await;
            return;
        }
    };
    let (remote_addr, local_rx, local_tx) = tunnel;

    let datagram_flow = if header.transport_mode == QuicTransportMode::Datagram {
        match datagram_hub.register_flow(header.flow_id) {
            Ok(flow) => Some(flow),
            Err(err) => {
                warn!("Rejecting QUIC datagram tunnel for {client_addr}: {err}");
                send_err(&mut send, STATUS_BAD_REQUEST, format!("bad datagram flow: {err}")).await;
                return;
            }
        }
    } else {
        None
    };

    let cookie = if needs_cookie {
        tunnel_to_jwt_token(Uuid::from_u128(0), &remote_addr)
    } else {
        String::new()
    };
    let response = QuicResponseHeader::ok(cookie);
    if let Err(err) = response.write(&mut send).await {
        warn!("Failed to write QUIC response header: {err}");
        return;
    }

    info!("QUIC connected to {:?} {}:{}", req_protocol, remote_addr.host, remote_addr.port);

    let (ws_rx, ws_tx) = if let Some((rx, tx)) = datagram_flow {
        let _ = send.finish();
        drop(recv);
        (QuicTunnelRead::Datagram(rx), QuicTunnelWrite::Datagram(tx))
    } else {
        (
            QuicTunnelRead::Stream(QuicStreamTunnelRead::new(recv)),
            QuicTunnelWrite::Stream(QuicStreamTunnelWrite::new(send)),
        )
    };

    let (close_tx, close_rx) = oneshot::channel::<()>();
    let executor = server.executor.clone();
    let ping_frequency = server.config.websocket_ping_frequency;
    executor.spawn(transport::io::propagate_remote_to_local(local_tx, ws_rx, close_rx).instrument(Span::current()));
    let _ = transport::io::propagate_local_to_remote(local_rx, ws_tx, close_tx, ping_frequency).await;
}

/// Accept QUIC connections on the given endpoint and handle each bi-stream.
///
/// Polls `tls_reloader` (if any) before each accept so cert/key rotation propagates to the
/// QUIC endpoint without dropping the listener.
pub(super) async fn quic_server_serve<E: TokioExecutorRef>(
    server: WsServer<E>,
    endpoint: quinn::Endpoint,
    tls_reloader: Arc<crate::tunnel::tls_reloader::TlsReloader>,
    restrictions: Arc<ArcSwap<RestrictionsRules>>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    info!("QUIC server listening on {:?}", endpoint.local_addr());

    loop {
        // Reload TLS if the file watcher signaled a change.
        if tls_reloader.should_reload_certificate_quic() && server.config.tls.is_some() {
            match build_quic_server_config(server.config.as_ref()) {
                Ok(new_cfg) => {
                    endpoint.set_server_config(Some(new_cfg));
                    info!("Reloaded QUIC server TLS configuration");
                }
                Err(err) => {
                    error!("Failed to rebuild QUIC server config after cert reload: {err}");
                }
            }
        }

        let accept_res = tokio::select! {
            res = endpoint.accept() => res,
            _ = shutdown.cancelled() => {
                info!("QUIC server draining");
                endpoint.close(0u32.into(), b"shutdown");
                endpoint.wait_idle().await;
                break;
            }
        };

        let Some(incoming) = accept_res else {
            info!("QUIC endpoint closed, stopping accept loop");
            break;
        };

        let server = server.clone();
        let restrictions = restrictions.clone();
        let shutdown_for_conn = shutdown.clone();

        server.executor.clone().spawn(async move {
            let connection = match incoming.await {
                Ok(conn) => conn,
                Err(err) => {
                    error!("QUIC incoming connection failed: {err}");
                    return;
                }
            };

            let client_addr = connection.remote_address();
            info!("QUIC connection established from {client_addr}");
            let datagram_hub = crate::tunnel::transport::quic::QuicDatagramHub::new(connection.clone());
            server.executor.clone().spawn(datagram_hub.clone().run());
            let restrict_path_prefix = extract_restrict_path_prefix(&connection);

            // Accept multiplexed bi-directional streams from this connection.
            loop {
                let stream = match connection.accept_bi().await {
                    Ok(stream) => stream,
                    Err(quinn::ConnectionError::ApplicationClosed(_))
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::ConnectionClosed(_)) => {
                        info!("QUIC connection closed by client {client_addr}");
                        break;
                    }
                    Err(err) => {
                        warn!("QUIC accept_bi failed from {client_addr}: {err}");
                        break;
                    }
                };

                let (send, recv) = stream;
                let server = server.clone();
                let restrictions = restrictions.load().clone();
                let datagram_hub = datagram_hub.clone();
                let restrict_path_prefix = restrict_path_prefix.clone();
                let shutdown = shutdown_for_conn.clone();

                let request_id = Uuid::now_v7();
                let span = mk_quic_span();
                span.record("id", request_id.to_string());

                server.executor.clone().spawn(
                    handle_quic_stream(
                        server.clone(),
                        restrictions,
                        datagram_hub,
                        restrict_path_prefix,
                        client_addr,
                        send,
                        recv,
                        shutdown,
                    )
                    .instrument(span),
                );
            }
        });
    }
}
