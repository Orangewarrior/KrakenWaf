use crate::{app::AppState, proxy::plain_response};
use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder};
use std::{future::Future, sync::Arc, time::Duration};
use tokio::{net::TcpListener, task, time::timeout};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

/// Start the TLS listener (normal production mode).
pub async fn run(
    listener_addr: std::net::SocketAddr,
    tls_acceptor: Arc<tokio::sync::RwLock<TlsAcceptor>>,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(state.cli.max_connections));
    let h2_enabled = state.network.http2.server_enabled;
    info!(target: "krakenwaf", addr=%listener_addr, tls=true, http2_enabled=h2_enabled, "KrakenWaf listener started");

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!(target: "krakenwaf", "accept loop stopping — draining in-flight connections");
                break;
            }
            result = semaphore.clone().acquire_owned() => {
                let permit = match result {
                    Ok(p) => p,
                    Err(_) => return Err(anyhow::anyhow!("connection semaphore closed")),
                };

                let (stream, peer) = listener.accept().await?;
                let acceptor = tls_acceptor.read().await.clone();
                let state = state.clone();

                task::spawn(async move {
                    let _permit = permit;
                    match acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let timeout_secs = state.cli.connection_timeout_secs;
                            let state_for_service = Arc::clone(&state);
                            let client_ip = peer.ip().to_string();
                            let builder = Builder::new(TokioExecutor::new());
                            let service = service_fn(move |req: Request<Incoming>| {
                                let state = Arc::clone(&state_for_service);
                                let client_ip = client_ip.clone();
                                async move {
                                    let timeout_secs = state.cli.request_timeout_secs;
                                    let result = tokio::time::timeout(
                                        Duration::from_secs(timeout_secs),
                                        handle(req, Arc::clone(&state), client_ip.clone()),
                                    ).await;
                                    let resp = match result {
                                        Ok(r) => r,
                                        Err(_) => {
                                            plain_response(http::StatusCode::REQUEST_TIMEOUT, "KrakenWaf: request timed out")
                                        }
                                    };
                                    Ok::<_, std::convert::Infallible>(resp)
                                }
                            });
                            let conn = builder.serve_connection(io, service);
                            match timeout(Duration::from_secs(timeout_secs), conn).await {
                                Ok(Ok(())) => {}
                                Ok(Err(err)) => error!(target: "krakenwaf", "connection error: {err}"),
                                Err(err) => error!(target: "krakenwaf", "connection timed out: {err}"),
                            }
                        }
                        Err(err) => error!(target: "krakenwaf", "TLS handshake failed for {}: {}", peer, err),
                    }
                });
            }
        }
    }

    // Wait for all in-flight connections to complete (drain semaphore).
    // close() prevents new permits from being issued.
    semaphore.close();
    // Give up to 30s for connections to drain.
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        semaphore.acquire_many(state.cli.max_connections as u32),
    ).await;
    info!(target: "krakenwaf", "all connections drained");
    Ok(())
}

/// Start the plain-HTTP listener (--no-tls mode — for testing or load-balancer deployments).
pub async fn run_plain(
    listener_addr: std::net::SocketAddr,
    state: Arc<AppState>,
    shutdown: impl Future<Output = ()>,
) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(state.cli.max_connections));
    info!(target: "krakenwaf", addr=%listener_addr, tls=false, "KrakenWaf listener started (plain HTTP)");

    tokio::pin!(shutdown);

    loop {
        tokio::select! {
            _ = &mut shutdown => {
                info!(target: "krakenwaf", "accept loop stopping — draining in-flight connections");
                break;
            }
            result = semaphore.clone().acquire_owned() => {
                let permit = match result {
                    Ok(p) => p,
                    Err(_) => return Err(anyhow::anyhow!("connection semaphore closed")),
                };

                let (stream, peer) = listener.accept().await?;
                let state = state.clone();

                task::spawn(async move {
                    let _permit = permit;
                    let io = TokioIo::new(stream);
                    let timeout_secs = state.cli.connection_timeout_secs;
                    let state_for_service = Arc::clone(&state);
                    let client_ip = peer.ip().to_string();
                    let builder = Builder::new(TokioExecutor::new());
                    let service = service_fn(move |req: Request<Incoming>| {
                        let state = Arc::clone(&state_for_service);
                        let client_ip = client_ip.clone();
                        async move {
                            let timeout_secs = state.cli.request_timeout_secs;
                            let result = tokio::time::timeout(
                                Duration::from_secs(timeout_secs),
                                handle(req, Arc::clone(&state), client_ip.clone()),
                            ).await;
                            let resp = match result {
                                Ok(r) => r,
                                Err(_) => {
                                    plain_response(http::StatusCode::REQUEST_TIMEOUT, "KrakenWaf: request timed out")
                                }
                            };
                            Ok::<_, std::convert::Infallible>(resp)
                        }
                    });
                    let conn = builder.serve_connection(io, service);
                    match timeout(Duration::from_secs(timeout_secs), conn).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!(target: "krakenwaf", "connection error: {err}"),
                        Err(err) => error!(target: "krakenwaf", "connection timed out: {err}"),
                    }
                });
            }
        }
    }

    // Wait for all in-flight connections to complete (drain semaphore).
    // close() prevents new permits from being issued.
    semaphore.close();
    // Give up to 30s for connections to drain.
    let _ = tokio::time::timeout(
        Duration::from_secs(30),
        semaphore.acquire_many(state.cli.max_connections as u32),
    ).await;
    info!(target: "krakenwaf", "all connections drained");
    Ok(())
}

async fn handle(req: Request<Incoming>, state: Arc<AppState>, client_ip: String) -> Response<Full<Bytes>> {
    let path = req.uri().path();

    // Health and metrics endpoints respect the addr allowlist.
    if path == "/__krakenwaf/health" || path == "/__krakenwaf/livez" || path == "/__krakenwaf/readyz" || path == "/metrics" {
        let snap = state.waf.rules_snapshot();
        if !snap.is_ip_allowed(&client_ip) {
            let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
            state.response_header_policy.apply(resp.headers_mut(), false);
            return resp;
        }
        if path == "/__krakenwaf/livez" {
            let mut response = plain_response(StatusCode::OK, "ok");
            state.response_header_policy.apply(response.headers_mut(), false);
            return response;
        }
        if path == "/__krakenwaf/health" || path == "/__krakenwaf/readyz" {
            // Readiness: WAF must have rules loaded (non-empty blocklist or at least one rule configured).
            let ready = !snap.uri_keywords.is_empty()
                || !snap.header_keywords.is_empty()
                || !snap.body_keywords.is_empty()
                || !snap.path_regex.is_empty()
                || !snap.blocked_ips.is_empty()
                || !snap.blocked_ip_prefixes.is_empty();
            if ready {
                let mut response = plain_response(StatusCode::OK, "KrakenWaf OK");
                state.response_header_policy.apply(response.headers_mut(), false);
                return response;
            } else {
                let mut response = plain_response(StatusCode::SERVICE_UNAVAILABLE, "KrakenWaf not ready");
                state.response_header_policy.apply(response.headers_mut(), false);
                return response;
            }
        }
        // /metrics
        let mut response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "text/plain; version=0.0.4; charset=utf-8")
            .body(Full::new(Bytes::from(state.metrics.render_prometheus())))
            .unwrap_or_else(|_| plain_response(StatusCode::OK, ""));
        state.response_header_policy.apply(response.headers_mut(), false);
        return response;
    }

    state.proxy.handle(&state, req, client_ip).await
}
