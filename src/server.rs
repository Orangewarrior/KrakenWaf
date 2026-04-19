use crate::{app::AppState, proxy::plain_response};
use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder};
use std::{sync::Arc, time::Duration};
use tokio::{net::TcpListener, task, time::timeout};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

pub async fn run(listener_addr: std::net::SocketAddr, tls_acceptor: TlsAcceptor, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(state.cli.max_connections));
    info!(target: "krakenwaf", addr=%listener_addr, "KrakenWaf listener started");

    loop {
        // Acquire a connection slot BEFORE accepting the TCP connection. This prevents
        // the kernel from completing the 3-way handshake (and allocating TLS state) for
        // connections we cannot serve yet, providing backpressure under SYN floods.
        let permit = match semaphore.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => return Err(anyhow::anyhow!("connection semaphore closed")),
        };

        let (stream, peer) = listener.accept().await?;
        let acceptor = tls_acceptor.clone();
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
                            Ok::<_, std::convert::Infallible>(handle(req, state, client_ip).await)
                        }
                    });
                    let conn = builder.serve_connection(io, service);
                    match timeout(Duration::from_secs(timeout_secs), conn).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!(target: "krakenwaf", "connection error: {err}"),
                        Err(err) => error!(target: "krakenwaf", "connection timed out: {err}"),
                    }
                }
                Err(err) => {
                    error!(target: "krakenwaf", "TLS handshake failed for {}: {}", peer, err);
                }
            }
        });
    }
}

async fn handle(req: Request<Incoming>, state: Arc<AppState>, client_ip: String) -> Response<Full<Bytes>> {
    if req.uri().path() == "/__krakenwaf/health" {
        let mut response = plain_response(StatusCode::OK, "KrakenWaf OK");
        state.response_header_policy.apply(response.headers_mut(), false);
        return response;
    }
    if req.uri().path() == "/metrics" {
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
