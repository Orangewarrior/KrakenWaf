use crate::{app::AppState, proxy::plain_response};
use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use http_body_util::Full;
use hyper::{body::Incoming, service::service_fn};
use hyper_util::{rt::{TokioExecutor, TokioIo}, server::conn::auto::Builder};
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{net::TcpListener, sync::Notify, task, time::timeout};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};

/// Maximum time the listener waits for in-flight connections to drain after
/// receiving SIGINT/SIGTERM before forcibly returning.
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolves when the process receives SIGINT or, on Unix, SIGTERM. Used to wire
/// graceful shutdown into both the TLS and plain-HTTP listener loops.
async fn wait_for_shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(sig) => sig,
            Err(err) => {
                warn!(target: "krakenwaf", "failed to install SIGTERM handler: {err}");
                let _ = tokio::signal::ctrl_c().await;
                return;
            }
        };
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

/// Wait up to `SHUTDOWN_DRAIN_TIMEOUT` for the in-flight connection counter to
/// reach zero. Logs a warning and returns when the deadline passes.
async fn wait_for_drain(in_flight: &AtomicUsize, notify: &Notify) {
    let deadline = tokio::time::Instant::now() + SHUTDOWN_DRAIN_TIMEOUT;
    loop {
        let pending = in_flight.load(Ordering::Acquire);
        if pending == 0 {
            return;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            warn!(
                target: "krakenwaf",
                pending,
                "shutdown drain deadline reached; abandoning in-flight connections"
            );
            return;
        }
        let _ = tokio::time::timeout(deadline - now, notify.notified()).await;
    }
}

/// Start the TLS listener (normal production mode).
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to the given address.
pub async fn run(listener_addr: std::net::SocketAddr, tls_acceptor: TlsAcceptor, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(state.cli.max_connections));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let drain_notify = Arc::new(Notify::new());
    info!(target: "krakenwaf", addr=%listener_addr, tls=true, "KrakenWaf listener started");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            result = semaphore.clone().acquire_owned() => match result {
                Ok(p) => p,
                Err(_) => return Err(anyhow::anyhow!("connection semaphore closed")),
            },
            () = &mut shutdown => break,
        };

        let (stream, peer) = tokio::select! {
            result = listener.accept() => result?,
            () = &mut shutdown => break,
        };

        let acceptor = tls_acceptor.clone();
        let state = state.clone();
        let in_flight = in_flight.clone();
        let drain_notify = drain_notify.clone();

        in_flight.fetch_add(1, Ordering::AcqRel);
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
                        async move { Ok::<_, std::convert::Infallible>(handle(req, state, client_ip).await) }
                    });
                    let conn = builder.serve_connection(io, service);
                    match timeout(Duration::from_secs(timeout_secs), conn).await {
                        Ok(Ok(())) => {}
                        Ok(Err(err)) => error!(target: "krakenwaf", "connection error: {err}"),
                        Err(_) => error!(target: "krakenwaf", "connection timed out"),
                    }
                }
                Err(err) => error!(target: "krakenwaf", "TLS handshake failed for {}: {}", peer, err),
            }
            if in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
                drain_notify.notify_waiters();
            }
        });
    }

    info!(target: "krakenwaf", "shutdown signal received; draining in-flight connections (up to 30 s)");
    wait_for_drain(&in_flight, &drain_notify).await;
    info!(target: "krakenwaf", "drain complete, exiting");
    Ok(())
}

/// Start the plain-HTTP listener (--no-tls mode — for testing or load-balancer deployments).
///
/// # Errors
/// Returns an error if the TCP listener cannot bind to the given address.
pub async fn run_plain(listener_addr: std::net::SocketAddr, state: Arc<AppState>) -> Result<()> {
    let listener = TcpListener::bind(listener_addr).await?;
    let semaphore = Arc::new(tokio::sync::Semaphore::new(state.cli.max_connections));
    let in_flight = Arc::new(AtomicUsize::new(0));
    let drain_notify = Arc::new(Notify::new());
    info!(target: "krakenwaf", addr=%listener_addr, tls=false, "KrakenWaf listener started (plain HTTP)");

    let shutdown = wait_for_shutdown_signal();
    tokio::pin!(shutdown);

    loop {
        let permit = tokio::select! {
            result = semaphore.clone().acquire_owned() => match result {
                Ok(p) => p,
                Err(_) => return Err(anyhow::anyhow!("connection semaphore closed")),
            },
            () = &mut shutdown => break,
        };

        let (stream, peer) = tokio::select! {
            result = listener.accept() => result?,
            () = &mut shutdown => break,
        };

        let state = state.clone();
        let in_flight = in_flight.clone();
        let drain_notify = drain_notify.clone();

        in_flight.fetch_add(1, Ordering::AcqRel);
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
                async move { Ok::<_, std::convert::Infallible>(handle(req, state, client_ip).await) }
            });
            let conn = builder.serve_connection(io, service);
            match timeout(Duration::from_secs(timeout_secs), conn).await {
                Ok(Ok(())) => {}
                Ok(Err(err)) => error!(target: "krakenwaf", "connection error: {err}"),
                Err(_) => error!(target: "krakenwaf", "connection timed out"),
            }
            if in_flight.fetch_sub(1, Ordering::AcqRel) == 1 {
                drain_notify.notify_waiters();
            }
        });
        let _ = peer;
    }

    info!(target: "krakenwaf", "shutdown signal received; draining in-flight connections (up to 30 s)");
    wait_for_drain(&in_flight, &drain_notify).await;
    info!(target: "krakenwaf", "drain complete, exiting");
    Ok(())
}

async fn handle(req: Request<Incoming>, state: Arc<AppState>, client_ip: String) -> Response<Full<Bytes>> {
    let path = req.uri().path();

    // Health and metrics endpoints respect the addr allowlist.
    if path == "/__krakenwaf/health" || path == "/metrics" {
        let snap = state.waf.rules_snapshot();
        if !snap.is_ip_allowed(&client_ip) {
            let mut resp = plain_response(StatusCode::FORBIDDEN, "Access denied");
            state.response_header_policy.apply(resp.headers_mut(), false);
            return resp;
        }
        if path == "/__krakenwaf/health" {
            let mut response = plain_response(StatusCode::OK, "KrakenWaf OK");
            state.response_header_policy.apply(response.headers_mut(), false);
            return response;
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
