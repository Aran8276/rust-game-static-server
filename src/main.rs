//! Static asset server for streamed WASM game builds.
//!
//! * Cross-origin isolation headers (COOP / COEP / CORP) for SharedArrayBuffer.
//! * Logs every file transfer: start (debug), and on completion / abort (info/warn):
//!   path, status, bytes actually written to the socket, encoding, range, speed, peer.
//! * Serves pre-compressed siblings (`.br`, `.zst`, `.gz`) when the client accepts them.
//!   No on-the-fly compression: game data is already compressed, so it would only burn CPU.
//! * HTTP Range requests (resumable / chunked streaming) and conditional requests (304).
//! * Hardened: dotfiles are never served, only GET/HEAD are allowed, serves `STATIC_DIR`
//!   (not the current directory, which would leak source, `.env`, etc.).
//! * Periodic throughput stats and graceful shutdown on SIGINT / SIGTERM.
//!
//! Configuration (environment variables, all optional):
//!   BIND_ADDR            default 127.0.0.1:8084   (use 0.0.0.0:8084 to listen publicly)
//!   STATIC_DIR           default ./public
//!   LOG_FORMAT           text | json              (default text)
//!   RUST_LOG             default info             (use `debug` to also log transfer starts)
//!   STATS_INTERVAL_SECS  default 10               (0 disables the stats line)
//!   CORP_POLICY          default same-origin      (cross-origin | same-site | same-origin)
//!   CACHE_CONTROL_ENTRY  default no-cache         (html/js/css/json/wasm/... - revalidated)
//!   CACHE_CONTROL_ASSET  default public, max-age=31536000, immutable  (everything else)

use std::{
    future::IntoFuture,
    io::IsTerminal,
    net::SocketAddr,
    path::PathBuf,
    pin::Pin,
    sync::{
        atomic::{AtomicU64, Ordering::Relaxed},
        Arc,
    },
    task::{Context, Poll},
    time::{Duration, Instant},
};

use axum::{
    body::{Body, Bytes},
    extract::{ConnectInfo, Request, State},
    http::{
        header::{self, HeaderName, HeaderValue},
        Method, StatusCode,
    },
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    serve::ListenerExt,
    Router,
};
use http_body::{Frame, SizeHint};
use percent_encoding::percent_decode_str;
use tokio::{net::TcpSocket, sync::Notify};
use tower_http::services::ServeDir;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

/// Size of each read from disk. 256 KiB keeps syscall overhead low for multi-MB files
/// while still giving smooth streaming for the 4 KB - 10 MB range.
const READ_CHUNK_SIZE: usize = 256 * 1024;
/// Pending-connection queue; a game launch can open hundreds of parallel fetches.
const LISTEN_BACKLOG: u32 = 4096;
/// How long in-flight downloads may keep running after SIGINT/SIGTERM.
const SHUTDOWN_GRACE: Duration = Duration::from_secs(30);

static COOP: HeaderName = HeaderName::from_static("cross-origin-opener-policy");
static COEP: HeaderName = HeaderName::from_static("cross-origin-embedder-policy");
static CORP: HeaderName = HeaderName::from_static("cross-origin-resource-policy");

// ---------------------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------------------

struct Config {
    bind: SocketAddr,
    root: PathBuf,
    json_logs: bool,
    stats_every: Duration,
    policy: HeaderPolicy,
}

struct HeaderPolicy {
    corp: HeaderValue,
    cache_entry: HeaderValue,
    cache_asset: HeaderValue,
}

impl HeaderPolicy {
    /// Entry points (loader, manifests, wasm glue) must be revalidated so a new build is
    /// picked up immediately. Bulk data chunks are assumed to be content-addressed or
    /// versioned, so they can be cached "forever".
    fn cache_control_for(&self, path: &str) -> &HeaderValue {
        let ext = path
            .rsplit('/')
            .next()
            .and_then(|file| file.rsplit_once('.'))
            .map(|(_, ext)| ext.to_ascii_lowercase());

        match ext.as_deref() {
            None
            | Some(
                "html" | "htm" | "js" | "mjs" | "css" | "json" | "wasm" | "webmanifest" | "xml"
                | "txt",
            ) => &self.cache_entry,
            _ => &self.cache_asset,
        }
    }
}

fn env_or(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_owned())
}

impl Config {
    fn from_env() -> Result<Self, Box<dyn std::error::Error>> {
        let bind: SocketAddr = env_or("BIND_ADDR", "127.0.0.1:8084")
            .parse()
            .map_err(|e| format!("invalid BIND_ADDR: {e}"))?;

        let root_raw = PathBuf::from(env_or("STATIC_DIR", "./public"));
        let root = root_raw
            .canonicalize()
            .map_err(|e| format!("STATIC_DIR {root_raw:?} is not accessible: {e}"))?;
        if !root.is_dir() {
            return Err(format!("STATIC_DIR {root:?} is not a directory").into());
        }

        let corp = env_or("CORP_POLICY", "same-origin");
        if !matches!(corp.as_str(), "same-origin" | "same-site" | "cross-origin") {
            return Err("CORP_POLICY must be same-origin, same-site or cross-origin".into());
        }

        let stats_secs: u64 = env_or("STATS_INTERVAL_SECS", "10")
            .parse()
            .map_err(|e| format!("invalid STATS_INTERVAL_SECS: {e}"))?;

        Ok(Self {
            bind,
            root,
            json_logs: env_or("LOG_FORMAT", "text").eq_ignore_ascii_case("json"),
            stats_every: Duration::from_secs(stats_secs),
            policy: HeaderPolicy {
                corp: HeaderValue::from_str(&corp)?,
                cache_entry: HeaderValue::from_str(&env_or("CACHE_CONTROL_ENTRY", "no-cache"))?,
                cache_asset: HeaderValue::from_str(&env_or(
                    "CACHE_CONTROL_ASSET",
                    "public, max-age=31536000, immutable",
                ))?,
            },
        })
    }
}

// ---------------------------------------------------------------------------------------
// Global counters (cheap, lock-free) used by the periodic stats line
// ---------------------------------------------------------------------------------------

struct Stats {
    requests: AtomicU64,
    active: AtomicU64,
    bytes_sent: AtomicU64,
    aborted: AtomicU64,
}

static STATS: Stats = Stats {
    requests: AtomicU64::new(0),
    active: AtomicU64::new(0),
    bytes_sent: AtomicU64::new(0),
    aborted: AtomicU64::new(0),
};

fn human(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

// ---------------------------------------------------------------------------------------
// Per-transfer accounting + logging
// ---------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
enum Sev {
    Info,
    Warn,
    Error,
}

macro_rules! log_at {
    ($sev:expr, $($rest:tt)+) => {
        match $sev {
            Sev::Info => info!(target: "transfer", $($rest)+),
            Sev::Warn => warn!(target: "transfer", $($rest)+),
            Sev::Error => error!(target: "transfer", $($rest)+),
        }
    };
}

/// Tracks one request from arrival to the last byte. Logging happens in `Drop`, so every
/// outcome (finished, client hung up mid-file, cancelled before headers) is reported
/// exactly once and the `active` gauge can never leak.
struct Transfer {
    peer: SocketAddr,
    method: Method,
    path: String,
    range: Option<String>,
    started: Instant,
    /// 0 until the response head exists; stays 0 if the client left before that.
    status: u16,
    encoding: Option<String>,
    expected: Option<u64>,
    body_expected: bool,
    bytes: u64,
    finished: bool,
    body_error: bool,
}

impl Drop for Transfer {
    fn drop(&mut self) {
        STATS.active.fetch_sub(1, Relaxed);

        let (outcome, sev) = if self.status == 0 {
            ("cancelled", Sev::Warn)
        } else if self.body_error {
            ("error", Sev::Error)
        } else if self.body_expected && !self.finished {
            STATS.aborted.fetch_add(1, Relaxed);
            ("aborted", Sev::Warn)
        } else {
            let sev = match self.status {
                500..=599 => Sev::Error,
                400..=499 => Sev::Warn,
                _ => Sev::Info,
            };
            ("sent", sev)
        };

        let secs = self.started.elapsed().as_secs_f64().max(0.000_001);
        let rate = format!("{}/s", human((self.bytes as f64 / secs) as u64));

        log_at!(
            sev,
            peer = %self.peer,
            method = %self.method,
            path = %self.path,
            status = self.status,
            bytes = self.bytes,
            size = %human(self.bytes),
            expected = self.expected,
            encoding = self.encoding.as_deref(),
            range = self.range.as_deref(),
            ms = (secs * 1000.0) as u64,
            rate = %rate,
            "{outcome}"
        );
    }
}

/// Wraps a response body and counts the bytes that are actually pulled out of it for the
/// socket, so the log reflects what was transferred, not just what was promised.
struct CountingBody {
    inner: Body,
    transfer: Transfer,
}

impl http_body::Body for CountingBody {
    type Data = Bytes;
    type Error = axum::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = &mut *self;
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let n = data.len() as u64;
                    this.transfer.bytes += n;
                    STATS.bytes_sent.fetch_add(n, Relaxed);
                    // hyper stops polling once Content-Length bytes were written and may
                    // never see the final `None`, so completion is also inferred here.
                    if this.transfer.expected.is_some_and(|e| this.transfer.bytes >= e) {
                        this.transfer.finished = true;
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.transfer.body_error = true;
                Poll::Ready(Some(Err(e)))
            }
            Poll::Ready(None) => {
                this.transfer.finished = true;
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

// ---------------------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------------------

/// Outermost layer: logs every file transfer.
async fn access_log(
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path() == "/healthz" {
        return next.run(req).await; // keep load-balancer probes out of the log
    }

    let path = percent_decode_str(req.uri().path())
        .decode_utf8_lossy()
        .into_owned();
    let range = req
        .headers()
        .get(header::RANGE)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);

    STATS.requests.fetch_add(1, Relaxed);
    STATS.active.fetch_add(1, Relaxed);
    let mut transfer = Transfer {
        peer,
        method: req.method().clone(),
        path,
        range,
        started: Instant::now(),
        status: 0,
        encoding: None,
        expected: None,
        body_expected: true,
        bytes: 0,
        finished: false,
        body_error: false,
    };

    debug!(
        target: "transfer",
        peer = %transfer.peer,
        method = %transfer.method,
        path = %transfer.path,
        range = transfer.range.as_deref(),
        "start"
    );

    let (parts, body) = next.run(req).await.into_parts();

    transfer.status = parts.status.as_u16();
    transfer.expected = parts
        .headers
        .get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok()?.parse().ok());
    transfer.encoding = parts
        .headers
        .get(header::CONTENT_ENCODING)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    transfer.body_expected = transfer.method != Method::HEAD
        && !matches!(parts.status.as_u16(), 100..=199 | 204 | 304)
        && transfer.expected != Some(0);

    if !transfer.body_expected {
        // Nothing will be streamed; `transfer` drops here and logs immediately.
        return Response::from_parts(parts, body);
    }

    Response::from_parts(parts, Body::new(CountingBody { inner: body, transfer }))
}

/// Cross-origin isolation, security and caching headers.
async fn response_headers(
    State(policy): State<Arc<HeaderPolicy>>,
    req: Request,
    next: Next,
) -> Response {
    let path = req.uri().path().to_owned();
    let mut res = next.run(req).await;
    let cacheable = matches!(res.status().as_u16(), 200 | 206 | 304);

    let headers = res.headers_mut();
    headers.insert(&COOP, HeaderValue::from_static("same-origin"));
    headers.insert(&COEP, HeaderValue::from_static("require-corp"));
    headers.insert(&CORP, policy.corp.clone());
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );

    if cacheable {
        if !headers.contains_key(header::CACHE_CONTROL) {
            let decoded = percent_decode_str(&path).decode_utf8_lossy();
            headers.insert(
                header::CACHE_CONTROL,
                policy.cache_control_for(&decoded).clone(),
            );
        }
        // Compressed and identity variants share one URL.
        headers.append(header::VARY, HeaderValue::from_static("Accept-Encoding"));
    }
    res
}

/// Never serve dotfiles (`.env`, `.git/`, ...) even if they sit inside the asset directory.
async fn block_dotfiles(req: Request, next: Next) -> Response {
    let hidden = {
        let decoded = percent_decode_str(req.uri().path()).decode_utf8_lossy();
        decoded
            .split('/')
            .any(|seg| seg.starts_with('.') && seg != ".well-known")
    };
    if hidden {
        return StatusCode::NOT_FOUND.into_response();
    }
    next.run(req).await
}

// ---------------------------------------------------------------------------------------
// Runtime plumbing
// ---------------------------------------------------------------------------------------

fn init_tracing(json: bool) -> tracing_appender::non_blocking::WorkerGuard {
    // Non-blocking writer: logging thousands of transfers never stalls the async workers.
    let (writer, guard) = tracing_appender::non_blocking::NonBlockingBuilder::default()
        .buffered_lines_limit(131_072)
        .finish(std::io::stdout());

    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(writer)
        .with_ansi(std::io::stdout().is_terminal());

    if json {
        builder.json().init();
    } else {
        builder.init();
    }
    guard
}

async fn stats_reporter(every: Duration) {
    let mut ticker = tokio::time::interval(every);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    ticker.tick().await; // first tick fires immediately
    let mut last_bytes = STATS.bytes_sent.load(Relaxed);

    loop {
        ticker.tick().await;
        let total = STATS.bytes_sent.load(Relaxed);
        let delta = total - last_bytes;
        last_bytes = total;
        let active = STATS.active.load(Relaxed);
        if delta == 0 && active == 0 {
            continue; // idle: stay quiet
        }
        info!(
            target: "stats",
            active,
            requests = STATS.requests.load(Relaxed),
            aborted = STATS.aborted.load(Relaxed),
            total_sent = %human(total),
            throughput = %format!("{}/s", human((delta as f64 / every.as_secs_f64()) as u64)),
            "traffic"
        );
    }
}

async fn shutdown_signal() {
    let ctrl_c = async {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };

    #[cfg(unix)]
    let terminate = async {
        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }
}

fn bind_listener(addr: SocketAddr) -> std::io::Result<tokio::net::TcpListener> {
    let socket = if addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    // Fast restarts. (Deliberately not set on Windows, where it allows port hijacking.)
    #[cfg(unix)]
    socket.set_reuseaddr(true)?;
    // SO_SNDBUF is intentionally left alone: setting it disables Linux TCP buffer
    // auto-tuning, which hurts throughput on high-latency links.
    socket.bind(addr)?;
    socket.listen(LISTEN_BACKLOG)
}

// ---------------------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cfg = Config::from_env()?;
    let _log_guard = init_tracing(cfg.json_logs); // keep alive so buffered logs flush on exit

    // Pre-compressed siblings only. Tooling example:
    //   brotli -q 11 -k file.bin   -> file.bin.br
    //   zstd -19 -k file.bin       -> file.bin.zst
    let serve_dir = ServeDir::new(&cfg.root)
        .precompressed_br()
        .precompressed_zstd()
        .precompressed_gzip()
        .with_buf_chunk_size(READ_CHUNK_SIZE);

    let policy = Arc::new(cfg.policy);

    // Layers added last are outermost: log -> headers -> dotfile guard -> files.
    let app = Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .fallback_service(serve_dir)
        .layer(middleware::from_fn(block_dotfiles))
        .layer(middleware::from_fn_with_state(policy, response_headers))
        .layer(middleware::from_fn(access_log));

    let listener = bind_listener(cfg.bind)
        .map_err(|e| format!("cannot bind {}: {e}", cfg.bind))?
        .tap_io(|tcp| {
            // Small (4 KB) chunk responses shouldn't wait on Nagle.
            if let Err(e) = tcp.set_nodelay(true) {
                debug!("set_nodelay failed: {e}");
            }
        });

    info!("COOP/COEP cross-origin isolation enabled");
    info!("serving {} on http://{}", cfg.root.display(), cfg.bind);

    if !cfg.stats_every.is_zero() {
        tokio::spawn(stats_reporter(cfg.stats_every));
    }

    let signalled = Arc::new(Notify::new());
    let notify = signalled.clone();
    let server = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        shutdown_signal().await;
        info!(
            "shutdown signal received; draining {} active transfer(s) (max {}s)",
            STATS.active.load(Relaxed),
            SHUTDOWN_GRACE.as_secs()
        );
        notify.notify_one();
    });

    tokio::select! {
        res = server.into_future() => res?,
        _ = async {
            signalled.notified().await;
            tokio::time::sleep(SHUTDOWN_GRACE).await;
        } => warn!("grace period elapsed; dropping remaining transfers"),
    }

    info!(
        "stopped; total sent {} over {} request(s)",
        human(STATS.bytes_sent.load(Relaxed)),
        STATS.requests.load(Relaxed)
    );
    Ok(())
}