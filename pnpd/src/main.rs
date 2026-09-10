//! pnpd — the Peios Network Policy daemon, starting life as the PNP viewer's
//! wire tap: capture every frame on every interface, hold a bounded backlog,
//! and serve the viewer UI plus a live stream over HTTP.
//!
//! Runs as SYSTEM (jack's call, 2026-08-31, PEI-599): the networking work is
//! in a tight development loop and permission plumbing would be friction with
//! no audience — this daemon predates any user.

mod capture;
mod engine;
mod http;
mod json;
mod log;
mod policy;
mod ring;
mod sid;

use std::net::TcpListener;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

// 8080 is atriumd's; 8081 is the next slot in the image's forwarding convention.
const DEFAULT_PORT: u16 = 8081;
const DEFAULT_RING: usize = 4096;

fn main() {
    let mut port = DEFAULT_PORT;
    let mut ring_capacity = DEFAULT_RING;
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--port" => port = expect_num(args.next(), "--port"),
            "--ring" => ring_capacity = expect_num(args.next(), "--ring"),
            other => {
                eprintln!("pnpd: unknown argument {other}");
                eprintln!("usage: pnpd [--port N] [--ring N]");
                std::process::exit(2);
            }
        }
    }

    let ring = Arc::new(ring::Ring::new(ring_capacity));
    let stats = Arc::new(capture::CaptureStats {
        captured: AtomicU64::new(0),
        dropped: AtomicU64::new(0),
        suppressed: AtomicU64::new(0),
    });

    let cap = match capture::Capture::open(ring.clone(), stats.clone(), port) {
        Ok(c) => c,
        Err(err) => {
            log::error(&format!("cannot open packet socket: {err}"));
            std::process::exit(1);
        }
    };
    std::thread::spawn(move || cap.run());

    // The kernel verdict stream (retries until /dev/peios-pnp exists).
    let eng = engine::Engine::new(port);
    {
        let eng = eng.clone();
        std::thread::spawn(move || engine::run(eng));
    }

    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(err) => {
            log::error(&format!("cannot bind port {port}: {err}"));
            std::process::exit(1);
        }
    };
    log::info(&format!(
        "wire tap up, serving on port {port}, ring {ring_capacity}"
    ));
    notify_ready();

    let server = Arc::new(http::Server {
        ring,
        stats,
        engine: eng,
        started: std::time::Instant::now(),
    });
    http::serve(listener, server);
}

fn expect_num<T: std::str::FromStr>(value: Option<String>, flag: &str) -> T {
    match value.and_then(|v| v.parse().ok()) {
        Some(v) => v,
        None => {
            eprintln!("pnpd: {flag} needs a number");
            std::process::exit(2);
        }
    }
}

/// Readiness for the service manager, netd-style: a datagram to
/// NOTIFY_SOCKET when we are up. Harmless when unset (dev runs).
fn notify_ready() {
    let path = match std::env::var("NOTIFY_SOCKET") {
        Ok(p) => p,
        Err(_) => return,
    };
    if let Ok(sock) = std::os::unix::net::UnixDatagram::unbound() {
        let _ = sock.send_to(b"READY=1", path);
    }
}
