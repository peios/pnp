//! A deliberately small HTTP server: static UI, two JSON endpoints, and a
//! server-sent-events packet stream. Thread per connection, `Connection:
//! close` everywhere except the stream — at PNP-viewer scale that is the
//! whole story, and it keeps the daemon dependency-free.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::RecvTimeoutError;
use std::sync::Arc;
use std::time::Duration;

use crate::capture::CaptureStats;
use crate::json::{self, Obj};
use crate::ring::{Packet, Ring};

const UI: &str = include_str!("../ui/index.html");

pub struct Server {
    pub ring: Arc<Ring>,
    pub stats: Arc<CaptureStats>,
    pub started: std::time::Instant,
}

pub fn serve(listener: TcpListener, server: Arc<Server>) {
    for conn in listener.incoming() {
        match conn {
            Ok(stream) => {
                let server = server.clone();
                std::thread::spawn(move || {
                    let _ = handle(stream, &server);
                });
            }
            Err(err) => crate::log::error(&format!("http: accept: {err}")),
        }
    }
}

fn handle(stream: TcpStream, server: &Server) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    let path = match request_line.split_whitespace().nth(1) {
        Some(p) => p.to_owned(),
        None => return Ok(()),
    };
    // Drain headers; nothing in them steers this server.
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 || line == "\r\n" || line == "\n" {
            break;
        }
    }

    let (route, query) = match path.split_once('?') {
        Some((r, q)) => (r, q),
        None => (path.as_str(), ""),
    };
    match route {
        "/" => respond(stream, "200 OK", "text/html; charset=utf-8", UI.as_bytes()),
        "/api/status" => {
            let body = status_json(server);
            respond(stream, "200 OK", "application/json", body.as_bytes())
        }
        "/api/packets" => {
            let since = query
                .split('&')
                .find_map(|kv| kv.strip_prefix("since="))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(0);
            let mut body = String::from("[");
            for (i, p) in server.ring.since(since).iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&packet_json(p));
            }
            body.push(']');
            respond(stream, "200 OK", "application/json", body.as_bytes())
        }
        "/api/stream" => stream_events(stream, server),
        _ => respond(stream, "404 Not Found", "text/plain", b"not found\n"),
    }
}

fn respond(mut stream: TcpStream, code: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

/// The SSE stream: live packets as `packet` events, a `stats` event every
/// two seconds so the header numbers stay honest even on a silent wire.
fn stream_events(mut stream: TcpStream, server: &Server) -> std::io::Result<()> {
    let rx = server.ring.subscribe();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n"
    )?;
    stream.set_read_timeout(None)?;
    loop {
        match rx.recv_timeout(Duration::from_secs(2)) {
            Ok(packet) => {
                write!(stream, "event: packet\ndata: {}\n\n", packet_json(&packet))?;
            }
            Err(RecvTimeoutError::Timeout) => {
                write!(stream, "event: stats\ndata: {}\n\n", status_json(server))?;
            }
            Err(RecvTimeoutError::Disconnected) => return Ok(()),
        }
        stream.flush()?;
    }
}

fn status_json(server: &Server) -> String {
    Obj::new()
        .str("daemon", concat!("pnpd ", env!("CARGO_PKG_VERSION")))
        .num("uptime_s", server.started.elapsed().as_secs() as i64)
        .num("captured", server.stats.captured.load(Ordering::Relaxed) as i128)
        .num("dropped", server.stats.dropped.load(Ordering::Relaxed) as i128)
        .num("suppressed", server.stats.suppressed.load(Ordering::Relaxed) as i128)
        .num("ring_capacity", server.ring.capacity() as i128)
        .finish()
}

fn packet_json(p: &Packet) -> String {
    Obj::new()
        .num("seq", p.seq as i128)
        .num("ts_sec", p.ts_sec as i128)
        .num("ts_nsec", p.ts_nsec as i128)
        .num("ifindex", p.ifindex as i128)
        .str("ifname", &p.ifname)
        .str("dir", p.dir.as_str())
        .num("wire_len", p.wire_len as i128)
        .raw("data", &json::escape(&json::hex(&p.data)))
        .finish()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ring::Direction;

    #[test]
    fn packet_json_shape() {
        let p = Packet {
            seq: 7,
            ts_sec: 100,
            ts_nsec: 5,
            ifindex: 2,
            ifname: "eth0".into(),
            dir: Direction::In,
            wire_len: 3,
            data: vec![0xde, 0xad, 0xbe],
        };
        assert_eq!(
            packet_json(&p),
            r#"{"seq":7,"ts_sec":100,"ts_nsec":5,"ifindex":2,"ifname":"eth0","dir":"in","wire_len":3,"data":"deadbe"}"#
        );
    }
}
