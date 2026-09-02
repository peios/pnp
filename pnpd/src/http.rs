//! A deliberately small HTTP server: static UI, JSON endpoints, and a
//! server-sent-events stream carrying packets, verdicts, and stats.
//! Thread per connection, `Connection: close` everywhere except the
//! stream — at PNP-viewer scale that is the whole story, and it keeps the
//! daemon's HTTP surface dependency-free.

use std::io::{BufRead, BufReader, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::Ordering;
use std::sync::mpsc::TryRecvError;
use std::sync::Arc;
use std::time::Duration;

use crate::capture::CaptureStats;
use crate::engine::{self, Engine, PnpEvent};
use crate::json::{self, Obj};
use crate::policy;
use crate::ring::{Packet, Ring};

const UI: &str = include_str!("../ui/index.html");

pub struct Server {
    pub ring: Arc<Ring>,
    pub stats: Arc<CaptureStats>,
    pub engine: Arc<Engine>,
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
        "/api/engine" => {
            let body = engine_json(server);
            respond(stream, "200 OK", "application/json", body.as_bytes())
        }
        "/api/packets" => {
            let since = query_u64(query, "since").unwrap_or(0);
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
        "/api/verdicts" => {
            let since = query_u64(query, "since").unwrap_or(0);
            let mut body = String::from("[");
            for (i, ev) in server.engine.since(since).iter().enumerate() {
                if i > 0 {
                    body.push(',');
                }
                body.push_str(&verdict_json(ev));
            }
            body.push(']');
            respond(stream, "200 OK", "application/json", body.as_bytes())
        }
        "/api/counters" => {
            let body = counters_json(server);
            respond(stream, "200 OK", "application/json", body.as_bytes())
        }
        "/api/flows" => {
            let body = flows_json(server);
            respond(stream, "200 OK", "application/json", body.as_bytes())
        }
        "/api/policy" => {
            let body = policy::read_policy();
            respond(stream, "200 OK", "application/json", body.as_bytes())
        }
        "/api/policy/set" => policy_mutation(stream, query, true),
        "/api/policy/delete" => policy_mutation(stream, query, false),
        "/api/stream" => stream_events(stream, server),
        _ => respond(stream, "404 Not Found", "text/plain", b"not found\n"),
    }
}

/// Authoring endpoints. Query shape:
///   path=Packet/no-inbound/ssh   (segments relative to the Rules key)
///   v.<ValueName>=<value>        (set only; see policy::encode_value)
fn policy_mutation(stream: TcpStream, query: &str, is_set: bool) -> std::io::Result<()> {
    let mut path: Vec<String> = Vec::new();
    let mut values: Vec<(String, String)> = Vec::new();
    for kv in query.split('&') {
        let (k, v) = match kv.split_once('=') {
            Some((k, v)) => (k, url_decode(v)),
            None => continue,
        };
        if k == "path" {
            path = v
                .split('/')
                .filter(|s| !s.is_empty())
                .map(str::to_owned)
                .collect();
        } else if let Some(name) = k.strip_prefix("v.") {
            values.push((url_decode(name), v));
        }
    }
    let result = if is_set {
        policy::set_rule(&path, &values)
    } else {
        policy::delete_rule(&path)
    };
    match result {
        Ok(()) => respond(stream, "200 OK", "application/json", b"{\"ok\":true}"),
        Err(err) => {
            let body = Obj::new().str("error", &err).finish();
            respond(stream, "400 Bad Request", "application/json", body.as_bytes())
        }
    }
}

fn query_u64(query: &str, name: &str) -> Option<u64> {
    query
        .split('&')
        .find_map(|kv| kv.strip_prefix(name).and_then(|r| r.strip_prefix('=')))
        .and_then(|v| v.parse().ok())
}

fn url_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                if let Some(hex) = bytes.get(i + 1..i + 3) {
                    if let Ok(v) =
                        u8::from_str_radix(std::str::from_utf8(hex).unwrap_or("zz"), 16)
                    {
                        out.push(v);
                        i += 3;
                        continue;
                    }
                }
                out.push(b'%');
                i += 1;
            }
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn respond(mut stream: TcpStream, code: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}

/// The SSE stream: live packets as `packet` events, verdicts as `verdict`
/// events, and a `stats` event every two seconds so the header numbers
/// stay honest even on a silent wire.
fn stream_events(mut stream: TcpStream, server: &Server) -> std::io::Result<()> {
    let packets = server.ring.subscribe();
    let verdicts = server.engine.subscribe();
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-store\r\nConnection: keep-alive\r\n\r\n"
    )?;
    stream.set_read_timeout(None)?;
    let mut last_stats = std::time::Instant::now();
    loop {
        loop {
            match verdicts.try_recv() {
                Ok(ev) => {
                    write!(stream, "event: verdict\ndata: {}\n\n", verdict_json(&ev))?;
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => return Ok(()),
            }
        }
        // Block briefly for the first packet, then drain the rest of the
        // queue — one packet per tick throttles a busy wire behind the
        // timeout and lets verdicts race far ahead of their packets.
        match packets.recv_timeout(Duration::from_millis(150)) {
            Ok(packet) => {
                write!(stream, "event: packet\ndata: {}\n\n", packet_json(&packet))?;
                loop {
                    match packets.try_recv() {
                        Ok(p) => {
                            write!(stream, "event: packet\ndata: {}\n\n", packet_json(&p))?;
                        }
                        Err(TryRecvError::Empty) => break,
                        Err(TryRecvError::Disconnected) => return Ok(()),
                    }
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {}
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
        }
        if last_stats.elapsed() >= Duration::from_secs(2) {
            write!(stream, "event: stats\ndata: {}\n\n", status_json(server))?;
            write!(stream, "event: engine\ndata: {}\n\n", engine_json(server))?;
            last_stats = std::time::Instant::now();
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

fn engine_json(server: &Server) -> String {
    let (s, connected) = server.engine.status();
    Obj::new()
        .num("connected", connected as i64)
        .num("own_verdicts_hidden", server.engine.own_hidden() as i128)
        .num("abi", s.abi as i128)
        .num("generation", s.generation as i128)
        .num("enforcing", s.enforcing as i128)
        .num("events_dropped", s.events_dropped as i128)
        .num("seen_ingress", s.seen_ingress as i128)
        .num("seen_egress", s.seen_egress as i128)
        .num("seen_local_in", s.seen_local_in as i128)
        .num("deferred", s.deferred as i128)
        .num("fallback_judged", s.fallback_judged as i128)
        .num("parse_errors", s.parse_errors as i128)
        .num("judged", s.judged as i128)
        .num("permissive", s.permissive as i128)
        .num("fail_closed", s.fail_closed as i128)
        .num("verdict_pass", s.verdict_pass as i128)
        .num("verdict_drop", s.verdict_drop as i128)
        .num("verdict_reject", s.verdict_reject as i128)
        .num("reject_degraded", s.reject_degraded as i128)
        .num("fx_tags", s.fx_tags as i128)
        .num("fx_counts", s.fx_counts as i128)
        .num("fx_reports", s.fx_reports as i128)
        .num("fx_prompts", s.fx_prompts as i128)
        .num("last_ingest_error", s.last_ingest_error as i128)
        .num("last_ingest_t_ns", s.last_ingest_t_ns as i128)
        .num("tag_writes", s.tag_writes as i128)
        .num("tag_untracked", s.tag_untracked as i128)
        .num("tag_refused", s.tag_refused as i128)
        .num("count_writes", s.count_writes as i128)
        .num("count_key_absent", s.count_key_absent as i128)
        .num("count_refused", s.count_refused as i128)
        .num("reports_emitted", s.reports_emitted as i128)
        .num("counter_cells", s.counter_cells as i128)
        .num("reporting_level", s.reporting_level as i128)
        .num("seen_local_out", s.seen_local_out as i128)
        .num("flow_judged", s.flow_judged as i128)
        .num("flow_cached", s.flow_cached as i128)
        .num("flow_rejudged", s.flow_rejudged as i128)
        .num("flow_expired", s.flow_expired as i128)
        .num("flow_uncached", s.flow_uncached as i128)
        .num("refusals_emitted", s.refusals_emitted as i128)
        .num("refusals_bypassed", s.refusals_bypassed as i128)
        .num("teardowns_emitted", s.teardowns_emitted as i128)
        .finish()
}

fn verdict_name(v: u8) -> &'static str {
    match v {
        engine::VERDICT_PASS => "pass",
        engine::VERDICT_REJECT => "reject",
        _ => "drop",
    }
}

fn sentence_json(r: &engine::PnpFlowRec, slot: usize) -> String {
    let verdict = r.sentence_verdict[slot];
    Obj::new()
        .num("slot", slot as i64)
        .num("generation", r.sentence_generation[slot] as i128)
        .num("expires_at", r.sentence_expires_at[slot] as i128)
        .str("rule_hash", &format!("{:016x}", r.sentence_rule_hash[slot]))
        .str("verdict", verdict_name(verdict))
        .str(
            "reject_kind",
            if verdict == engine::VERDICT_REJECT {
                if r.sentence_reject_kind[slot] == 1 { "Prohibited" } else { "Refused" }
            } else {
                ""
            },
        )
        .finish()
}

/// The live flows: `{"connected":1,"total":N,"records":[{id,family,
/// protocol,dir,loopback,seen_reply,assured,related,judged,ifindex,
/// timeout_secs,src,dst,src_port,dst_port,icmp_type,icmp_code,start_secs,
/// packets:[o,r],bytes:[o,r],sentences:[...],tags:[{hash,value}]}]}`.
/// Sentences are listed for slot 0 (the flow's) and slot 1 (a loopback
/// flow's inbound endpoint) when present; rule hashes are FNV-1a-64 of
/// the attributing rule's path, which the viewer resolves against the
/// policy it can read.
fn flows_json(server: &Server) -> String {
    let dump = match server.engine.flows() {
        Ok(d) => d,
        Err(err) => {
            return Obj::new()
                .num("connected", 0)
                .str("error", &err)
                .finish()
        }
    };
    let mut records = Vec::with_capacity(dump.records.len());
    for r in &dump.records {
        let sentences: Vec<String> = (0..engine::FLOW_SENTENCES)
            .filter(|&slot| r.sentence_generation[slot] != 0)
            .map(|slot| sentence_json(r, slot))
            .collect();
        let tags: Vec<String> = (0..(r.n_tags as usize).min(engine::FLOW_MAX_TAGS))
            .map(|i| {
                Obj::new()
                    .str("hash", &format!("{:016x}", r.tag_hash[i]))
                    .num("value", r.tag_value[i] as i128)
                    .finish()
            })
            .collect();
        records.push(
            Obj::new()
                .num("id", r.id as i128)
                .num("family", r.family as i64)
                .num("protocol", r.protocol as i64)
                .str("dir", if r.direction == 1 { "out" } else { "in" })
                .num("loopback", r.loopback as i64)
                .num("seen_reply", r.seen_reply as i64)
                .num("assured", r.assured as i64)
                .num("related", r.related as i64)
                .num("judged", r.judged as i64)
                .num("ifindex", r.ifindex as i64)
                .num("timeout_secs", r.timeout_secs as i128)
                .str("src", &fmt_addr(r.family, &r.src_addr))
                .str("dst", &fmt_addr(r.family, &r.dst_addr))
                .num("src_port", r.src_port as i64)
                .num("dst_port", r.dst_port as i64)
                .num("icmp_type", r.icmp_type as i64)
                .num("icmp_code", r.icmp_code as i64)
                .num("start_secs", r.start_secs as i128)
                .raw("packets", &format!("[{},{}]", r.packets[0], r.packets[1]))
                .raw("bytes", &format!("[{},{}]", r.bytes[0], r.bytes[1]))
                .raw("sentences", &format!("[{}]", sentences.join(",")))
                .raw("tags", &format!("[{}]", tags.join(",")))
                .finish(),
        );
    }
    Obj::new()
        .num("connected", 1)
        .num("total", dump.total as i128)
        .raw("records", &format!("[{}]", records.join(",")))
        .finish()
}

fn keyspec_json(keyspec: u8) -> String {
    let mut names = Vec::new();
    if keyspec & engine::KEY_SRC_ADDR != 0 {
        names.push("\"SrcAddr\"");
    }
    if keyspec & engine::KEY_DST_ADDR != 0 {
        names.push("\"DstAddr\"");
    }
    if keyspec & engine::KEY_INTERFACE != 0 {
        names.push("\"Interface\"");
    }
    format!("[{}]", names.join(","))
}

/// The counter store, every cell: `{"connected":1,"total_cells":N,
/// "records":[{name,keyspec,family,ifindex,src,dst,total,last_secs,
/// windows:[{secs,value}]}]}`.
fn counters_json(server: &Server) -> String {
    let dump = match server.engine.counters() {
        Ok(d) => d,
        Err(err) => {
            return Obj::new()
                .num("connected", 0)
                .str("error", &err)
                .finish()
        }
    };
    let mut records = Vec::with_capacity(dump.records.len());
    for r in &dump.records {
        let name_end = r.name.iter().position(|&b| b == 0).unwrap_or(r.name.len());
        let name = String::from_utf8_lossy(&r.name[..name_end]);
        let mut windows = Vec::new();
        for w in 0..(r.n_windows as usize).min(8) {
            windows.push(
                Obj::new()
                    .num("secs", r.window_secs[w] as i64)
                    .num("value", r.window_value[w] as i128)
                    .finish(),
            );
        }
        records.push(
            Obj::new()
                .str("name", &name)
                .raw("keyspec", &keyspec_json(r.keyspec))
                .num("family", r.family as i64)
                .num("ifindex", r.ifindex as i64)
                .str("src", &fmt_addr(r.family, &r.src_addr))
                .str("dst", &fmt_addr(r.family, &r.dst_addr))
                .num("total", r.total as i128)
                .num("last_secs", r.last_secs as i128)
                .raw("windows", &format!("[{}]", windows.join(",")))
                .finish(),
        );
    }
    Obj::new()
        .num("connected", 1)
        .num("total_cells", dump.total_cells as i64)
        .raw("records", &format!("[{}]", records.join(",")))
        .finish()
}

fn fmt_addr(family: u8, bytes: &[u8; 16]) -> String {
    match family {
        4 => format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]),
        6 => {
            let mut parts = Vec::with_capacity(8);
            for i in 0..8 {
                parts.push(format!(
                    "{:x}",
                    u16::from_be_bytes([bytes[2 * i], bytes[2 * i + 1]])
                ));
            }
            parts.join(":")
        }
        _ => String::new(),
    }
}

fn verdict_json(ev: &PnpEvent) -> String {
    let verdict = verdict_name(ev.verdict);
    let seat = match ev.seat {
        1 => "ingress",
        2 => "egress",
        4 => "local-out",
        _ => "local-in",
    };
    let layer = match ev.layer {
        1 => "RawPacket",
        2 => "Flow",
        _ => "Packet",
    };
    let attr_end = ev
        .attributed
        .iter()
        .position(|&b| b == 0)
        .unwrap_or(ev.attributed.len());
    let attributed = String::from_utf8_lossy(&ev.attributed[..attr_end]);
    Obj::new()
        .num("seq", ev.seq as i128)
        .num("t_ns", ev.t_ns as i128)
        .str("seat", seat)
        .str("layer", layer)
        .str("verdict", verdict)
        .str(
            "reject_kind",
            if ev.verdict == engine::VERDICT_REJECT {
                if ev.reject_kind == 1 { "Prohibited" } else { "Refused" }
            } else {
                ""
            },
        )
        .num("backstop", (ev.flags & engine::EV_F_BACKSTOP != 0) as i64)
        .num("fail_closed", (ev.flags & engine::EV_F_FAIL_CLOSED != 0) as i64)
        .num(
            "reject_degraded",
            (ev.flags & engine::EV_F_REJECT_DEGRADED != 0) as i64,
        )
        .num("rejudged", (ev.flags & engine::EV_F_REJUDGED != 0) as i64)
        .str("dir", if ev.direction == 1 { "out" } else { "in" })
        .num("family", ev.addr_family as i64)
        .num("protocol", ev.protocol as i64)
        .num("flow_state", ev.flow_state as i64)
        .num("ifindex", ev.ifindex as i128)
        .str("src", &fmt_addr(ev.addr_family, &ev.src_addr))
        .str("dst", &fmt_addr(ev.addr_family, &ev.dst_addr))
        .num("src_port", ev.src_port as i64)
        .num("dst_port", ev.dst_port as i64)
        .num("ether_type", ev.ether_type as i64)
        .num("length", ev.length as i128)
        .num("fx_tags", (ev.effects & 0xff) as i64)
        .num("fx_counts", (ev.effects >> 8 & 0xff) as i64)
        .num("fx_reports", (ev.effects >> 16 & 0xff) as i64)
        .num("fx_prompts", (ev.effects >> 24 & 0xff) as i64)
        .str("by", &attributed)
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

    #[test]
    fn verdict_json_shape() {
        let mut ev: PnpEvent = unsafe { std::mem::zeroed() };
        ev.seq = 9;
        ev.seat = 3;
        ev.verdict = engine::VERDICT_DROP;
        ev.flags = engine::EV_F_BACKSTOP;
        ev.addr_family = 4;
        ev.src_addr[..4].copy_from_slice(&[10, 0, 0, 7]);
        ev.dst_addr[..4].copy_from_slice(&[10, 0, 0, 5]);
        ev.src_port = 4444;
        ev.dst_port = 23;
        ev.attributed[..8].copy_from_slice(b"backstop");
        let j = verdict_json(&ev);
        assert!(j.contains("\"verdict\":\"drop\""));
        assert!(j.contains("\"backstop\":1"));
        assert!(j.contains("\"src\":\"10.0.0.7\""));
        assert!(j.contains("\"by\":\"backstop\""));
    }

    #[test]
    fn url_decoding() {
        assert_eq!(url_decode("PASS%2CREPORT(3)"), "PASS,REPORT(3)");
        assert_eq!(url_decode("a+b%20c"), "a b c");
        assert_eq!(url_decode("plain"), "plain");
    }
}
