//! The verdict stream: /dev/peios-pnp, drained into a ring the HTTP layer
//! serves, plus the engine STATUS ioctl polled on a slow tick.
//!
//! Struct layouts mirror the canonical ABI in pkm/uapi/pkm/pnp.h (also
//! machine-mirrored in pkm/uapi/generated/rust). Hand-copied here because
//! pnpd builds from its own repo; the sizes are asserted and the ABI field
//! is checked at open. Experimental ABI — pnpd and the kernel ship
//! together on the experimental edition.

use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::os::unix::io::AsRawFd;
use std::sync::mpsc::{Receiver, SyncSender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::log;

pub const VERDICT_PASS: u8 = 0;
pub const VERDICT_REJECT: u8 = 1;
#[allow(dead_code)] // ABI documentation; the match's catch-all covers it.
pub const VERDICT_DROP: u8 = 2;

pub const EV_F_BACKSTOP: u8 = 0x01;
pub const EV_F_FAIL_CLOSED: u8 = 0x02;
pub const EV_F_REJECT_DEGRADED: u8 = 0x04;

/// Mirror of `struct peios_pnp_event` (pkm/uapi/pkm/pnp.h).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct PnpEvent {
    pub seq: u64,
    pub t_ns: u64,
    pub seat: u8,
    pub layer: u8,
    pub verdict: u8,
    pub flags: u8,
    pub direction: u8,
    pub addr_family: u8,
    pub protocol: u8,
    pub flow_state: u8,
    pub ifindex: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub ether_type: u16,
    pub _pad0: u16,
    pub src_addr: [u8; 16],
    pub dst_addr: [u8; 16],
    pub length: u32,
    pub effects: u32,
    pub attributed: [u8; 96],
    pub _pad1: u32,
}

const _: () = assert!(std::mem::size_of::<PnpEvent>() == 176);

/// Mirror of `struct peios_pnp_status` (pkm/uapi/pkm/pnp.h).
#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PnpStatus {
    pub abi: u64,
    pub generation: u64,
    pub enforcing: u64,
    pub events_dropped: u64,
    pub seen_ingress: u64,
    pub seen_egress: u64,
    pub seen_local_in: u64,
    pub deferred: u64,
    pub fallback_judged: u64,
    pub parse_errors: u64,
    pub judged: u64,
    pub permissive: u64,
    pub fail_closed: u64,
    pub verdict_pass: u64,
    pub verdict_drop: u64,
    pub verdict_reject: u64,
    pub reject_degraded: u64,
    pub fx_tags: u64,
    pub fx_counts: u64,
    pub fx_reports: u64,
    pub fx_prompts: u64,
    pub last_ingest_error: u64,
    pub last_ingest_t_ns: u64,
    pub _reserved: [u64; 5],
}

const _: () = assert!(std::mem::size_of::<PnpStatus>() == 224);

/// _IOR('N', 1, struct peios_pnp_status): dir=2, size, type 'N', nr 1.
const IOC_STATUS: libc::c_ulong = (2u64 << 30
    | (std::mem::size_of::<PnpStatus>() as u64) << 16
    | (b'N' as u64) << 8
    | 1) as libc::c_ulong;

const DEVICE: &str = "/dev/peios-pnp";
const RING: usize = 8192;

struct Inner {
    events: VecDeque<PnpEvent>,
    subscribers: Vec<SyncSender<PnpEvent>>,
    status: PnpStatus,
    /// Whether the device is currently open and streaming.
    connected: bool,
    /// Own-flow verdicts hidden from the ring (counted, per the honesty
    /// rule — same treatment the tap gives its own packets).
    own_hidden: u64,
}

/// Shared engine view: the verdict ring and the latest status snapshot.
pub struct Engine {
    inner: Mutex<Inner>,
    /// The port pnpd serves on: verdicts about our own HTTP flow feed
    /// back (each SSE verdict event is itself judged traffic), so they
    /// are hidden from the ring and counted instead.
    own_port: u16,
}

impl Engine {
    pub fn new(own_port: u16) -> Arc<Engine> {
        Arc::new(Engine {
            inner: Mutex::new(Inner {
                events: VecDeque::with_capacity(RING),
                subscribers: Vec::new(),
                status: PnpStatus::default(),
                connected: false,
                own_hidden: 0,
            }),
            own_port,
        })
    }

    pub fn own_hidden(&self) -> u64 {
        self.inner.lock().unwrap().own_hidden
    }

    pub fn status(&self) -> (PnpStatus, bool) {
        let inner = self.inner.lock().unwrap();
        (inner.status, inner.connected)
    }

    /// Events with seq > since, oldest first.
    pub fn since(&self, since: u64) -> Vec<PnpEvent> {
        let inner = self.inner.lock().unwrap();
        inner
            .events
            .iter()
            .filter(|e| e.seq > since)
            .cloned()
            .collect()
    }

    pub fn subscribe(&self) -> Receiver<PnpEvent> {
        let (tx, rx) = std::sync::mpsc::sync_channel(1024);
        self.inner.lock().unwrap().subscribers.push(tx);
        rx
    }

    fn push(&self, ev: PnpEvent) {
        let mut inner = self.inner.lock().unwrap();
        // The observer must not observe itself into a feedback loop:
        // sending a verdict event over SSE is itself judged TCP traffic.
        if ev.protocol == 6
            && (ev.addr_family == 4 || ev.addr_family == 6)
            && (ev.src_port == self.own_port || ev.dst_port == self.own_port)
        {
            inner.own_hidden += 1;
            return;
        }
        if inner.events.len() == RING {
            inner.events.pop_front();
        }
        inner.events.push_back(ev);
        // Slow or gone subscribers are cut off; they rejoin by seq.
        inner
            .subscribers
            .retain(|tx| !matches!(tx.try_send(ev), Err(std::sync::mpsc::TrySendError::Disconnected(_))));
    }

    fn set_status(&self, status: PnpStatus, connected: bool) {
        let mut inner = self.inner.lock().unwrap();
        inner.status = status;
        inner.connected = connected;
    }
}

/// Runs forever: opens the device (retrying — the daemon may start before
/// the node exists), streams events into the ring, and refreshes status
/// about once a second.
pub fn run(engine: Arc<Engine>) {
    loop {
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(DEVICE)
        {
            Ok(f) => f,
            Err(err) => {
                log::info(&format!(
                    "verdict stream: {DEVICE} not available ({err}); retrying"
                ));
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        };

        match refresh_status(&file, &engine) {
            Ok(abi) if abi == 1 => {
                log::info("verdict stream: connected to /dev/peios-pnp (abi 1)")
            }
            Ok(abi) => {
                log::error(&format!(
                    "verdict stream: unknown ABI {abi}; refusing to parse events"
                ));
                std::thread::sleep(Duration::from_secs(30));
                continue;
            }
            Err(err) => {
                log::error(&format!("verdict stream: STATUS ioctl failed: {err}"));
                std::thread::sleep(Duration::from_secs(5));
                continue;
            }
        }

        if let Err(err) = stream(&file, &engine) {
            log::error(&format!("verdict stream: {err}; reconnecting"));
        }
        engine.set_status(engine.status().0, false);
        std::thread::sleep(Duration::from_secs(2));
    }
}

fn refresh_status(file: &File, engine: &Arc<Engine>) -> Result<u64, String> {
    let mut status = PnpStatus::default();
    let rc = unsafe {
        libc::ioctl(
            file.as_raw_fd(),
            IOC_STATUS,
            &mut status as *mut PnpStatus,
        )
    };
    if rc != 0 {
        return Err(format!("errno {}", std::io::Error::last_os_error()));
    }
    let abi = status.abi;
    engine.set_status(status, true);
    Ok(abi)
}

fn stream(file: &File, engine: &Arc<Engine>) -> Result<(), String> {
    let mut file = file;
    let mut buf = vec![0u8; std::mem::size_of::<PnpEvent>() * 64];
    let mut last_status = std::time::Instant::now();
    loop {
        match file.read(&mut buf) {
            Ok(0) => return Err("device closed".into()),
            Ok(n) => {
                let count = n / std::mem::size_of::<PnpEvent>();
                for i in 0..count {
                    let off = i * std::mem::size_of::<PnpEvent>();
                    let mut ev = PnpEvent {
                        // Overwritten by the copy below.
                        ..unsafe { std::mem::zeroed() }
                    };
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            buf.as_ptr().add(off),
                            &mut ev as *mut PnpEvent as *mut u8,
                            std::mem::size_of::<PnpEvent>(),
                        );
                    }
                    engine.push(ev);
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                let mut pfd = libc::pollfd {
                    fd: file.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                unsafe { libc::poll(&mut pfd, 1, 1000) };
            }
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => {}
            Err(err) => return Err(err.to_string()),
        }
        if last_status.elapsed() >= Duration::from_secs(1) {
            refresh_status(file, engine)?;
            last_status = std::time::Instant::now();
        }
    }
}
