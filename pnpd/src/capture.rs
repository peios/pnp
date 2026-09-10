//! The wire tap: one packet socket receiving a copy of every frame on every
//! interface, both directions. Purely observational — a packet socket is a
//! kernel tap that clones frames; it cannot delay or drop the traffic itself.
//!
//! Placement honesty (surfaced in the viewer's docs): inbound frames are
//! copied before the IP stack or any filtering sees them, outbound frames as
//! they are handed to the driver. Outbound frames may therefore show unfilled
//! checksums (hardware fills them later) and offload-coalesced sizes larger
//! than any single wire frame. That is the tap telling the truth about where
//! it stands, not corruption.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use crate::ring::{Direction, Packet, Ring};

const ETH_P_ALL: u16 = 0x0003;
const SOL_PACKET: libc::c_int = 263;
const PACKET_STATISTICS: libc::c_int = 6;
const PACKET_OUTGOING: u8 = 4;
const PACKET_BROADCAST: u8 = 1;
const PACKET_MULTICAST: u8 = 2;
const PACKET_OTHERHOST: u8 = 3;

#[repr(C)]
struct TpacketStats {
    tp_packets: u32,
    tp_drops: u32,
}

/// Counters the capture publishes for the status endpoint. `dropped` is the
/// kernel's own tally of frames it could not fit in the socket buffer — the
/// tap confesses its gaps rather than papering over them. `suppressed` counts
/// pnpd's own HTTP traffic, excluded from the ring to break the feedback loop
/// (serving a packet event generates packets, which would generate events,
/// which would generate packets...). Suppressed frames are counted, never
/// silently vanished.
pub struct CaptureStats {
    pub captured: AtomicU64,
    pub dropped: AtomicU64,
    pub suppressed: AtomicU64,
}

pub struct Capture {
    fd: libc::c_int,
    ring: Arc<Ring>,
    stats: Arc<CaptureStats>,
    /// The daemon's own TCP listen port; frames of that flow are suppressed.
    own_port: u16,
    names: HashMap<u32, String>,
}

impl Capture {
    pub fn open(ring: Arc<Ring>, stats: Arc<CaptureStats>, own_port: u16) -> io::Result<Capture> {
        let fd = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_CLOEXEC,
                (ETH_P_ALL.to_be()) as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // A generous socket buffer: the ring in userspace is the real bound,
        // this just rides out bursts between wakeups.
        let sz: libc::c_int = 4 * 1024 * 1024;
        unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &sz as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
        Ok(Capture {
            fd,
            ring,
            stats,
            own_port,
            names: HashMap::new(),
        })
    }

    /// Receive loop; runs on its own thread for the life of the daemon.
    pub fn run(mut self) {
        let mut buf = vec![0u8; 65536];
        loop {
            let mut addr: libc::sockaddr_ll = unsafe { std::mem::zeroed() };
            let mut addrlen = std::mem::size_of::<libc::sockaddr_ll>() as libc::socklen_t;
            let n = unsafe {
                libc::recvfrom(
                    self.fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    libc::MSG_TRUNC,
                    &mut addr as *mut _ as *mut libc::sockaddr,
                    &mut addrlen,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                if err.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                crate::log::error(&format!("capture: recvfrom: {err}"));
                std::thread::sleep(std::time::Duration::from_millis(100));
                continue;
            }
            let wire_len = n as usize;
            let captured = wire_len.min(buf.len());
            let data = &buf[..captured];

            self.harvest_kernel_drops();

            if is_own_flow(data, self.own_port) {
                self.stats.suppressed.fetch_add(1, Ordering::Relaxed);
                continue;
            }

            let mut ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut ts) };

            let ifindex = addr.sll_ifindex as u32;
            let ifname = self.name_of(ifindex);
            let dir = match addr.sll_pkttype {
                PACKET_OUTGOING => Direction::Out,
                PACKET_BROADCAST => Direction::Broadcast,
                PACKET_MULTICAST => Direction::Multicast,
                PACKET_OTHERHOST => Direction::Other,
                _ => Direction::In,
            };

            self.stats.captured.fetch_add(1, Ordering::Relaxed);
            self.ring.push(Packet {
                seq: 0, // assigned by the ring
                ts_sec: ts.tv_sec as i64,
                ts_nsec: ts.tv_nsec as i64,
                ifindex,
                ifname,
                dir,
                wire_len,
                data: data.to_vec(),
            });
        }
    }

    /// PACKET_STATISTICS resets on read, so accumulate into our counter.
    fn harvest_kernel_drops(&self) {
        let mut st = TpacketStats {
            tp_packets: 0,
            tp_drops: 0,
        };
        let mut len = std::mem::size_of::<TpacketStats>() as libc::socklen_t;
        let r = unsafe {
            libc::getsockopt(
                self.fd,
                SOL_PACKET,
                PACKET_STATISTICS,
                &mut st as *mut _ as *mut libc::c_void,
                &mut len,
            )
        };
        if r == 0 && st.tp_drops > 0 {
            self.stats
                .dropped
                .fetch_add(st.tp_drops as u64, Ordering::Relaxed);
        }
    }

    fn name_of(&mut self, ifindex: u32) -> String {
        if let Some(name) = self.names.get(&ifindex) {
            return name.clone();
        }
        let mut buf = [0u8; libc::IF_NAMESIZE];
        let p = unsafe { libc::if_indextoname(ifindex, buf.as_mut_ptr() as *mut libc::c_char) };
        let name = if p.is_null() {
            format!("if{ifindex}")
        } else {
            let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
            String::from_utf8_lossy(&buf[..end]).into_owned()
        };
        self.names.insert(ifindex, name.clone());
        name
    }
}

/// Whether a frame belongs to pnpd's own HTTP flow: TCP with our listen port
/// on either end. Deliberately minimal — plain IPv4/IPv6 with no extension
/// headers, which is all our own server traffic ever is.
fn is_own_flow(frame: &[u8], own_port: u16) -> bool {
    let (ethertype, mut off) = match frame.get(12..14) {
        Some(t) => (u16::from_be_bytes([t[0], t[1]]), 14),
        None => return false,
    };
    let ethertype = if ethertype == 0x8100 {
        // One VLAN tag: real ethertype 4 bytes later.
        match frame.get(16..18) {
            Some(t) => {
                off = 18;
                u16::from_be_bytes([t[0], t[1]])
            }
            None => return false,
        }
    } else {
        ethertype
    };
    let l4 = match ethertype {
        0x0800 => {
            // IPv4: protocol at +9, header length from IHL.
            let ihl = match frame.get(off) {
                Some(b) => (b & 0x0f) as usize * 4,
                None => return false,
            };
            if frame.get(off + 9) != Some(&6) {
                return false;
            }
            off + ihl
        }
        0x86dd => {
            // IPv6: next header at +6; no extension-header walk needed for
            // our own plain TCP.
            if frame.get(off + 6) != Some(&6) {
                return false;
            }
            off + 40
        }
        _ => return false,
    };
    let (src, dst) = match (frame.get(l4..l4 + 2), frame.get(l4 + 2..l4 + 4)) {
        (Some(s), Some(d)) => (
            u16::from_be_bytes([s[0], s[1]]),
            u16::from_be_bytes([d[0], d[1]]),
        ),
        _ => return false,
    };
    src == own_port || dst == own_port
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tcp4_frame(src: u16, dst: u16) -> Vec<u8> {
        let mut f = vec![0u8; 54];
        f[12] = 0x08;
        f[13] = 0x00; // IPv4
        f[14] = 0x45; // v4, IHL 5
        f[14 + 9] = 6; // TCP
        f[34..36].copy_from_slice(&src.to_be_bytes());
        f[36..38].copy_from_slice(&dst.to_be_bytes());
        f
    }

    #[test]
    fn own_flow_is_recognised_and_only_own_flow() {
        assert!(is_own_flow(&tcp4_frame(7370, 40000), 7370));
        assert!(is_own_flow(&tcp4_frame(40000, 7370), 7370));
        assert!(!is_own_flow(&tcp4_frame(80, 40000), 7370));
        assert!(
            !is_own_flow(&[0u8; 10], 7370),
            "runt frames are not own flow"
        );
    }

    #[test]
    fn non_tcp_is_never_suppressed() {
        let mut arp = vec![0u8; 42];
        arp[12] = 0x08;
        arp[13] = 0x06;
        assert!(!is_own_flow(&arp, 7370));
    }
}
