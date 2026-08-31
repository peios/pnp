//! The packet ring: a bounded backlog plus live fan-out to stream
//! subscribers. The ring is the daemon's whole memory — when it wraps, the
//! oldest packets are gone, and the sequence numbers make the gap visible to
//! a client that asks for history it no longer has.

use std::collections::VecDeque;
use std::sync::mpsc;
use std::sync::{Arc, Mutex};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    In,
    Out,
    Broadcast,
    Multicast,
    /// Promiscuous sightings of frames addressed to someone else entirely.
    Other,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::In => "in",
            Direction::Out => "out",
            Direction::Broadcast => "bcast",
            Direction::Multicast => "mcast",
            Direction::Other => "other",
        }
    }
}

pub struct Packet {
    pub seq: u64,
    pub ts_sec: i64,
    pub ts_nsec: i64,
    pub ifindex: u32,
    pub ifname: String,
    pub dir: Direction,
    /// Length on the wire; `data` may be shorter if the frame outgrew the
    /// capture buffer (offload-coalesced frames can).
    pub wire_len: usize,
    pub data: Vec<u8>,
}

struct Inner {
    packets: VecDeque<Arc<Packet>>,
    next_seq: u64,
    subscribers: Vec<mpsc::SyncSender<Arc<Packet>>>,
}

pub struct Ring {
    capacity: usize,
    inner: Mutex<Inner>,
}

impl Ring {
    pub fn new(capacity: usize) -> Ring {
        Ring {
            capacity,
            inner: Mutex::new(Inner {
                packets: VecDeque::with_capacity(capacity),
                next_seq: 1,
                subscribers: Vec::new(),
            }),
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn push(&self, mut packet: Packet) {
        let mut inner = self.inner.lock().unwrap();
        packet.seq = inner.next_seq;
        inner.next_seq += 1;
        let packet = Arc::new(packet);
        if inner.packets.len() == self.capacity {
            inner.packets.pop_front();
        }
        inner.packets.push_back(packet.clone());
        // A subscriber that cannot keep up loses its stream rather than
        // stalling the capture: try_send, and on a full channel the client is
        // cut off (it can rejoin and see the gap by sequence number).
        inner.subscribers.retain(|tx| match tx.try_send(packet.clone()) {
            Ok(()) => true,
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => false,
        });
    }

    /// Everything currently held with seq > since, oldest first.
    pub fn since(&self, since: u64) -> Vec<Arc<Packet>> {
        let inner = self.inner.lock().unwrap();
        inner.packets.iter().filter(|p| p.seq > since).cloned().collect()
    }

    pub fn subscribe(&self) -> mpsc::Receiver<Arc<Packet>> {
        let (tx, rx) = mpsc::sync_channel(1024);
        self.inner.lock().unwrap().subscribers.push(tx);
        rx
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet() -> Packet {
        Packet {
            seq: 0,
            ts_sec: 0,
            ts_nsec: 0,
            ifindex: 2,
            ifname: "eth0".into(),
            dir: Direction::In,
            wire_len: 60,
            data: vec![0; 60],
        }
    }

    #[test]
    fn ring_wraps_and_sequences_stay_monotonic() {
        let ring = Ring::new(3);
        for _ in 0..5 {
            ring.push(packet());
        }
        let held: Vec<u64> = ring.since(0).iter().map(|p| p.seq).collect();
        assert_eq!(held, vec![3, 4, 5], "oldest two fell off, seqs unchanged");
        assert_eq!(ring.since(4).len(), 1);
    }

    #[test]
    fn subscribers_get_live_packets() {
        let ring = Ring::new(8);
        let rx = ring.subscribe();
        ring.push(packet());
        assert_eq!(rx.recv().unwrap().seq, 1);
    }
}
