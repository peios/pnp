//! Security identifiers as the viewer shows them: the textual form of a
//! binary SID, the well-known names an owner would recognise, and the
//! service names behind `S-1-5-80-…` SIDs, derived from the service
//! definitions in the registry exactly as peinit derives a service's SID
//! (the SHA-1 of the uppercased UTF-16LE name). The kernel never resolves
//! a name; the viewer does, and says when it cannot.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use peios::registry::{Key, KeyAccess, OpenFlags};

const SERVICES_PATH: &str = "Machine\\System\\Services";
/// How long a service-name map is trusted before the registry is re-read.
const SERVICES_TTL: Duration = Duration::from_secs(30);

/// The textual form of a binary SID (`S-1-5-18`), or `None` for an absent
/// (all-zero) or malformed one.
pub fn sid_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 8 || bytes[0] != 1 {
        return None;
    }
    let count = usize::from(bytes[1]);
    if count > 15 || bytes.len() < 8 + count * 4 {
        return None;
    }
    let mut authority = [0u8; 8];
    authority[2..].copy_from_slice(&bytes[2..8]);
    let mut out = format!("S-1-{}", u64::from_be_bytes(authority));
    for i in 0..count {
        let at = 8 + i * 4;
        let sub = u32::from_le_bytes([bytes[at], bytes[at + 1], bytes[at + 2], bytes[at + 3]]);
        out.push_str(&format!("-{sub}"));
    }
    Some(out)
}

/// A process GUID as lowercase hyphenated text (8-4-4-4-12).
pub fn guid_text(guid: &[u8]) -> String {
    let hex: String = guid.iter().map(|b| format!("{b:02x}")).collect();
    if hex.len() != 32 {
        return hex;
    }
    format!("{}-{}-{}-{}-{}", &hex[..8], &hex[8..12], &hex[12..16], &hex[16..20], &hex[20..])
}

/// The names of the principals an owner is likely to meet.
pub fn well_known_name(sid: &str) -> Option<&'static str> {
    Some(match sid {
        "S-1-1-0" => "Everyone",
        "S-1-3-0" => "CreatorOwner",
        "S-1-5-2" => "Network",
        "S-1-5-4" => "Interactive",
        "S-1-5-6" => "Service",
        "S-1-5-7" => "Anonymous",
        "S-1-5-11" => "AuthenticatedUsers",
        "S-1-5-18" => "SYSTEM",
        "S-1-5-19" => "LocalService",
        "S-1-5-20" => "NetworkService",
        "S-1-5-32-544" => "Administrators",
        "S-1-5-32-545" => "Users",
        "S-1-5-32-546" => "Guests",
        _ => return None,
    })
}

/// The per-service SID of a service name, as peinit derives it.
pub fn service_sid(name: &str) -> String {
    let mut encoded = Vec::with_capacity(name.len() * 2);
    for unit in name.to_uppercase().encode_utf16() {
        encoded.extend_from_slice(&unit.to_le_bytes());
    }
    let digest = sha1(&encoded);
    let mut out = String::from("S-1-5-80");
    for chunk in digest.chunks_exact(4) {
        out.push_str(&format!(
            "-{}",
            u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]])
        ));
    }
    out
}

struct ServiceMap {
    read_at: Option<Instant>,
    /// (service SID, service name); a machine has dozens of services, so
    /// a scan is fine and the static stays constant-constructible.
    by_sid: Vec<(String, String)>,
}

static SERVICES: Mutex<ServiceMap> = Mutex::new(ServiceMap {
    read_at: None,
    by_sid: Vec::new(),
});

/// The service name behind a per-service SID, from the service definitions
/// under `Machine\System\Services`; `None` when no definition derives to
/// it (a service defined elsewhere, or a SID that is not a service's).
pub fn service_name(sid: &str) -> Option<String> {
    if !sid.starts_with("S-1-5-80-") {
        return None;
    }
    let mut map = SERVICES.lock().unwrap_or_else(|e| e.into_inner());
    let stale = map
        .read_at
        .map(|t| t.elapsed() > SERVICES_TTL)
        .unwrap_or(true);
    if stale {
        map.by_sid = read_services().unwrap_or_default();
        map.read_at = Some(Instant::now());
    }
    map.by_sid
        .iter()
        .find(|(s, _)| s == sid)
        .map(|(_, name)| name.clone())
}

fn read_services() -> peios::Result<Vec<(String, String)>> {
    let root = Key::open(None, SERVICES_PATH, KeyAccess::READ, OpenFlags::empty())?;
    let mut out = Vec::new();
    for subkey in root.subkeys(None) {
        let Ok(subkey) = subkey else { continue };
        let name = String::from_utf8_lossy(&subkey.name).into_owned();
        out.push((service_sid(&name), name));
    }
    Ok(out)
}

/// SHA-1, for the service-SID derivation only.
fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0];
    let bit_len = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_be_bytes());
    for block in msg.chunks_exact(64) {
        let mut w = [0u32; 80];
        for (i, word) in w.iter_mut().enumerate().take(16) {
            *word = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let (mut a, mut b, mut c, mut d, mut e) = (h[0], h[1], h[2], h[3], h[4]);
        for (i, word) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5A82_7999),
                20..=39 => (b ^ c ^ d, 0x6ED9_EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1B_BCDC),
                _ => (b ^ c ^ d, 0xCA62_C1D6),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(*word);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
    }
    let mut out = [0u8; 20];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sid_text_reads_the_binary_form() {
        let mut bytes = vec![1u8, 2, 0, 0, 0, 0, 0, 5];
        bytes.extend_from_slice(&32u32.to_le_bytes());
        bytes.extend_from_slice(&544u32.to_le_bytes());
        assert_eq!(sid_text(&bytes).as_deref(), Some("S-1-5-32-544"));
        assert_eq!(well_known_name("S-1-5-32-544"), Some("Administrators"));
        assert_eq!(sid_text(&[0u8; 68]), None);
    }

    #[test]
    fn service_sids_match_peinit() {
        assert_eq!(
            service_sid("app"),
            "S-1-5-80-2426739453-2501902915-3009591593-922485235-2122754908"
        );
        assert_eq!(
            service_sid("resolvd"),
            "S-1-5-80-3864064249-1823296737-2008945602-1354971773-2894779966"
        );
    }

    #[test]
    fn guid_text_is_hyphenated_lowercase() {
        let guid: Vec<u8> = (0..16u8).collect();
        assert_eq!(guid_text(&guid), "00010203-0405-0607-0809-0a0b0c0d0e0f");
    }
}
