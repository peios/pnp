//! Logging: stderr always (eventd captures service stderr where present),
//! mirrored best-effort to /dev/kmsg so the daemon is diagnosable from the
//! serial console even when nothing collects stderr.

use std::io::Write;

fn emit(level: &str, msg: &str) {
    eprintln!("pnpd: {level}: {msg}");
    if let Ok(mut kmsg) = std::fs::OpenOptions::new().write(true).open("/dev/kmsg") {
        let _ = writeln!(kmsg, "pnpd: {level}: {msg}");
    }
}

pub fn info(msg: &str) {
    emit("info", msg);
}

pub fn error(msg: &str) {
    emit("error", msg);
}
