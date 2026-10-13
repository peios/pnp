//! Logging: information on stdout, errors on stderr (peinit captures both),
//! mirrored best-effort to /dev/kmsg so the daemon is diagnosable from the
//! serial console even when nothing collects stderr.

use std::io::Write;

fn emit(level: &str, msg: &str) {
    if level == "info" {
        println!("pnpd: {level}: {msg}");
    } else {
        eprintln!("pnpd: {level}: {msg}");
    }
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
