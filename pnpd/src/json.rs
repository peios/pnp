//! Hand-rolled JSON encoding — the daemon emits a handful of fixed shapes,
//! which does not justify a serialization dependency.

pub struct Obj {
    out: String,
    first: bool,
}

impl Obj {
    pub fn new() -> Obj {
        Obj { out: String::from("{"), first: true }
    }

    fn key(&mut self, key: &str) {
        if !self.first {
            self.out.push(',');
        }
        self.first = false;
        self.out.push('"');
        self.out.push_str(key);
        self.out.push_str("\":");
    }

    pub fn num(mut self, key: &str, value: impl Into<i128>) -> Obj {
        self.key(key);
        self.out.push_str(&value.into().to_string());
        self
    }

    pub fn str(mut self, key: &str, value: &str) -> Obj {
        self.key(key);
        self.out.push_str(&escape(value));
        self
    }

    pub fn raw(mut self, key: &str, value: &str) -> Obj {
        self.key(key);
        self.out.push_str(value);
        self
    }

    pub fn finish(mut self) -> String {
        self.out.push('}');
        self.out
    }
}

pub fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len() * 2);
    for b in data {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn objects_encode() {
        let s = Obj::new().num("a", 1u32).str("b", "x\"y").finish();
        assert_eq!(s, r#"{"a":1,"b":"x\"y"}"#);
    }

    #[test]
    fn hex_encodes() {
        assert_eq!(hex(&[0x00, 0xff, 0x0a]), "00ff0a");
    }
}
