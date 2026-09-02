//! Policy authoring: read and edit Machine\System\Network\Rules through
//! the peios registry API.
//!
//! pnpd is an observer and an authoring surface, never in the enforcement
//! path: the kernel reads the subtree itself and re-walks on change, so an
//! edit here becomes a new policy generation (or a loudly-kept old one,
//! when validation refuses it — the engine status carries the verdict).
//! Multi-key edits ride one registry transaction so the kernel's watch
//! never sees a half-written rule.

use std::fmt::Write as _;

use peios::registry::{CreateFlags, Key, KeyAccess, OpenFlags, Transaction, ValueType};

use crate::json;

const RULES_PATH: &str = "Machine\\System\\Network\\Rules";
const MAX_DEPTH: usize = 12;

fn open_rules_root(access: KeyAccess) -> peios::Result<Key> {
    Key::open(None, RULES_PATH, access, OpenFlags::empty())
}

fn decode_value(ty: ValueType, data: &[u8]) -> (String, String) {
    // (kind, json-encoded value)
    match ty {
        ValueType::SZ | ValueType::EXPAND_SZ => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            let s = String::from_utf8_lossy(&data[..end]);
            ("sz".into(), json::escape(&s))
        }
        ValueType::DWORD => {
            if data.len() == 4 {
                let v = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
                ("dword".into(), v.to_string())
            } else {
                ("dword".into(), "null".into())
            }
        }
        ValueType::QWORD => {
            if data.len() == 8 {
                let mut b = [0u8; 8];
                b.copy_from_slice(data);
                ("qword".into(), (i64::from_le_bytes(b)).to_string())
            } else {
                ("qword".into(), "null".into())
            }
        }
        ValueType::MULTI_SZ => {
            let mut out = String::from("[");
            let mut first = true;
            for part in data.split(|&b| b == 0) {
                if part.is_empty() {
                    continue;
                }
                if !first {
                    out.push(',');
                }
                first = false;
                out.push_str(&json::escape(&String::from_utf8_lossy(part)));
            }
            out.push(']');
            ("multi".into(), out)
        }
        other => (format!("type-{}", other.0), json::escape(&json::hex(data))),
    }
}

fn rule_to_json(key: &Key, name: &str, depth: usize, out: &mut String) -> peios::Result<()> {
    let _ = write!(out, "{{\"name\":{},\"values\":{{", json::escape(name));
    let mut first = true;
    for record in key.query_values_batch(None)? {
        let vname = String::from_utf8_lossy(&record.name).into_owned();
        let (kind, value) = decode_value(record.ty, &record.data);
        if !first {
            out.push(',');
        }
        first = false;
        let _ = write!(
            out,
            "{}:{{\"kind\":\"{}\",\"value\":{}}}",
            json::escape(&vname),
            kind,
            value
        );
    }
    out.push_str("},\"children\":[");
    if depth < MAX_DEPTH {
        let mut first_child = true;
        for subkey in key.subkeys(None) {
            let subkey = subkey?;
            let child_name = String::from_utf8_lossy(&subkey.name).into_owned();
            let child = Key::open(
                Some(key),
                &child_name,
                KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
                OpenFlags::empty(),
            )?;
            if !first_child {
                out.push(',');
            }
            first_child = false;
            rule_to_json(&child, &child_name, depth + 1, out)?;
        }
    }
    out.push_str("]}");
    Ok(())
}

/// The whole policy tree as JSON:
/// {"present":bool,"layers":{"Packet":[rule...],"RawPacket":[rule...]}}
pub fn read_policy() -> String {
    let root = match open_rules_root(KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS) {
        Ok(k) => k,
        Err(err) => {
            let mut out = String::from("{\"present\":false,\"layers\":{},\"error\":");
            out.push_str(&json::escape(&err.to_string()));
            out.push('}');
            return out;
        }
    };
    let mut out = String::from("{\"present\":true,\"layers\":{");
    let mut first_layer = true;
    for subkey in root.subkeys(None) {
        let Ok(subkey) = subkey else { continue };
        let layer_name = String::from_utf8_lossy(&subkey.name).into_owned();
        let Ok(layer) = Key::open(
            Some(&root),
            &layer_name,
            KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
            OpenFlags::empty(),
        ) else {
            continue;
        };
        if !first_layer {
            out.push(',');
        }
        first_layer = false;
        let _ = write!(out, "{}:[", json::escape(&layer_name));
        let mut first_rule = true;
        for rule in layer.subkeys(None) {
            let Ok(rule) = rule else { continue };
            let rule_name = String::from_utf8_lossy(&rule.name).into_owned();
            let Ok(rule_key) = Key::open(
                Some(&layer),
                &rule_name,
                KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS,
                OpenFlags::empty(),
            ) else {
                continue;
            };
            if !first_rule {
                out.push(',');
            }
            first_rule = false;
            let mut rule_json = String::new();
            if rule_to_json(&rule_key, &rule_name, 0, &mut rule_json).is_ok() {
                out.push_str(&rule_json);
            } else {
                let _ = write!(
                    out,
                    "{{\"name\":{},\"values\":{{}},\"children\":[],\"error\":true}}",
                    json::escape(&rule_name)
                );
            }
        }
        out.push(']');
    }
    out.push_str("}}");
    out
}

/// Typing convention for authored values, matching what the kernel walk
/// accepts (ingest.c): Actions and comma-separated inputs become multi;
/// integers become dword (qword when negative or too big); everything
/// else is sz. `multi:`/`sz:`/`int:` prefixes force a type.
fn encode_value(name: &str, raw: &str) -> (ValueType, Vec<u8>) {
    let (forced, raw) = match raw.split_once(':') {
        Some(("multi", rest)) => (Some("multi"), rest),
        Some(("sz", rest)) => (Some("sz"), rest),
        Some(("int", rest)) => (Some("int"), rest),
        _ => (None, raw),
    };
    // Action expressions carry commas of their own — `TAG(x, Add)`,
    // `COUNT(x, Length)`, `PROMPT(a, DROP)` — so only commas outside
    // parentheses separate list elements.
    let parts = split_top_level(raw);
    let want_multi = forced == Some("multi")
        || (forced.is_none() && (name == "Actions" || parts.len() > 1));
    if want_multi {
        let mut data = Vec::new();
        for part in parts {
            let part = part.trim();
            if part.is_empty() {
                continue;
            }
            data.extend_from_slice(part.as_bytes());
            data.push(0);
        }
        data.push(0);
        return (ValueType::MULTI_SZ, data);
    }
    if forced != Some("sz") {
        if let Ok(v) = raw.trim().parse::<i64>() {
            if forced == Some("int") || raw.trim().parse::<f64>().is_ok() {
                if (0..=u32::MAX as i64).contains(&v) {
                    return (ValueType::DWORD, (v as u32).to_le_bytes().to_vec());
                }
                return (ValueType::QWORD, v.to_le_bytes().to_vec());
            }
        }
    }
    let mut data = raw.as_bytes().to_vec();
    data.push(0);
    (ValueType::SZ, data)
}

/// Splits on commas at parenthesis depth zero.
fn split_top_level(raw: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut depth = 0usize;
    let mut start = 0usize;
    for (i, c) in raw.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                parts.push(&raw[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&raw[start..]);
    parts
}

fn validate_segment(seg: &str) -> Result<(), String> {
    if seg.is_empty() || seg.contains('\\') || seg.contains('/') || seg.len() > 128 {
        return Err(format!("bad path segment: {seg:?}"));
    }
    Ok(())
}

/// Creates or replaces one rule's own values (children untouched).
/// `path` segments are relative to the Rules key, e.g. ["Packet", "no-inbound", "ssh"].
pub fn set_rule(path: &[String], values: &[(String, String)]) -> Result<(), String> {
    if path.len() < 2 {
        return Err("path must be <Layer>/<rule>[/exception...]".into());
    }
    if path.len() > MAX_DEPTH + 1 {
        return Err("rule nesting too deep".into());
    }
    for seg in path {
        validate_segment(seg)?;
    }

    let root = open_rules_root(
        KeyAccess::QUERY_VALUE
            | KeyAccess::SET_VALUE
            | KeyAccess::CREATE_SUB_KEY
            | KeyAccess::ENUMERATE_SUB_KEYS,
    )
    .map_err(|e| e.to_string())?;
    let txn = Transaction::begin().map_err(|e| e.to_string())?;

    // Chain create: one level per call (the API's contract).
    let mut key = root;
    for seg in path {
        let (child, _) = Key::create(
            Some(&key),
            seg,
            KeyAccess::QUERY_VALUE
                | KeyAccess::SET_VALUE
                | KeyAccess::CREATE_SUB_KEY
                | KeyAccess::ENUMERATE_SUB_KEYS,
            CreateFlags::empty(),
            None,
            Some(&txn),
        )
        .map_err(|e| e.to_string())?;
        key = child;
    }

    // Replace semantics for the rule's own values.
    let existing = key.query_values_batch(Some(&txn)).map_err(|e| e.to_string())?;
    for record in existing {
        let name = record.name.clone();
        if !values
            .iter()
            .any(|(n, _)| n.as_bytes() == name.as_slice())
        {
            key.delete_value(&name, None, Some(&txn))
                .map_err(|e| e.to_string())?;
        }
    }
    for (name, raw) in values {
        let (ty, data) = encode_value(name, raw);
        key.set_value(name.as_bytes(), ty, &data)
            .in_txn(&txn)
            .call()
            .map_err(|e| e.to_string())?;
    }

    txn.commit().map_err(|e| e.to_string())
}

fn delete_recursive(key: &Key, txn: &Transaction, depth: usize) -> Result<(), String> {
    if depth > MAX_DEPTH {
        return Err("rule nesting too deep".into());
    }
    let children: Vec<String> = key
        .subkeys(Some(txn))
        .filter_map(|s| s.ok())
        .map(|s| String::from_utf8_lossy(&s.name).into_owned())
        .collect();
    for child_name in children {
        let child = Key::open(
            Some(key),
            &child_name,
            KeyAccess::QUERY_VALUE
                | KeyAccess::ENUMERATE_SUB_KEYS
                | KeyAccess::DELETE,
            OpenFlags::empty(),
        )
        .map_err(|e| e.to_string())?;
        delete_recursive(&child, txn, depth + 1)?;
    }
    key.delete_key(None, Some(txn)).map_err(|e| e.to_string())
}

/// Deletes one rule and its exceptions.
pub fn delete_rule(path: &[String]) -> Result<(), String> {
    if path.len() < 2 {
        return Err("refusing to delete a whole layer".into());
    }
    for seg in path {
        validate_segment(seg)?;
    }
    let root = open_rules_root(KeyAccess::QUERY_VALUE | KeyAccess::ENUMERATE_SUB_KEYS)
        .map_err(|e| e.to_string())?;
    let mut key = root;
    for seg in path {
        key = Key::open(
            Some(&key),
            seg,
            KeyAccess::QUERY_VALUE
                | KeyAccess::ENUMERATE_SUB_KEYS
                | KeyAccess::DELETE,
            OpenFlags::empty(),
        )
        .map_err(|e| e.to_string())?;
    }
    let txn = Transaction::begin().map_err(|e| e.to_string())?;
    delete_recursive(&key, &txn, path.len())?;
    txn.commit().map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_typing_convention() {
        assert_eq!(encode_value("Actions", "PASS").0, ValueType::MULTI_SZ);
        assert_eq!(
            encode_value("FlowState.Equal", "established,related").0,
            ValueType::MULTI_SZ
        );
        assert_eq!(encode_value("DstPort.Equal", "22").0, ValueType::DWORD);
        assert_eq!(encode_value("Priority", "-5").0, ValueType::QWORD);
        assert_eq!(encode_value("Direction.Equal", "out").0, ValueType::SZ);
        assert_eq!(encode_value("Interface.Equal", "sz:22").0, ValueType::SZ);
        let (ty, data) = encode_value("SrcAddr.Equal", "10.0.0.0/8");
        assert_eq!(ty, ValueType::SZ);
        assert_eq!(&data[..data.len() - 1], b"10.0.0.0/8");
    }

    #[test]
    fn segment_validation_refuses_separators() {
        assert!(validate_segment("ssh").is_ok());
        assert!(validate_segment("a\\b").is_err());
        assert!(validate_segment("a/b").is_err());
        assert!(validate_segment("").is_err());
    }
}

#[cfg(test)]
mod split_tests {
    use super::*;

    #[test]
    fn actions_split_only_on_top_level_commas() {
        assert_eq!(split_top_level("TAG(dnsq, Add)"), vec!["TAG(dnsq, Add)"]);
        assert_eq!(
            split_top_level("COUNT(dns),REPORT(3)"),
            vec!["COUNT(dns)", "REPORT(3)"]
        );
        assert_eq!(
            split_top_level("PROMPT(a, PROMPT(b, DROP)), PASS"),
            vec!["PROMPT(a, PROMPT(b, DROP))", " PASS"]
        );
        let (ty, data) = encode_value("Actions", "TAG(dnsq, Add)");
        assert_eq!(ty.0, ValueType::MULTI_SZ.0);
        assert_eq!(data, b"TAG(dnsq, Add)\0\0".to_vec());
    }
}
