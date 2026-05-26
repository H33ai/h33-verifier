//! Canonical JSON encoding for signed verification reports.
//!
//! The signing/verification pipeline needs a deterministic, byte-exact
//! encoding so that a verifier in one language can verify a signed report
//! produced by a verifier in another language. This module implements a
//! lightweight subset of RFC 8785 (JSON Canonicalization Scheme) sufficient
//! for our report structure — we never emit floats, never emit non-ASCII
//! object keys, and never need RFC 8785's float-normalization machinery.
//!
//! # Rules
//!
//! 1. Object members are sorted lexicographically by key (byte-wise on UTF-8).
//! 2. No whitespace anywhere — no spaces, tabs, or newlines between tokens.
//! 3. Strings are escaped per RFC 8259 §7 minimal form (control chars + `"`
//!    + `\\` only; the optional `/` escape is NOT used).
//! 4. Numbers are emitted as integers (`u64`/`i64`/`u32`/etc). Floats are not
//!    supported and cause a panic — fail loud rather than silently emit
//!    something the receiver can't reproduce.
//! 5. `true`, `false`, `null` are the keywords.
//!
//! # Why these specific rules
//!
//! The report consumer must be able to reconstruct the exact bytes the
//! verifier signed, given only the JSON document plus the signature field.
//! Any divergence in whitespace, key order, escape style, or number form
//! breaks verification. The rules above are the smallest set that gives
//! that property for our concrete report schema.

use serde_json::Value;

/// Write a `serde_json::Value` to `out` in canonical form.
///
/// Panics if `value` contains a non-integer number (floats are not in our
/// report schema, and emitting them deterministically requires either
/// fixed-point or RFC 8785's full ECMAScript dtoa, which we deliberately
/// don't carry).
pub fn write(value: &Value, out: &mut Vec<u8>) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else {
                panic!(
                    "canonical: non-integer number {:?} is not supported in the report schema",
                    n
                );
            }
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, v) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write(v, out);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push(b'{');
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(k, out);
                out.push(b':');
                write(&map[*k], out);
            }
            out.push(b'}');
        }
    }
}

/// Convenience: build the canonical byte string from a `Value`.
pub fn encode(value: &Value) -> Vec<u8> {
    let mut out = Vec::with_capacity(256);
    write(value, &mut out);
    out
}

/// Write a JSON string literal per RFC 8259 §7. Control characters get
/// `\uXXXX`, backslash and double-quote get backslash-escaped, the rest
/// are emitted verbatim as UTF-8.
fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for ch in s.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{0C}' => out.extend_from_slice(b"\\f"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            c if (c as u32) < 0x20 => {
                let buf = format!("\\u{:04x}", c as u32);
                out.extend_from_slice(buf.as_bytes());
            }
            c => {
                let mut b = [0u8; 4];
                let s = c.encode_utf8(&mut b);
                out.extend_from_slice(s.as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_sorted() {
        let v = json!({"z": 1, "a": 2, "m": 3});
        assert_eq!(encode(&v), br#"{"a":2,"m":3,"z":1}"#);
    }

    #[test]
    fn no_whitespace() {
        let v = json!({"k": [1, 2, 3], "x": "y"});
        assert_eq!(encode(&v), br#"{"k":[1,2,3],"x":"y"}"#);
    }

    #[test]
    fn nested_objects_sorted_recursively() {
        let v = json!({"outer": {"z": 1, "a": 2}, "alpha": "first"});
        assert_eq!(
            encode(&v),
            br#"{"alpha":"first","outer":{"a":2,"z":1}}"#
        );
    }

    #[test]
    fn strings_escape_correctly() {
        let v = json!({"k": "with \"quotes\" and \\ slash and \n newline"});
        assert_eq!(
            encode(&v),
            br#"{"k":"with \"quotes\" and \\ slash and \n newline"}"#
        );
    }

    #[test]
    fn deterministic_across_runs() {
        let v = json!({"b": 2, "a": 1, "c": [3, 2, 1], "nested": {"y": "y", "x": "x"}});
        let a = encode(&v);
        let b = encode(&v);
        assert_eq!(a, b);
    }
}
