//! Parser for the `h33-substrate-pubkeys-v1` JSON file.
//!
//! H33 publishes a JSON file per key-generation epoch listing the public
//! keys that signed substrates minted under that epoch. The Mode 2
//! verifier consumes the file via the `--pubkeys` flag.
//!
//! # File format (v1)
//!
//! ```json
//! {
//!   "format": "h33-substrate-pubkeys-v1",
//!   "epoch_id": "h33-substrate-2026-04-11-001",
//!   "epoch": "2026-04-11",
//!   "issued_at_utc": "2026-04-11T00:00:00Z",
//!   "algorithms": {
//!     "dilithium": { "name": "ML-DSA-65",                  "public_key_hex": "..." },
//!     "falcon":    { "name": "FALCON-512",                 "public_key_hex": "..." },
//!     "sphincs":   { "name": "SPHINCS+-SHA2-128f-simple",  "public_key_hex": "..." }
//!   }
//! }
//! ```
//!
//! - `epoch_id` is the canonical identifier; opaque to consumers, stable
//!   across renames/format adjustments. Use this for trust establishment.
//! - `epoch` is human-readable (typically a date) — informational only.
//! - `format` tag must equal `"h33-substrate-pubkeys-v1"`.

use serde::{Deserialize, Serialize};

pub const PUBKEYS_FORMAT_TAG: &str = "h33-substrate-pubkeys-v1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PubkeysFile {
    pub format: String,
    pub epoch_id: String,
    pub epoch: String,
    #[serde(default)]
    pub issued_at_utc: String,
    pub algorithms: AlgorithmKeys,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmKeys {
    pub dilithium: AlgorithmKey,
    pub falcon: AlgorithmKey,
    pub sphincs: AlgorithmKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlgorithmKey {
    pub name: String,
    pub public_key_hex: String,
}

#[derive(Debug)]
pub enum PubkeysError {
    InvalidJson(String),
    UnsupportedFormat(String),
    HexDecode { which: &'static str, error: String },
    KeyNameMismatch { which: &'static str, claimed: String, expected: &'static str },
}

impl std::fmt::Display for PubkeysError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(s) => write!(f, "pubkeys file is not valid JSON: {s}"),
            Self::UnsupportedFormat(s) => write!(f, "unsupported pubkeys format '{s}'"),
            Self::HexDecode { which, error } => write!(f, "{which} public_key_hex decode: {error}"),
            Self::KeyNameMismatch { which, claimed, expected } => {
                write!(f, "{which} algorithm name '{claimed}' does not match expected '{expected}'")
            }
        }
    }
}

impl std::error::Error for PubkeysError {}

/// Parse a pubkeys JSON file. Validates the format tag and the three
/// algorithm names match their expected NIST identifiers, then hex-decodes
/// each public key.
///
/// Returns the parsed `PubkeysFile` plus three byte vectors for the
/// algorithms in the order (dilithium, falcon, sphincs).
pub fn parse(raw: &str) -> Result<ParsedPubkeys, PubkeysError> {
    let file: PubkeysFile =
        serde_json::from_str(raw).map_err(|e| PubkeysError::InvalidJson(e.to_string()))?;
    if file.format != PUBKEYS_FORMAT_TAG {
        return Err(PubkeysError::UnsupportedFormat(file.format.clone()));
    }
    // Name-string sanity (we accept the canonical NIST names; substrate
    // currently mints under exactly these).
    check_name(&file.algorithms.dilithium.name, "ML-DSA-65", "dilithium")?;
    check_name(&file.algorithms.falcon.name, "FALCON-512", "falcon")?;
    // SPHINCS+ has been published under a few different name strings; accept
    // both the FIPS 205 "SLH-DSA-SHA2-128f-simple" form and the SPHINCS+
    // upstream form. Reject anything else.
    let sph_name = &file.algorithms.sphincs.name;
    if sph_name != "SPHINCS+-SHA2-128f-simple"
        && sph_name != "SLH-DSA-SHA2-128f-simple"
        && sph_name != "SLH-DSA-SHA2-128F"
    {
        return Err(PubkeysError::KeyNameMismatch {
            which: "sphincs",
            claimed: sph_name.clone(),
            expected: "SPHINCS+-SHA2-128f-simple",
        });
    }

    let dilithium = hex::decode(file.algorithms.dilithium.public_key_hex.trim())
        .map_err(|e| PubkeysError::HexDecode { which: "dilithium", error: e.to_string() })?;
    let falcon = hex::decode(file.algorithms.falcon.public_key_hex.trim())
        .map_err(|e| PubkeysError::HexDecode { which: "falcon", error: e.to_string() })?;
    let sphincs = hex::decode(file.algorithms.sphincs.public_key_hex.trim())
        .map_err(|e| PubkeysError::HexDecode { which: "sphincs", error: e.to_string() })?;

    Ok(ParsedPubkeys {
        file,
        dilithium,
        falcon,
        sphincs,
    })
}

fn check_name(claimed: &str, expected: &'static str, which: &'static str) -> Result<(), PubkeysError> {
    if claimed != expected {
        return Err(PubkeysError::KeyNameMismatch {
            which,
            claimed: claimed.to_string(),
            expected,
        });
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub struct ParsedPubkeys {
    pub file: PubkeysFile,
    pub dilithium: Vec<u8>,
    pub falcon: Vec<u8>,
    pub sphincs: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> String {
        // Plausibly-shaped pubkeys file. Public-key bytes here are placeholders;
        // the file parser does not validate key bytes are valid PQ public keys
        // (that happens at verify time when the algorithm crate is asked to
        // load them).
        let dil_hex = "00".repeat(1952);
        let fal_hex = "11".repeat(897);
        let sph_hex = "22".repeat(32);
        format!(
            r#"{{
                "format": "h33-substrate-pubkeys-v1",
                "epoch_id": "h33-substrate-2026-04-11-001",
                "epoch": "2026-04-11",
                "issued_at_utc": "2026-04-11T00:00:00Z",
                "algorithms": {{
                    "dilithium": {{ "name": "ML-DSA-65",                 "public_key_hex": "{dil_hex}" }},
                    "falcon":    {{ "name": "FALCON-512",                "public_key_hex": "{fal_hex}" }},
                    "sphincs":   {{ "name": "SPHINCS+-SHA2-128f-simple", "public_key_hex": "{sph_hex}" }}
                }}
            }}"#
        )
    }

    #[test]
    fn parses_canonical_pubkeys_file() {
        let parsed = parse(&sample()).expect("must parse");
        assert_eq!(parsed.file.epoch_id, "h33-substrate-2026-04-11-001");
        assert_eq!(parsed.file.epoch, "2026-04-11");
        assert_eq!(parsed.dilithium.len(), 1952);
        assert_eq!(parsed.falcon.len(), 897);
        assert_eq!(parsed.sphincs.len(), 32);
    }

    #[test]
    fn rejects_unsupported_format() {
        let s = sample().replace("h33-substrate-pubkeys-v1", "some-other-format");
        assert!(matches!(parse(&s), Err(PubkeysError::UnsupportedFormat(_))));
    }

    #[test]
    fn rejects_wrong_algorithm_name() {
        let s = sample().replace("ML-DSA-65", "ML-DSA-87");
        assert!(matches!(
            parse(&s),
            Err(PubkeysError::KeyNameMismatch { which: "dilithium", .. })
        ));
    }

    #[test]
    fn accepts_slh_dsa_alias_for_sphincs() {
        let s = sample().replace("SPHINCS+-SHA2-128f-simple", "SLH-DSA-SHA2-128f-simple");
        assert!(parse(&s).is_ok());
    }
}
