//! Parser for the `h33-substrate-bundle-v1` Mode 2 verification bundle.
//!
//! The bundle is the ~21 KB blob a Mode 2 verifier needs to check the three
//! post-quantum signatures inside an H33 receipt. It is served by
//! `GET /api/v1/substrate/attestations/:id/bundle` and content-addressed
//! by `id = hex(SHA3-256(canonical bundle bytes))` — the same hash that
//! appears as `bundle_hash` in the `/attest` response.
//!
//! # Wire format (v1)
//!
//! Big-endian, fixed magic, no padding:
//!
//! ```text
//!   offset  size       field
//!     0       4         magic "H33B"
//!     4       1         version 0x01
//!     5       3         reserved (zero)
//!     8      32         signing_message (SHA3-256 of the substrate)
//!    40       4         dilithium_signed_message_len (u32 BE)
//!    44       L1        dilithium_signed_message  (sig || msg, pqcrypto convention)
//!   ...       4         falcon_signed_message_len
//!   ...       L2        falcon_signed_message
//!   ...       4         sphincs_signed_message_len
//!   ...       L3        sphincs_signed_message
//! ```
//!
//! Any verifier in any language must produce byte-identical bundle bytes
//! for the same inputs. SHA3-256 over those bytes is the content address.

use crate::sha3_256;

pub const BUNDLE_MAGIC: &[u8; 4] = b"H33B";
pub const BUNDLE_VERSION: u8 = 0x01;
pub const HEADER_SIZE: usize = 40; // 4 magic + 1 ver + 3 reserved + 32 signing_message

/// Parsed view into a bundle. All slices borrow from the input bytes.
#[derive(Debug, Clone)]
pub struct BundleView<'a> {
    pub signing_message: [u8; 32],
    pub dilithium_signed_message: &'a [u8],
    pub falcon_signed_message: &'a [u8],
    pub sphincs_signed_message: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum BundleError {
    TooShort(usize),
    BadMagic([u8; 4]),
    UnknownVersion(u8),
    NonZeroReserved,
    InvalidLengthField {
        which: &'static str,
        claimed: u32,
        remaining: usize,
    },
    TrailingBytes(usize),
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TooShort(n) => write!(f, "bundle too short: {n} bytes (need at least {HEADER_SIZE} + 12 for length prefixes)"),
            Self::BadMagic(m) => write!(f, "bad magic: expected H33B, got {:02x?}", m),
            Self::UnknownVersion(v) => write!(f, "unknown bundle version 0x{v:02x}, only 0x01 is defined"),
            Self::NonZeroReserved => write!(f, "reserved bytes 5..8 are non-zero"),
            Self::InvalidLengthField { which, claimed, remaining } => {
                write!(f, "{which} claims {claimed} bytes but only {remaining} remain in the buffer")
            }
            Self::TrailingBytes(n) => write!(f, "{n} trailing bytes after sphincs payload (bundle is malformed)"),
        }
    }
}

impl std::error::Error for BundleError {}

/// Parse a bundle. Returns a `BundleView` referencing slices of the input.
pub fn parse(bytes: &[u8]) -> Result<BundleView<'_>, BundleError> {
    if bytes.len() < HEADER_SIZE + 12 {
        return Err(BundleError::TooShort(bytes.len()));
    }
    let mut magic = [0u8; 4];
    magic.copy_from_slice(&bytes[0..4]);
    if &magic != BUNDLE_MAGIC {
        return Err(BundleError::BadMagic(magic));
    }
    if bytes[4] != BUNDLE_VERSION {
        return Err(BundleError::UnknownVersion(bytes[4]));
    }
    if bytes[5..8].iter().any(|&b| b != 0) {
        return Err(BundleError::NonZeroReserved);
    }

    let mut signing_message = [0u8; 32];
    signing_message.copy_from_slice(&bytes[8..40]);

    let mut cursor = HEADER_SIZE;

    let dilithium_signed_message = read_len_prefixed_blob(bytes, &mut cursor, "dilithium")?;
    let falcon_signed_message = read_len_prefixed_blob(bytes, &mut cursor, "falcon")?;
    let sphincs_signed_message = read_len_prefixed_blob(bytes, &mut cursor, "sphincs")?;

    if cursor != bytes.len() {
        return Err(BundleError::TrailingBytes(bytes.len() - cursor));
    }

    Ok(BundleView {
        signing_message,
        dilithium_signed_message,
        falcon_signed_message,
        sphincs_signed_message,
    })
}

fn read_len_prefixed_blob<'a>(
    buf: &'a [u8],
    cursor: &mut usize,
    which: &'static str,
) -> Result<&'a [u8], BundleError> {
    if buf.len() < *cursor + 4 {
        return Err(BundleError::InvalidLengthField {
            which,
            claimed: 0,
            remaining: buf.len().saturating_sub(*cursor),
        });
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&buf[*cursor..*cursor + 4]);
    let claimed = u32::from_be_bytes(len_bytes);
    let start = *cursor + 4;
    let end = start + claimed as usize;
    if end > buf.len() {
        return Err(BundleError::InvalidLengthField {
            which,
            claimed,
            remaining: buf.len().saturating_sub(start),
        });
    }
    *cursor = end;
    Ok(&buf[start..end])
}

/// Build the canonical bundle bytes from components. Mirrors the server-side
/// `build_substrate_bundle_v1` so verifier-side and server-side stay
/// byte-identical for the same inputs (round-trip test).
pub fn build(
    signing_message: &[u8; 32],
    dilithium_signed_message: &[u8],
    falcon_signed_message: &[u8],
    sphincs_signed_message: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        HEADER_SIZE
            + 12
            + dilithium_signed_message.len()
            + falcon_signed_message.len()
            + sphincs_signed_message.len(),
    );
    out.extend_from_slice(BUNDLE_MAGIC);
    out.push(BUNDLE_VERSION);
    out.extend_from_slice(&[0u8; 3]);
    out.extend_from_slice(signing_message);
    out.extend_from_slice(&(dilithium_signed_message.len() as u32).to_be_bytes());
    out.extend_from_slice(dilithium_signed_message);
    out.extend_from_slice(&(falcon_signed_message.len() as u32).to_be_bytes());
    out.extend_from_slice(falcon_signed_message);
    out.extend_from_slice(&(sphincs_signed_message.len() as u32).to_be_bytes());
    out.extend_from_slice(sphincs_signed_message);
    out
}

/// SHA3-256 of canonical bundle bytes — the content address.
pub fn bundle_hash(bundle_bytes: &[u8]) -> [u8; 32] {
    sha3_256(bundle_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_bundle() -> Vec<u8> {
        let sm = [0xAB; 32];
        let dil = vec![0x11u8; 100]; // synthetic — not crypto-valid
        let fal = vec![0x22u8; 50];
        let sph = vec![0x33u8; 200];
        build(&sm, &dil, &fal, &sph)
    }

    #[test]
    fn roundtrip_build_then_parse() {
        let bytes = make_test_bundle();
        let view = parse(&bytes).expect("roundtrip must parse");
        assert_eq!(view.signing_message, [0xAB; 32]);
        assert_eq!(view.dilithium_signed_message.len(), 100);
        assert_eq!(view.falcon_signed_message.len(), 50);
        assert_eq!(view.sphincs_signed_message.len(), 200);
        assert!(view.dilithium_signed_message.iter().all(|&b| b == 0x11));
        assert!(view.falcon_signed_message.iter().all(|&b| b == 0x22));
        assert!(view.sphincs_signed_message.iter().all(|&b| b == 0x33));
    }

    #[test]
    fn rejects_bad_magic() {
        let mut bytes = make_test_bundle();
        bytes[0] = b'X';
        assert!(matches!(parse(&bytes), Err(BundleError::BadMagic(_))));
    }

    #[test]
    fn rejects_unknown_version() {
        let mut bytes = make_test_bundle();
        bytes[4] = 0x02;
        assert!(matches!(parse(&bytes), Err(BundleError::UnknownVersion(0x02))));
    }

    #[test]
    fn rejects_non_zero_reserved() {
        let mut bytes = make_test_bundle();
        bytes[5] = 0x01;
        assert!(matches!(parse(&bytes), Err(BundleError::NonZeroReserved)));
    }

    #[test]
    fn rejects_oversized_length_claim() {
        let mut bytes = make_test_bundle();
        // Inflate dilithium length to point past the end of buffer.
        let evil_len = (bytes.len() as u32 + 100).to_be_bytes();
        bytes[40..44].copy_from_slice(&evil_len);
        assert!(matches!(
            parse(&bytes),
            Err(BundleError::InvalidLengthField { which: "dilithium", .. })
        ));
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut bytes = make_test_bundle();
        bytes.push(0xFF);
        assert!(matches!(parse(&bytes), Err(BundleError::TrailingBytes(1))));
    }

    #[test]
    fn rejects_short_buffer() {
        let bytes = vec![0u8; 10];
        assert!(matches!(parse(&bytes), Err(BundleError::TooShort(10))));
    }

    #[test]
    fn bundle_hash_is_sha3_of_canonical_bytes() {
        let bytes = make_test_bundle();
        let h = bundle_hash(&bytes);
        assert_eq!(h.len(), 32);
        // Cross-check: same input must produce same hash.
        assert_eq!(h, bundle_hash(&bytes));
        // Tamper one byte → hash must change.
        let mut tampered = bytes.clone();
        tampered[100] ^= 0xFF;
        assert_ne!(h, bundle_hash(&tampered));
    }
}
