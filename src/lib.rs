//! H33-74 offline verifier — substrate reconstruction + deterministic
//! commitment binding verification, plus (v0.2) verifier-signed reports.
//!
//! Implements the H33 Signing Substrate Specification v1 in pure Rust against
//! only `sha3` from RustCrypto + Ed25519 for report signing. No dependency
//! on the proprietary `h33-substrate` crate — the spec is the contract.
//!
//! # What this proves (Mode 1)
//!
//! - The 58-byte substrate decodes to a structurally valid v1 layout.
//! - `signing_message = SHA3-256(substrate_bytes)` matches the on-chain hash.
//! - The receipt buffer is the canonical 42-byte compact size.
//!
//! # What this does NOT prove (Mode 1)
//!
//! - PQ signature validity (Dilithium / FALCON / SPHINCS+). Mode 2 in v0.3.
//! - Authenticity of the entity that issued the receipt.
//! - Truth of the FHE computation that produced the `fhe_commitment`.
//!
//! # v0.2 addition: signed verification reports
//!
//! The library also exposes `produce_signed_report` and
//! `verify_signed_report` so the verifier's verdict itself becomes an
//! attestable artifact. Per-instance Ed25519 keypair; canonical JSON
//! encoding for byte-exact reproducibility across implementations.
//!
//! See SPEC.md for the substrate layout and the signed-report contract.

use sha3::{Digest, Sha3_256};

pub mod bundle;
pub mod canonical;
pub mod identity;
pub mod mode2;
pub mod pq;
pub mod pubkeys;
pub mod report;
pub mod signed_report;

pub const SUBSTRATE_VERSION: u8 = 0x01;
pub const SUBSTRATE_SIZE: usize = 58;
pub const SIGNING_MESSAGE_SIZE: usize = 32;
pub const RECEIPT_SIZE: usize = 42;
pub const TOTAL_FOOTPRINT: usize = SUBSTRATE_SIZE - 16 /* nonce */ + 32 /* signing_message on-chain */;
// Note: TOTAL_FOOTPRINT is the published "74 bytes" figure: 32 bytes on-chain
// (the signing_message commitment) + 42 bytes off-chain (the compact receipt
// summarising the PQ signature bundle). The 58-byte substrate is the
// *interior* state from which the 32-byte signing_message is derived.

/// All computation types defined by H33 Signing Substrate Spec v1.
/// Append-only — never reuse a value (would invalidate every historical
/// signature that used the old meaning).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComputationType {
    BiometricAuth,     // 0x01
    FraudScore,        // 0x02
    FedNowPayment,     // 0x03
    SolanaAttestation, // 0x04
    HatsGovernance,    // 0x05
    BitcoinUtxo,       // 0x06
    KycVerification,   // 0x07
    ShareComputation,  // 0x08
    ArchiveSign,       // 0x09
    MedVaultPhi,       // 0x0A
    VaultKeyOp,        // 0x0B
    GenericFhe,        // 0xFF
}

impl ComputationType {
    pub fn from_byte(b: u8) -> Option<Self> {
        Some(match b {
            0x01 => Self::BiometricAuth,
            0x02 => Self::FraudScore,
            0x03 => Self::FedNowPayment,
            0x04 => Self::SolanaAttestation,
            0x05 => Self::HatsGovernance,
            0x06 => Self::BitcoinUtxo,
            0x07 => Self::KycVerification,
            0x08 => Self::ShareComputation,
            0x09 => Self::ArchiveSign,
            0x0A => Self::MedVaultPhi,
            0x0B => Self::VaultKeyOp,
            0xFF => Self::GenericFhe,
            _ => return None,
        })
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::BiometricAuth => "BiometricAuth",
            Self::FraudScore => "FraudScore",
            Self::FedNowPayment => "FedNowPayment",
            Self::SolanaAttestation => "SolanaAttestation",
            Self::HatsGovernance => "HatsGovernance",
            Self::BitcoinUtxo => "BitcoinUtxo",
            Self::KycVerification => "KycVerification",
            Self::ShareComputation => "ShareComputation",
            Self::ArchiveSign => "ArchiveSign",
            Self::MedVaultPhi => "MedVaultPhi",
            Self::VaultKeyOp => "VaultKeyOp",
            Self::GenericFhe => "GenericFhe",
        }
    }
}

/// Decoded substrate — what the 58 bytes mean.
#[derive(Debug, Clone)]
pub struct SubstrateView {
    pub version: u8,
    pub computation_type: ComputationType,
    pub fhe_commitment: [u8; 32],
    pub timestamp_ms: u64,
    pub nonce: [u8; 16],
}

#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    BadLength(usize),
    UnknownVersion(u8),
    UnknownComputationType(u8),
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BadLength(n) => write!(f, "expected {SUBSTRATE_SIZE} bytes, got {n}"),
            Self::UnknownVersion(v) => write!(f, "unknown substrate version 0x{v:02x}, only 0x01 is defined"),
            Self::UnknownComputationType(b) => write!(f, "unknown computation_type 0x{b:02x}"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Decode the 58-byte substrate per Spec v1.
///
/// Byte layout (big-endian, no padding):
///   [0]      version (must be 0x01)
///   [1]      computation_type (1 byte enum)
///   [2..34]  fhe_commitment (32 bytes)
///   [34..42] timestamp_ms (u64 big-endian)
///   [42..58] nonce (16 bytes)
pub fn decode_substrate(bytes: &[u8]) -> Result<SubstrateView, DecodeError> {
    if bytes.len() != SUBSTRATE_SIZE {
        return Err(DecodeError::BadLength(bytes.len()));
    }
    let version = bytes[0];
    if version != SUBSTRATE_VERSION {
        return Err(DecodeError::UnknownVersion(version));
    }
    let computation_type = ComputationType::from_byte(bytes[1])
        .ok_or(DecodeError::UnknownComputationType(bytes[1]))?;

    let mut fhe_commitment = [0u8; 32];
    fhe_commitment.copy_from_slice(&bytes[2..34]);

    let mut ts_bytes = [0u8; 8];
    ts_bytes.copy_from_slice(&bytes[34..42]);
    let timestamp_ms = u64::from_be_bytes(ts_bytes);

    let mut nonce = [0u8; 16];
    nonce.copy_from_slice(&bytes[42..58]);

    Ok(SubstrateView {
        version,
        computation_type,
        fhe_commitment,
        timestamp_ms,
        nonce,
    })
}

/// `signing_message = SHA3-256(substrate_bytes)`. Per spec, this is the
/// 32-byte value that PQ signatures sign over and that gets published
/// on-chain as the canonical commitment.
pub fn signing_message(substrate_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(substrate_bytes);
    h.finalize().into()
}

/// Recompute SHA3-256 of arbitrary bytes — used to verify the optional
/// `fhe_commitment` binding when the caller supplies the original payload.
pub fn sha3_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha3_256::new();
    h.update(data);
    h.finalize().into()
}

/// ISO 8601 UTC timestamp for the current moment. Stdlib only.
/// Returns e.g. `"2026-05-26T22:31:14.123Z"`.
pub fn iso8601_now() -> String {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    iso8601_from_unix_ms(ms)
}

/// ISO 8601 UTC formatting of a millisecond Unix timestamp. Stdlib only.
///
/// Uses the Howard Hinnant civil-from-days algorithm (paraphrased) so we
/// don't pull in chrono / time for a single date format.
pub fn iso8601_from_unix_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let millis_part = ms % 1000;

    let z = (secs / 86400) as i64 + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };

    let hours = (secs % 86400) / 3600;
    let minutes = (secs % 3600) / 60;
    let seconds = secs % 60;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        y, m, d, hours, minutes, seconds, millis_part
    )
}
