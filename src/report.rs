//! Verification report types + the pure `verify_receipt` function.
//!
//! `verify_receipt` is the library entry point used by both:
//!  - the CLI `verify` subcommand (emits the report as pretty JSON)
//!  - the CLI `verify --signed-report` flow (wraps the report in a
//!    signed envelope)
//!
//! Keeping report production in the library means there is exactly ONE
//! definition of "what the verifier checks and what it says." The signed
//! envelope is purely a transport layer; it does not change verdicts.

use crate::{decode_substrate, sha3_256, signing_message, SubstrateView, RECEIPT_SIZE};
use serde::{Deserialize, Serialize};

/// What every report — signed or not — declares about the verifier that
/// produced it. Frozen at v0.1 for backward compatibility.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerifierInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub spec_version: &'static str,
    pub deterministic: bool,
    pub network_required: bool,
}

pub const VERIFIER_INFO: VerifierInfo = VerifierInfo {
    name: env!("CARGO_PKG_NAME"),
    version: env!("CARGO_PKG_VERSION"),
    spec_version: "H33 Signing Substrate Spec v1",
    deterministic: true,
    network_required: false,
};

#[derive(Debug, Serialize, Clone)]
pub struct DeterministicChecks {
    pub substrate_decodes: bool,
    pub version_byte_v1: bool,
    pub computation_type_recognized: bool,
    pub computation_type_name: Option<String>,
    pub signing_message_matches_on_chain_hash: bool,
    pub receipt_length_42: bool,
    pub on_chain_hash_length_32: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct DecodedSubstrate {
    pub version: u8,
    pub computation_type: String,
    pub fhe_commitment_hex: String,
    pub timestamp_ms: u64,
    pub timestamp_iso: String,
    pub nonce_hex: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct OptionalDataCheck {
    pub data_path: String,
    pub data_sha3_256: String,
    pub substrate_fhe_commitment: String,
    pub fhe_commitment_matches: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct VerificationReport {
    pub verifier: VerifierInfo,
    pub input_receipt_path: String,
    pub deterministic_checks: DeterministicChecks,
    pub decoded_substrate: Option<DecodedSubstrate>,
    pub optional_data_check: Option<OptionalDataCheck>,
    pub verdict: String,
    pub what_was_proven: Vec<&'static str>,
    pub what_was_not_proven: Vec<&'static str>,
}

pub const PROVEN_LIST: &[&str] = &[
    "Substrate bytes decode to a structurally valid v1 H33-74 substrate layout (58 bytes, version 0x01, recognized computation_type).",
    "SHA3-256(substrate_bytes) equals the claimed on_chain_hash byte-for-byte.",
    "Receipt buffer is the canonical 42-byte compact format.",
];

pub const NOT_PROVEN_LIST: &[&str] = &[
    "PQ signature validity (Dilithium ML-DSA-65, FALCON-512, SPHINCS+-SHA2-128f) over signing_message — requires the 21KB ephemeral signature bundle and H33's published PQ public keys for the relevant key-gen epoch (Mode 2 verification, v0.3).",
    "Authenticity of the entity that issued the receipt — anyone with access to a substrate could publish a syntactically valid receipt; signature verification (Mode 2) is what binds it to H33.",
    "Truth of the FHE computation that produced fhe_commitment — the substrate commits to a hash, not to the semantic correctness of the computation.",
];

/// The input bytes a verification consumes. Hex-decoded already.
pub struct VerifyInput<'a> {
    pub receipt_path_display: String,
    pub on_chain_hash: &'a [u8],
    pub receipt_bytes: &'a [u8],
    pub substrate_bytes: &'a [u8],
    /// Optional payload to check `SHA3(payload) == substrate.fhe_commitment`.
    pub data: Option<(&'a [u8], String)>, // (bytes, path-for-display)
}

/// Run Mode 1 verification and return the report.
/// This is pure: it does not touch disk, network, env vars, or globals.
pub fn verify_receipt(input: &VerifyInput<'_>) -> VerificationReport {
    let on_chain_hash_length_32 = input.on_chain_hash.len() == 32;
    let receipt_length_42 = input.receipt_bytes.len() == RECEIPT_SIZE;

    let decoded = decode_substrate(input.substrate_bytes);
    let substrate_decodes = decoded.is_ok();
    let view: Option<SubstrateView> = decoded.ok();

    let version_byte_v1 = view.as_ref().map(|s| s.version == 0x01).unwrap_or(false);
    let computation_type_recognized = view.is_some();
    let computation_type_name = view.as_ref().map(|s| s.computation_type.name().to_string());

    let signing_message_matches_on_chain_hash = if substrate_decodes && on_chain_hash_length_32 {
        let computed = signing_message(input.substrate_bytes);
        computed[..] == input.on_chain_hash[..]
    } else {
        false
    };

    let decoded_substrate = view.as_ref().map(|s| DecodedSubstrate {
        version: s.version,
        computation_type: s.computation_type.name().to_string(),
        fhe_commitment_hex: hex::encode(s.fhe_commitment),
        timestamp_ms: s.timestamp_ms,
        timestamp_iso: crate::iso8601_from_unix_ms(s.timestamp_ms),
        nonce_hex: hex::encode(s.nonce),
    });

    let optional_data_check = input.data.as_ref().and_then(|(bytes, path)| {
        let computed = sha3_256(bytes);
        view.as_ref().map(|s| OptionalDataCheck {
            data_path: path.clone(),
            data_sha3_256: hex::encode(computed),
            substrate_fhe_commitment: hex::encode(s.fhe_commitment),
            fhe_commitment_matches: computed == s.fhe_commitment,
        })
    });

    let all_deterministic_ok = substrate_decodes
        && version_byte_v1
        && computation_type_recognized
        && signing_message_matches_on_chain_hash
        && receipt_length_42
        && on_chain_hash_length_32;
    let optional_ok = optional_data_check
        .as_ref()
        .map(|c| c.fhe_commitment_matches)
        .unwrap_or(true);

    let verdict = if all_deterministic_ok && optional_ok {
        "PASS"
    } else {
        "FAIL"
    };

    VerificationReport {
        verifier: VERIFIER_INFO,
        input_receipt_path: input.receipt_path_display.clone(),
        deterministic_checks: DeterministicChecks {
            substrate_decodes,
            version_byte_v1,
            computation_type_recognized,
            computation_type_name,
            signing_message_matches_on_chain_hash,
            receipt_length_42,
            on_chain_hash_length_32,
        },
        decoded_substrate,
        optional_data_check,
        verdict: verdict.to_string(),
        what_was_proven: PROVEN_LIST.to_vec(),
        what_was_not_proven: NOT_PROVEN_LIST.to_vec(),
    }
}
