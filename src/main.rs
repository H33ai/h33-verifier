//! `h33-verify` — CLI entry. Two commands: `verify` and `inspect`.
//!
//! Brutally simple by design: no config file, no daemon, no network call,
//! no auth, no cloud dep. Just SHA3 + the published spec.

use clap::{Parser, Subcommand};
use h33_verify::{decode_substrate, sha3_256, signing_message, RECEIPT_SIZE};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "h33-verify",
    version,
    about = "Offline verifier for H33-74 substrate receipts (Mode 1, deterministic only)",
    long_about = "Independent offline verifier for H33-74 substrate receipts.\n\n\
                  Reconstructs the 58-byte substrate per H33 Signing Substrate Spec v1, \
                  recomputes SHA3-256, and compares to the claimed on-chain hash. \
                  No network, no H33 dependency, no trust assumption beyond SHA3."
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a receipt by reconstructing its substrate and recomputing SHA3-256.
    Verify {
        /// Path to the receipt JSON file.
        receipt: PathBuf,
        /// Optional path to the original payload bytes — when supplied, also
        /// verifies that SHA3-256(payload) equals the substrate's fhe_commitment field.
        #[arg(long)]
        data: Option<PathBuf>,
    },
    /// Decode a receipt's substrate and print its fields without running verification.
    Inspect {
        receipt: PathBuf,
    },
}

#[derive(Debug, Deserialize)]
struct ReceiptInput {
    on_chain_hash: String,
    receipt_hex: String,
    substrate_hex: String,
}

#[derive(Debug, Serialize)]
struct DeterministicChecks {
    substrate_decodes: bool,
    version_byte_v1: bool,
    computation_type_recognized: bool,
    computation_type_name: Option<String>,
    signing_message_matches_on_chain_hash: bool,
    receipt_length_42: bool,
    on_chain_hash_length_32: bool,
}

#[derive(Debug, Serialize)]
struct DecodedSubstrate {
    version: u8,
    computation_type: String,
    fhe_commitment_hex: String,
    timestamp_ms: u64,
    timestamp_iso: String,
    nonce_hex: String,
}

#[derive(Debug, Serialize)]
struct OptionalDataCheck {
    data_path: String,
    data_sha3_256: String,
    substrate_fhe_commitment: String,
    fhe_commitment_matches: bool,
}

#[derive(Debug, Serialize)]
struct VerificationReport {
    verifier: VerifierInfo,
    input_receipt_path: String,
    deterministic_checks: DeterministicChecks,
    decoded_substrate: Option<DecodedSubstrate>,
    optional_data_check: Option<OptionalDataCheck>,
    verdict: String,
    what_was_proven: Vec<&'static str>,
    what_was_not_proven: Vec<&'static str>,
}

#[derive(Debug, Serialize)]
struct VerifierInfo {
    name: &'static str,
    version: &'static str,
    spec_version: &'static str,
    deterministic: bool,
    network_required: bool,
}

const VERIFIER_INFO: VerifierInfo = VerifierInfo {
    name: env!("CARGO_PKG_NAME"),
    version: env!("CARGO_PKG_VERSION"),
    spec_version: "H33 Signing Substrate Spec v1",
    deterministic: true,
    network_required: false,
};

const PROVEN_LIST: &[&str] = &[
    "Substrate bytes decode to a structurally valid v1 H33-74 substrate layout (58 bytes, version 0x01, recognized computation_type).",
    "SHA3-256(substrate_bytes) equals the claimed on_chain_hash byte-for-byte.",
    "Receipt buffer is the canonical 42-byte compact format.",
];

const NOT_PROVEN_LIST: &[&str] = &[
    "PQ signature validity (Dilithium ML-DSA-65, FALCON-512, SPHINCS+-SHA2-128f) over signing_message — requires the 21KB ephemeral signature bundle and H33's published PQ public keys for the relevant key-gen epoch (Mode 2 verification).",
    "Authenticity of the entity that issued the receipt — anyone with access to a substrate could publish a syntactically valid receipt; signature verification (Mode 2) is what binds it to H33.",
    "Truth of the FHE computation that produced fhe_commitment — the substrate commits to a hash, not to the semantic correctness of the computation.",
];

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify { receipt, data } => run_verify(&receipt, data.as_deref()),
        Command::Inspect { receipt } => run_inspect(&receipt),
    }
}

fn run_verify(receipt_path: &std::path::Path, data_path: Option<&std::path::Path>) -> ExitCode {
    let input = match load_receipt(receipt_path) {
        Ok(v) => v,
        Err(e) => return die(&format!("could not read receipt: {e}")),
    };

    let on_chain_hash_bytes = match hex::decode(input.on_chain_hash.trim()) {
        Ok(v) => v,
        Err(e) => return die(&format!("on_chain_hash hex decode: {e}")),
    };
    let receipt_bytes = match hex::decode(input.receipt_hex.trim()) {
        Ok(v) => v,
        Err(e) => return die(&format!("receipt_hex hex decode: {e}")),
    };
    let substrate_bytes = match hex::decode(input.substrate_hex.trim()) {
        Ok(v) => v,
        Err(e) => return die(&format!("substrate_hex hex decode: {e}")),
    };

    let on_chain_hash_length_32 = on_chain_hash_bytes.len() == 32;
    let receipt_length_42 = receipt_bytes.len() == RECEIPT_SIZE;

    let decoded = decode_substrate(&substrate_bytes);
    let substrate_decodes = decoded.is_ok();
    let view = decoded.ok();

    let version_byte_v1 = view.as_ref().map(|s| s.version == 0x01).unwrap_or(false);
    let computation_type_recognized = view.is_some();
    let computation_type_name = view.as_ref().map(|s| s.computation_type.name().to_string());

    let signing_message_matches_on_chain_hash = if substrate_decodes && on_chain_hash_length_32 {
        let computed = signing_message(&substrate_bytes);
        computed[..] == on_chain_hash_bytes[..]
    } else {
        false
    };

    let decoded_substrate = view.as_ref().map(|s| DecodedSubstrate {
        version: s.version,
        computation_type: s.computation_type.name().to_string(),
        fhe_commitment_hex: hex::encode(s.fhe_commitment),
        timestamp_ms: s.timestamp_ms,
        timestamp_iso: format_timestamp(s.timestamp_ms),
        nonce_hex: hex::encode(s.nonce),
    });

    let optional_data_check = data_path.and_then(|p| {
        let data_bytes = match fs::read(p) {
            Ok(v) => v,
            Err(_) => return None,
        };
        let computed = sha3_256(&data_bytes);
        view.as_ref().map(|s| OptionalDataCheck {
            data_path: p.display().to_string(),
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

    let report = VerificationReport {
        verifier: VERIFIER_INFO,
        input_receipt_path: receipt_path.display().to_string(),
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
    };

    println!(
        "{}",
        serde_json::to_string_pretty(&report).expect("report always serializes")
    );

    if verdict == "PASS" {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

fn run_inspect(receipt_path: &std::path::Path) -> ExitCode {
    let input = match load_receipt(receipt_path) {
        Ok(v) => v,
        Err(e) => return die(&format!("could not read receipt: {e}")),
    };
    let substrate_bytes = match hex::decode(input.substrate_hex.trim()) {
        Ok(v) => v,
        Err(e) => return die(&format!("substrate_hex hex decode: {e}")),
    };
    let view = match decode_substrate(&substrate_bytes) {
        Ok(v) => v,
        Err(e) => return die(&format!("substrate decode failed: {e}")),
    };

    let dump = DecodedSubstrate {
        version: view.version,
        computation_type: view.computation_type.name().to_string(),
        fhe_commitment_hex: hex::encode(view.fhe_commitment),
        timestamp_ms: view.timestamp_ms,
        timestamp_iso: format_timestamp(view.timestamp_ms),
        nonce_hex: hex::encode(view.nonce),
    };
    println!("{}", serde_json::to_string_pretty(&dump).unwrap());
    ExitCode::SUCCESS
}

fn load_receipt(path: &std::path::Path) -> Result<ReceiptInput, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str::<ReceiptInput>(&raw).map_err(|e| e.to_string())
}

fn die(msg: &str) -> ExitCode {
    eprintln!("h33-verify: error: {msg}");
    ExitCode::from(2)
}

/// Format a millisecond Unix timestamp as ISO 8601 UTC. Stdlib only —
/// avoids pulling in chrono / time crates for one format call.
fn format_timestamp(ms: u64) -> String {
    let secs = ms / 1000;
    let millis_part = ms % 1000;

    // Compute Y/M/D/H/M/S from epoch seconds. Public-domain civil-from-days
    // algorithm by Howard Hinnant (paraphrased).
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
