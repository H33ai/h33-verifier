//! `h33-verify` CLI — v0.2.
//!
//! Subcommands:
//!   verify         — verify a receipt (Mode 1); pretty JSON report on stdout.
//!                    With `--signed-report`, also signs the report with
//!                    the verifier instance's Ed25519 key.
//!   inspect        — decode a receipt's substrate without verifying it.
//!   keygen         — generate or rotate this verifier instance's keypair.
//!   identity       — print this instance's public key + fingerprint.
//!   verify-report  — verify a previously produced signed report.
//!
//! Brutally simple by design: no daemon, no network call, no auth, no cloud
//! dep, no implicit state besides the persisted identity file.

use clap::{Parser, Subcommand};
use h33_verify::{
    decode_substrate,
    identity::Identity,
    report::{verify_receipt, DecodedSubstrate, VerifyInput},
    signed_report::{produce_signed_report, verify_signed_report},
};
use serde::Deserialize;
use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "h33-verify",
    version,
    about = "Offline verifier for H33-74 substrate receipts. Mode 1 deterministic; Ed25519-signed reports in v0.2.",
    long_about = "Independent offline verifier for H33-74 substrate receipts.\n\n\
                  Reconstructs the 58-byte substrate per H33 Signing Substrate Spec v1, \
                  recomputes SHA3-256, and compares to the claimed on-chain hash. \
                  No network, no H33 dependency, no trust assumption beyond SHA3.\n\n\
                  v0.2 adds verifier-signed reports: each verification can be wrapped \
                  in an Ed25519-signed envelope that names which verifier instance ran \
                  the check, when, and over what receipt — so the verdict itself \
                  becomes a portable, attestable artifact."
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
        /// Wrap the report in an Ed25519-signed envelope using this
        /// verifier instance's keypair. Generates a keypair on first use.
        #[arg(long)]
        signed_report: bool,
        /// Override the verifier instance identity file location.
        /// Defaults to $H33_VERIFY_IDENTITY, $XDG_CONFIG_HOME/h33-verify/identity.json,
        /// or $HOME/.config/h33-verify/identity.json.
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Decode a receipt's substrate and print its fields without running verification.
    Inspect { receipt: PathBuf },
    /// Generate or rotate this verifier instance's keypair.
    /// Writes to the identity file (default $HOME/.config/h33-verify/identity.json).
    Keygen {
        /// Identity file path; defaults to the standard location.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Overwrite an existing keypair if one is already present. Without
        /// this flag, `keygen` refuses to clobber.
        #[arg(long)]
        force: bool,
    },
    /// Print this verifier instance's public key and fingerprint.
    Identity {
        #[arg(long)]
        identity: Option<PathBuf>,
    },
    /// Verify a previously produced signed report.
    VerifyReport {
        /// Path to the signed report JSON.
        report: PathBuf,
    },
    /// Attest a target against the H33-PQ Verified standard. Walks the target's
    /// attestation manifest, fetches every pillar bundle named, structurally
    /// validates each, and emits a per-pillar report with an overall verdict.
    /// `--manifest` accepts a local path, file:// URL, or http(s):// URL
    /// (URLs are fetched via the system `curl` binary as a subprocess).
    Attest {
        /// Path or URL to the attestation manifest (typically
        /// https://h33.ai/standards/post-quantum-verified/h33-self-attestation/bundles/manifest.json).
        #[arg(long)]
        manifest: String,
        /// Optional output path for the JSON report; defaults to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
    },
}

#[derive(Debug, Deserialize)]
struct ReceiptInput {
    on_chain_hash: String,
    receipt_hex: String,
    substrate_hex: String,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Verify { receipt, data, signed_report, identity } => {
            run_verify(&receipt, data.as_deref(), signed_report, identity.as_deref())
        }
        Command::Inspect { receipt } => run_inspect(&receipt),
        Command::Keygen { identity, force } => run_keygen(identity.as_deref(), force),
        Command::Identity { identity } => run_identity(identity.as_deref()),
        Command::VerifyReport { report } => run_verify_report(&report),
        Command::Attest { manifest, output } => run_attest_cmd(&manifest, output.as_deref()),
    }
}

fn run_attest_cmd(manifest: &str, output: Option<&std::path::Path>) -> ExitCode {
    use h33_verify::attest::run_attest;
    match run_attest(manifest, env!("CARGO_PKG_VERSION")) {
        Ok((report, ok)) => {
            let json = match serde_json::to_string_pretty(&report) {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("attest: report serialization failed: {e}");
                    return ExitCode::from(2);
                }
            };
            if let Some(p) = output {
                if let Err(e) = std::fs::write(p, &json) {
                    eprintln!("attest: failed to write {}: {e}", p.display());
                    return ExitCode::from(2);
                }
                eprintln!(
                    "attest: report written to {} — overall: {}",
                    p.display(),
                    report.overall
                );
            } else {
                println!("{json}");
            }
            if ok {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("attest: {e}");
            ExitCode::from(2)
        }
    }
}

fn run_verify(
    receipt_path: &std::path::Path,
    data_path: Option<&std::path::Path>,
    signed: bool,
    identity_path: Option<&std::path::Path>,
) -> ExitCode {
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

    let data_pair = match data_path {
        Some(p) => match fs::read(p) {
            Ok(bytes) => Some((bytes, p.display().to_string())),
            Err(e) => return die(&format!("could not read --data file: {e}")),
        },
        None => None,
    };
    let data_borrow = data_pair.as_ref().map(|(b, p)| (b.as_slice(), p.clone()));

    let verify_input = VerifyInput {
        receipt_path_display: receipt_path.display().to_string(),
        on_chain_hash: &on_chain_hash_bytes,
        receipt_bytes: &receipt_bytes,
        substrate_bytes: &substrate_bytes,
        data: data_borrow,
    };

    let report = verify_receipt(&verify_input);
    let verdict_is_pass = report.verdict == "PASS";

    if signed {
        let path = identity_path
            .map(|p| p.to_path_buf())
            .unwrap_or_else(Identity::default_path);
        let (identity, was_created) = match Identity::load_or_create(&path) {
            Ok(v) => v,
            Err(e) => return die(&format!("identity error at {}: {e}", path.display())),
        };
        if was_created {
            eprintln!(
                "h33-verify: generated new verifier instance keypair at {} (fingerprint {})",
                path.display(),
                identity.fingerprint()
            );
        }
        let signed_value = produce_signed_report(
            &report,
            &identity,
            input.on_chain_hash.trim(),
            input.receipt_hex.trim(),
            input.substrate_hex.trim(),
        );
        println!("{}", serde_json::to_string_pretty(&signed_value).unwrap());
    } else {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).expect("report always serializes")
        );
    }

    if verdict_is_pass {
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
        timestamp_iso: h33_verify::iso8601_from_unix_ms(view.timestamp_ms),
        nonce_hex: hex::encode(view.nonce),
    };
    println!("{}", serde_json::to_string_pretty(&dump).unwrap());
    ExitCode::SUCCESS
}

fn run_keygen(identity_path: Option<&std::path::Path>, force: bool) -> ExitCode {
    let path = identity_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(Identity::default_path);
    if path.exists() && !force {
        return die(&format!(
            "identity already exists at {} — pass --force to overwrite (this will rotate your verifier instance key, invalidating consumer trust)",
            path.display()
        ));
    }
    let id = Identity::generate();
    if let Err(e) = id.save(&path) {
        return die(&format!("save: {e}"));
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "action": if force { "rotated" } else { "created" },
            "path": path.display().to_string(),
            "public_key_hex": id.public_key_hex(),
            "fingerprint": id.fingerprint(),
            "created_at_utc": id.created_at_utc(),
        }))
        .unwrap()
    );
    ExitCode::SUCCESS
}

fn run_identity(identity_path: Option<&std::path::Path>) -> ExitCode {
    let path = identity_path
        .map(|p| p.to_path_buf())
        .unwrap_or_else(Identity::default_path);
    if !path.exists() {
        return die(&format!(
            "no identity at {} — run `h33-verify keygen` to create one",
            path.display()
        ));
    }
    let id = match Identity::load(&path) {
        Ok(v) => v,
        Err(e) => return die(&format!("identity load: {e}")),
    };
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "path": path.display().to_string(),
            "public_key_hex": id.public_key_hex(),
            "fingerprint": id.fingerprint(),
            "created_at_utc": id.created_at_utc(),
            "algorithm": "ed25519",
        }))
        .unwrap()
    );
    ExitCode::SUCCESS
}

fn run_verify_report(report_path: &std::path::Path) -> ExitCode {
    let raw = match fs::read_to_string(report_path) {
        Ok(v) => v,
        Err(e) => return die(&format!("could not read signed report: {e}")),
    };
    match verify_signed_report(&raw) {
        Ok(v) => {
            let body = serde_json::json!({
                "signed_report_path": report_path.display().to_string(),
                "signature_verified": true,
                "report_verdict": v.verdict,
                "verifier_instance": {
                    "public_key_hex": v.verifier_public_key_hex,
                    "fingerprint": v.verifier_fingerprint,
                },
                "verified_at_utc": v.verified_at_utc,
                "attested_receipt": {
                    "on_chain_hash": v.on_chain_hash_hex,
                    "receipt_input_sha3_256": v.receipt_input_sha3_256_hex,
                },
                "what_this_proves": [
                    "The signed report has not been tampered with since it was signed.",
                    "The Ed25519 public key embedded in the report signed this specific verdict.",
                    "The verifier instance with that public key claimed `verdict` over the receipt identified by `attested_receipt.receipt_input_sha3_256`.",
                ],
                "what_this_does_NOT_prove": [
                    "Whether you should trust the verifier instance that produced this report — that is an out-of-band relationship (key directory, fingerprint comparison, known-instance list).",
                    "Whether the original receipt is itself authentic — Mode 1 verification of the receipt is included in the report's deterministic_checks; PQ signature validity (Mode 2) is the v0.3 closure.",
                ],
            });
            println!("{}", serde_json::to_string_pretty(&body).unwrap());
            if v.verdict == "PASS" {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(1)
            }
        }
        Err(e) => {
            eprintln!("h33-verify: signed report verification FAILED: {e}");
            ExitCode::from(1)
        }
    }
}

fn load_receipt(path: &std::path::Path) -> Result<ReceiptInput, String> {
    let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
    serde_json::from_str::<ReceiptInput>(&raw).map_err(|e| e.to_string())
}

fn die(msg: &str) -> ExitCode {
    eprintln!("h33-verify: error: {msg}");
    ExitCode::from(2)
}
