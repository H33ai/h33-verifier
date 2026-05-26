//! Verifier-signed verification reports — v0.2 wedge artifact.
//!
//! A signed report wraps a `VerificationReport` (from the existing Mode 1
//! check) with three additional facts:
//!
//!  1. **Verifier instance identity.** The Ed25519 public key + fingerprint
//!     of the running verifier instance. Out-of-band trust establishment
//!     (key directory, fingerprint comparison) is the consumer's
//!     responsibility; the report itself only attests "this key signed
//!     this verdict."
//!  2. **Verified-at timestamp.** When the verification ran, as ISO 8601
//!     UTC milliseconds.
//!  3. **Receipt input hash.** SHA3-256 over a canonical encoding of the
//!     three required receipt fields (`on_chain_hash`, `receipt_hex`,
//!     `substrate_hex`). This ties the report to its specific input
//!     receipt without depending on the file's whitespace or extra fields.
//!
//! The signature covers a canonical JSON encoding (see `crate::canonical`)
//! of the entire report MINUS the signature field. Any conforming
//! implementation in any language can reproduce the signed bytes
//! deterministically and verify the Ed25519 signature.
//!
//! # Signed report wire format (v1)
//!
//! ```json
//! {
//!   "decoded_substrate": { ... },        // from VerificationReport
//!   "deterministic_checks": { ... },      // from VerificationReport
//!   "input_receipt_path": "...",
//!   "optional_data_check": null | { ... },
//!   "receipt_input": {
//!     "on_chain_hash": "<hex>",
//!     "receipt_input_sha3_256": "<hex of SHA3 over canonical input>"
//!   },
//!   "report_format": "h33-verify-signed-report-v1",
//!   "signature": {
//!     "algorithm": "ed25519",
//!     "value_hex": "<64 bytes hex>"
//!   },
//!   "verdict": "PASS" | "FAIL",
//!   "verified_at_utc": "<ISO 8601>",
//!   "verifier": {
//!     "deterministic": true,
//!     "fingerprint": "<8 bytes hex>",
//!     "instance_public_key": "<32 bytes hex>",
//!     "name": "h33-verify",
//!     "network_required": false,
//!     "spec_version": "H33 Signing Substrate Spec v1",
//!     "version": "0.2.0"
//!   },
//!   "what_was_proven": [ ... ],
//!   "what_was_not_proven": [ ... ]
//! }
//! ```
//!
//! Field order doesn't matter for canonical encoding (keys are sorted at
//! signing/verification time), but the field SET is fixed.

use crate::canonical;
use crate::identity::{verify_ed25519, Identity};
use crate::report::VerificationReport;
use crate::sha3_256;
use serde_json::{json, Map, Value};

pub const REPORT_FORMAT_TAG: &str = "h33-verify-signed-report-v1";

#[derive(Debug)]
pub enum SignedReportError {
    InvalidJson(String),
    MissingField(&'static str),
    FieldTypeMismatch(&'static str),
    HexDecode(String),
    SignatureVerificationFailed(String),
    AlgorithmMismatch(String),
    ReportFormatMismatch(String),
    ChecksFailedAfterRedo,
}

impl std::fmt::Display for SignedReportError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJson(s) => write!(f, "report is not valid JSON: {s}"),
            Self::MissingField(s) => write!(f, "report missing required field: {s}"),
            Self::FieldTypeMismatch(s) => write!(f, "report field '{s}' has wrong type"),
            Self::HexDecode(s) => write!(f, "hex decode: {s}"),
            Self::SignatureVerificationFailed(s) => write!(f, "signature did not verify: {s}"),
            Self::AlgorithmMismatch(s) => write!(f, "unsupported signature algorithm '{s}'"),
            Self::ReportFormatMismatch(s) => write!(f, "unsupported report_format '{s}'"),
            Self::ChecksFailedAfterRedo => write!(f, "redo of deterministic checks did not match — signed report is INTERNALLY INCONSISTENT"),
        }
    }
}

impl std::error::Error for SignedReportError {}

/// Compute the input-receipt hash that goes into `receipt_input.receipt_input_sha3_256`.
///
/// Canonical: SHA3-256 over a canonical-JSON encoding of the three required
/// receipt fields (object with keys `on_chain_hash`, `receipt_hex`,
/// `substrate_hex`, each value the original hex string trimmed). The
/// purpose is to make the report attest to a *specific* receipt regardless
/// of whitespace, key order, or extra fields in the source JSON.
pub fn receipt_input_sha3(
    on_chain_hash_hex: &str,
    receipt_hex: &str,
    substrate_hex: &str,
) -> [u8; 32] {
    let canonical_input = json!({
        "on_chain_hash": on_chain_hash_hex.trim(),
        "receipt_hex": receipt_hex.trim(),
        "substrate_hex": substrate_hex.trim(),
    });
    sha3_256(&canonical::encode(&canonical_input))
}

/// Build the unsigned-body JSON Value that gets canonical-encoded and signed.
fn build_unsigned_body(
    report: &VerificationReport,
    identity: &Identity,
    verified_at_utc: &str,
    receipt_input_hash_hex: &str,
    on_chain_hash_hex: &str,
) -> Value {
    let mut verifier = Map::new();
    verifier.insert("name".into(), Value::String(report.verifier.name.into()));
    verifier.insert("version".into(), Value::String(report.verifier.version.into()));
    verifier.insert("spec_version".into(), Value::String(report.verifier.spec_version.into()));
    verifier.insert("deterministic".into(), Value::Bool(report.verifier.deterministic));
    verifier.insert("network_required".into(), Value::Bool(report.verifier.network_required));
    verifier.insert("instance_public_key".into(), Value::String(identity.public_key_hex()));
    verifier.insert("fingerprint".into(), Value::String(identity.fingerprint()));

    let receipt_input = json!({
        "on_chain_hash": on_chain_hash_hex,
        "receipt_input_sha3_256": receipt_input_hash_hex,
    });

    // We serialize the existing VerificationReport into a serde_json::Value
    // tree so we can compose it. serde_json's default serializer for our
    // struct produces predictable per-field shapes; canonical encoding
    // happens at sign/verify time independently.
    let proven: Vec<Value> = report.what_was_proven.iter().map(|s| Value::String((*s).into())).collect();
    let not_proven: Vec<Value> = report.what_was_not_proven.iter().map(|s| Value::String((*s).into())).collect();

    let det = serde_json::to_value(&report.deterministic_checks).expect("checks always serialize");
    let decoded = serde_json::to_value(&report.decoded_substrate).expect("decoded always serializes");
    let optional = serde_json::to_value(&report.optional_data_check).expect("optional always serializes");

    let mut top = Map::new();
    top.insert("report_format".into(), Value::String(REPORT_FORMAT_TAG.into()));
    top.insert("verifier".into(), Value::Object(verifier));
    top.insert("verified_at_utc".into(), Value::String(verified_at_utc.into()));
    top.insert("receipt_input".into(), receipt_input);
    top.insert("input_receipt_path".into(), Value::String(report.input_receipt_path.clone()));
    top.insert("deterministic_checks".into(), det);
    top.insert("decoded_substrate".into(), decoded);
    top.insert("optional_data_check".into(), optional);
    top.insert("verdict".into(), Value::String(report.verdict.clone()));
    top.insert("what_was_proven".into(), Value::Array(proven));
    top.insert("what_was_not_proven".into(), Value::Array(not_proven));

    Value::Object(top)
}

/// Produce a signed report. The output is a `serde_json::Value` ready to
/// be serialized (we recommend `serde_json::to_string_pretty` for human
/// inspection; the SIGNATURE was computed over the canonical encoding, so
/// pretty-printing the wrapper has no effect on verifiability).
pub fn produce_signed_report(
    report: &VerificationReport,
    identity: &Identity,
    on_chain_hash_hex: &str,
    receipt_hex: &str,
    substrate_hex: &str,
) -> Value {
    let verified_at_utc = crate::iso8601_now();
    let receipt_input_hash = receipt_input_sha3(on_chain_hash_hex, receipt_hex, substrate_hex);
    let receipt_input_hash_hex = hex::encode(receipt_input_hash);

    let unsigned = build_unsigned_body(
        report,
        identity,
        &verified_at_utc,
        &receipt_input_hash_hex,
        on_chain_hash_hex.trim(),
    );

    let canonical_bytes = canonical::encode(&unsigned);
    let message_hash = sha3_256(&canonical_bytes);
    let signature = identity.sign(&message_hash);

    // Now attach the signature field to produce the final report.
    let mut final_obj = match unsigned {
        Value::Object(m) => m,
        _ => unreachable!("build_unsigned_body always returns Object"),
    };
    final_obj.insert(
        "signature".into(),
        json!({
            "algorithm": "ed25519",
            "value_hex": hex::encode(signature),
        }),
    );
    Value::Object(final_obj)
}

/// Result of `verify_signed_report`.
#[derive(Debug)]
pub struct SignedReportVerdict {
    /// The verdict claimed by the signed report ("PASS" or "FAIL").
    pub verdict: String,
    /// The Ed25519 public key (hex) that signed the report.
    pub verifier_public_key_hex: String,
    /// The verifier instance fingerprint (hex).
    pub verifier_fingerprint: String,
    /// When the verifier ran the check.
    pub verified_at_utc: String,
    /// `on_chain_hash` of the receipt the report attests.
    pub on_chain_hash_hex: String,
    /// SHA3-256 of the canonical (on_chain, receipt, substrate) tuple.
    pub receipt_input_sha3_256_hex: String,
}

/// Verify a signed report:
///   1. Parse JSON; check `report_format` tag matches v1.
///   2. Extract the `signature` field; strip it from the unsigned body.
///   3. Canonical-encode the unsigned body; SHA3-256; verify Ed25519
///      against the embedded `verifier.instance_public_key`.
///   4. Sanity check `verifier.fingerprint` matches SHA3-256(public_key)[..8].
///
/// On success, returns a `SignedReportVerdict` summary. Callers should
/// trust the verdict only to the extent they trust the verifier instance's
/// public key — that is an out-of-band relationship.
pub fn verify_signed_report(report_json: &str) -> Result<SignedReportVerdict, SignedReportError> {
    let report: Value = serde_json::from_str(report_json)
        .map_err(|e| SignedReportError::InvalidJson(e.to_string()))?;

    let Value::Object(mut obj) = report else {
        return Err(SignedReportError::FieldTypeMismatch("(top-level not object)"));
    };

    let format = obj
        .get("report_format")
        .and_then(|v| v.as_str())
        .ok_or(SignedReportError::MissingField("report_format"))?;
    if format != REPORT_FORMAT_TAG {
        return Err(SignedReportError::ReportFormatMismatch(format.to_string()));
    }

    let signature_value = obj
        .remove("signature")
        .ok_or(SignedReportError::MissingField("signature"))?;
    let Value::Object(sig_obj) = signature_value else {
        return Err(SignedReportError::FieldTypeMismatch("signature"));
    };
    let algorithm = sig_obj
        .get("algorithm")
        .and_then(|v| v.as_str())
        .ok_or(SignedReportError::MissingField("signature.algorithm"))?;
    if algorithm != "ed25519" {
        return Err(SignedReportError::AlgorithmMismatch(algorithm.to_string()));
    }
    let sig_hex = sig_obj
        .get("value_hex")
        .and_then(|v| v.as_str())
        .ok_or(SignedReportError::MissingField("signature.value_hex"))?;
    let sig_bytes =
        hex::decode(sig_hex.trim()).map_err(|e| SignedReportError::HexDecode(e.to_string()))?;

    let verifier = obj
        .get("verifier")
        .and_then(|v| v.as_object())
        .ok_or(SignedReportError::MissingField("verifier"))?;
    let pk_hex = verifier
        .get("instance_public_key")
        .and_then(|v| v.as_str())
        .ok_or(SignedReportError::MissingField("verifier.instance_public_key"))?;
    let pk_bytes =
        hex::decode(pk_hex.trim()).map_err(|e| SignedReportError::HexDecode(e.to_string()))?;
    let claimed_fingerprint = verifier
        .get("fingerprint")
        .and_then(|v| v.as_str())
        .ok_or(SignedReportError::MissingField("verifier.fingerprint"))?;

    // Recompute fingerprint and check it matches.
    let recomputed_fp_full = sha3_256(&pk_bytes);
    let recomputed_fp_hex = hex::encode(&recomputed_fp_full[..8]);
    if recomputed_fp_hex != claimed_fingerprint {
        return Err(SignedReportError::SignatureVerificationFailed(
            "fingerprint != SHA3(public_key)[..8]".to_string(),
        ));
    }

    // Reconstruct the unsigned body and verify the signature.
    let unsigned = Value::Object(obj.clone());
    let canonical_bytes = canonical::encode(&unsigned);
    let message_hash = sha3_256(&canonical_bytes);
    verify_ed25519(&pk_bytes, &message_hash, &sig_bytes)
        .map_err(SignedReportError::SignatureVerificationFailed)?;

    // Extract summary fields.
    let verdict = obj
        .get("verdict")
        .and_then(|v| v.as_str())
        .unwrap_or("UNKNOWN")
        .to_string();
    let verified_at_utc = obj
        .get("verified_at_utc")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt_input = obj
        .get("receipt_input")
        .and_then(|v| v.as_object())
        .ok_or(SignedReportError::MissingField("receipt_input"))?;
    let on_chain_hash_hex = receipt_input
        .get("on_chain_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let receipt_input_sha3_256_hex = receipt_input
        .get("receipt_input_sha3_256")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(SignedReportVerdict {
        verdict,
        verifier_public_key_hex: pk_hex.to_string(),
        verifier_fingerprint: claimed_fingerprint.to_string(),
        verified_at_utc,
        on_chain_hash_hex,
        receipt_input_sha3_256_hex,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::report::{verify_receipt, VerifyInput};

    fn dummy_input_from_canonical_fixture() -> (Vec<u8>, Vec<u8>, Vec<u8>, &'static str, &'static str, &'static str) {
        // Real production fixture from tests/fixtures/real/.
        let on_chain_hex = "673c3412fa861f9a928761661ef1e6e4ee5eaf93da21516c5e0b3a7eee5416cc";
        let substrate_hex = "01fff6a298ea7a07d9a951f9e42fe3ba1e13615333df03375fee17d544b36fd93d180000019e61524dd37964a4fcd9c7c1ef7c7220b37efa331e";
        let receipt_hex = "012d26fc3f5b9a602ac67f116410005b9a42c9f6d7dac273cc1183c1e4137127a60000019e61524dd307";
        (
            hex::decode(on_chain_hex).unwrap(),
            hex::decode(receipt_hex).unwrap(),
            hex::decode(substrate_hex).unwrap(),
            on_chain_hex,
            receipt_hex,
            substrate_hex,
        )
    }

    #[test]
    fn sign_then_verify_roundtrip_pass() {
        let (on_chain, receipt, substrate, oc_hex, r_hex, s_hex) = dummy_input_from_canonical_fixture();
        let input = VerifyInput {
            receipt_path_display: "test-fixture".to_string(),
            on_chain_hash: &on_chain,
            receipt_bytes: &receipt,
            substrate_bytes: &substrate,
            data: None,
        };
        let report = verify_receipt(&input);
        assert_eq!(report.verdict, "PASS");

        let identity = Identity::generate();
        let signed = produce_signed_report(&report, &identity, oc_hex, r_hex, s_hex);
        let serialized = serde_json::to_string(&signed).unwrap();

        let verdict = verify_signed_report(&serialized).expect("must verify");
        assert_eq!(verdict.verdict, "PASS");
        assert_eq!(verdict.on_chain_hash_hex, oc_hex);
        assert_eq!(verdict.verifier_public_key_hex, identity.public_key_hex());
        assert_eq!(verdict.verifier_fingerprint, identity.fingerprint());
    }

    #[test]
    fn tampered_verdict_fails_signature_check() {
        let (on_chain, receipt, substrate, oc_hex, r_hex, s_hex) = dummy_input_from_canonical_fixture();
        let input = VerifyInput {
            receipt_path_display: "test-fixture".to_string(),
            on_chain_hash: &on_chain,
            receipt_bytes: &receipt,
            substrate_bytes: &substrate,
            data: None,
        };
        let report = verify_receipt(&input);
        let identity = Identity::generate();
        let signed = produce_signed_report(&report, &identity, oc_hex, r_hex, s_hex);
        let mut serialized = serde_json::to_string(&signed).unwrap();
        // Flip PASS -> FAIL inside the verdict field
        serialized = serialized.replace("\"PASS\"", "\"FAIL\"");
        let result = verify_signed_report(&serialized);
        assert!(matches!(result, Err(SignedReportError::SignatureVerificationFailed(_))));
    }

    #[test]
    fn tampered_pubkey_fails_fingerprint_check() {
        let (on_chain, receipt, substrate, oc_hex, r_hex, s_hex) = dummy_input_from_canonical_fixture();
        let input = VerifyInput {
            receipt_path_display: "test-fixture".to_string(),
            on_chain_hash: &on_chain,
            receipt_bytes: &receipt,
            substrate_bytes: &substrate,
            data: None,
        };
        let report = verify_receipt(&input);
        let identity = Identity::generate();
        let mut signed = produce_signed_report(&report, &identity, oc_hex, r_hex, s_hex);
        // Replace instance_public_key with another random key — fingerprint won't match.
        let other = Identity::generate();
        if let Value::Object(obj) = &mut signed {
            if let Some(Value::Object(verifier)) = obj.get_mut("verifier") {
                verifier.insert(
                    "instance_public_key".into(),
                    Value::String(other.public_key_hex()),
                );
                // Fingerprint left as identity's original — mismatch.
            }
        }
        let serialized = serde_json::to_string(&signed).unwrap();
        let result = verify_signed_report(&serialized);
        assert!(matches!(result, Err(SignedReportError::SignatureVerificationFailed(_))));
    }

    #[test]
    fn signed_report_for_fail_verdict_is_still_attestable() {
        // A signed FAIL report is just as valuable as a PASS — it's the
        // signed CHAIN OF CUSTODY of a verification, regardless of outcome.
        let mut on_chain = vec![0u8; 32];
        on_chain[0] = 0xFF; // wrong on_chain → verdict = FAIL
        let substrate = hex::decode("01fff6a298ea7a07d9a951f9e42fe3ba1e13615333df03375fee17d544b36fd93d180000019e61524dd37964a4fcd9c7c1ef7c7220b37efa331e").unwrap();
        let receipt = hex::decode("012d26fc3f5b9a602ac67f116410005b9a42c9f6d7dac273cc1183c1e4137127a60000019e61524dd307").unwrap();
        let input = VerifyInput {
            receipt_path_display: "fail-fixture".to_string(),
            on_chain_hash: &on_chain,
            receipt_bytes: &receipt,
            substrate_bytes: &substrate,
            data: None,
        };
        let report = verify_receipt(&input);
        assert_eq!(report.verdict, "FAIL");

        let identity = Identity::generate();
        let signed = produce_signed_report(
            &report,
            &identity,
            &hex::encode(&on_chain),
            "012d26fc3f5b9a602ac67f116410005b9a42c9f6d7dac273cc1183c1e4137127a60000019e61524dd307",
            "01fff6a298ea7a07d9a951f9e42fe3ba1e13615333df03375fee17d544b36fd93d180000019e61524dd37964a4fcd9c7c1ef7c7220b37efa331e",
        );
        let serialized = serde_json::to_string(&signed).unwrap();
        let verdict = verify_signed_report(&serialized).expect("signed FAIL must verify");
        assert_eq!(verdict.verdict, "FAIL");
    }
}
