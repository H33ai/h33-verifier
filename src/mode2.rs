//! Mode 2 verification — orchestrates bundle + pubkeys + the three PQ
//! checks into a single verdict the CLI / report can attach.
//!
//! Mode 2 PASS requires ALL FIVE:
//!   1. Bundle decodes (`h33-substrate-bundle-v1` magic + version).
//!   2. Pubkeys file decodes (`h33-substrate-pubkeys-v1` format + names).
//!   3. Bundle's `signing_message` equals the receipt's `on_chain_hash`.
//!   4. ML-DSA-65 signature opens to the signing_message under the
//!      dilithium public key.
//!   5. FALCON-512 signature opens to the signing_message under the
//!      falcon public key.
//!   6. SPHINCS+-SHA2-128f-simple signature opens to the signing_message
//!      under the sphincs public key.
//!
//! (Yes, that's six. Item 1+2 are gate conditions; 3 is the
//! bundle↔receipt link; 4–6 are the actual cryptographic verifications.)
//!
//! All checks are independent: any single failure → Mode 2 FAIL with a
//! specific error. PASS means simultaneous binding to all three NIST
//! hardness assumptions — module lattices, NTRU lattices, and stateless
//! hash signatures.

use crate::bundle::{self, BundleError};
use crate::pq::{verify_dilithium, verify_falcon, verify_sphincs, Algorithm, PqError};
use crate::pubkeys::{self, ParsedPubkeys, PubkeysError};
use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct Mode2Report {
    pub bundle_size_bytes: usize,
    pub bundle_hash_hex: String,
    pub bundle_signing_message_hex: String,
    pub bundle_matches_receipt_on_chain_hash: bool,
    pub pubkeys_epoch_id: String,
    pub pubkeys_epoch: String,
    pub checks: Mode2Checks,
    pub verdict: String, // "PASS" | "FAIL"
    pub failure_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Mode2Checks {
    pub bundle_decodes: bool,
    pub pubkeys_decode: bool,
    pub signing_message_links_bundle_to_receipt: bool,
    pub dilithium_signature_verifies: bool,
    pub falcon_signature_verifies: bool,
    pub sphincs_signature_verifies: bool,
}

#[derive(Debug)]
pub enum Mode2Error {
    BundleDecode(BundleError),
    PubkeysDecode(PubkeysError),
    SigningMessageMismatch {
        bundle_signing_message_hex: String,
        receipt_on_chain_hash_hex: String,
    },
    PqVerify(PqError),
}

impl std::fmt::Display for Mode2Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::BundleDecode(e) => write!(f, "bundle decode failed: {e}"),
            Self::PubkeysDecode(e) => write!(f, "pubkeys decode failed: {e}"),
            Self::SigningMessageMismatch { bundle_signing_message_hex, receipt_on_chain_hash_hex } => {
                write!(
                    f,
                    "bundle signing_message ({bundle_signing_message_hex}) does not match receipt on_chain_hash ({receipt_on_chain_hash_hex}) — bundle is for a DIFFERENT receipt"
                )
            }
            Self::PqVerify(e) => write!(f, "PQ signature verification failed: {e}"),
        }
    }
}

impl std::error::Error for Mode2Error {}

/// Run Mode 2 verification. All three of `bundle_bytes`, `pubkeys_json`,
/// and `receipt_on_chain_hash` are required.
pub fn run_mode2(
    bundle_bytes: &[u8],
    pubkeys_json: &str,
    receipt_on_chain_hash: &[u8; 32],
) -> Mode2Report {
    let bundle_hash_bytes = bundle::bundle_hash(bundle_bytes);
    let bundle_hash_hex = hex::encode(bundle_hash_bytes);

    let view = match bundle::parse(bundle_bytes) {
        Ok(v) => v,
        Err(e) => {
            return fail(
                bundle_bytes.len(),
                bundle_hash_hex,
                "(undecoded)".to_string(),
                false,
                "(no link check — bundle did not decode)".to_string(),
                "(no epoch — bundle did not decode)".to_string(),
                Mode2Checks {
                    bundle_decodes: false,
                    pubkeys_decode: false,
                    signing_message_links_bundle_to_receipt: false,
                    dilithium_signature_verifies: false,
                    falcon_signature_verifies: false,
                    sphincs_signature_verifies: false,
                },
                format!("bundle decode failed: {e}"),
            );
        }
    };

    let signing_message_hex = hex::encode(view.signing_message);

    let pk: ParsedPubkeys = match pubkeys::parse(pubkeys_json) {
        Ok(p) => p,
        Err(e) => {
            return fail(
                bundle_bytes.len(),
                bundle_hash_hex,
                signing_message_hex,
                false,
                "(no epoch — pubkeys did not decode)".to_string(),
                "(no epoch — pubkeys did not decode)".to_string(),
                Mode2Checks {
                    bundle_decodes: true,
                    pubkeys_decode: false,
                    signing_message_links_bundle_to_receipt: false,
                    dilithium_signature_verifies: false,
                    falcon_signature_verifies: false,
                    sphincs_signature_verifies: false,
                },
                format!("pubkeys decode failed: {e}"),
            );
        }
    };

    let epoch_id = pk.file.epoch_id.clone();
    let epoch = pk.file.epoch.clone();

    let link_ok = view.signing_message == *receipt_on_chain_hash;
    if !link_ok {
        return fail(
            bundle_bytes.len(),
            bundle_hash_hex,
            signing_message_hex.clone(),
            false,
            epoch_id,
            epoch,
            Mode2Checks {
                bundle_decodes: true,
                pubkeys_decode: true,
                signing_message_links_bundle_to_receipt: false,
                dilithium_signature_verifies: false,
                falcon_signature_verifies: false,
                sphincs_signature_verifies: false,
            },
            format!(
                "bundle signing_message ({}) does not match receipt on_chain_hash ({}) — bundle is for a DIFFERENT receipt",
                signing_message_hex,
                hex::encode(receipt_on_chain_hash)
            ),
        );
    }

    let dil_ok =
        verify_dilithium(view.dilithium_signed_message, &pk.dilithium, &view.signing_message).is_ok();
    let fal_ok =
        verify_falcon(view.falcon_signed_message, &pk.falcon, &view.signing_message).is_ok();
    let sph_ok =
        verify_sphincs(view.sphincs_signed_message, &pk.sphincs, &view.signing_message).is_ok();

    let all_ok = link_ok && dil_ok && fal_ok && sph_ok;
    let checks = Mode2Checks {
        bundle_decodes: true,
        pubkeys_decode: true,
        signing_message_links_bundle_to_receipt: link_ok,
        dilithium_signature_verifies: dil_ok,
        falcon_signature_verifies: fal_ok,
        sphincs_signature_verifies: sph_ok,
    };

    if all_ok {
        Mode2Report {
            bundle_size_bytes: bundle_bytes.len(),
            bundle_hash_hex,
            bundle_signing_message_hex: signing_message_hex,
            bundle_matches_receipt_on_chain_hash: true,
            pubkeys_epoch_id: epoch_id,
            pubkeys_epoch: epoch,
            checks,
            verdict: "PASS".to_string(),
            failure_reason: None,
        }
    } else {
        let mut reasons = Vec::new();
        if !dil_ok {
            reasons.push(Algorithm::Dilithium.name().to_string());
        }
        if !fal_ok {
            reasons.push(Algorithm::Falcon.name().to_string());
        }
        if !sph_ok {
            reasons.push(Algorithm::Sphincs.name().to_string());
        }
        let reason = format!("signature(s) failed: {}", reasons.join(", "));
        fail(
            bundle_bytes.len(),
            bundle_hash_hex,
            signing_message_hex,
            true,
            epoch_id,
            epoch,
            checks,
            reason,
        )
    }
}

#[allow(clippy::too_many_arguments)]
fn fail(
    bundle_size_bytes: usize,
    bundle_hash_hex: String,
    bundle_signing_message_hex: String,
    bundle_matches_receipt_on_chain_hash: bool,
    pubkeys_epoch_id: String,
    pubkeys_epoch: String,
    checks: Mode2Checks,
    reason: String,
) -> Mode2Report {
    Mode2Report {
        bundle_size_bytes,
        bundle_hash_hex,
        bundle_signing_message_hex,
        bundle_matches_receipt_on_chain_hash,
        pubkeys_epoch_id,
        pubkeys_epoch,
        checks,
        verdict: "FAIL".to_string(),
        failure_reason: Some(reason),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bundle;
    use pqcrypto_traits::sign::{PublicKey as PqPk, SignedMessage as PqSm};

    fn build_real_bundle_and_pubkeys(signing_message: &[u8; 32]) -> (Vec<u8>, String) {
        use pqcrypto_falcon::falcon512;
        use pqcrypto_mldsa::mldsa65;
        use pqcrypto_sphincsplus::sphincssha2128fsimple as sph;

        let (dpk, dsk) = mldsa65::keypair();
        let dsm = mldsa65::sign(signing_message, &dsk);

        let (fpk, fsk) = falcon512::keypair();
        let fsm = falcon512::sign(signing_message, &fsk);

        let (spk, ssk) = sph::keypair();
        let ssm = sph::sign(signing_message, &ssk);

        let bundle = bundle::build(
            signing_message,
            dsm.as_bytes(),
            fsm.as_bytes(),
            ssm.as_bytes(),
        );

        let pubkeys_json = format!(
            r#"{{
                "format": "h33-substrate-pubkeys-v1",
                "epoch_id": "self-generated-test-vector-2026-05-26",
                "epoch": "2026-05-26",
                "issued_at_utc": "2026-05-26T00:00:00Z",
                "algorithms": {{
                    "dilithium": {{ "name": "ML-DSA-65",                 "public_key_hex": "{}" }},
                    "falcon":    {{ "name": "FALCON-512",                "public_key_hex": "{}" }},
                    "sphincs":   {{ "name": "SPHINCS+-SHA2-128f-simple", "public_key_hex": "{}" }}
                }}
            }}"#,
            hex::encode(dpk.as_bytes()),
            hex::encode(fpk.as_bytes()),
            hex::encode(spk.as_bytes()),
        );

        (bundle, pubkeys_json)
    }

    #[test]
    fn full_mode2_roundtrip_pass() {
        let signing_message = [0x7Eu8; 32];
        let (bundle, pubkeys) = build_real_bundle_and_pubkeys(&signing_message);
        let report = run_mode2(&bundle, &pubkeys, &signing_message);
        assert_eq!(report.verdict, "PASS", "{:?}", report);
        assert!(report.checks.bundle_decodes);
        assert!(report.checks.pubkeys_decode);
        assert!(report.checks.signing_message_links_bundle_to_receipt);
        assert!(report.checks.dilithium_signature_verifies);
        assert!(report.checks.falcon_signature_verifies);
        assert!(report.checks.sphincs_signature_verifies);
        assert_eq!(
            report.bundle_signing_message_hex,
            hex::encode(signing_message)
        );
    }

    #[test]
    fn mode2_fails_when_receipt_hash_does_not_match_bundle() {
        let signing_message = [0x7Eu8; 32];
        let (bundle, pubkeys) = build_real_bundle_and_pubkeys(&signing_message);
        let wrong_hash = [0x99u8; 32];
        let report = run_mode2(&bundle, &pubkeys, &wrong_hash);
        assert_eq!(report.verdict, "FAIL");
        assert!(!report.checks.signing_message_links_bundle_to_receipt);
        assert!(report.failure_reason.unwrap().contains("DIFFERENT receipt"));
    }

    #[test]
    fn mode2_fails_when_dilithium_signature_is_tampered() {
        let signing_message = [0x7Eu8; 32];
        let (mut bundle, pubkeys) = build_real_bundle_and_pubkeys(&signing_message);
        // Flip a byte in the dilithium signed_message portion (starts at offset 44).
        bundle[44] ^= 0xFF;
        let report = run_mode2(&bundle, &pubkeys, &signing_message);
        assert_eq!(report.verdict, "FAIL");
        assert!(!report.checks.dilithium_signature_verifies);
        // Falcon and SPHINCS should still verify (their blobs untouched).
        assert!(report.checks.falcon_signature_verifies);
        assert!(report.checks.sphincs_signature_verifies);
    }

    #[test]
    fn mode2_fails_when_wrong_pubkeys_supplied() {
        let signing_message = [0x7Eu8; 32];
        let (bundle, _pubkeys_a) = build_real_bundle_and_pubkeys(&signing_message);
        // Different keypair entirely.
        let (_bundle_b, pubkeys_b) = build_real_bundle_and_pubkeys(&signing_message);
        let report = run_mode2(&bundle, &pubkeys_b, &signing_message);
        assert_eq!(report.verdict, "FAIL");
        // All three should fail because all three pubkeys are wrong.
        assert!(!report.checks.dilithium_signature_verifies);
        assert!(!report.checks.falcon_signature_verifies);
        assert!(!report.checks.sphincs_signature_verifies);
    }

    #[test]
    fn mode2_fails_on_malformed_bundle() {
        let signing_message = [0x7Eu8; 32];
        let (_b, pubkeys) = build_real_bundle_and_pubkeys(&signing_message);
        let report = run_mode2(b"H33B not really a bundle", &pubkeys, &signing_message);
        assert_eq!(report.verdict, "FAIL");
        assert!(!report.checks.bundle_decodes);
    }

    #[test]
    fn mode2_fails_on_malformed_pubkeys() {
        let signing_message = [0x7Eu8; 32];
        let (bundle, _p) = build_real_bundle_and_pubkeys(&signing_message);
        let report = run_mode2(&bundle, "{ invalid }", &signing_message);
        assert_eq!(report.verdict, "FAIL");
        assert!(report.checks.bundle_decodes);
        assert!(!report.checks.pubkeys_decode);
    }
}
