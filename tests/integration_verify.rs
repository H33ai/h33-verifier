//! Integration tests against canonical fixtures.
//!
//! These tests are the contract: any change that breaks them is a behavioral
//! change to the verifier. They also serve as deterministic test vectors —
//! third-party implementations of the H33-74 spec should produce byte-
//! identical decode outputs for the same fixtures.

use h33_verify::{decode_substrate, sha3_256, signing_message, ComputationType, SUBSTRATE_SIZE};

/// The canonical generic fixture from scif-backend's substrate_anchor.rs test.
/// This is a real attestation response from production substrate code.
const SAMPLE_SUBSTRATE_HEX: &str =
    "01ff42012470e20e90036b3098da71e1056ce0e561031bc41fa47faa1d1269f93a2e0000019d79bbe68283f8aeddabbcae0279787de9a7fdbd9d";
const SAMPLE_ON_CHAIN_HEX: &str =
    "91f55fd1fa55d2c675c0def6f0892a3cd86c9495fe3b23348537f1b86e9aa429";
const SAMPLE_RECEIPT_HEX: &str =
    "012bbec6a8d4e63c1cbcaba59a17ef7ca62024c3f1ab455bc6c6755baaad009a550000019d79e6101407";

#[test]
fn substrate_decodes_to_58_bytes() {
    let bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    assert_eq!(bytes.len(), SUBSTRATE_SIZE);
}

#[test]
fn substrate_version_is_v1() {
    let bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    let view = decode_substrate(&bytes).expect("decode should succeed");
    assert_eq!(view.version, 0x01);
}

#[test]
fn substrate_computation_type_is_generic_fhe() {
    let bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    let view = decode_substrate(&bytes).unwrap();
    assert_eq!(view.computation_type, ComputationType::GenericFhe);
    assert_eq!(view.computation_type.name(), "GenericFhe");
}

#[test]
fn verifier_correctly_rejects_synthetic_fixture() {
    // The sample fixture is from a parser-test in scif-backend — its
    // on_chain_hash was chosen for shape, NOT computed as
    // SHA3-256(substrate_hex). A correct verifier MUST detect this
    // mismatch. This test asserts the verifier's job-doing.
    let substrate_bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    let on_chain = hex::decode(SAMPLE_ON_CHAIN_HEX).unwrap();
    let computed = signing_message(&substrate_bytes);
    assert_ne!(
        computed[..], on_chain[..],
        "synthetic fixture's on_chain_hash should NOT match SHA3 — if this assert reverses, \
         the fixture was upgraded to real (which is fine, but then also update the test name)"
    );
}

/// Canonical Known-Answer Test for H33 Signing Substrate Spec v1.
///
/// Build the substrate from the SPEC's canonical input (per Spec v1
/// Cross-Language Implementation section), compute signing_message, and
/// hardcode the result. Any conforming verifier in any language must
/// produce these exact bytes.
///
/// NOTE: The SPEC.md text states `timestamp_ms: 1744156800000
/// (big-endian: 0x00000195F3B28800)` — that hex string is an editorial
/// errata; the actual BE encoding of 1744156800000 is 0x0000019617D8B400.
/// This test uses the numeric value as source-of-truth, builds the bytes
/// in code, and verifies against the SHA3 of THAT input. Spec v2 should
/// correct the hex string in SPEC.md.
fn canonical_kat_substrate() -> Vec<u8> {
    let mut out = Vec::with_capacity(58);
    out.push(0x01); // version
    out.push(0x01); // ComputationType::BiometricAuth
    out.extend(std::iter::repeat(0xAB).take(32)); // fhe_commitment
    out.extend(1_744_156_800_000u64.to_be_bytes()); // timestamp_ms
    out.extend(std::iter::repeat(0xCD).take(16)); // nonce
    assert_eq!(out.len(), 58);
    out
}

#[test]
fn canonical_kat_substrate_layout() {
    let bytes = canonical_kat_substrate();
    let view = decode_substrate(&bytes).expect("KAT must decode");
    assert_eq!(view.version, 0x01);
    assert_eq!(view.computation_type, ComputationType::BiometricAuth);
    assert_eq!(view.fhe_commitment, [0xAB; 32]);
    assert_eq!(view.timestamp_ms, 1_744_156_800_000);
    assert_eq!(view.nonce, [0xCD; 16]);
}

#[test]
fn canonical_kat_signing_message_is_stable() {
    // This is THE deterministic test vector for cross-language conformance.
    // Once observed, the expected hex below must never change — every future
    // verifier implementation in every language must produce the same 32 bytes.
    let bytes = canonical_kat_substrate();
    let computed = signing_message(&bytes);
    let observed_hex = hex::encode(computed);

    // Hardcoded after first observation. If this assert ever fails, either
    // (a) the SPEC's substrate layout changed (would be a breaking change
    // requiring a version bump in the substrate version byte), or (b) the
    // SHA3-256 implementation diverged from RustCrypto's. Neither should
    // happen silently.
    const EXPECTED_KAT_SIGNING_MESSAGE_HEX: &str =
        "108d7b3b6a0c46431b022432041a25b42eb2a682759724b5119a013cdea6461a";

    assert_eq!(
        observed_hex, EXPECTED_KAT_SIGNING_MESSAGE_HEX,
        "KAT signing_message diverged — spec or SHA3 changed"
    );
}

#[test]
fn receipt_is_exactly_42_bytes() {
    let bytes = hex::decode(SAMPLE_RECEIPT_HEX).unwrap();
    assert_eq!(bytes.len(), 42);
}

#[test]
fn substrate_timestamp_is_recent_millis() {
    let bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    let view = decode_substrate(&bytes).unwrap();
    // The fixture timestamp should be a reasonable millisecond unix time.
    // 1700000000000 = 2023-11-14 UTC; anything before that is suspicious for an H33-era substrate.
    assert!(view.timestamp_ms > 1_700_000_000_000);
    // And not in the far future (10 years past 2026).
    assert!(view.timestamp_ms < 2_000_000_000_000);
}

#[test]
fn substrate_nonce_is_16_bytes_nonzero() {
    let bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    let view = decode_substrate(&bytes).unwrap();
    assert_eq!(view.nonce.len(), 16);
    // A zero nonce would indicate uninitialized memory. Real attestations
    // should always have random nonces.
    assert_ne!(view.nonce, [0u8; 16]);
}

#[test]
fn decode_rejects_wrong_length() {
    let mut bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    bytes.push(0xFF);
    assert!(decode_substrate(&bytes).is_err());
    bytes.truncate(57);
    assert!(decode_substrate(&bytes).is_err());
}

#[test]
fn decode_rejects_unknown_version() {
    let mut bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    bytes[0] = 0x02;
    assert!(decode_substrate(&bytes).is_err());
}

#[test]
fn decode_rejects_unknown_computation_type() {
    let mut bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    bytes[1] = 0xAB; // not in the enum
    assert!(decode_substrate(&bytes).is_err());
}

#[test]
fn sha3_256_matches_reference() {
    // Known SHA3-256 test vector: empty input → a7ffc6f8...
    assert_eq!(
        hex::encode(sha3_256(b"")),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
    );
    // The classic abc test vector.
    assert_eq!(
        hex::encode(sha3_256(b"abc")),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
    );
}

#[test]
fn signing_message_is_just_sha3_of_substrate() {
    // The spec defines: signing_message = SHA3-256(substrate_bytes).
    // Verify the convenience function matches that identity.
    let bytes = hex::decode(SAMPLE_SUBSTRATE_HEX).unwrap();
    let via_signing_message = signing_message(&bytes);
    let via_sha3 = sha3_256(&bytes);
    assert_eq!(via_signing_message, via_sha3);
}

/// PRODUCTION receipt captured 2026-05-26 from
/// `POST https://api.h33.ai/api/v1/substrate/attest` with input data
/// `"h33-verify v0.1 production test vector 2026-05-26"`. This vector is
/// the load-bearing regression test for "real-world Mode 1 PASS" — if it
/// ever breaks, either the substrate's wire format changed (would be a
/// version-byte bump) or h33-verify's SHA3/decode diverged.
///
/// Source of truth: `tests/fixtures/real/production-anchor-2026-05-26.json`.
/// Values inlined here so the test doesn't depend on filesystem layout.
mod real_production_2026_05_26 {
    use super::*;

    const SUBSTRATE_HEX: &str = "01fff6a298ea7a07d9a951f9e42fe3ba1e13615333df03375fee17d544b36fd93d180000019e61524dd37964a4fcd9c7c1ef7c7220b37efa331e";
    const ON_CHAIN_HEX: &str = "673c3412fa861f9a928761661ef1e6e4ee5eaf93da21516c5e0b3a7eee5416cc";
    const RECEIPT_HEX: &str = "012d26fc3f5b9a602ac67f116410005b9a42c9f6d7dac273cc1183c1e4137127a60000019e61524dd307";
    const INPUT_DATA: &[u8] = b"h33-verify v0.1 production test vector 2026-05-26";

    #[test]
    fn substrate_decodes_as_generic_fhe_v1() {
        let bytes = hex::decode(SUBSTRATE_HEX).unwrap();
        let view = decode_substrate(&bytes).expect("real production substrate must decode");
        assert_eq!(view.version, 0x01);
        assert_eq!(view.computation_type, ComputationType::GenericFhe);
        assert_eq!(view.computation_type.name(), "GenericFhe");
        // Timestamp 1779749244371 = 2026-05-25T22:47:24.371Z — sanity-check it's in our era.
        assert_eq!(view.timestamp_ms, 1_779_749_244_371);
    }

    #[test]
    fn signing_message_matches_on_chain_hash() {
        // The Mode 1 verification core: SHA3-256(substrate_bytes) == on_chain_hash.
        // This is THE check the verifier exists to perform; a real production
        // receipt MUST satisfy it.
        let substrate = hex::decode(SUBSTRATE_HEX).unwrap();
        let on_chain = hex::decode(ON_CHAIN_HEX).unwrap();
        let computed = signing_message(&substrate);
        assert_eq!(computed[..], on_chain[..], "Mode 1 binding broken on real fixture");
    }

    #[test]
    fn fhe_commitment_binds_to_public_input_data() {
        // The substrate's fhe_commitment field (bytes 2..34) must equal
        // SHA3-256 of the declared input data. This is what `--data` checks.
        let bytes = hex::decode(SUBSTRATE_HEX).unwrap();
        let view = decode_substrate(&bytes).unwrap();
        let expected = sha3_256(INPUT_DATA);
        assert_eq!(view.fhe_commitment, expected, "fhe_commitment != SHA3(declared input)");
    }

    #[test]
    fn receipt_is_42_bytes() {
        assert_eq!(hex::decode(RECEIPT_HEX).unwrap().len(), 42);
    }
}
