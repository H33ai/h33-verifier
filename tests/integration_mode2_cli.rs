//! End-to-end CLI test for Mode 2: spawn the built binary against a
//! self-generated bundle + pubkeys + receipt fixture and assert PASS.
//!
//! The fixture is built in-process at test time using the same pqcrypto
//! crates the production substrate uses, so signatures are real (not
//! mocked) — what differs from a production receipt is the key material
//! (we keep the secrets local) and the substrate's `fhe_commitment` /
//! timestamp / nonce (we craft them deterministically). The signature
//! verification logic exercised is identical to what runs against
//! production receipts.

use std::process::Command;

fn h33_verify_binary() -> std::path::PathBuf {
    // tests/ runs from the workspace root; CARGO_BIN_EXE_<bin> points at
    // the release/debug binary cargo just built.
    std::path::PathBuf::from(env!("CARGO_BIN_EXE_h33-verify"))
}

fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("h33-verify-mode2-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn build_self_generated_fixture() -> (std::path::PathBuf, std::path::PathBuf, std::path::PathBuf, std::path::PathBuf) {
    use h33_verify::{bundle, sha3_256, ComputationType, SUBSTRATE_VERSION};
    use pqcrypto_falcon::falcon512;
    use pqcrypto_mldsa::mldsa65;
    use pqcrypto_sphincsplus::sphincssha2128fsimple as sph;
    use pqcrypto_traits::sign::{PublicKey as PqPk, SignedMessage as PqSm};

    // Synthetic substrate: version + GenericFhe + 0xAA commitment + ts + 0xBB nonce.
    let mut substrate = Vec::with_capacity(58);
    substrate.push(SUBSTRATE_VERSION);
    substrate.push(0xFF); // GenericFhe
    substrate.extend_from_slice(&[0xAA; 32]);
    substrate.extend_from_slice(&1_700_000_000_000u64.to_be_bytes());
    substrate.extend_from_slice(&[0xBB; 16]);
    assert_eq!(substrate.len(), 58);

    let signing_message = sha3_256(&substrate);
    let on_chain_hash_hex = hex::encode(signing_message);

    // Sign with all three PQ algorithms.
    let (dpk, dsk) = mldsa65::keypair();
    let dsm = mldsa65::sign(&signing_message, &dsk);
    let (fpk, fsk) = falcon512::keypair();
    let fsm = falcon512::sign(&signing_message, &fsk);
    let (spk, ssk) = sph::keypair();
    let ssm = sph::sign(&signing_message, &ssk);

    let bundle_bytes = bundle::build(
        &signing_message,
        dsm.as_bytes(),
        fsm.as_bytes(),
        ssm.as_bytes(),
    );

    // Fake compact receipt (size 42, doesn't matter for Mode 2 — Mode 1 only checks length).
    let receipt = vec![0xCC; 42];

    // Receipt JSON
    let receipt_json = format!(
        r#"{{
            "on_chain_hash": "{}",
            "receipt_hex":   "{}",
            "substrate_hex": "{}",
            "_comment": "self-generated test vector — exercises Mode 1 + Mode 2 end-to-end"
        }}"#,
        on_chain_hash_hex,
        hex::encode(&receipt),
        hex::encode(&substrate),
    );

    // Pubkeys JSON
    let pubkeys_json = format!(
        r#"{{
            "format": "h33-substrate-pubkeys-v1",
            "epoch_id": "self-generated-test-fixture",
            "epoch": "test",
            "issued_at_utc": "2024-01-01T00:00:00Z",
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

    let receipt_path = write_tmp("receipt.json", receipt_json.as_bytes());
    let bundle_path = write_tmp("bundle.bin", &bundle_bytes);
    let pubkeys_path = write_tmp("pubkeys.json", pubkeys_json.as_bytes());
    let tampered_bundle_path = {
        let mut b = bundle_bytes.clone();
        b[44] ^= 0xFF; // flip a byte inside the dilithium signed_message
        write_tmp("tampered_bundle.bin", &b)
    };

    (receipt_path, bundle_path, pubkeys_path, tampered_bundle_path)
}

#[test]
fn mode2_cli_self_generated_pass() {
    let (receipt, bundle, pubkeys, _) = build_self_generated_fixture();
    let output = Command::new(h33_verify_binary())
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
            "--pubkeys",
            pubkeys.to_str().unwrap(),
        ])
        .output()
        .expect("h33-verify must run");

    assert!(output.status.success(), "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr));

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"verdict\": \"PASS\""), "expected verdict PASS:\n{stdout}");
    assert!(stdout.contains("\"mode_2_check\""), "report must include mode_2_check:\n{stdout}");
    assert!(stdout.contains("\"dilithium_signature_verifies\": true"));
    assert!(stdout.contains("\"falcon_signature_verifies\": true"));
    assert!(stdout.contains("\"sphincs_signature_verifies\": true"));
}

#[test]
fn mode2_cli_tampered_bundle_fails() {
    let (receipt, _, pubkeys, tampered_bundle) = build_self_generated_fixture();
    let output = Command::new(h33_verify_binary())
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--bundle",
            tampered_bundle.to_str().unwrap(),
            "--pubkeys",
            pubkeys.to_str().unwrap(),
        ])
        .output()
        .expect("h33-verify must run");

    // Tampered bundle → exit code 1
    assert_eq!(
        output.status.code(),
        Some(1),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"verdict\": \"FAIL\""));
    assert!(stdout.contains("\"dilithium_signature_verifies\": false"));
}

#[test]
fn mode2_cli_asymmetric_flags_hard_error() {
    let (receipt, bundle, _, _) = build_self_generated_fixture();
    // --bundle alone (no --pubkeys) must be hard error, exit 2.
    let output = Command::new(h33_verify_binary())
        .args([
            "verify",
            receipt.to_str().unwrap(),
            "--bundle",
            bundle.to_str().unwrap(),
        ])
        .output()
        .expect("h33-verify must run");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--bundle requires --pubkeys"));
}

#[test]
fn mode2_cli_no_flags_still_runs_mode1_only() {
    // Backwards compat: when neither --bundle nor --pubkeys is passed, the
    // verifier runs Mode 1 unchanged. The mode_2_check field must be null.
    let (receipt, _, _, _) = build_self_generated_fixture();
    let output = Command::new(h33_verify_binary())
        .args(["verify", receipt.to_str().unwrap()])
        .output()
        .expect("h33-verify must run");

    // Receipt is self-generated and Mode 1 may FAIL because we used a
    // 0xCC-filled receipt buffer (size 42, fine) but no synthetic
    // signing_message check matters here — let's just check exit code
    // is 0 or 1 (not 2), and that mode_2_check is null.
    assert!(matches!(output.status.code(), Some(0) | Some(1)));
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\"mode_2_check\": null"));
}
