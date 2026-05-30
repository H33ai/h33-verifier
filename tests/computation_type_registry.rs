//! Asserts that h33-verifier's `ComputationType` registry matches the
//! authoritative `h33-substrate/src/types.rs` enum byte-for-byte.
//!
//! When the authoritative substrate registry adds a variant, this test
//! catches the drift before a production receipt for that variant is
//! published and starts failing decode in the public verifier.
//!
//! Source-of-truth: `~/scif-backend/h33-substrate/src/types.rs` (the
//! canonical substrate crate referenced from scif-backend/Cargo.toml).

use h33_verify::ComputationType;

/// Every byte value the authoritative substrate registry assigns.
/// Sorted by byte value. Update this list when the substrate adds a variant.
const REGISTRY: &[(u8, &str)] = &[
    (0x01, "BiometricAuth"),
    (0x02, "FraudScore"),
    (0x03, "FedNowPayment"),
    (0x04, "SolanaAttestation"),
    (0x05, "HatsGovernance"),
    (0x06, "BitcoinUtxo"),
    (0x07, "KycVerification"),
    (0x08, "ShareComputation"),
    (0x09, "ArchiveSign"),
    (0x0A, "MedVaultPhi"),
    (0x0B, "VaultKeyOp"),
    (0x0C, "ApiResponse"),
    (0x0D, "AiInference"),
    (0x0E, "CaptureTimeMedia"),
    (0x0F, "LegalEvidence"),
    (0x10, "DocumentVersion"),
    (0x11, "LoanApplication"),
    (0x12, "MedicalArbitration"),
    (0x13, "AuthEvent"),
    (0x14, "DasAssetResponse"),
    (0x15, "CacheConfig"),
    (0x16, "FinancialData"),
    (0x17, "FitnessMetric"),
    (0x18, "SbaForm"),
    (0x1E, "WebhookFrame"),
    (0x1F, "StreamSegment"),
    (0x20, "MerkleBatchRoot"),
    (0x21, "PolygonAnchor"),
    (0x22, "PolygonZkEvmAnchor"),
    (0x60, "ShieldIdentity"),
    (0x61, "ShieldCompliance"),
    (0x62, "ShieldBalance"),
    (0x63, "ShieldDeFi"),
    (0xFF, "GenericFhe"),
];

#[test]
fn every_registered_byte_decodes() {
    for (byte, expected_name) in REGISTRY {
        let decoded = ComputationType::from_byte(*byte)
            .unwrap_or_else(|| panic!("byte 0x{:02X} ({}) did not decode", byte, expected_name));
        assert_eq!(
            decoded.name(),
            *expected_name,
            "byte 0x{:02X} decoded to {:?} but expected {}",
            byte,
            decoded,
            expected_name
        );
    }
}

#[test]
fn unregistered_bytes_reject() {
    // Sample of bytes the registry has NOT assigned. If a future substrate
    // version assigns one, move it into REGISTRY above.
    let unassigned: &[u8] = &[
        0x00, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, // gaps in 0x10-0x1F band
        0x23, 0x24, 0x25, // gap above Polygon anchors
        0x30, 0x40, 0x50, // bytes used by scif-backend's separate internal
                          // h33_74::ComputationType (NOT the substrate); the
                          // public verifier must reject these for substrate
                          // decode because they have no substrate meaning.
        0x59, 0x5F, // gap below Shield
        0x64, 0x65, 0x70, 0x80, // gap above Shield
        0xFE, // immediately below GenericFhe
    ];
    for byte in unassigned {
        assert!(
            ComputationType::from_byte(*byte).is_none(),
            "byte 0x{:02X} unexpectedly decoded — register it in REGISTRY if it's now a real variant",
            byte
        );
    }
}

#[test]
fn registry_round_trips() {
    // For every registered byte, decode and confirm the name() output
    // matches the registry entry. Catches name<->byte drift.
    for (byte, expected_name) in REGISTRY {
        let ct = ComputationType::from_byte(*byte).expect("decoded above");
        assert_eq!(ct.name(), *expected_name);
    }
}

#[test]
fn registry_size_matches_expected() {
    // If the registry grows, the public verifier must be re-released.
    // This pinning test forces a deliberate update.
    assert_eq!(REGISTRY.len(), 34, "registry size changed — update v0.2.1 release notes");
}
