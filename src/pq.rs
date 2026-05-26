//! Post-quantum signature verification — Mode 2.
//!
//! Three independent verifications, each against an independent NIST-
//! finalized hardness assumption:
//!
//! - **ML-DSA-65** (FIPS 204 / Dilithium3) — module lattices.
//! - **FALCON-512** — NTRU lattices + Fast Fourier sampling.
//! - **SPHINCS+-SHA2-128f-simple** (FIPS 205 / SLH-DSA) — stateless hash
//!   signatures.
//!
//! Forgery requires simultaneously breaking all three families. This is
//! the property that makes a Mode 2 PASS "binds to H33" — anyone with
//! H33's epoch public keys can confirm offline.
//!
//! All three pqcrypto crates expose `open(&signed_message, &public_key)`
//! which takes the pqcrypto-canonical `sig || msg` format (= our bundle's
//! signed-message blobs) and returns the original message bytes on success.

use pqcrypto_traits::sign::{PublicKey as PqPk, SignedMessage as PqSm};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Dilithium,
    Falcon,
    Sphincs,
}

impl Algorithm {
    pub fn name(self) -> &'static str {
        match self {
            Self::Dilithium => "ML-DSA-65",
            Self::Falcon => "FALCON-512",
            Self::Sphincs => "SPHINCS+-SHA2-128f-simple",
        }
    }
}

#[derive(Debug)]
pub enum PqError {
    KeyParseFailed { algorithm: Algorithm, reason: String },
    SignedMessageParseFailed { algorithm: Algorithm, reason: String },
    SignatureInvalid { algorithm: Algorithm },
    OpenedMessageMismatch { algorithm: Algorithm, opened_len: usize },
}

impl std::fmt::Display for PqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyParseFailed { algorithm, reason } => {
                write!(f, "{} public key parse failed: {reason}", algorithm.name())
            }
            Self::SignedMessageParseFailed { algorithm, reason } => {
                write!(f, "{} signed-message parse failed: {reason}", algorithm.name())
            }
            Self::SignatureInvalid { algorithm } => {
                write!(f, "{} signature does not verify against the supplied public key", algorithm.name())
            }
            Self::OpenedMessageMismatch { algorithm, opened_len } => {
                write!(
                    f,
                    "{} signature opened to a {opened_len}-byte message, but Mode 2 requires exactly the 32-byte signing_message — bundle is malformed or the signing_message does not match",
                    algorithm.name()
                )
            }
        }
    }
}

impl std::error::Error for PqError {}

/// Verify ML-DSA-65 over a signed message. Returns Ok(()) iff the
/// signature opens to exactly the expected `signing_message` bytes.
pub fn verify_dilithium(
    signed_message: &[u8],
    public_key_bytes: &[u8],
    expected_signing_message: &[u8; 32],
) -> Result<(), PqError> {
    use pqcrypto_mldsa::mldsa65;
    let pk = mldsa65::PublicKey::from_bytes(public_key_bytes).map_err(|e| {
        PqError::KeyParseFailed { algorithm: Algorithm::Dilithium, reason: e.to_string() }
    })?;
    let sm = mldsa65::SignedMessage::from_bytes(signed_message).map_err(|e| {
        PqError::SignedMessageParseFailed { algorithm: Algorithm::Dilithium, reason: e.to_string() }
    })?;
    let opened = mldsa65::open(&sm, &pk)
        .map_err(|_| PqError::SignatureInvalid { algorithm: Algorithm::Dilithium })?;
    check_opened(Algorithm::Dilithium, &opened, expected_signing_message)
}

/// Verify FALCON-512 over a signed message.
pub fn verify_falcon(
    signed_message: &[u8],
    public_key_bytes: &[u8],
    expected_signing_message: &[u8; 32],
) -> Result<(), PqError> {
    use pqcrypto_falcon::falcon512;
    let pk = falcon512::PublicKey::from_bytes(public_key_bytes).map_err(|e| {
        PqError::KeyParseFailed { algorithm: Algorithm::Falcon, reason: e.to_string() }
    })?;
    let sm = falcon512::SignedMessage::from_bytes(signed_message).map_err(|e| {
        PqError::SignedMessageParseFailed { algorithm: Algorithm::Falcon, reason: e.to_string() }
    })?;
    let opened = falcon512::open(&sm, &pk)
        .map_err(|_| PqError::SignatureInvalid { algorithm: Algorithm::Falcon })?;
    check_opened(Algorithm::Falcon, &opened, expected_signing_message)
}

/// Verify SPHINCS+-SHA2-128f-simple over a signed message.
pub fn verify_sphincs(
    signed_message: &[u8],
    public_key_bytes: &[u8],
    expected_signing_message: &[u8; 32],
) -> Result<(), PqError> {
    use pqcrypto_sphincsplus::sphincssha2128fsimple as sph;
    let pk = sph::PublicKey::from_bytes(public_key_bytes).map_err(|e| {
        PqError::KeyParseFailed { algorithm: Algorithm::Sphincs, reason: e.to_string() }
    })?;
    let sm = sph::SignedMessage::from_bytes(signed_message).map_err(|e| {
        PqError::SignedMessageParseFailed { algorithm: Algorithm::Sphincs, reason: e.to_string() }
    })?;
    let opened = sph::open(&sm, &pk)
        .map_err(|_| PqError::SignatureInvalid { algorithm: Algorithm::Sphincs })?;
    check_opened(Algorithm::Sphincs, &opened, expected_signing_message)
}

fn check_opened(
    algorithm: Algorithm,
    opened: &[u8],
    expected: &[u8; 32],
) -> Result<(), PqError> {
    if opened.len() != 32 {
        return Err(PqError::OpenedMessageMismatch {
            algorithm,
            opened_len: opened.len(),
        });
    }
    if opened != expected.as_slice() {
        return Err(PqError::SignatureInvalid { algorithm });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pqcrypto_traits::sign::{PublicKey as PqPkTest, SignedMessage as PqSmTest};

    fn sign_dil(msg: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        use pqcrypto_mldsa::mldsa65;
        let (pk, sk) = mldsa65::keypair();
        let sm = mldsa65::sign(msg, &sk);
        (sm.as_bytes().to_vec(), pk.as_bytes().to_vec())
    }

    fn sign_fal(msg: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        use pqcrypto_falcon::falcon512;
        let (pk, sk) = falcon512::keypair();
        let sm = falcon512::sign(msg, &sk);
        (sm.as_bytes().to_vec(), pk.as_bytes().to_vec())
    }

    fn sign_sph(msg: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
        use pqcrypto_sphincsplus::sphincssha2128fsimple as sph;
        let (pk, sk) = sph::keypair();
        let sm = sph::sign(msg, &sk);
        (sm.as_bytes().to_vec(), pk.as_bytes().to_vec())
    }

    #[test]
    fn dilithium_roundtrip_pass() {
        let msg = [0x42; 32];
        let (sm, pk) = sign_dil(&msg);
        verify_dilithium(&sm, &pk, &msg).expect("self-roundtrip must verify");
    }

    #[test]
    fn falcon_roundtrip_pass() {
        let msg = [0x42; 32];
        let (sm, pk) = sign_fal(&msg);
        verify_falcon(&sm, &pk, &msg).expect("self-roundtrip must verify");
    }

    #[test]
    fn sphincs_roundtrip_pass() {
        let msg = [0x42; 32];
        let (sm, pk) = sign_sph(&msg);
        verify_sphincs(&sm, &pk, &msg).expect("self-roundtrip must verify");
    }

    #[test]
    fn dilithium_tampered_msg_fails() {
        let msg = [0x42; 32];
        let other = [0x99; 32];
        let (sm, pk) = sign_dil(&msg);
        assert!(verify_dilithium(&sm, &pk, &other).is_err());
    }

    #[test]
    fn falcon_tampered_sig_fails() {
        let msg = [0x42; 32];
        let (mut sm, pk) = sign_fal(&msg);
        // Flip a high-entropy byte inside the signature region.
        sm[0] ^= 0xFF;
        assert!(verify_falcon(&sm, &pk, &msg).is_err());
    }

    #[test]
    fn sphincs_wrong_pubkey_fails() {
        let msg = [0x42; 32];
        let (sm, _pk) = sign_sph(&msg);
        // Different keypair → wrong pubkey for this signature.
        let (_, other_pk) = sign_sph(&msg);
        // Either parse fails or verify fails — both acceptable; we just
        // require it does NOT succeed.
        assert!(verify_sphincs(&sm, &other_pk, &msg).is_err());
    }
}
