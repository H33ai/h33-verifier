//! Verifier instance identity — Ed25519 signing keypair management.
//!
//! Every running instance of `h33-verify` that produces signed reports has
//! an instance-scoped Ed25519 keypair. The keypair is generated once on
//! first use and persisted at:
//!
//! - `$H33_VERIFY_IDENTITY` (if set), else
//! - `$XDG_CONFIG_HOME/h33-verify/identity.json` (if set), else
//! - `$HOME/.config/h33-verify/identity.json`
//!
//! The file is written with mode `0600`. The secret key never leaves disk
//! except into the running process's memory.
//!
//! # Why per-instance keypairs and not a well-known H33 key
//!
//! The whole point of an independent verifier is that the consumer of a
//! signed report does NOT have to trust H33. If a single H33-published key
//! signed every report, the report's integrity would collapse back into
//! "trust H33" — defeating the architecture. Per-instance keypairs mean
//! each report attests to *which verifier ran the check*, separate from
//! the entity whose receipts are being verified.
//!
//! Consumers establish trust in a verifier instance's public key
//! out-of-band (fingerprint comparison, key directory, etc.). The report
//! itself embeds the public key so the signature can always be checked.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug)]
pub struct Identity {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    created_at_utc: String,
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    version: u32,
    algorithm: String,
    secret_key_hex: String,
    public_key_hex: String,
    fingerprint: String,
    created_at_utc: String,
}

#[derive(Debug)]
pub enum IdentityError {
    Io(std::io::Error),
    Decode(String),
    BadKeyLength(usize),
    UnsupportedAlgorithm(String),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "io: {e}"),
            Self::Decode(s) => write!(f, "decode: {s}"),
            Self::BadKeyLength(n) => write!(f, "bad key length: {n} bytes (expected 32)"),
            Self::UnsupportedAlgorithm(s) => write!(f, "unsupported algorithm '{s}' (only ed25519)"),
        }
    }
}

impl std::error::Error for IdentityError {}

impl From<std::io::Error> for IdentityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

impl Identity {
    /// Generate a fresh Ed25519 keypair backed by the OS RNG.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
            created_at_utc: crate::iso8601_now(),
        }
    }

    /// Sign a message; returns the 64-byte Ed25519 signature.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing_key.sign(message).to_bytes()
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn public_key_hex(&self) -> String {
        hex::encode(self.public_key_bytes())
    }

    /// First 8 bytes of SHA3-256(public_key), hex-encoded — 16 chars.
    /// Short enough to read aloud or compare visually; long enough to
    /// preclude accidental collision in practice. Not a security
    /// boundary on its own — always verify the full key for trust.
    pub fn fingerprint(&self) -> String {
        let mut h = Sha3_256::new();
        h.update(self.public_key_bytes());
        let full = h.finalize();
        hex::encode(&full[..8])
    }

    pub fn created_at_utc(&self) -> &str {
        &self.created_at_utc
    }

    /// Resolve the default identity file location.
    /// Honors `$H33_VERIFY_IDENTITY` then `$XDG_CONFIG_HOME` then `$HOME`.
    pub fn default_path() -> PathBuf {
        if let Ok(p) = std::env::var("H33_VERIFY_IDENTITY") {
            return PathBuf::from(p);
        }
        let base = std::env::var("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .ok()
            .or_else(|| std::env::var("HOME").ok().map(|h| PathBuf::from(h).join(".config")))
            .unwrap_or_else(|| PathBuf::from(".config"));
        base.join("h33-verify").join("identity.json")
    }

    /// Load an existing identity from disk.
    pub fn load(path: &Path) -> Result<Self, IdentityError> {
        let raw = fs::read_to_string(path)?;
        let file: IdentityFile =
            serde_json::from_str(&raw).map_err(|e| IdentityError::Decode(e.to_string()))?;
        if file.algorithm != "ed25519" {
            return Err(IdentityError::UnsupportedAlgorithm(file.algorithm));
        }
        let secret_bytes =
            hex::decode(&file.secret_key_hex).map_err(|e| IdentityError::Decode(e.to_string()))?;
        if secret_bytes.len() != 32 {
            return Err(IdentityError::BadKeyLength(secret_bytes.len()));
        }
        let mut sk = [0u8; 32];
        sk.copy_from_slice(&secret_bytes);
        let signing_key = SigningKey::from_bytes(&sk);
        let verifying_key = signing_key.verifying_key();
        Ok(Self {
            signing_key,
            verifying_key,
            created_at_utc: file.created_at_utc,
        })
    }

    /// Load if the file exists, otherwise generate a new identity and save it.
    /// Returns `(identity, was_newly_generated)`.
    pub fn load_or_create(path: &Path) -> Result<(Self, bool), IdentityError> {
        if path.exists() {
            Ok((Self::load(path)?, false))
        } else {
            let id = Self::generate();
            id.save(path)?;
            Ok((id, true))
        }
    }

    /// Save the identity to disk. Creates parent directories as needed.
    /// On Unix, sets file mode to 0600.
    pub fn save(&self, path: &Path) -> Result<(), IdentityError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = IdentityFile {
            version: 1,
            algorithm: "ed25519".to_string(),
            secret_key_hex: hex::encode(self.signing_key.to_bytes()),
            public_key_hex: self.public_key_hex(),
            fingerprint: self.fingerprint(),
            created_at_utc: self.created_at_utc.clone(),
        };
        let json = serde_json::to_string_pretty(&file)
            .map_err(|e| IdentityError::Decode(e.to_string()))?;
        fs::write(path, json)?;
        set_owner_only_permissions(path)?;
        Ok(())
    }
}

#[cfg(unix)]
fn set_owner_only_permissions(path: &Path) -> Result<(), IdentityError> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(0o600);
    fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_owner_only_permissions(_path: &Path) -> Result<(), IdentityError> {
    Ok(())
}

/// Verify an Ed25519 signature against an arbitrary public key. Used by
/// the report consumer to check a signed report without instantiating the
/// signer's `Identity`.
pub fn verify_ed25519(
    public_key_bytes: &[u8],
    message: &[u8],
    signature: &[u8],
) -> Result<(), String> {
    use ed25519_dalek::Verifier;
    if public_key_bytes.len() != 32 {
        return Err(format!("public key length {} (expected 32)", public_key_bytes.len()));
    }
    if signature.len() != 64 {
        return Err(format!("signature length {} (expected 64)", signature.len()));
    }
    let mut pk = [0u8; 32];
    pk.copy_from_slice(public_key_bytes);
    let verifying = VerifyingKey::from_bytes(&pk).map_err(|e| format!("pubkey parse: {e}"))?;
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(signature);
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    verifying.verify(message, &sig).map_err(|e| format!("signature check: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_identity_is_self_consistent() {
        let id = Identity::generate();
        assert_eq!(id.public_key_bytes().len(), 32);
        assert_eq!(id.public_key_hex().len(), 64);
        assert_eq!(id.fingerprint().len(), 16);
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let id = Identity::generate();
        let msg = b"the quick brown fox";
        let sig = id.sign(msg);
        let pk = id.public_key_bytes();
        verify_ed25519(&pk, msg, &sig).expect("self-roundtrip must verify");
    }

    #[test]
    fn tampered_message_fails_verify() {
        let id = Identity::generate();
        let sig = id.sign(b"original message");
        let pk = id.public_key_bytes();
        assert!(verify_ed25519(&pk, b"tampered message", &sig).is_err());
    }

    #[test]
    fn save_load_roundtrip() {
        let tmpdir = std::env::temp_dir().join(format!(
            "h33-verify-identity-{}",
            std::process::id()
        ));
        let path = tmpdir.join("identity.json");
        let id1 = Identity::generate();
        id1.save(&path).expect("save");

        let id2 = Identity::load(&path).expect("load");
        assert_eq!(id1.public_key_hex(), id2.public_key_hex());
        assert_eq!(id1.fingerprint(), id2.fingerprint());

        // Sign with id1, verify with id2's loaded key
        let msg = b"roundtrip";
        let sig = id1.sign(msg);
        verify_ed25519(&id2.public_key_bytes(), msg, &sig).expect("verify after load");

        // Clean up
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&tmpdir);
    }
}
