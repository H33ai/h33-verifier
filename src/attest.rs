//! `h33-verify attest` — the H33-PQ Verified standard verification subcommand.
//!
//! Walks an attestation manifest (the discovery contract published by an
//! organization attesting itself against the H33-PQ Verified standard),
//! pulls every pillar bundle named in the manifest, structurally validates
//! each, computes SHA3-384 over the bundle bytes, and emits a per-pillar
//! report with an overall verdict.
//!
//! Brutally simple by design: no HTTP client crate. URLs are fetched via
//! the system `curl` binary as a subprocess. Local file paths are read
//! directly. This preserves the v0.2 posture of "no network call from the
//! binary, no daemon, no cloud dep" — `curl` is a separate process the
//! user can replace with any HTTP tool.
//!
//! Acceptance criteria for `overall` field:
//!   - PASS    — every pillar in the manifest has status == "VERIFIED"
//!                AND every named bundle was fetched, structurally valid,
//!                and matched its claimed SHA3-384 (when claimed).
//!   - PARTIAL — some pillars VERIFIED, others PREPARING/PENDING, no FAIL
//!   - PENDING — only the at-launch pillars (4, 5) VERIFIED
//!   - FAIL    — any pillar marked FAIL, or any fetched bundle failed
//!                structural validation, or any bundle hash mismatch.

use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_384};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Deserialize)]
pub struct Manifest {
    pub schema_version: String,
    pub cycle_id: String,
    pub standard: ManifestStandard,
    pub issuer: ManifestIssuer,
    pub pillars: Vec<ManifestPillar>,
}

#[derive(Debug, Deserialize)]
pub struct ManifestStandard {
    pub name: String,
    pub version: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ManifestIssuer {
    pub name: String,
    pub principal: String,
    pub url: String,
}

#[derive(Debug, Deserialize)]
pub struct ManifestPillar {
    pub pillar: u8,
    pub name: String,
    pub status: String,
    #[serde(default)]
    pub bundle_url: Option<String>,
    #[serde(default)]
    pub bundle_sha3_384: Option<String>,
    #[serde(default)]
    pub schema_url: Option<String>,
    pub verifier_command: String,
    #[serde(default)]
    pub notes: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct AttestReport {
    pub standard: String,
    pub standard_version: String,
    pub cycle_id: String,
    pub issuer_name: String,
    pub issuer_principal: String,
    pub manifest_source: String,
    pub pillars: Vec<PillarResult>,
    pub overall: String,
    pub overall_explanation: String,
    pub verifier_version: String,
}

#[derive(Debug, Serialize)]
pub struct PillarResult {
    pub pillar: u8,
    pub name: String,
    pub status_in_manifest: String,
    pub bundle_url: Option<String>,
    pub bundle_fetched: bool,
    pub bundle_size_bytes: Option<usize>,
    pub bundle_sha3_384_computed: Option<String>,
    pub bundle_sha3_384_claimed: Option<String>,
    pub bundle_hash_match: Option<bool>,
    pub bundle_structural_check: PillarStructuralCheck,
    pub verifier_command: String,
    pub verdict: String,
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
pub struct PillarStructuralCheck {
    pub schema_version_present: bool,
    pub schema_version_matches_expected: Option<bool>,
    pub is_json: bool,
    pub is_placeholder: bool,
}

/// Read a manifest from a local path or a URL.
/// URLs use `curl -sSL` as a subprocess. Returns the manifest body bytes.
pub fn fetch(source: &str) -> Result<Vec<u8>, String> {
    if source.starts_with("http://") || source.starts_with("https://") {
        let out = Command::new("curl")
            .args(["-sSL", "--fail", "--max-time", "20", source])
            .output()
            .map_err(|e| format!("curl execution failed: {e}"))?;
        if !out.status.success() {
            return Err(format!(
                "curl exited {} fetching {}: {}",
                out.status,
                source,
                String::from_utf8_lossy(&out.stderr).trim()
            ));
        }
        Ok(out.stdout)
    } else if let Some(p) = source.strip_prefix("file://") {
        std::fs::read(p).map_err(|e| format!("read {p}: {e}"))
    } else {
        std::fs::read(source).map_err(|e| format!("read {source}: {e}"))
    }
}

fn sha3_384_hex(bytes: &[u8]) -> String {
    let mut h = Sha3_384::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

fn expected_schema_for_pillar(pillar: u8) -> Option<&'static str> {
    match pillar {
        1 => Some("h33-pq-verified/pillar1-evidence-receipt/"),
        2 => Some("h33-pq-verified/pillar2-governance-lineage/"),
        3 => Some("h33-pq-verified/pillar3-privacy-release-readiness/"),
        _ => None,
    }
}

/// Run the attest workflow against a manifest source (path or URL).
/// Returns the AttestReport plus the overall ExitCode-equivalent boolean
/// (true = pass-with-no-failures, false = at least one FAIL).
pub fn run_attest(
    manifest_source: &str,
    verifier_version: &str,
) -> Result<(AttestReport, bool), String> {
    // 1. Fetch manifest.
    let manifest_bytes = fetch(manifest_source)?;
    let manifest: Manifest = serde_json::from_slice(&manifest_bytes)
        .map_err(|e| format!("manifest parse: {e}"))?;

    // 2. For each pillar, evaluate.
    let mut results = Vec::with_capacity(manifest.pillars.len());
    let mut any_fail = false;
    let mut any_verified = false;
    let mut all_verified = true;

    for p in &manifest.pillars {
        let mut notes = Vec::new();
        let mut bundle_fetched = false;
        let mut bundle_size_bytes: Option<usize> = None;
        let mut bundle_sha3_384_computed: Option<String> = None;
        let mut bundle_hash_match: Option<bool> = None;
        let mut structural = PillarStructuralCheck {
            schema_version_present: false,
            schema_version_matches_expected: None,
            is_json: false,
            is_placeholder: false,
        };
        let mut verdict_fail = false;

        let manifest_status_upper = p.status.to_uppercase();

        if let Some(url) = &p.bundle_url {
            match fetch(url) {
                Ok(body) => {
                    bundle_fetched = true;
                    bundle_size_bytes = Some(body.len());
                    let computed = sha3_384_hex(&body);
                    if let Some(claimed) = &p.bundle_sha3_384 {
                        let m = claimed.to_lowercase() == computed;
                        bundle_hash_match = Some(m);
                        if !m {
                            notes.push(format!(
                                "bundle SHA3-384 mismatch: claimed {} computed {}",
                                claimed, computed
                            ));
                            verdict_fail = true;
                        }
                    }
                    bundle_sha3_384_computed = Some(computed);

                    // Structural: is it JSON? Does it have a schema_version?
                    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) {
                        structural.is_json = true;
                        if let Some(sv) = v.get("schema_version").and_then(|s| s.as_str()) {
                            structural.schema_version_present = true;
                            if let Some(expected) = expected_schema_for_pillar(p.pillar) {
                                let matches = sv.starts_with(expected);
                                structural.schema_version_matches_expected = Some(matches);
                                if !matches && manifest_status_upper == "VERIFIED" {
                                    notes.push(format!(
                                        "bundle schema_version {} does not start with expected {}",
                                        sv, expected
                                    ));
                                    verdict_fail = true;
                                }
                            }
                        }
                        // Detect placeholder marker
                        if v.get("_status")
                            .and_then(|s| s.as_str())
                            .map(|s| s.contains("PENDING"))
                            .unwrap_or(false)
                        {
                            structural.is_placeholder = true;
                            if manifest_status_upper == "VERIFIED" {
                                notes.push(
                                    "bundle is a placeholder (_status: PENDING_*) but manifest says VERIFIED — inconsistent state".into()
                                );
                                verdict_fail = true;
                            } else {
                                notes.push("bundle is a placeholder; consistent with PREPARING status".into());
                            }
                        }
                    } else {
                        // Not JSON — only acceptable for binary bundle types
                        notes.push("bundle is not JSON".into());
                    }
                }
                Err(e) => {
                    notes.push(format!("bundle fetch failed: {e}"));
                    if manifest_status_upper == "VERIFIED" {
                        verdict_fail = true;
                    }
                }
            }
        } else if manifest_status_upper == "VERIFIED" && p.pillar <= 3 {
            notes.push(
                "manifest declares VERIFIED but no bundle_url provided for pillar 1/2/3".into(),
            );
            verdict_fail = true;
        } else {
            // Pillars 4 and 5 do not require a bundle file — their evidence is
            // the existence of the open-source verifier and the algorithm
            // manifest, which the substrate already exposes.
            notes.push("pillar verified by substrate, no bundle required".into());
        }

        let verdict = if verdict_fail {
            any_fail = true;
            all_verified = false;
            "FAIL".to_string()
        } else if manifest_status_upper == "VERIFIED" {
            any_verified = true;
            "PASS".to_string()
        } else if manifest_status_upper == "PREPARING" || manifest_status_upper == "PENDING" {
            all_verified = false;
            "PENDING".to_string()
        } else if manifest_status_upper == "FAIL" {
            any_fail = true;
            all_verified = false;
            "FAIL".to_string()
        } else {
            all_verified = false;
            format!("UNKNOWN_STATUS:{}", p.status)
        };

        results.push(PillarResult {
            pillar: p.pillar,
            name: p.name.clone(),
            status_in_manifest: p.status.clone(),
            bundle_url: p.bundle_url.clone(),
            bundle_fetched,
            bundle_size_bytes,
            bundle_sha3_384_computed,
            bundle_sha3_384_claimed: p.bundle_sha3_384.clone(),
            bundle_hash_match,
            bundle_structural_check: structural,
            verifier_command: p.verifier_command.clone(),
            verdict,
            notes,
        });
    }

    let (overall, explanation) = if any_fail {
        ("FAIL".to_string(), "at least one pillar failed verification".to_string())
    } else if all_verified {
        ("PASS".to_string(), "all pillars VERIFIED".to_string())
    } else if any_verified {
        let verified_count = results.iter().filter(|r| r.verdict == "PASS").count();
        let total = results.len();
        ("PARTIAL".to_string(), format!("{verified_count} of {total} pillars VERIFIED, others PREPARING/PENDING"))
    } else {
        ("PENDING".to_string(), "no pillars VERIFIED yet".to_string())
    };

    let report = AttestReport {
        standard: manifest.standard.name,
        standard_version: manifest.standard.version,
        cycle_id: manifest.cycle_id,
        issuer_name: manifest.issuer.name,
        issuer_principal: manifest.issuer.principal,
        manifest_source: manifest_source.to_string(),
        pillars: results,
        overall,
        overall_explanation: explanation,
        verifier_version: verifier_version.to_string(),
    };

    Ok((report, !any_fail))
}

/// Compute SHA3-384 of arbitrary file path (utility used by tests).
pub fn sha3_384_file(p: &Path) -> Result<String, String> {
    let bytes = std::fs::read(p).map_err(|e| format!("{e}"))?;
    Ok(sha3_384_hex(&bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha3_384_known_vector() {
        // NIST FIPS 202 KAT for empty input
        assert_eq!(
            sha3_384_hex(b""),
            "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004"
        );
    }

    #[test]
    fn manifest_parses_with_known_shape() {
        let json = r#"{
            "schema_version": "h33-pq-verified/attestation-manifest/v1.0",
            "cycle_id": "2026-Q2-001",
            "standard": {"name": "H33-PQ Verified", "version": "v1.0", "url": "https://h33.ai/standards/post-quantum-verified/"},
            "issuer": {"name": "H33.ai, Inc.", "principal": "test", "url": "https://h33.ai/"},
            "pillars": [
                {"pillar": 4, "name": "Independent Verification", "status": "VERIFIED",
                 "verifier_command": "h33-verifier --version"}
            ]
        }"#;
        let m: Manifest = serde_json::from_str(json).unwrap();
        assert_eq!(m.pillars.len(), 1);
        assert_eq!(m.pillars[0].status, "VERIFIED");
    }

    #[test]
    fn expected_schema_mapping() {
        assert!(expected_schema_for_pillar(1).is_some());
        assert!(expected_schema_for_pillar(2).is_some());
        assert!(expected_schema_for_pillar(3).is_some());
        assert!(expected_schema_for_pillar(4).is_none());
        assert!(expected_schema_for_pillar(5).is_none());
    }
}
