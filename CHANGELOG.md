# Changelog

All notable changes to `h33-verify` are documented here. The crate
adheres to [Semantic Versioning](https://semver.org); pre-1.0 minor
versions may include behavior changes within the documented surface.

## [0.2.0] — 2026-05-26

### Added

- **Verifier-signed verification reports.** New `--signed-report` flag on
  `verify` wraps the verdict in an Ed25519-signed envelope; the verifier
  instance's public key + fingerprint are embedded so consumers can verify
  the signature without contacting H33.
- **`keygen` subcommand.** Generate or rotate this verifier instance's
  Ed25519 keypair. Default location: `$XDG_CONFIG_HOME/h33-verify/identity.json`
  or `$HOME/.config/h33-verify/identity.json`. File mode `0600` on Unix.
- **`identity` subcommand.** Print this instance's public key + fingerprint
  + creation timestamp.
- **`verify-report` subcommand.** Verify a previously produced signed
  report — parses JSON, strips the signature, reconstructs the canonical
  encoding, recomputes the SHA3-256 message hash, verifies the Ed25519
  signature. Returns exit code 1 on either signature failure or a FAIL
  verdict inside a validly-signed report; exit code 0 on PASS verdict in
  a validly-signed report.
- **`h33-verify-signed-report-v1` wire format.** Documented in
  [SPEC.md](./SPEC.md) "Signed Verification Reports (v0.2)" section, with
  canonical encoding rules + signing/verification procedures so any
  conforming implementation in any language can produce/verify reports.
- **Canonical JSON encoder** (`src/canonical.rs`) — lightweight RFC 8785
  subset: sorted object keys, no whitespace, RFC 8259 §7 string escaping,
  integer-only numbers. Used for signed-report serialization.
- **Identity management** (`src/identity.rs`) — Ed25519 keypair generation
  via OsRng, deterministic SHA3-256-based fingerprinting, JSON file
  persistence with mode 0600.
- **Library entry point** `h33_verify::report::verify_receipt` — pure
  function (no I/O) that takes byte slices and returns a
  `VerificationReport`. Both the CLI and the signed-report flow use it.

### Changed

- `VerificationReport` type moved from binary into library
  (`h33_verify::report::VerificationReport`) so external Rust callers can
  drive verification programmatically.
- Dependency list grows from 5 to 7 crates: adds `ed25519-dalek` and
  `rand_core` (both for the signing layer). `sha3`, `clap`, `serde`,
  `serde_json`, `hex` unchanged.

### Documentation

- **SPEC.md** — new section "Signed Verification Reports (v0.2)" with
  format tag, field set, canonical encoding rules, signing/verification
  procedures.
- **THREAT_MODEL.md** — new section covering what the signed-report layer
  detects (verdict mutation, receipt-input swap, identity substitution,
  algorithm downgrade, format drift), what it does NOT detect (verifier
  instance trustworthiness, runtime binary tampering, identity-file
  compromise), and rotation guidance.
- **README.md** — new "Signed verification reports (v0.2)" section
  showing the four new CLI verbs end-to-end.

### Backward compatibility

- Plain `h33-verify verify` (without `--signed-report`) produces the same
  v0.1 unsigned JSON report bit-for-bit. No existing consumer needs to
  upgrade.
- The 18 v0.1 integration tests still pass identically against v0.2.
- The Cross-Language KAT vector (`108d7b3b6a0c4643…`) is unchanged.
- The production receipt fixture `tests/fixtures/real/production-anchor-2026-05-26.json`
  still PASSes against v0.2.

### Tests

- 13 new unit tests (`canonical`, `identity`, `signed_report` modules).
- 18 existing integration tests preserved.
- Total: **31 passing.**

### Not in v0.2 (deferred to v0.3)

- **Mode 2 (input-side PQ signature verification).** Accepting a
  user-supplied ephemeral signature bundle (~21 KB) and H33's published
  epoch public keys to verify Dilithium / FALCON / SPHINCS+ signatures
  over `signing_message`. Closes the "binds to H33" gap on the input side.
- **Hybrid PQ verifier signing.** Co-signing the verifier's own report
  with Ed25519 + ML-DSA-65 so the report is post-quantum forward.

## [0.1.0] — 2026-05-26 (earlier)

### Added

- Initial public release. Mode 1 offline verification of H33-74
  substrate receipts: decode the 58-byte substrate, recompute SHA3-256,
  check against the claimed `on_chain_hash`, validate the 42-byte
  compact receipt size, optionally check `--data` payload against the
  `fhe_commitment`.
- 18 deterministic integration tests, including the Cross-Language KAT
  vector and a real production receipt captured from
  `api.h33.ai/api/v1/substrate/attest`.
- `SECURITY.md`, `THREAT_MODEL.md`, `BOUNDARY.md` governance documents.
- Apache-2.0 license.

[0.2.0]: https://github.com/H33ai/h33-verifier/releases/tag/v0.2.0
[0.1.0]: https://github.com/H33ai/h33-verifier/releases/tag/v0.1.0
