# h33-verify

**Independent, offline, deterministic verifier for H33-74 substrate receipts.**

```
$ h33-verify verify ./receipt.json
{
  "verdict": "PASS",
  "what_was_proven": [
    "Substrate bytes decode to a structurally valid v1 H33-74 substrate layout...",
    "SHA3-256(substrate_bytes) equals the claimed on_chain_hash byte-for-byte.",
    "Receipt buffer is the canonical 42-byte compact format."
  ],
  ...
}
```

## What it does

Given a 74-byte H33 substrate receipt (32 bytes on-chain + 42 bytes compact), `h33-verify` reconstructs the 58-byte substrate, recomputes `SHA3-256`, and checks that it equals the receipt's claimed on-chain hash.

> **Relationship to `h33-replay-verify`:** `h33-verify` validates individual H33-74 receipt commitments. `h33-replay-verify` (separate tool) validates full replay bundles: actions, proofs, frames, continuity roots, and case-level consistency. Use this tool when you have a single receipt; use `h33-replay-verify` when you have a full case replay.

No network. No daemon. No config. No H33 dependency. Just SHA3 and the [published spec](./SPEC.md).

## Why it exists

H33-74 receipts only matter if anyone — your auditor, your insurer, your regulator, a competing implementation — can verify them without trusting H33's infrastructure. This binary is that verifier.

It is intentionally minimal:

- Eleven dependencies in v0.3 (`sha3`, `clap`, `serde`, `serde_json`, `hex`, `ed25519-dalek`, `rand_core`, `pqcrypto-mldsa`, `pqcrypto-falcon`, `pqcrypto-sphincsplus`, `pqcrypto-traits`). The four pqcrypto crates carry NIST-finalized PQ signature verification; same crate versions as the production substrate signer.
- Single binary, auditable.
- JSON-first output, machine-readable by default.
- Tells you honestly what it proved — and what it did *not* prove.

## Install

```
cargo install --git https://github.com/H33ai/h33-verifier
```

Or build from source:

```
git clone https://github.com/H33ai/h33-verifier
cd h33-verifier
cargo build --release
./target/release/h33-verify --help
```

## Use

### Verify a receipt

```
h33-verify verify ./receipt.json
```

Exits `0` on PASS, `1` on FAIL, `2` on input error. The verification report goes to stdout as JSON.

### Verify and bind to original payload

```
h33-verify verify ./receipt.json --data ./payload.bin
```

This additionally checks that `SHA3-256(payload.bin)` equals the substrate's `fhe_commitment` field. Use this to prove a specific receipt was derived from a specific payload.

### Inspect a receipt without verifying

```
h33-verify inspect ./receipt.json
```

Just decodes the 58-byte substrate and prints its fields. Useful for debugging or for archival summaries.

### Mode 2 — offline PQ signature verification (v0.3)

The receipt's `on_chain_hash` is a commitment over a 58-byte substrate. The substrate's signing_message is signed by H33 with three independent post-quantum algorithms (ML-DSA-65, FALCON-512, SPHINCS+-SHA2-128f-simple). Mode 2 lets anyone verify those three signatures locally:

```
# Mode 1 only (default — backwards compatible)
h33-verify verify ./receipt.json

# Mode 1 + Mode 2 — also opens the three PQ signatures
h33-verify verify ./receipt.json \
    --bundle  ./bundle.bin \
    --pubkeys ./pubkeys-2026-04-11.json
```

`--bundle` and `--pubkeys` must be supplied together. One without the other is a hard error.

Inputs are user-supplied files — no network call, no H33 trust. The verifier crate has zero runtime dependency on H33 infrastructure. The bundle comes from `GET /api/v1/substrate/attestations/:id/bundle` on the substrate (content-addressable via the `bundle_hash` returned alongside the `/attest` response). The pubkeys file is published by H33 per key-generation epoch. Both are public verification material with no embedded secrets.

A Mode 2 PASS adds three new things to what the report proves:
- The ML-DSA-65 signature in the bundle opens to the receipt's signing_message under the dilithium public key you supplied.
- Same for FALCON-512 under the falcon public key.
- Same for SPHINCS+-SHA2-128f-simple under the sphincs public key.
- The bundle's embedded signing_message equals the receipt's on_chain_hash — the bundle is for *this* receipt and no other.

Forgery requires simultaneously breaking all three NIST-finalized hardness assumptions (module lattices, NTRU lattices, and stateless hash signatures). This is the "binds to H33" cryptographic closure.

What Mode 2 still doesn't prove: that the holder of the dilithium/falcon/sphincs secret keys *is* H33. Trust in the supplied pubkeys file is out-of-band — typically by checking that the pubkeys file came from H33's signed key directory for the relevant epoch.

### Signed verification reports (v0.2)

Make the verdict itself an attestable artifact — a regulator-grade chain-of-custody record signed by the verifier instance:

```
# One-time: generate this verifier instance's Ed25519 keypair
h33-verify keygen

# Show this instance's public key + fingerprint
h33-verify identity

# Verify a receipt AND sign the verdict with this instance's key
h33-verify verify ./receipt.json --signed-report > attested.json

# Verify a signed report later (anyone, anywhere, no network)
h33-verify verify-report ./attested.json
```

`attested.json` includes:

- the full v0.1 verdict (`deterministic_checks`, `decoded_substrate`, `verdict`, etc.)
- a `verified_at_utc` timestamp
- a `receipt_input` block linking the report to a specific receipt by SHA3-256 of its three canonical fields
- the verifier instance's public key + fingerprint
- an Ed25519 signature over a canonical JSON encoding of all the above

Tamper any field — the verdict, the timestamp, the public key, anything — and `verify-report` returns a signature failure with a clear error message.

The verifier identity is persisted at `$H33_VERIFY_IDENTITY` if set, else `$XDG_CONFIG_HOME/h33-verify/identity.json`, else `$HOME/.config/h33-verify/identity.json`. The file is written with mode `0600`. Per-instance keypairs are intentional — each running verifier is its own attestable entity, so a signed report tells the consumer *which verifier ran the check* separate from the entity whose receipts are being checked. Consumers establish trust in a verifier instance's public key out-of-band (key directory, fingerprint comparison, known-instance list).

## Receipt format

A receipt is a JSON file with three required hex fields:

```json
{
  "on_chain_hash": "<64 hex chars — 32 bytes>",
  "receipt_hex":   "<84 hex chars — 42 bytes>",
  "substrate_hex": "<116 hex chars — 58 bytes>"
}
```

Other fields (timestamps, algorithm metadata, comments) are ignored.

## What a PASS proves

1. The 58-byte substrate decodes to a valid v1 layout.
2. `SHA3-256(substrate_bytes) == on_chain_hash` byte-for-byte.
3. The 42-byte receipt is the canonical compact size.
4. (Optional, with `--data`) `SHA3-256(payload) == substrate.fhe_commitment`.

## What a PASS does NOT prove

1. **PQ signature validity** — verifying the Dilithium / FALCON / SPHINCS+ signatures over `signing_message` requires the 21 KB ephemeral bundle and H33's public keys. That's Mode 2, planned for v0.2.
2. **Issuer authenticity** — anyone can SHA3 some bytes and produce a syntactically valid receipt. Mode 2 binds it cryptographically to H33.
3. **Computation correctness** — the substrate commits to a hash, not to the truth of the FHE computation that produced it.

The verifier prints both lists in every report. This honesty is by design — verifiers that overclaim are worse than ones that don't exist.

## Try it against a real production receipt

The repo ships with a real receipt captured from H33's production substrate at `api.h33.ai`:

```
$ h33-verify verify tests/fixtures/real/production-anchor-2026-05-26.json
{ "verdict": "PASS", ... }

$ h33-verify verify tests/fixtures/real/production-anchor-2026-05-26.json \
    --data    tests/fixtures/real/production-anchor-2026-05-26.input
{ "verdict": "PASS", "optional_data_check": { "fhe_commitment_matches": true, ... } }
```

This fixture is a *public verification artifact*, not a secret — it contains only the substrate hex, the on-chain SHA3, the compact receipt, and the deliberately-public input string used to mint it. Captured by curl to `POST /api/v1/substrate/attest` with `{"data": "h33-verify v0.1 production test vector 2026-05-26", "type": "generic"}`. Any third party can re-run the verifier locally, decode the substrate, recompute SHA3, and reach the same PASS verdict without trusting H33's infrastructure for anything beyond the SHA3-256 standard itself.

## Specification

See [SPEC.md](./SPEC.md) for the input/output schemas, exit codes, KAT vector, and stability commitments.

The H33 Signing Substrate Specification v1 itself is published with the H33 substrate crate.

## Security, threat model, public/proprietary boundary

- [SECURITY.md](./SECURITY.md) — how to report a vulnerability, what's in scope, disclosure timeline.
- [THREAT_MODEL.md](./THREAT_MODEL.md) — what the verifier detects, what it explicitly does not, and the trust assumptions a user inherits.
- [BOUNDARY.md](./BOUNDARY.md) — what's public (this verifier, the spec, receipts, replay tooling, SDKs) vs proprietary (signing pipeline, FHE engines, STARK provers, orchestration, infrastructure). The principle: **verification is public, computation is proprietary.**

## License

Apache-2.0. Permissive on purpose — anyone who wants to build a competing verifier should be able to start from this one.
