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

- Five dependencies (`sha3`, `clap`, `serde`, `serde_json`, `hex`).
- Single static binary, tiny, auditable.
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

## License

Apache-2.0. Permissive on purpose — anyone who wants to build a competing verifier should be able to start from this one.
