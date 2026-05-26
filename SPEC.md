# h33-verify — Verifier Specification v0.1

## Purpose

`h33-verify` is an independent, offline, deterministic verifier for H33-74 substrate receipts. It performs **Mode 1 verification** (commitment-binding) against the H33 Signing Substrate Specification v1.

This document defines:

1. The input JSON receipt format the CLI consumes.
2. The output JSON verification report the CLI produces.
3. The deterministic checks performed.
4. What is proven by a PASS verdict — and, critically, **what is not proven**.

## What this verifier proves (Mode 1)

A PASS verdict from `h33-verify` proves:

1. **Substrate structural validity.** The 58 bytes of `substrate_hex` decode into a v1 H33-74 substrate layout: version byte `0x01`, recognized `computation_type`, 32-byte `fhe_commitment`, 8-byte big-endian `timestamp_ms`, 16-byte `nonce`.
2. **Commitment binding.** `SHA3-256(substrate_bytes)` equals the claimed `on_chain_hash` byte-for-byte. This proves the on-chain hash is deterministically derived from the declared substrate inputs, and that neither was altered after attestation.
3. **Receipt size.** The receipt buffer is exactly 42 bytes — the canonical compact format.
4. **Optional FHE-output binding.** If `--data <file>` is provided, `SHA3-256(file_bytes)` is checked against the `fhe_commitment` field of the substrate, proving the substrate was derived from that specific FHE output.

## What this verifier does NOT prove (Mode 1)

A PASS verdict in Mode 1 explicitly does **not** prove:

1. **Post-quantum signature validity.** The receipt's binding to the three PQ families (Dilithium ML-DSA-65, FALCON-512, SPHINCS+-SHA2-128f) is committed via the 42-byte compact receipt, but verifying the signatures themselves requires the ~21 KB ephemeral signature bundle (fetched from H33 Cachee) and H33's published PQ public keys for the relevant key-generation epoch. This is Mode 2 verification, planned for v0.2.
2. **Issuer authenticity.** Anyone who can compute SHA3-256 and pack a 58-byte substrate can produce a syntactically valid receipt. PQ signature verification (Mode 2) is what cryptographically binds a receipt to H33's attestation infrastructure.
3. **Computation correctness.** The substrate commits to `SHA3-256(fhe_output)`. It does not prove that the FHE computation that produced `fhe_output` was correct, only that *this specific output* was committed at *this specific timestamp* under *this specific computation_type*.
4. **Liveness or recency.** A valid receipt could be replayed — Mode 1 doesn't verify whether the receipt was issued recently or whether the substrate has since been revoked. Liveness is an application-layer concern.

This honesty about scope is deliberate. The next version (Mode 2) closes the signature gap; Mode 1 is shipped first because deterministic SHA3-based verification with zero network dependencies is already strategically valuable for regulator, auditor, insurer, and standards-body workflows.

## Input format

The verifier accepts a JSON file with three required hex-encoded fields:

```json
{
  "on_chain_hash": "<64 hex chars — 32 bytes>",
  "receipt_hex":   "<84 hex chars — 42 bytes>",
  "substrate_hex": "<116 hex chars — 58 bytes>"
}
```

Any other fields (e.g. `_comment`, `algorithms`, `latency`) are tolerated and ignored. Trailing whitespace in hex strings is trimmed.

## Output format

The verifier emits a single JSON object to `stdout`:

```json
{
  "verifier": {
    "name": "h33-verify",
    "version": "0.1.0",
    "spec_version": "H33 Signing Substrate Spec v1",
    "deterministic": true,
    "network_required": false
  },
  "input_receipt_path": "<path>",
  "deterministic_checks": {
    "substrate_decodes": true,
    "version_byte_v1": true,
    "computation_type_recognized": true,
    "computation_type_name": "<enum name or null>",
    "signing_message_matches_on_chain_hash": true,
    "receipt_length_42": true,
    "on_chain_hash_length_32": true
  },
  "decoded_substrate": {
    "version": 1,
    "computation_type": "<enum name>",
    "fhe_commitment_hex": "<64 hex>",
    "timestamp_ms": <u64>,
    "timestamp_iso": "<ISO 8601 UTC>",
    "nonce_hex": "<32 hex>"
  },
  "optional_data_check": null | { ... },
  "verdict": "PASS" | "FAIL",
  "what_was_proven":     [ <list of strings> ],
  "what_was_not_proven": [ <list of strings> ]
}
```

`verdict` is `"PASS"` if and only if every deterministic check is true AND, if `--data` was provided, the optional FHE-binding check is also true.

## Exit codes

| Code | Meaning |
|------|---------|
| 0 | PASS |
| 1 | FAIL (at least one deterministic check failed, or `--data` mismatch) |
| 2 | Input error (couldn't read receipt file, hex decode error, etc.) |

## CLI surface

```
h33-verify verify <receipt.json>
h33-verify verify <receipt.json> --data <payload-file>
h33-verify inspect <receipt.json>
h33-verify --version
h33-verify --help
```

No subcommands beyond `verify` and `inspect`. No config file. No daemon. No environment variables consumed. No network calls (verified by the absence of a `tokio` / `reqwest` dependency in `Cargo.toml`).

## Known-Answer Test (KAT) for cross-language conformance

Any compliant verifier implementation, in any language, MUST produce the following `signing_message` when given the canonical input from H33 Signing Substrate Spec v1:

**Input substrate (58 bytes, hex):**

```
0101abababababababababababababababababababababababababababababababab
0000019617d8b400cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd
```

Field decomposition:
- `version`: `0x01`
- `computation_type`: `0x01` (BiometricAuth)
- `fhe_commitment`: `0xab` repeated 32 times
- `timestamp_ms`: `1744156800000` (= `2025-04-09T00:00:00Z`), big-endian = `0x0000019617D8B400`
- `nonce`: `0xcd` repeated 16 times

**Expected signing_message (SHA3-256 of the above, 32 bytes, hex):**

```
108d7b3b6a0c46431b022432041a25b42eb2a682759724b5119a013cdea6461a
```

This vector is the source of truth. If your implementation produces different bytes, your implementation is wrong.

(Note: the original H33 Signing Substrate Spec v1 markdown contained a hex-encoding typo for the timestamp — it stated `0x00000195F3B28800`, which is not the BE encoding of `1744156800000`. The correct encoding is `0x0000019617D8B400`, used above. Spec v1.1 should correct the markdown.)

## Production receipt vector (real-world PASS reference)

A live receipt captured from H33's production substrate at
`https://api.h33.ai/api/v1/substrate/attest` on 2026-05-26 is shipped at
`tests/fixtures/real/production-anchor-2026-05-26.json`. It was minted with
the deliberately-public input string `h33-verify v0.1 production test vector
2026-05-26` and the `generic` computation type.

The receipt's three load-bearing fields:

- `substrate_hex` (58 bytes): `01fff6a298ea7a07d9a951f9e42fe3ba1e13615333df03375fee17d544b36fd93d180000019e61524dd37964a4fcd9c7c1ef7c7220b37efa331e`
- `on_chain_hash` (32 bytes): `673c3412fa861f9a928761661ef1e6e4ee5eaf93da21516c5e0b3a7eee5416cc`
- `receipt_hex`   (42 bytes): `012d26fc3f5b9a602ac67f116410005b9a42c9f6d7dac273cc1183c1e4137127a60000019e61524dd307`

A correctly-implemented verifier MUST decode the substrate as
`version=0x01, computation_type=GenericFhe, timestamp_ms=1779749244371,
fhe_commitment=SHA3-256(declared input)`, and MUST find that
`SHA3-256(substrate_hex)` equals `on_chain_hash` byte-for-byte.

This is a public verification artifact, not a secret. Anyone can re-run the
verifier locally against it.

## Test vector reproducibility

```
$ git clone https://github.com/H33ai/h33-verifier
$ cd h33-verifier
$ cargo test --release
running 18 tests
test canonical_kat_signing_message_is_stable ... ok
test canonical_kat_substrate_layout         ... ok
[...]
test result: ok. 14 passed; 0 failed
```

Every test in `tests/integration_verify.rs` is a deterministic conformance assertion. Re-run on any platform, in any cargo version, in any year — they must continue to pass identically. If they ever diverge, either the SPEC changed (would require a substrate version bump in the version byte) or SHA3-256 diverged (would require a CVE-class crypto bug). Neither should happen silently.

## Stability commitment

- The output JSON schema is **frozen at v0.1** for the duration of the H33 Signing Substrate Spec v1 lifetime.
- Additive changes (new fields appended to the report) may occur in minor versions (v0.2, v0.3) without breaking existing consumers.
- The KAT signing_message hex is frozen forever — it is the cross-language interoperability anchor.
- The 6 deterministic check names (`substrate_decodes`, `version_byte_v1`, `computation_type_recognized`, `signing_message_matches_on_chain_hash`, `receipt_length_42`, `on_chain_hash_length_32`) are stable contract.

## Signed Verification Reports (v0.2)

`h33-verify` can wrap any verification verdict in an Ed25519-signed
envelope so the verdict itself becomes an attestable, portable artifact.
This section specifies the wire format.

### Format tag

The signed report MUST contain a top-level field:

```json
"report_format": "h33-verify-signed-report-v1"
```

Any conforming verifier MUST refuse to verify a report whose `report_format`
is not exactly `"h33-verify-signed-report-v1"`. Future versions will use
distinct tags (`...-v2`, `...-v3`) so old verifiers fail fast rather than
mis-interpret newer reports.

### Field set (v1)

A v1 signed report is a JSON object with exactly these top-level fields
(presence required unless noted):

| Field | Type | Description |
|-------|------|-------------|
| `report_format` | string | Always `"h33-verify-signed-report-v1"`. |
| `verifier` | object | Identity + version of the verifier instance that produced the report. |
| `verified_at_utc` | string | ISO 8601 UTC timestamp with millisecond precision (e.g. `"2026-05-26T00:57:24.939Z"`). |
| `receipt_input` | object | Links this report to a specific input receipt (see below). |
| `input_receipt_path` | string | Where the verifier read the receipt from (informational only — not load-bearing for verification). |
| `deterministic_checks` | object | The six v1 Mode-1 checks. |
| `decoded_substrate` | object \| null | Decoded substrate fields, when decoding succeeded; `null` otherwise. |
| `optional_data_check` | object \| null | Optional FHE-binding check; `null` when `--data` was not used. |
| `verdict` | string | `"PASS"` or `"FAIL"`. |
| `what_was_proven` | array of strings | What the verifier asserts. |
| `what_was_not_proven` | array of strings | What the verifier explicitly does NOT assert. |
| `signature` | object | The Ed25519 signature (see below). |

The `verifier` object MUST contain:

| Subfield | Type | Description |
|----------|------|-------------|
| `name` | string | Always `"h33-verify"` for this implementation. |
| `version` | string | Crate version of the verifier that produced the report. |
| `spec_version` | string | The substrate spec version this verifier targets. |
| `deterministic` | bool | Always `true` for v0.x. |
| `network_required` | bool | Always `false` for v0.x. |
| `instance_public_key` | string | 32-byte Ed25519 public key, hex-encoded (64 chars). |
| `fingerprint` | string | First 8 bytes of `SHA3-256(instance_public_key)`, hex-encoded (16 chars). |

The `receipt_input` object MUST contain:

| Subfield | Type | Description |
|----------|------|-------------|
| `on_chain_hash` | string | The 32-byte on-chain hash hex from the input receipt, trimmed. |
| `receipt_input_sha3_256` | string | `SHA3-256` over a canonical encoding of `{"on_chain_hash":..., "receipt_hex":..., "substrate_hex":...}` (each trimmed). 32 bytes hex. Ties the report to a specific receipt independent of source-file whitespace or extra fields. |

The `signature` object MUST contain:

| Subfield | Type | Description |
|----------|------|-------------|
| `algorithm` | string | Always `"ed25519"` for v1. |
| `value_hex` | string | 64-byte Ed25519 signature, hex-encoded (128 chars). |

### Canonical encoding (for signing and verification)

The signature is computed over a deterministic byte string derived from
the report's "unsigned body" — every field listed above EXCEPT
`signature`. The canonical encoding rules are:

1. **Object members sorted lexicographically by key** (byte-wise on UTF-8).
2. **No whitespace anywhere** — no spaces, tabs, or newlines between tokens.
3. **Strings escaped per RFC 8259 §7**, minimal form. `\"`, `\\`, `\b`,
   `\f`, `\n`, `\r`, `\t`, and `\uXXXX` for control characters below `0x20`.
   The optional `/` escape is NOT used.
4. **Numbers are integers**, emitted in shortest decimal form, no leading
   zeros, no trailing zeros, no exponent. Floating-point numbers are not
   used anywhere in the v1 report schema.
5. `true`, `false`, `null` are the keywords.

### Signing procedure

1. Build the unsigned body as a JSON Value with all fields except `signature`.
2. Canonical-encode it to bytes per the rules above.
3. Compute `message_hash = SHA3-256(canonical_bytes)`.
4. Sign: `signature_bytes = Ed25519_sign(secret_key, message_hash)`.
5. Attach `{"algorithm": "ed25519", "value_hex": hex(signature_bytes)}` as the `signature` field.

### Verification procedure

1. Parse the JSON. Reject if `report_format != "h33-verify-signed-report-v1"`.
2. Extract and remove the `signature` field. Reject if missing.
3. Reject if `signature.algorithm != "ed25519"`.
4. Hex-decode `signature.value_hex` (must yield 64 bytes).
5. Extract `verifier.instance_public_key` and hex-decode (must yield 32 bytes).
6. Recompute the fingerprint as `hex(SHA3-256(public_key)[..8])` and check it
   matches the report's `verifier.fingerprint`. (This is a sanity check, not
   a security boundary — the actual security boundary is the signature.)
7. Canonical-encode the unsigned body (the report minus `signature`) per the rules above.
8. Compute `message_hash = SHA3-256(canonical_bytes)`.
9. Ed25519-verify: `verify(public_key, message_hash, signature_bytes)`.
10. If all checks pass → the report is genuine; the `verdict` field
    represents what the verifier instance with that public key actually
    claimed.

### What a verified signature proves (and does not prove)

A verified signature proves:

- The signed report has not been mutated since it was signed.
- The Ed25519 public key embedded in the report signed *this exact*
  verdict-plus-context tuple.
- The verifier instance with that public key claimed `verdict` over the
  receipt identified by `receipt_input.receipt_input_sha3_256`.

It does **not** prove:

- Whether the consumer should trust the verifier instance. That is an
  out-of-band relationship (fingerprint comparison, key directory, known-
  instance list). The signature is the chain-of-custody primitive;
  identity establishment lives one layer above.
- Whether the original receipt the report attests is itself authentic.
  The report's `deterministic_checks` answer the Mode 1 question, and v0.3
  Mode 2 PQ-signature verification answers the "binds to H33" question.

### Backward compatibility

Plain `h33-verify verify` (without `--signed-report`) continues to emit the
v0.1 unsigned report format unchanged. Existing v0.1 consumers do not have
to upgrade unless they want the signed-envelope semantics.

## Versioning

| h33-verify version | H33 Signing Substrate Spec | Notes |
|--------------------|---------------------------|-------|
| 0.1.x              | v1                        | Mode 1 deterministic verification only. No PQ signature check, no signed reports. |
| 0.2.x              | v1                        | Adds Ed25519-signed verification reports. Mode 1 only on the receipt side. |
| 0.3.x (planned)    | v1                        | Adds Mode 2 — accepts user-supplied PQ signature bundle + epoch public keys, verifies Dilithium + FALCON + SPHINCS+ offline. Hybrid Ed25519+ML-DSA verifier signing co-lands. |
| 1.0.x (planned)    | v1                        | Stable surface for ecosystem use. SDK bindings in TypeScript and Python. |
