# Threat Model — h33-verify v0.1

This document states explicitly what `h33-verify` is designed to detect, what it cannot detect by design, and the trust assumptions any user inherits when running it.

The goal is honesty about scope. A verifier that overclaims is worse than one that doesn't exist — overclaim erodes the credibility of every other artifact in the chain.

## What the verifier is for

`h33-verify` answers exactly one question per receipt:

> Given a 74-byte H33 substrate receipt presented as JSON, does its `on_chain_hash` field equal `SHA3-256(substrate_bytes)`, and does its 58-byte substrate decode to a structurally valid v1 layout?

Optionally, with `--data <file>`:

> Does `SHA3-256(file_bytes)` equal the `fhe_commitment` field of the substrate?

That is Mode 1 verification. It is small. It is deterministic. It is the floor under everything else.

## Threats it detects (Mode 1)

| Threat | How it's detected |
|--------|-------------------|
| Substrate bytes silently mutated after attestation | `SHA3-256(substrate_bytes) != on_chain_hash` → FAIL |
| `on_chain_hash` field swapped | same — FAIL |
| Truncated or padded substrate (≠ 58 bytes) | length check → FAIL |
| Receipt padded or truncated (≠ 42 bytes) | length check → FAIL |
| Unknown spec version (substrate byte 0 ≠ `0x01`) | version gate → FAIL |
| Unrecognized `computation_type` | enum gate → FAIL |
| `--data` payload tampered or substituted | `SHA3-256(payload) != fhe_commitment` → FAIL |
| Forged "looks like a receipt" with random hex bytes | SHA3 binding fails → FAIL |

Every one of these is a deterministic check. No randomness. No network. No statefulness.

## Threats it does NOT detect (and the rationale)

### 1. Post-quantum signature validity

Mode 1 does not verify the Dilithium ML-DSA-65, FALCON-512, or SPHINCS+-SHA2-128f signatures over `signing_message`. Doing so requires the ~21 KB ephemeral signature bundle (currently in H33's Cachee, keyed by `on_chain_hash`) and H33's published PQ public keys for the receipt's key-generation epoch.

**Why deferred:** Mode 2 in v0.2 will accept those as user-supplied files (`--bundle`, `--pubkeys`) and perform the three PQ verifications offline. v0.2 closes this gap fully.

**What it means today:** a PASS verdict in v0.1 does not prove "H33 signed this." It proves "whoever assembled this receipt is internally consistent with the H33-74 substrate format." Until v0.2, signature-of-issuer is taken on faith of having fetched the receipt from a trusted H33 endpoint over TLS — *not* from the verifier itself.

### 2. Issuer authenticity (without Mode 2)

Anyone who can compute SHA3-256 and pack 58 bytes can produce a syntactically valid receipt. Mode 1 cannot tell an H33-issued receipt from a hand-crafted one. Only Mode 2 (v0.2) cryptographically binds a receipt to H33's key material.

### 3. Computation correctness

The substrate commits to `SHA3-256(fhe_output)`. The verifier confirms (with `--data`) that the claimed `fhe_output` matches the commitment. It does **not** prove the FHE computation that produced `fhe_output` was correct or that the computation was even an FHE computation. Computation correctness is the domain of the prover, not the verifier.

### 4. Liveness, recency, revocation

A valid receipt minted in March is still a valid receipt in November under Mode 1. The verifier doesn't know the current time, doesn't know if the receipt's epoch keys have been rotated, doesn't know if a downstream system marked the receipt as superseded. Liveness checks are an application-layer concern.

### 5. Replay (at the application layer)

If someone presents the same valid receipt twice for two different operations, the verifier will PASS both — that's correct behavior. Detecting replay requires application-layer state (was this `on_chain_hash` already used in this context?) which the verifier doesn't and shouldn't carry.

### 6. Side channels, supply chain, runtime tampering

The verifier is a small static binary that depends on `sha3`, `clap`, `serde`, `serde_json`, `hex`. It does not defend against:
- a compromised `sha3` crate (audit the dependency tree)
- a compromised cargo build (use signed releases, reproducible builds when those land)
- a runtime hooking your stdout/stderr to lie about the verdict (run the binary in a trusted environment)

If your threat model includes those, also build from source against pinned dependencies and run against the public KAT vector before trusting the binary.

## Trust assumptions the user inherits

Running `h33-verify` is equivalent to trusting:

1. **SHA3-256 itself.** The verifier collapses everything to that one primitive. If SHA3-256 is broken, this tool fails silently. (And so does much of modern cryptography. This is an acceptable global assumption.)
2. **The published spec** ([SPEC.md](./SPEC.md)) and the KAT vector inside it. Any conforming verifier in any language must produce the same `signing_message` bytes for the canonical input. If your local build doesn't, the build is bad — re-run `cargo test --release` before trusting it.
3. **Their own input.** The verifier does what its JSON receipt and optional `--data` file say. If the user gave it garbage, it returns FAIL honestly.

What you do **not** have to trust:

- Any H33-controlled system.
- Any H33-issued binary, key, or endpoint.
- This repository's network access (there is none).
- The continued existence of the company.

That last point is the strategic core of the design. An offline verifier survives company shutdown, API shutdown, internet isolation, and organizational distrust. The receipts you have today remain verifiable forever, by anyone, with a tool whose entire source is ~500 lines of public Rust.

## What an attacker would have to do to break a PASS

To produce a receipt that `h33-verify` would falsely report as PASS, an attacker would need:

- A collision in SHA3-256 (find substrate_bytes ≠ substrate_bytes' where SHA3-256 yields the same on_chain_hash), **or**
- A bug in this verifier's decoder/SHA3 wiring (please report — see [SECURITY.md](./SECURITY.md)).

The first is not believed feasible. The second is what the security policy exists to surface.

## What an attacker would have to do to forge "H33 issued this"

Under Mode 1 alone: nothing — Mode 1 does not check issuer. The attacker would only have to produce a structurally valid 58/32/42-byte tuple. **That is why Mode 1 PASS is not an authenticity claim.**

Under Mode 2 (v0.2): the attacker would have to forge three independent post-quantum signatures (Dilithium ML-DSA-65, FALCON-512, SPHINCS+-SHA2-128f) over the substrate's `signing_message`, all against H33's published public keys for the relevant epoch. Breaking that requires simultaneous breaks of MLWE lattices, NTRU lattices, and stateless hash signatures — three independent mathematical bets.

## v0.2 addition: signed verification reports

v0.2 adds an Ed25519 signing layer over the v0.1 verdict so the report
itself becomes a portable, attestable artifact. The threat model for that
layer:

### What the signed-report layer detects

| Threat | How |
|--------|-----|
| Verdict mutation after signing | canonical-encoding + SHA3 + Ed25519 verify all fail closed |
| Receipt-input swap (same verifier signs a different receipt and claims it was this one) | `receipt_input.receipt_input_sha3_256` is over the canonical (`on_chain_hash`, `receipt_hex`, `substrate_hex`) tuple; tampering yields a sig fail |
| Substituted verifier identity | `verifier.fingerprint` must equal `SHA3-256(instance_public_key)[..8]`; mismatch → reject |
| Algorithm-downgrade attempt | `signature.algorithm != "ed25519"` → reject |
| Format-version drift | `report_format != "h33-verify-signed-report-v1"` → reject |

### What the signed-report layer does NOT detect

- **Whether the verifier instance is trustworthy.** Anyone can generate an
  Ed25519 keypair and sign a report. The signature proves "this key
  signed this verdict" — not "this key is one you should trust." Trust
  establishment is out-of-band (fingerprint comparison, key directory,
  known-instance list, custom CA chain).
- **Whether the verifier code itself was tampered with at runtime.** A
  modified verifier binary could sign a fabricated verdict over an
  unrelated receipt. Defense: build from pinned source against the public
  KAT vector, then sign with a hardware-backed key.
- **Compromise of the identity file.** The identity file is written 0600
  but otherwise has no hardware backing in v0.2. If an attacker gains
  read access to the file, they can sign arbitrary reports as that
  verifier instance. Treat the identity file like any other long-lived
  signing key.

### Trust assumptions added by v0.2

Running `h33-verify verify --signed-report` adds these to the v0.1 list:

1. **Ed25519 itself.** Used per RFC 8032; pure-Rust implementation via
   `ed25519-dalek`, audited and widely deployed. If Ed25519 is broken,
   this layer fails (and so does much of the modern public-key
   ecosystem).
2. **`ed25519-dalek` and `rand_core` crates.** Audit the dependency tree
   if your threat model includes supply-chain compromise.
3. **Local OS entropy.** Keypair generation uses `OsRng`; if your kernel
   RNG is compromised, keys are predictable. Standard concern.

### Rotation guidance

`h33-verify keygen --force` rotates the keypair, breaking trust
relationships established with the prior public key. Consumers who
trusted the old key must re-establish trust with the new one
out-of-band. Use rotation when:

- The identity file is suspected to be compromised.
- The verifier instance is being transferred to a new operator.
- A documented operational lifecycle says it's time.

There is no automatic rotation in v0.2.

## v0.3 addition: Mode 2 PQ signature verification

v0.3 closes the "binds to H33" gap on the input side: given user-supplied
bundle bytes and a pubkeys JSON file, the verifier opens all three PQ
signatures inside the receipt offline.

### What Mode 2 detects

| Threat | How |
|--------|-----|
| Receipt forged with synthetic on_chain_hash (no real H33 signing) | All three PQ signatures fail to open against the supplied pubkeys → FAIL |
| Bundle substituted for a different receipt | `bundle.signing_message != receipt.on_chain_hash` → FAIL with "bundle is for a DIFFERENT receipt" |
| Single signature tampered (e.g., bit flip in dilithium blob) | That algorithm's `open()` fails; the other two still succeed; verdict FAIL with specific algorithm named |
| Wrong pubkeys file supplied (e.g., from a different epoch) | All three signatures fail against the wrong keys → FAIL |
| Bundle magic / version / reserved tampered | Decode-time error before any crypto runs → FAIL |

### What Mode 2 does NOT detect (and the rationale)

- **Whether the holder of the PQ secret keys is actually H33.** The
  verifier consumed the pubkeys file you supplied. If you supplied a
  pubkeys file you found in a parking lot, the signatures verify against
  those keys — Mode 2 cannot tell H33's keys from any other keys. Trust
  in pubkeys is out-of-band, typically via a signed key directory H33
  publishes and rotates.
- **Whether the keys have been compromised since the receipt was signed.**
  Mode 2 cannot distinguish "valid at signing time" from "key currently
  exposed." Out-of-band revocation lists and epoch rotation are the
  application-layer fix.
- **Replay / liveness.** Mode 2 PASS is timeless. The same bundle +
  pubkeys + receipt will PASS forever. If the receipt's semantic meaning
  is bound to a moment in time, that's an application-layer concern.

### Trust assumptions added by v0.3

Running `h33-verify verify --bundle --pubkeys` adds these to the v0.1+v0.2
list:

1. **ML-DSA-65 (FIPS 204), FALCON-512, and SPHINCS+-SHA2-128f-simple
   (FIPS 205 / SLH-DSA).** Three NIST-finalized PQ signature schemes,
   used via the RustCrypto-adjacent `pqcrypto-*` crate family. Same
   versions as the production substrate signing pipeline.
2. **The `pqcrypto-mldsa`, `pqcrypto-falcon`, `pqcrypto-sphincsplus`,
   `pqcrypto-traits` crates.** All maintained by the PQClean project,
   tracking NIST KAT vectors. Audit dependency tree if your threat model
   includes supply-chain compromise.
3. **You trust the pubkeys file you fed in.** This is the most important
   addition — see "does NOT detect" above. Establish out-of-band that the
   pubkeys are H33's actual epoch keys for the relevant epoch.

## Document scope

This threat model covers `h33-verify` v0.1.x + v0.2.x + v0.3.x. It will
be updated on each major version. See [BOUNDARY.md](./BOUNDARY.md) for
the public-vs-proprietary surface delineation.
