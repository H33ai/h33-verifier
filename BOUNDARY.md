# Public / Proprietary Boundary

H33 deliberately separates *verification* from *computation*. This document states which side of that boundary each artifact sits on.

The principle is simple:

> **Verification is public. Computation is proprietary.**

Anyone — auditor, regulator, insurer, researcher, competing vendor, AI agent, the public — can validate the bytes H33 produces, without permission, without a sales conversation, and without the company's continued existence. The *operational system that produces those bytes at scale* is the moat.

This is the opposite of the common pattern where verifiers are hidden because the verifier would expose how weak the underlying guarantees are. Here, the verifier is open precisely because the guarantees are strong enough to survive being looked at.

## Public surface

These exist on GitHub under permissive licenses (Apache-2.0 for this verifier). Anyone may inspect, copy, audit, fork, mirror, or build derivative tooling without H33 permission.

| Artifact | Where | Purpose |
|----------|-------|---------|
| `h33-verify` CLI + library | this repo | Offline Mode 1 receipt verification; offline Mode 2 in v0.2 |
| H33 Signing Substrate Specification v1 | [SPEC.md](./SPEC.md) | Wire format definition, byte layouts, KAT vector |
| Cross-Language KAT vector | [SPEC.md](./SPEC.md) — "Known-Answer Test" section | The 32-byte `signing_message` any conforming verifier in any language must reproduce |
| Real production receipt fixture | `tests/fixtures/real/production-anchor-2026-05-26.json` | Live PASS reference — anyone can re-run verification and reach identical verdict |
| Receipts emitted by `api.h33.ai/api/v1/substrate/attest` | the wire | The 58/32/42 bytes are by-design publicly observable |
| Future: replay tooling (`h33-replay-verify`) | (separate repo, planned) | Full case-level replay-bundle verification |
| Future: SDKs in Python, TypeScript, Go | (planned, post-v1.0) | Language bindings that conform to the same KAT |
| Future: prebuilt binaries + Homebrew tap | GitHub Releases | Convenience distribution; reproducible from source |
| `H33ai/h33-commerce` SDK | <https://github.com/H33ai/h33-commerce> | Public client for H33's commerce endpoints |

Receipts the user already holds are also public by definition — they're the user's own evidence to do with as they please.

## Proprietary surface (intentionally)

These are not published. They are where H33's operational engineering and patent claims live. Auditing them happens under NDA on commercial engagement; verifying their *outputs* does not require any of that.

| Layer | What it is | Why proprietary |
|-------|------------|-----------------|
| **Post-quantum signing pipeline** | Production Dilithium ML-DSA-65, FALCON-512, SPHINCS+-SHA2-128f signing under Graviton4 tuning | Performance + key-management infrastructure |
| **FHE engines** | BFV-128, BFV-256, BFV-32, CKKS variants, the FHE-IQ auto-router | Patent claims on multiple operations; performance moat |
| **STARK provers** | Lookup STARK, AIR STARK, future STARK-IQ | Patent claims; performance moat |
| **Substrate attestation orchestration** | The service behind `api.h33.ai/api/v1/substrate/attest` — substrate construction, ephemeral signature bundling, compression to 42 bytes, Cachee storage, response-middleware integration | Patent claims (incl. claims 124-125 on batched Merkle response attestation); operational topology |
| **Cachee** | The PQ-attested cache layer that holds ephemeral signature bundles + every API response | Patent claims; performance characteristics |
| **Biometric pipeline** | FHE biometric matching, template handling, the 128-bit security envelope | Patent claims; raw biometrics never leave the encrypted boundary |
| **Replay infrastructure** | The proving + replay-bundle generation systems behind `h33-replay-verify` outputs | Operational; the *verifier* of replay bundles is public, the *generator* is not |
| **Production keys, rotation, HSMs** | All cryptographic key material in production, rotation schedules, hardware-security-module integrations | Standard practice |
| **Production infrastructure** | EC2 topology, internal hostnames, AWS resource IDs, RDS credentials, IAM, secrets management | Standard practice |

These artifacts live in private GitLab (`gitlab.com/drata5764111/h33/*`) and are not mirrored to GitHub.

## Boundary rationale (why this split)

Public wire formats do not destroy defensibility — they create it. Compare:

- TLS is public. Cloudflare's operational TLS infrastructure is the moat.
- JWT is public. Auth0's identity orchestration is the moat.
- QUIC is public. Google's QUIC deployment scale is the moat.
- OAuth is public. Okta's enterprise integration is the moat.

In each case the *protocol* became infrastructure because independent verifiers, third-party tooling, regulators, and competitors could all read the bytes. The *operationalization* — running it at scale, integrating it, sustaining it, optimizing it, supporting it commercially — is where defensibility lives.

H33 follows the same pattern. Receipt format, verifier, replay tool, SDKs — public. Production signing, FHE, STARK, orchestration, infrastructure — proprietary.

## What this means for users

- **Auditors:** every claim H33 makes about a receipt is independently checkable by you, against open code, with no H33 access required. Run `h33-verify` on receipts your customer hands you. Disagree with the verdict? Read the source.
- **Regulators:** you can run the verifier in your own sandboxed environment. You don't have to trust H33's infrastructure for the verification step. The KAT vector is the deterministic conformance anchor — any implementation that passes the KAT is a conformant verifier, including ones you commission.
- **Enterprises evaluating H33:** the verifier surface is the artifact you should ask your security team to review. Everything else is normal commercial engineering and is happy to be discussed under NDA.
- **Researchers / OSS community:** fork the verifier, mirror it, port it, write a TypeScript implementation, submit conformance failures to GitHub Issues. None of this requires H33 permission.
- **AI agents:** every public file in this repo is intentionally machine-readable. Both `SPEC.md` and `THREAT_MODEL.md` are written to be parsed and reasoned about; the KAT vector is intended to be re-executed by independent implementations.

## What this does NOT mean

- The proprietary side is not "hidden because something is wrong with it." It is private because the operational system *running at scale* is the commercial product. The cryptographic primitives it composes are themselves NIST-standardized or peer-reviewed (ML-DSA, FALCON, SLH-DSA, SHA3, BFV, CKKS, STARK). H33 doesn't ship novel crypto behind the boundary — it ships an operational system built on standard crypto, plus the patent claims around how that system is constructed and orchestrated.
- "Public verifier" does not mean "no obligations." Receipts that contain references to private personal data, regulated material, or commercial confidence remain subject to the normal handling rules of those domains. The verifier checks bytes; it does not authorize their distribution.
- "Proprietary computation" does not mean "unverifiable." That is the entire point of the architecture. Computation runs on the proprietary side; *evidence of computation* (substrates, receipts, replay bundles) crosses the boundary to the public side and is verified there.

## Change control on this boundary

Moving an artifact from proprietary to public, or vice versa, requires:

- Explicit written approval from the H33 CEO.
- An update to this document in the same commit as the move.
- An accompanying note in the changelog of whichever side gained the artifact.

This is to prevent gradual drift in either direction. The boundary is a strategic asset; it is not casually editable.

## Last reviewed

2026-05-26 — alongside h33-verify v0.1.0 publication.
