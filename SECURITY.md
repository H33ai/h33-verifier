# Security Policy

## Scope

This policy covers the `h33-verify` binary, its library `h33_verify`, the published wire-format specification ([SPEC.md](./SPEC.md)), and the test fixtures shipped in this repository.

It does **not** cover H33's production infrastructure, the substrate attestation service at `api.h33.ai`, or the proprietary signing / FHE / STARK / biometric implementations that produce the receipts this tool verifies. Those are out of scope here — for issues in those systems, contact H33 directly through normal support channels.

## Reporting a vulnerability

**Preferred:** GitHub Security Advisories — <https://github.com/H33ai/h33-verifier/security/advisories/new>. This keeps the report private until a fix ships.

**Alternative:** email `support@h33.ai` with subject line beginning `[h33-verify security]`. We will route from there.

Please do not file public issues for security reports.

## What we want to hear about

- **Verification soundness bugs** — cases where the verifier returns `verdict=PASS` for a receipt that should fail Mode 1 (substrate decode invalid, SHA3-256 mismatch, wrong receipt size, or the `--data` binding check passing when payload doesn't match `fhe_commitment`).
- **Verification completeness bugs** — cases where the verifier returns `verdict=FAIL` for a valid receipt produced per [SPEC.md](./SPEC.md).
- **Spec/implementation divergence** — cases where the verifier behaves differently from what SPEC.md or the Cross-Language KAT vector mandates.
- **Crash, hang, or memory-safety issues** in `src/lib.rs` or `src/main.rs`, especially when triggered by malformed JSON, malformed hex, or boundary-condition inputs.
- **Information leaks** — anywhere the verifier inadvertently writes, logs, or transmits anything beyond its declared JSON output (it should be a pure stdin-files-to-stdout transformation).
- **Supply-chain concerns** — anything off about the five published dependencies (`sha3`, `clap`, `serde`, `serde_json`, `hex`) or how this crate uses them.

## What is not a vulnerability here

- The verifier explicitly does **not** check post-quantum signature validity in v0.1 (Mode 1 only); the absence of that check is documented and intentional. Mode 2 lands in v0.2.
- The verifier explicitly does **not** check liveness/recency, replay, or issuer authenticity — those are application-layer concerns. See [THREAT_MODEL.md](./THREAT_MODEL.md).
- Issues in the H33 substrate service (key handling, attestation logic, signing pipeline) are out of scope for this repo. Report them to H33 directly.

## Disclosure timeline

For valid reports:

- We aim to acknowledge within 3 business days.
- We aim to ship a fix within 30 days of acknowledgement.
- We will credit reporters (unless they prefer otherwise) in the changelog and the GitHub Security Advisory.
- If a report requires coordinated disclosure across the H33 substrate, we will keep the reporter looped in and time the public advisory accordingly.

## Supported versions

| Version | Status |
|---------|--------|
| 0.1.x   | Supported — Mode 1 verification |
| < 0.1   | Not applicable (no pre-0.1 release) |

Future major-version releases (v0.2 Mode 2, v1.0 stable) will have separate security windows once released.

## Out-of-band questions

If you're not sure whether something is a vulnerability or a feature request, file a regular GitHub issue with the `question` label. Honest doubts about the verifier's correctness are exactly the kind of conversation we want to be having in the open.
