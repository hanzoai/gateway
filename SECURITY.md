# Security Policy

## Reporting a vulnerability

Email security@hanzo.ai with details. Encrypt with our PGP key (fingerprint TBD).

We respond within 48 hours. Critical issues receive same-day acknowledgment.

## Scope

This policy covers code in this repository. For the broader Hanzo platform threat model, see [hanzoai/HIPs](https://github.com/hanzoai/HIPs).

## Sandbox boundary

`gateway` is the only Hanzo service that writes identity headers from JWTs — every client-supplied `X-User-*`, `X-Org-Id`, and `X-Roles` header is stripped unconditionally before processing. JWT validation runs against the Hanzo IAM JWKS endpoint, and rate limiting / circuit breakers isolate failures so a misbehaving client or downstream cannot affect other tenants.

For runtime sandbox guarantees, see HIP-0105 (in-process extension runtimes).
