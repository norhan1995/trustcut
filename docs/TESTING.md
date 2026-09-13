# Validation record

Run date: 11 September 2026. Runtime: Node 24.19.0. `pnpm test`: **49 passed, 0 failed**.

| Group | Tests | What was checked |
|---|---:|---|
| Engine and signatures | 39 | Twelve attack scenarios plus valid execution, native crypto, header confusion, narrowing, exact approvals, revocation, expiry, malformed data, isolated keys, checkpoint integrity, and independent verification. |
| Browser crypto fallback | 1 | A native-signed bundle verifies without WebCrypto using Noble; changed evidence fails. |
| Repository SQL | 4 | Eight competing snapshots produce one commit; prior revocation invalidates stale ALLOW; database-time deadline; expired session. |
| API handlers | 5 | Secure isolated cookies/no private keys, bad input/origin, concurrent execution, stale approval, prepare→revoke→execute. |

Repository and API tests execute the actual production SQL against in-memory Node SQLite through a small D1 API adapter. They exercise revision conflicts and handler retry logic, but are not a Cloudflare multi-region load test. API tests call exported Request/Response handlers directly, not a network endpoint.

## Browser verification

The managed local preview was exercised through its actual UI and persistent local D1 state:

- A valid $180 order executed and debited the $600 shared budget to $420.
- Another request passed preparation; parent revocation then caused execution to DENY with `AUTHORITY_REVOKED`.
- The ledger stayed at one order after denial.
- All twelve interactive attack trials reported the expected defense, including ESCALATE for status outage.
- Export evidence verified locally: five receipts, ten credentials, one signed supplier acceptance.
- The HTTP preview initially lacked WebCrypto; the local Noble verification fallback fixed this and was covered by a cross-implementation test.

Screenshots are actual app captures. Responsive CSS is implemented; no claim of an exhaustive mobile-device or cross-browser matrix is made.

## Build checks

TypeScript checking passed. Production build is validated during packaging. The supplied GitHub Actions workflow runs installation, tests, type checking, and build, but no GitHub Actions run is claimed until the source is published to a GitHub repository.

## Known limits

No external audit, formal proof, production load test, external payment integration, independent custody exercise, or interoperability certification has been performed. A passing suite is evidence for tested behaviors, not proof of absence of vulnerabilities.
