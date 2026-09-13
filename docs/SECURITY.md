# Security model and boundaries

This is a competition prototype, not a production authorization service.

## In scope

An attacker can change exported packets, invent a signing key, replay an intent, swap audiences/credentials/chains, over-delegate, reuse an ancestor budget, or act after authority revocation. These attempts must not create a sandbox order. Missing status fails closed as ESCALATE. Human approval is signed and bound to the exact intent, and cannot override revoked or excessive authority.

The session API checks JSON content type and same-host Origin when provided. Cookies are HttpOnly, SameSite Strict, Secure on HTTPS, and expire after 24 hours. The database stores a hash of the random session cookie. Public responses and evidence omit private keys. Monetary values are integer cents. State mutations are revision guarded. A stale request ID cannot approve a replacement pending order.

## Trusted assumptions

- The root and Witness DIDs are pinned through a trusted channel.
- The server, its clock, database, and operator are trusted for live state and sandbox key custody.
- SQLite/D1 serializes conditional updates to the sandbox row.
- Private keys have not been stolen; a signature proves key control, not benign intent.

All actors are scripted and all private keys are held by one operator in sandbox storage. Separate names and signatures demonstrate protocol roles, not independent organizations. Reset replaces keys; it is not a production key-rotation workflow. Expired sessions become inaccessible; opportunistic cleanup is not a guaranteed physical deletion schedule.

## Limits

- Orders are internal records; no stock, payment, or external delivery occurs.
- No independent security audit or formal verification has been performed.
- VC/JOSE-inspired profile is intentionally restricted. No full VC, DID, or UCAN conformance is claimed. Delegation is custom, not a UCAN token.
- Revocation is live at this database commit boundary, not globally instantaneous.
- A signed history can be internally consistent and still be dishonest if its operator is malicious. No external transparency witness anchors the latest checkpoint.
- The evidence verifier checks integrity/signatures, not the truth of every issuer claim or current policy compliance.
- The sample supplier vouch is seeded, not accumulated trust from real transactions.
- No global rate limiting, resource-abuse resistance, multi-region failover, HSM, independently held keys, or external connector idempotency is implemented.
- Demo bounds limit individual request size and audit length; they do not constitute production denial-of-service protection.
- Browser verification requires trusting the delivered application code; the independent CLI allows verification outside that delivery path.

## Production next steps

Separate custody and issuers, add external checkpoint witnesses, define a status-freshness protocol, integrate an idempotent tool boundary, obtain an external audit, and test cross-region failure before handling real value. These are roadmap items, not current functionality.
