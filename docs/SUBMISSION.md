# Submission draft — TrustCut

**Challenge:** The Agent That Earns Trust  
**Project:** TrustCut  
**Tagline:** Identity stays valid. Authority ends.

## What we built

TrustCut is a working cryptographic authority lab for AI agents. Its memorable moment is simple: a request passes verification, the principal revokes its parent mandate, and the same signed request is denied at execution. The identity remains valid; permission does not.

A principal delegates a shared purchasing budget through a coordinator to two buyer agents. A supplier verifies the buyer's credential, delegation chain, scope, freshness, live revocation, and remaining ancestor budgets. A domain-specific signed attestation establishes the supplier relationship. Human approval is required above a defined threshold and is bound to the exact request.

Execution commits the order, replay nonce, ancestor budget debits, supplier acceptance, and audit record as one revision-guarded state change. Stale authority cannot overwrite newer revocation. Signed checkpointed evidence is downloadable and independently verifiable with a separate native-crypto CLI.

## Why this approach

Agent identity and passport infrastructure already exist. We focused on a harder, more demonstrable boundary: authority can change between checking a request and acting on it. TrustCut makes that failure visible, testable, and auditable without relying on an LLM's opinion of trustworthiness.

## Technical implementation

Ed25519, did:key, strict JWS verification, a restricted VC 2.0 / JOSE-inspired profile, signed narrowing delegation, live ancestor revocation, shared budget conservation, exact-request approval, nonce replay prevention, SQLite/D1 conditional commit, signed supplier acceptance, and hash-linked audit receipts. React provides the visual lab; a Worker handles session-isolated execution. No paid API or model call is required.

## Failure demonstration

Run the five-step story. One $180 order executes; another is verified, then blocked after parent revocation. The ledger remains at one. Run all twelve attack trials to inspect spoofing, tampering, replay, scope escalation, revocation, overspend, recipient substitution, expiry, forged attestation, chain substitution, unavailable status, and excessive amount. The automated suite has 49 passing tests, including production-handler and SQL conflict tests.

## AI tools and key decisions

Codex assisted public research, competitive analysis, architecture, code, test design, debugging, and deliverables. We replaced the generic AgentPassport/TrustMesh framing with TrustCut after reviewing public prior art. We deliberately used deterministic cryptographic enforcement, one atomic sandbox aggregate, and an independently implemented verifier. No LLM is in the authorization path.

## Deliberately out of scope

Agents are scripted; orders are sandbox records; one operator holds all demo keys. Independent organizational custody, real purchases, global reputation, distributed revocation infrastructure, production abuse protection, and full standards conformance are not claimed. Evidence verifies recorded signatures and integrity, not current authority or an honest operator.

## Required materials

- Working application: deployed link supplied in the handoff.
- Public source: https://github.com/norhan1995/trustcut — includes clean-clone instructions and CI.
- Architecture: `docs/ARCHITECTURE.md` and the app's Technical brief.
- Failure case: guided revocation story and twelve interactive trials.
- Two-year thesis: `docs/THESIS.md` (under 300 words).
- Demo: `docs/DEMO.md` and the accompanying 90-second captioned screenshot walkthrough.
- Tests: `docs/TESTING.md`.

This is submission-ready copy, not confirmation that DOO accepted an entry. Confirm current submission availability and paste the actual public source and deployed URLs before submitting.
