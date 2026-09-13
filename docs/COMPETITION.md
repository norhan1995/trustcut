# Competitive position and judging strategy

Research date: 11 September 2026. This is public-source research, not knowledge of private entries.

## Official challenge

[The Agent That Earns Trust](https://build.doo.ooo/challenges/agent-earns-trust) asks for a working trust demonstration, public source that runs from a clean clone, a live demo, architecture, a failure case, and a short two-year thesis. The challenge page lists conceptual clarity 25%, technical depth 25%, demo quality 20%, failure handling 15%, and thesis quality 15%. A short video is recommended.

The public challenge page and challenge overview displayed inconsistent timing during research. Confirm submission availability in the signed-in challenge flow before claiming an entry was accepted. No deadline or prize amount is asserted here.

## What was and was not found

Public searches and the visible builder leaderboard did not yield verified public submissions for this specific challenge. Leaderboard badges and screening results are not proof of a submitted project. The following are relevant existing projects and standards, **not identified challenge entrants**.

| Public reference | Overlap | Consequence for our entry |
|---|---|---|
| [Agent Passport System](https://github.com/aeoess/agent-passport-system) | Agent identity, delegation, policy and signed evidence | A generic passport narrative is insufficient differentiation. |
| [APort](https://aport.io/) | Agent identity and authorization infrastructure | Focus the demonstration on a concrete execution failure instead of a directory of identities. |
| [UCAN](https://github.com/ucan-wg/spec) | Signed delegated capabilities and attenuation | Chained delegation is established work; acknowledge it. Our custom profile is not UCAN-conformant. |
| [W3C VC 2.0](https://www.w3.org/TR/vc-data-model-2.0/) and [VC JOSE/COSE](https://www.w3.org/TR/vc-jose-cose/) | Signed machine-verifiable claims | Standards shape the data model; a credential signature alone does not authorize an action. |
| [did:key](https://w3c-ccg.github.io/did-key-spec/) | Self-contained public-key identifiers | Use real key identifiers without inventing a blockchain dependency. |

Likely approaches—an inference, not observed entries—include reputation dashboards, identity passports, prompt-based trust scores, and human approval wrappers. Each can look plausible without demonstrating that a previously authorized action is stopped after conditions change.

## Differentiated proposition

**Identity stays valid. Authority ends. The order does not execute.**

TrustCut deliberately concentrates on the approve-to-execute interval, ancestor revocation, budget conservation between siblings, and portable signed evidence. We do not claim to be the first to implement these ideas or that competitors lack them. The competitive advantage sought is the combination of executable semantics, an intelligible failure moment, and an honest proof boundary in a short judging session.

## Rubric mapping

| Criterion | Weight | Evidence judges can inspect |
|---|---:|---|
| Conceptual clarity | 25% | One sentence, one visible mandate, one irreversible-in-the-demo cut; identity and authority are distinct. |
| Technical depth | 25% | Actual Ed25519 signatures, trusted issuer checks, narrowing linked grants, shared budget, conditional database commit, independent CLI. |
| Demo quality | 20% | Five-step guided story, live topology, decision trace, ledger, attacker trials, downloadable evidence. |
| Failure handling | 15% | Twelve executable attacks, 49 automated tests including storage conflicts and verifier tampering. |
| Two-year thesis | 15% | Narrow operational wedge, measurable pilot outcomes, explicit falsification condition. |

## Submission discipline

Lead with the stopped action, not a feature inventory. Show one successful order first so the DENY proves selective enforcement. Keep a signed acceptance in the ledger after revocation to clarify that withdrawal is prospective. End with evidence verification and the honest statement that the agents share one sandbox operator. Do not claim independent organizational trust, real purchasing, certification, or a production-ready security platform.
