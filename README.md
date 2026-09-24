# TrustCut — know when trust ends

A cryptographic authority lab for **The Agent That Earns Trust**, DOO Builders League.

**The demo:** a buyer executes a valid $180 order. A second request passes verification. Its principal revokes the parent mandate. The same signed request is denied at execution; both descendant agents lose that authority. Export the signed evidence and verify it independently.

Real Ed25519 signatures. Scripted agents. Sandbox orders. No LLM or paid API is required.

[Public GitHub repository](https://github.com/norhan1995/trustcut)

## Run from a clean clone

Requires Node **22.13+** (Node 24 recommended) and pnpm. Install the version declared in `package.json` or use `corepack enable` where available.

```sh
git clone https://github.com/norhan1995/trustcut.git
cd trustcut
pnpm install --frozen-lockfile
pnpm test
pnpm typecheck
pnpm dev
```

The terminal prints the local URL (normally port 5173). After starting once, in another terminal:

```sh
pnpm db:local
```

Reload the app. The migration helper touches only the single local SQLite database created by Wrangler. No environment secrets, remote database, wallet, or API key is needed. Each visitor receives an isolated 24-hour sandbox. Reset generates new agent keys.

```sh
pnpm build
pnpm start
```

`start` runs the built Worker locally. Its local database uses the same migration helper. Deployment to Cloudflare-compatible hosting requires a D1 binding named `DB` and the checked-in Drizzle migration; the included Sites manifest belongs to this project and should not be reused to publish a fork into its owner's site.

## Judge in 90 seconds

Click **Run the 90-second story** and follow its five actions. Then open **Attack lab → Run all 12 attacks**. Every trial checks that the blocked operation added no order. Enter $250 after resetting to demonstrate an **ESCALATE → exact human approval → ALLOW** flow.

In **Evidence**, download a bundle. Copy the Northstar and Witness DIDs from their trust profiles before exchanging evidence. Verify independently:

```sh
node scripts/verify-evidence.mjs trustcut-evidence.json ROOT_DID AUDITOR_DID
```

Replace the last two arguments with those separately pinned DIDs. Do not accept trust anchors merely because an untrusted bundle supplies them. This verifier uses Node's native crypto and does not import application verification code.

## What is built

- Ed25519 `did:key` identities; root-signed agent identity credentials.
- Restricted VC 2.0 / JOSE-inspired credential profile, with custom delegation and vouch claims.
- Signed, linked, narrowing delegation with amount, resource, action, recipient, expiry, and depth constraints.
- Live ancestor revocation and signed revocation commands.
- Conserved parent budgets across sibling agents; nonce replay protection.
- Database revision compare-and-swap and database-time expiry check at commit.
- Scoped supplier attestation; mutual credential and recipient verification.
- Deterministic ALLOW / DENY / ESCALATE decisions with checks and recovery guidance.
- Signed supplier acceptance, hash-linked audit trail, signed export checkpoint.
- Browser evidence verifier and independently implemented offline verifier.

## Inspect the work

- [Architecture](docs/ARCHITECTURE.md)
- [Competitive research and rubric](docs/COMPETITION.md)
- [Security boundaries](docs/SECURITY.md)
- [Validation record](docs/TESTING.md)
- [90-second script](docs/DEMO.md)
- [Two-year thesis](docs/THESIS.md)
- [Submission draft](docs/SUBMISSION.md)

The sandbox operator holds every private key. This is a working reference implementation of enforcement semantics, **not** independent organizational custody, external purchasing, a global reputation network, or a claim of full W3C/UCAN conformance. Historical evidence does not prove current authorization. See the security document before extending the prototype.

Built with Codex for research, architecture, implementation, and tests. Human product direction: Norhan. Cryptographic decisions are deterministic; no model participates in authorization.

## Author

**Norhan Rifaie**  
[Portfolio](https://norhan-rifaie-portfolio-t6s0kg.v2.appdeploy.ai/) · [GitHub](https://github.com/norhan1995)
