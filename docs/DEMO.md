# 90-second judging flow

Open the app and click **Run the 90-second story**. Complete the five steps within two minutes because signed requests expire. A reset creates a fresh sandbox with new keys.

| Time | On-screen action | Narration |
|---|---|---|
| 0–12s | Show the network | “A signature proves who an agent is. It does not prove what that agent may still do. TrustCut makes that distinction executable.” |
| 12–25s | Execute a valid order | “Northstar delegates a shared $600 budget through Atlas. Relay orders $180 from Harbor. Both sides verify credentials; Harbor signs acceptance. One order is committed.” |
| 25–38s | Prepare the next order | “A second signed request passes every check. Preparation is not execution, and this ALLOW is not a permanent promise.” |
| 38–51s | Cut parent authority | “Now the principal revokes Atlas's mandate. Both Relay and Scout lose authority derived from it. Their identity signatures remain valid.” |
| 51–66s | Attempt execution | “The same request is denied against live authority. The ledger still contains exactly one order. A database revision guard stops stale approval from committing after revocation.” |
| 66–79s | Verify the evidence | “The signed audit chain and supplier acceptance are portable. A separate Node verifier checks this bundle using separately pinned trust anchors.” |
| 79–90s | Show attack lab or close | “Twelve attack trials and 49 tests challenge the boundary. Real signatures, scripted agents, sandbox orders. Our thesis: the trust layer that matters is the one that knows when an agent must stop.” |

## Extra judge questions

- **Where is ESCALATE?** Reset, enter $250, prepare. Human approval is required. Approve the exact request, then execute. A human cannot approve away a revoked mandate.
- **What if status is unavailable?** Reset and use “Simulate status outage.” A prepared valid request yields ESCALATE and cannot create an order. Restore status and prepare again.
- **Can siblings overspend?** Run the shared-budget attack; it spends $540 legitimately across three prior actions and denies a further $180 attempt that exceeds the $600 parent budget.
- **Can I spoof the evidence?** Download and change a displayed reason, amount, receipt order, or checkpoint. Paste it into Evidence. Verification fails. The native CLI provides a separately implemented check.
- **Is this autonomous purchasing?** No. The roles are scripted and orders are internal records. The authorization and signature operations are real.

The accompanying 90-second MP4 is a captioned walkthrough with synthetic English narration, made from actual application screenshots. It is not continuous screen recording and contains no synthesized claim that a live action occurred between frames. For a recorded spoken presentation, use the script above while operating the app.
