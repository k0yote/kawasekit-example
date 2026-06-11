# kawasekit-example — an AI agent paying a metered API via the cryptographic co-signer

A minimal, end-to-end on-ramp for [kawasekit](https://github.com/k0yote/kawasekit): an **AI
agent pays a metered HTTP API in testnet JPYC** — and it pays through a **cryptographic 2-of-2
co-signer**, not a raw private key. The agent holds only *half* the signing key; **no valid
payment exists unless the owner backend re-checks its policy and contributes its share.**

> ⚠️ **Testnet-only, UNAUDITED.** This demo runs on Polygon Amoy with no real value. The DKLs23
> threshold-signature crypto is **unaudited** — a third-party cryptographic audit is the standing
> prerequisite before any mainnet / real-value use. Do **not** put real funds behind this.

## What it shows

```
  ┌─────────┐   GET /weather/Tokyo        ┌──────────────────┐
  │  agent  │ ──────────────────────────► │  metered API     │
  │ (payer) │ ◄───── 402 + JPYC reqs ───── │ (x402 server)    │
  └────┬────┘                              └────────┬─────────┘
       │ co-sign an EIP-3009 authorization          │ verify + settle
       │ for the GROUP EOA (2-of-2)                  │ via self-facilitator
       ▼                                             ▼
  ┌──────────────────────────────┐            Polygon Amoy (JPYC)
  │ cryptographic co-signer       │
  │  • public adapter (kawasekit) │  ── wss + mTLS ──►  owner backend
  │  • private glue (@kawasekit/  │                     (cosign_server):
  │    mpc-2p): WASM share +      │                      • owner half-share
  │    transport + A3 HMAC        │                      • the spending policy
  └──────────────────────────────┘                      • re-derives digest, re-checks
                                                           policy, then co-signs
```

The agent retries the `402` with an `X-PAYMENT` header carrying the co-signed EIP-3009
`transferWithAuthorization`; the server's facilitator settles it on-chain and returns the data
plus the settlement tx.

## The open-core seam (why two packages)

| Piece | Package | Open / private |
|---|---|---|
| The x402 client/server + the `PolicyGatedSigner` **adapter** (`createMpc2pPolicyGatedSigner`) | **`kawasekit`** | **public** (Apache-2.0, npm) |
| The **injected implementations** — the WASM DKLs agent share, the wss/mTLS transport, the A3 HMAC authenticator | **`@kawasekit/mpc-2p`** | **private** (the client you receive with your owner-hosted co-signer) |
| The **owner backend** that holds the other share + the policy | **`cosign_server`** (kawasekit-mpc-2p) | **private**, self-hosted by the owner |

The public SDK ships only the *protocol*; the crypto, the socket, and the key are injected. This
example wires the two together — see [`lib/cosigner.ts`](lib/cosigner.ts), the whole seam in one
file.

## ⚠️ Honesty caveat — this demo is NOT the production topology

To make the demo runnable by one person, **you run BOTH MPC parties** — the agent (one share) and
the owner backend (the other share + policy) — on your own testnet infrastructure. **That is not
the production non-custodial topology.** In production:

- the **owner self-hosts** the `cosign_server` (their share + their policy), and
- the **agent is the client's**, holding only its own share;

so neither party is a custodian, and the owner's policy is *cryptographically* non-bypassable for
a counterparty it does not control. Co-locating both parties (as here) collapses that separation —
fine for a demo, **never** how you'd run real value. This is testnet-only and unaudited; treat the
result as an integration proof, not a security guarantee.

## Prerequisites

1. **A deployed owner backend** — the `cosign_server` from
   [`kawasekit-mpc-2p`](https://github.com/k0yote/kawasekit-mpc-2p) (see its `docs/DEPLOY-RUNBOOK.md`),
   reachable over **wss + mTLS**, holding the owner share + the spending policy on a persistent
   volume.
2. **A DKG-provisioned 2-of-2 key** — run the distributed key generation so the **agent** holds
   one share (`AGENT_SHARE_HEX`) and the backend holds the other; both agree on the **group EOA**.
   Back up both shares before funding (B5). The shared **A3 key** and the **mTLS PKI** come from
   the same provisioning step.
3. **A funded group EOA** — fund the group EOA with **testnet JPYC** on Polygon Amoy, and a
   separate **facilitator EOA** with Amoy MATIC for gas.
4. **Node ≥ 22** and `pnpm` (or `npm`).

> Local dev wires the two sibling checkouts via `link:` (`kawasekit` and
> `kawasekit-mpc-2p/agent-ts`). In your own project you depend on `kawasekit` from npm + the
> private `@kawasekit/mpc-2p` client you received with your co-signer.

## Run it

```sh
cp .env.example .env      # fill in the facilitator key, recipient, and the co-signer config
pnpm install
pnpm typecheck            # optional — verifies the wiring against the SDK types

# terminal 1 — the metered API
pnpm dev:server

# terminal 2 — the paying agent (pays via the cryptographic co-signer)
pnpm dev:agent
```

Expected: the agent prints the weather for the city plus a Polygon Amoy settlement tx hash. The
co-signer enforces the owner's policy on every payment — an over-policy request comes back as a
typed rejection (no signature), and an unreachable co-signer **throws** (`CoSignUnavailableError`)
rather than silently falling back to an advisory signature.

## Files

| Path | What |
|---|---|
| [`server/index.ts`](server/index.ts) | The metered API — a Hono x402 paywall + self-facilitator on Amoy. |
| [`agent/index.ts`](agent/index.ts) | The paying agent — `wrapFetch` + `createX402PaymentSigner({ signer })` over the cryptographic co-signer, with a budget guard. |
| [`lib/cosigner.ts`](lib/cosigner.ts) | The open-core seam — the public adapter driven by the private glue, over mTLS. |
| [`.env.example`](.env.example) | Every variable, with the secret/maintainer-hand ones flagged. |

## License

Apache-2.0. The crypto remains unaudited and testnet-only; see the caveat above.
