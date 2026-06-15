# RFC-0001 — ZeroDev session-key e2e JPYC payment (Polygon Amoy)

A runnable harness proving the **L2 enforcement de-risk**: an agent holding a
**serialized, buy-list-scoped session key** pays an **allowlisted** merchant in
**JPYC** via a **session-key userOp** whose **on-chain permission policy**
(`createBuyListPolicies`) authorizes the transfer, with **gas sponsored** by a
ZeroDev paymaster. Settlement = the userOp itself (Option A). **Amoy / zero-value
/ UNAUDITED.**

Consumes `kawasekit@^0.7.0` as an external npm dependency (the SDK public-API
boundary test — see "SDK boundary findings" below).

## Prerequisites (owner action required before a live run)

1. **JPYC on Amoy.** Fill `JPYC_ADDRESS_AMOY` + `JPYC_DECIMALS` from the
   **official JPYC faucet/docs**, verified on [Amoy PolygonScan](https://amoy.polygonscan.com).
   Do **not** trust a search-derived address. The harness asserts on-chain
   `decimals()` matches and that the address equals kawasekit's built-in
   `getJpycAddress(80002)` at startup, and aborts on mismatch.
2. **Fund the smart account** with testnet JPYC (JPYC Amoy faucet). The agent
   holds **0 POL** (gas is sponsored) — that is the H2 acceptance.
3. **Set a ZeroDev gas policy on the Amoy project BEFORE running**, covering the
   demo userOps. Without it the paymaster declines and the harness throws a
   `SponsorshipError` (there is **no** owner-pays-gas fallback, by design).
4. **ZeroDev project**: bundler + paymaster RPC (`ZERODEV_RPC`) and
   `ZERODEV_PROJECT_ID` from the dashboard (Amoy project).
5. **Keys** (`OWNER_PRIVATE_KEY`, `SESSION_PRIVATE_KEY`): testnet-only, never
   reused from any value-bearing context.

## Setup

Copy the vars from [`./.env.example`](./.env.example) into the repo-root `.env`
(gitignored) and fill them in. Then:

```sh
pnpm install          # installs kawasekit@0.7.0 + aligned @zerodev/* + vitest
pnpm zerodev:demo     # H1 happy path (needs the funded env + gas policy above)
pnpm test             # unit cases always; H1/H2/N1–N4/I1/I2 run only when the live env is set
```

`pnpm test` runs the §8 suite: 3 **unit** cases always (idempotency-key
determinism, observability emit, buy-list mapping), and 7 **integration** cases
that auto-skip unless the full live env is present.

## Acceptance (RFC-0001 §8)

A passing live run = **H1+H2 succeed** AND **N1–N4 each revert at userOp
validation** (asserted by the merchant `balanceOf` being unchanged — the
discriminator from a token-balance failure), on Amoy, with sponsored gas.
**I1** = a replay of the same `{conversationId, stepId}` returns the cached
result without a second submission. **I2** = submit/sponsor/settle spans emit.

## SDK public-API boundary findings (RFC §6.4 canary)

What `kawasekit@0.7.0` covered (used as-is, no internals): `createBuyListPolicies`;
`issueSessionKey` + `serializeSessionEnvelope` (owner; wraps ZeroDev's
`serializePermissionAccount` + `addressToEmptyAccount` — the owner never signs
with the session key); `parseSessionEnvelope` + `restoreSessionAccount` (agent,
real signer); `transferJpyc(client, …)`; `jpycAbi` / `getJpycAddress` /
`JPYC_DECIMALS` / `polygonAmoy`; `deriveIdempotencyKey`; `invokeHookSafely`.

Where the harness had to drop to the **raw `@zerodev/sdk`** (gaps):

- **G1 — sponsored kernel-account client construction.** kawasekit exports the
  `ConfiguredKernelClient` *type* and `transferJpyc(client, …)` that *consumes*
  one, but **no helper to BUILD it** with a bundler + ZeroDev paymaster. So
  `harness.ts` uses raw `createKernelAccountClient` + `createZeroDevPaymasterClient`
  for the entire sponsor-gas wiring (D6/O6). This is the main gap: the SDK can
  *spend* through a sponsored client but cannot *construct* one. A `kawasekit`
  helper (e.g. `createSponsoredKernelClient({ account, bundlerRpc, paymasterRpc })`)
  would close it.
- **G2 — `issueSessionKey` requires a full session `LocalAccount`** (it only uses
  `.address` internally via `addressToEmptyAccount`). The clean "agent generates
  the key, owner only ever sees the address" split isn't directly expressible;
  an address-only issuance variant would help. (Harmless for this single-operator
  demo.)
- **G3 — observability events are x402-facilitator-shaped** (`SettleEvent`,
  `VerifyEvent`, payment-required/accepted). The Option-A userOp path has
  `submit`/`sponsor` phases with no native SDK event, so the harness defines its
  own phase events and fires them via the SDK's generic `invokeHookSafely`. A
  userOp-native observability surface would close it.
- **G4 (type-only) — `createKernelAccountClient`'s deep generics don't unify with
  the exported `ConfiguredKernelClient` alias**, so one documented
  `as unknown as ConfiguredKernelClient` is needed (same runtime client).

Minor: `transferJpyc` resolves the JPYC address from kawasekit's built-in
deployments, not a caller argument — so `JPYC_ADDRESS_AMOY` is a *verification
anchor* (asserted to equal `getJpycAddress(80002)`), not the address actually used.
