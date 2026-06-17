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
2. **Fund the smart account** with testnet JPYC (JPYC Amoy faucet). The address to
   fund is the **counterfactual Kernel account** (derived from the owner sudo
   validator — *not* either EOA); run the **preflight** (it's the head of
   `pnpm zerodev:demo`, or call `preflight()` directly) to print that exact address,
   its current JPYC balance, and whether it's deployed yet. The agent holds **0 POL**
   (gas is sponsored) — that is the H2 acceptance; do **not** fund POL to it.
3. **Set a blanket "sponsor-all" ZeroDev gas policy on the Amoy project BEFORE
   running**, covering the demo userOps. Without it the paymaster declines and the
   harness throws a `SponsorshipError` (there is **no** owner-pays-gas fallback, by
   design). The gas policy MUST NOT restrict recipient/amount: the §8 negatives
   (N1–N4) prove the *permission validator* is the boundary, so a gas policy that
   itself filtered recipient/amount would reject at the paymaster instead and mask
   the validator (the harness fails such a run — see "Acceptance").
4. **ZeroDev project**: bundler + paymaster RPC (`ZERODEV_RPC`) and
   `ZERODEV_PROJECT_ID` from the dashboard (Amoy project).
5. **Keys** (`OWNER_PRIVATE_KEY`, `SESSION_PRIVATE_KEY`): testnet-only, never
   reused from any value-bearing context.

## Setup

Copy the vars from [`./.env.example`](./.env.example) into the repo-root `.env`
(gitignored) and fill them in. Then:

```sh
pnpm install          # installs kawasekit@0.7.0 + aligned @zerodev/* + vitest
pnpm zerodev:demo     # preflight (prints the account to fund) then the H1 happy path
pnpm test:rfc0001     # this harness only — unit always; integration runs when the live env is set
pnpm typecheck:rfc0001 # typecheck this harness only (independent of the rest of the repo)
```

`pnpm test:rfc0001` runs the §8 suite: **unit** cases always (idempotency-key
determinism, observability emit + the sponsor/validation reject routing, buy-list
mapping), and **integration** cases (H1/H2/N1–N4/I1/I2 + preflight) that auto-skip
unless the full live env is present.

> **Independent gate (RFC §11).** `test:rfc0001` and `typecheck:rfc0001` (the latter
> via a dedicated [`./tsconfig.json`](./tsconfig.json)) exercise *only* this harness,
> so they stay green **without** the private `@kawasekit/mpc-2p` optional dep that the
> repo's other examples (`../lib`, `../server`, `../agent`) need. The repo-wide
> `pnpm typecheck` / `pnpm test` require that dep installed (GitHub Packages auth).

## Acceptance (RFC-0001 §8)

> **⛒ Premise gate (F1) — unit green ≠ de-risk closed.** The discriminator below
> is only sound if ZeroDev's verifying paymaster, under the blanket "sponsor-all"
> policy, **sponsors** an out-of-allowlist op (so the *validator* rejects it) rather
> than **simulate-and-declining** it at `pm_sponsorUserOperation`. So the FIRST thing
> the live Amoy run must establish is: a live **N1** (out-of-allowlist) throws a
> **non-`SponsorshipError`** with **no `sponsor_reject`** span. The test logs which
> branch each negative took (`[F1 premise] …`). If N1 instead returns
> `SponsorshipError`/`sponsor_reject`, **STOP** — apply the RFC-0001 §9 fallback (run
> N1–N4 without the paymaster on a deployed, POL-funded account). Until confirmed
> on-chain, step 3 is **implemented, not de-risked**.

A passing live run = **the premise gate holds** AND **H1+H2 succeed** AND **N1–N4 are
each rejected by the on-chain permission validator**, on Amoy, with sponsored gas. The
de-risk is that the *policy*, not the paymaster or token balance, is the boundary, so
each negative asserts: the throw is **not** a `SponsorshipError` (the paymaster did not
decline), the span stream carries **no** `sponsor_reject` and **no** `settle`, and the
merchant `balanceOf` is **unchanged**. (A bare "it threw" would also pass for a paymaster
decline — which is exactly what this discriminates against; see
`expectPolicyValidationReject` in `harness.test.ts`.)

**I1** = a replay of the same `{conversationId, stepId}` returns the cached result
without a second submission — **call-level, in-process dedup only** (the cache is
an in-memory `Map`; it is lost on restart and keyed on harness-local ids that
diverge across agent-harness boundaries). The real over-spend backstop is the
on-chain rateLimit count, not this cache. Durable / protocol-normalized-intent
idempotency is future work. **I2** = submit/sponsor/settle spans emit.

## SDK public-API boundary findings (RFC §6.4 canary)

What kawasekit covered (used as-is, no internals): `createBuyListPolicies`;
**`createSponsoredKernelClient`** (the 0.8.0 helper — builds the gas-sponsored
client; see G1/G4 closed); `issueSessionKey` + `serializeSessionEnvelope` (owner;
wraps ZeroDev's `serializePermissionAccount`, building the permission account with
the **real** session signer — see G2); `parseSessionEnvelope` + `restoreSessionAccount`
(agent, real signer); `transferJpyc(client, …)`; `jpycAbi` / `getJpycAddress` /
`JPYC_DECIMALS` / `polygonAmoy`; `deriveIdempotencyKey`; `invokeHookSafely`.

SDK gaps surfaced by this boundary test (**G1 + G4 now CLOSED** by `createSponsoredKernelClient`):

- **G1 — sponsored kernel-account client construction — CLOSED.** kawasekit now
  ships `createSponsoredKernelClient({ account, chain, zerodevRpc, publicClient?, observability? })`;
  `harness.ts` uses it and **no longer touches raw `@zerodev/sdk`** for client
  construction. The optional `observability` hook (`onSponsor` / `onSponsorError`)
  carries the §8 `sponsor` / `sponsor_reject` discrimination; the harness re-raises
  a typed `SponsorshipError` on a genuine decline (no owner-pays fallback).
- **G2 — `issueSessionKey` requires a full session `LocalAccount`** (its private
  key), because internally it builds the permission account with the **real**
  session signer (`toECDSASigner`) rather than `addressToEmptyAccount` (which is
  used nowhere in kawasekit). So the issuer must hold the session secret at
  issuance time, and the clean "agent generates the key, owner only ever sees the
  address" split is **not** directly expressible. An address-only issuance variant
  (built on `addressToEmptyAccount` + `serializePermissionAccount`) would close it
  and is relevant to the Hub L1 design (RFC §10). Harmless for this single-operator
  demo, where both keys are co-located.
- **G3 — observability events are x402-facilitator-shaped** (`SettleEvent`,
  `VerifyEvent`, payment-required/accepted) — **partially closed.** The
  **sponsorship** seam now has a native hook (`createSponsoredKernelClient`'s
  `observability.onSponsor` / `onSponsorError`); the `submit` / `settle` phases are
  still harness-defined and fired via the SDK's generic `invokeHookSafely`. A
  userOp-native observability surface for those would close the remainder.
- **G4 (type-only) — CLOSED.** `createSponsoredKernelClient` returns a typed
  `ConfiguredKernelClient`; the harness's `buildSponsoredKernelClient` no longer
  needs the `as unknown as ConfiguredKernelClient` cast or an `any`-typed account
  (the single documented cast now lives once, inside the SDK helper).

Minor: `transferJpyc` resolves the JPYC address from kawasekit's built-in
deployments, not a caller argument — so `JPYC_ADDRESS_AMOY` is a *verification
anchor* (asserted to equal `getJpycAddress(80002)`), not the address actually used.
