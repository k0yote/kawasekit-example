# RFC-0003 — passkey (WebAuthn) owner + non-custodial recovery (Polygon Amoy)

A runnable harness proving a **passkey (WebAuthn P256) sudo owner** can drive the agent
payment path on Amoy (**Cycle 1**, below), and that the owner is **recoverable without
custody** via a weighted-validator + guardian quorum (**[Cycle 2](#rfc-0003-cycle-2-approach-b--non-custodial-recovery-polygon-amoy)**).

## Cycle 1 — passkey owner e2e JPYC payment

A passkey (WebAuthn P256) sudo owner drives the agent payment path on Amoy:

- **P1** — a **passkey-signed userOp lands** (the owner-direct path): the headless
  P256 authenticator signs a Kernel userOp, the ZeroDev passkey validator verifies
  it on-chain (RIP-7212 precompile / Daimo fallback duo-mode), and a sponsored JPYC
  transfer settles.
- **P2** — the **de-risked RFC-0001 floor still holds under the passkey owner**: a
  **buy-list-scoped session key** issued *under the passkey sudo* (`createBuyListPolicies`)
  authorizes an allowlisted JPYC transfer, gas sponsored by a ZeroDev paymaster, and
  every §8 negative (recipient / cap / count / window out-of-scope) is rejected with
  **no funds moved**.

**Amoy / zero-value / UNAUDITED.** Consumes `kawasekit@^0.8.0` as an external npm
dependency (the SDK public-API boundary test — see "SDK boundary findings" below).

## The passkey is a headless software authenticator (no browser, no `navigator`)

The owner credential is a **software P256 authenticator** built with [`ox`](https://oxlib.sh)
(`P256.sign` + `WebAuthnP256.getSignPayload`), persisted to `.passkey-cycle1.json`
(gitignored, testnet-only) so the counterfactual account address stays stable across
runs. There is **no `OWNER_PRIVATE_KEY`** — the owner is a WebAuthn key, and signing
goes through ZeroDev's `signMessageCallback` seam:

`(message: SignableMessage, rpId: string, chainId: number, allowCredentials?) => Promise<Hex>`

The adapter (`account.ts`) returns a single ZeroDev-encoded `Hex`: it assembles the
WebAuthn bytes via `ox` (`authenticatorData`, `clientDataJSON`, challenge/type
indices, UP|UV flags), signs the payload with P256, and encodes them in the EXACT
validator wire format copied verbatim from `@zerodev/passkey-validator`'s own
`signMessageUsingWebAuthn` (`responseTypeLocation = findQuoteIndices(...).beforeType`,
`usePrecompiled = isRIP7212SupportedNetwork(chainId)`). The off-chain half (the
authenticator bytes verify against the public key for a given challenge) is pinned
by `passkey.test.ts` (`ox/WebAuthnP256.verify`, always-run); the on-chain half is
proven by P1.

## Prerequisites (owner action required before a live run)

1. **JPYC on Amoy.** Fill `JPYC_ADDRESS_AMOY` + `JPYC_DECIMALS` from the
   **official JPYC faucet/docs**, verified on [Amoy PolygonScan](https://amoy.polygonscan.com).
   Do **not** trust a search-derived address. The harness asserts on-chain
   `decimals()` matches and that the address equals kawasekit's built-in
   `getJpycAddress(80002)` at startup, and aborts on mismatch.
2. **Fund the PASSKEY smart account** — the **counterfactual Kernel account** (derived
   from the passkey sudo validator, *not* an EOA). Two distinct accounts are involved:
   - **P1 (owner-direct):** the passkey-sudo-only account. `pnpm passkey:p1`
     (`probe-passkey.ts`) prints its address; fund it with a little JPYC.
   - **P2 (session-key floor):** the passkey-sudo + buy-list-session account. Run the
     **preflight** (head of `pnpm zerodev:passkey:demo`, or call `preflight()`) to print
     that exact address + its JPYC and POL balances. Fund it:
     - **JPYC** (Amoy faucet) — ≥ 1 JPYC for the full §8 suite.
     - **~0.1 POL** (Amoy POL faucet, https://faucet.polygon.technology/) — **only** for
       the **paymaster-less** N1–N4 (the bundler prefund check); it is **NOT consumed**
       (those ops revert at validation). The **sponsored** path (H1/H2 + sponsored
       N1–N4) needs **0 POL**.
3. **Set a blanket "sponsor-all" ZeroDev gas policy on the Amoy project BEFORE
   running**, covering the demo userOps. Without it the paymaster declines and the
   harness throws a `SponsorshipError` (there is **no** owner-pays-gas fallback, by
   design). The gas policy MUST NOT restrict recipient/amount: the §8 negatives
   (N1–N4) prove the *permission validator* is the boundary, so a gas policy that
   itself filtered recipient/amount would reject at the paymaster instead and mask
   the validator.
4. **ZeroDev project**: bundler + paymaster RPC (`ZERODEV_RPC`) and
   `ZERODEV_PROJECT_ID` from the dashboard (Amoy project).
5. **`PASSKEY_RPID`** (optional): the WebAuthn relying-party id (defaults to
   `kawasekit.local`). It is baked into the credential; changing it changes the
   account address.
6. **Session key** (`SESSION_PRIVATE_KEY`): testnet-only, never reused from any
   value-bearing context. (The owner is a passkey — there is no owner private key.)

## Setup

Copy the vars from the repo-root `.env.example` into the repo-root `.env`
(gitignored) and fill them in (note: **no `OWNER_PRIVATE_KEY`**; add `PASSKEY_RPID`
if not using the default). Then:

```sh
pnpm install              # installs kawasekit@0.8.0 + aligned @zerodev/* + ox + vitest
pnpm passkey:p1           # P1: prints the owner-direct account to fund, then lands a passkey userOp
pnpm zerodev:passkey:demo # P2: preflight (prints the session-key account to fund) then the happy path
pnpm test:rfc0003         # this harness only — unit always; integration runs when the live env is set
pnpm typecheck:rfc0003    # typecheck this harness only (independent of the rest of the repo)
```

`pnpm test:rfc0003` runs the suite: **unit** cases always (idempotency-key
determinism, observability emit + the sponsor/validation reject routing, buy-list
mapping; plus `passkey.test.ts`'s off-chain ox verify), and **integration** cases
(P1 + P2's H1/H2/N1–N4/I1/I2 + preflight) that auto-skip unless the full live env
is present.

> **Independent gate (RFC §11).** `test:rfc0003` and `typecheck:rfc0003` (the latter
> via a dedicated `./tsconfig.json`) exercise *only* this harness, so they stay green
> **without** the private `@kawasekit/mpc-2p` optional dep that the repo's other
> examples need.

## Acceptance (RFC-0003 Cycle 1)

A passing live run =

- **P1** — `pnpm passkey:p1` lands a passkey-signed sponsored JPYC transfer on Amoy
  (`success: true`, merchant balance +amount). The harness P1 integration test asserts
  the same. **= the adapter + duo-mode P256 verification work on-chain.**
- **P2** — the full RFC-0001 §8 floor, issued **under the passkey owner**, all hold:
  - **H1/H2** — sponsored happy path settles (H2 = 0 POL on the account).
  - **sponsored N1–N4** — the durable invariant (`expectPolicyEnforced`): threw + **no
    `settle`** + merchant `balanceOf` unchanged, the `sponsor_reject`/`validation_reject`
    branch **recorded** (per RFC-0001 F1) but not hard-asserted.
  - **paymaster-less N1–N4** — `expectOnChainValidationReject`: self-paid (POL) so the
    **on-chain permission validator is the SOLE rejecter**; every negative is a
    `validation_reject` with no `settle` and balance unchanged. The immutable,
    paymaster-independent proof that the floor survives the ECDSA→passkey owner swap.

**Live run result — Amoy 2026-06-18: 20/20 PASS ✅** (`pnpm test:rfc0003`; 4 harness
unit + 3 ox-verify + 13 integration). **P1** ✅ — passkey-signed userOp landed
([tx `0xeff3008c…cebdd`](https://amoy.polygonscan.com/tx/0xeff3008c4e233e46021aec4b8d0284df35ea66427d7b8f3beabecfd707fcebdd)).
**P2** ✅ — H1/H2 settle ([demo tx `0x509c806c…3567`](https://amoy.polygonscan.com/tx/0x509c806c440b549c49a3a6f73a884303a67ac5526e4932261e4ccccb0bbc3567));
sponsored N1–N3 `sponsor_reject`, N4 `validation_reject`; paymaster-less N1–N4 all
`validation_reject`; merchant balance unchanged in every negative. **The de-risked
RFC-0001 floor survives the ECDSA→passkey owner swap byte-for-byte.**

**I1** = a replay of the same `{conversationId, stepId}` returns the cached result
without a second submission (call-level, in-process dedup only; the on-chain
rateLimit count is the real over-spend backstop). **I2** = submit/sponsor/settle
spans emit.

## SDK boundary finding (RFC-0003 §11) — passkey-issuance helper is the Cycle-1 follow-up

kawasekit's `issueSessionKey` / `createAgentSmartAccount` build the sudo via
`signerToEcdsaValidator` (**ECDSA-only**). So P2 **cannot** issue a session key under
a passkey owner through kawasekit's current API. The harness works around this in
`issuePasskeyScopedSessionKey` (`harness.ts`): it builds the account **raw** with
`@zerodev` — `sudo` = the passkey validator (`@zerodev/passkey-validator`), `regular`
= the buy-list permission validator (policies from kawasekit's `createBuyListPolicies`)
— then wraps ZeroDev's `serializePermissionAccount` blob in kawasekit's
`serializeSessionEnvelope` so the **agent side is byte-for-byte RFC-0001**
(`parseSessionEnvelope` + `restoreSessionAccount` + `transferJpyc`, unchanged).

A **passkey-capable issuance helper** in kawasekit (an `issueSessionKey` variant that
accepts a non-ECDSA sudo validator) would close this — the analog of RFC-0001's G1,
and directly relevant to the Hub design where the owner is a passkey. Recorded as the
Cycle-1 SDK gap.

What kawasekit covered as-is (no internals): `createBuyListPolicies`;
`createSponsoredKernelClient`; `serializeSessionEnvelope` / `parseSessionEnvelope` /
`restoreSessionAccount` / `KAWASEKIT_SESSION_ENVELOPE_VERSION`; `transferJpyc`;
`jpycAbi` / `getJpycAddress` / `polygonAmoy`; `deriveIdempotencyKey`.

---

# RFC-0003 Cycle 2 (Approach B) — non-custodial recovery (Polygon Amoy)

Cycle 1's owner is a **bare passkey**: lose it and the account is gone. Cycle 2 makes
the owner **recoverable without custody**. The owner is now **one weighted validator**
with three signers and a threshold:

| Signer | Weight | Role |
|---|---|---|
| Passkey (WebAuthn P256) | **100** | the user; signs alone for every normal op |
| Hub guardian (ECDSA) | **50** | the service — cannot act alone |
| User backup (ECDSA) | **50** | the user's recovery key — cannot act alone |
| **threshold** | **100** | |

The passkey alone (100) meets the threshold, so day-to-day the account behaves exactly
like Cycle 1. **Recovery** = the **guardian quorum (Hub + backup = 100)** resets the
weighted config to a *new* passkey via `doRecovery(weightedValidatorAddress,
newWeighted.getEnableData())` — the lost passkey is never used, and **the account
address is unchanged** (in Kernel v3.1 the address is `f(sudo + initial config)`, fixed
at deploy; recovery changes the config, not the address).

## Why this is non-custodial (stated honestly)

- **Hub alone (50) < threshold (100) for EVERYTHING.** The service can never move funds,
  rotate the owner, or revoke a key by itself. This is the on-chain boundary — **R2**
  proves it: a Hub-alone userOp is **rejected at on-chain `validateUserOp`**, shown
  **paymaster-less** so the rejecter is the weighted threshold and not a sponsor decline.
- The recovery quorum (Hub + backup) is **not** a recovery-only power — it holds **full
  owner authority**. Non-custodial therefore rests on **the user's `backup` key being
  required** for any quorum action (Hub + the user's own key), plus out-of-band auth on
  the Hub side before it co-signs. The Hub can never reach the threshold without the user.

## What the harness adds over Cycle 1

- **`weighted-account.ts`** — the weighted-sudo owner builders: `ownerConfig` (the
  `[100,50,50]/100` config), `buildOwnerSudoValidator` (passkey-owner sudo),
  `weightedClientFor` (one client per signer; installs the recovery executor as a
  **fallback module** via `getRecoveryFallbackActionInstallModuleData` + `pluginMigrations`
  — `plugins.action` would revert `InvalidSelector`), `sendWeighted` (approve each signer
  → `sendUserOperationWithSignatures`), and `approveSessionKeyEnable`.
- **`recovery.ts`** — `recoverOwner` (guardian-quorum config-reset → new passkey),
  `bindNewOwnerAccount` (act as the new owner at the same address), `recoveryCallData`.
- **`harness.ts`** — `issueSessionKeyUnderWeightedSudo` (the RFC-0001 floor under the
  weighted owner) and `revokeSessionKeyUnderWeightedSudo` (R4c).
- **`probe-recovery.ts`** — the runnable gate proof (`pnpm recovery:probe`).

## SDK boundary findings (Cycle 2)

Two places where the weighted sudo needs more than the single-signer SDK path — the
analog of Cycle 1's passkey-issuance gap:

- **U-B1 — session-key enable under a weighted sudo.** `serializePermissionAccount`'s
  default single-signer enable is rejected on-chain (`EnableNotApproved` / `0xc48cf8ee`)
  by a weighted sudo. The fix is the canonical weighted pattern: the passkey owner
  `approvePlugin` + `encodeSignatures([approval], true)`, passed as the 3rd arg of
  `serializePermissionAccount(account, undefined, enableSignature)`
  (`approveSessionKeyEnable`).
- **U-B2 — revoke under a weighted sudo.** kawasekit's `revokeSessionKey` calls
  `@zerodev/sdk`'s `uninstallPlugin`, which **hardcodes the single-signer
  `sendUserOperation` path** — the weighted validator rejects it (it needs the
  approve/aggregate format). The harness reproduces `uninstallPlugin`'s one inner call
  byte-faithfully — `uninstallValidation(vId, deinitData, "0x")`, where
  `vId = VALIDATOR_TYPE.PERMISSION ‖ pad(getIdentifier(),20)` and the plugin is rebuilt
  from the **same session signer + same policies** installed at issue — and submits it
  through `sendWeighted` (`uninstallSessionKeyData` + `revokeSessionKeyUnderWeightedSudo`).

A kawasekit `revokeSessionKey` variant that accepts a non-single-signer owner client (and
a weighted-capable issuance helper) would close both — recorded as the Cycle-2 SDK gaps.

## Acceptance (RFC-0003 Cycle 2) + run

Set `HUB_GUARDIAN_PRIVATE_KEY` + `USER_BACKUP_PRIVATE_KEY` (testnet-only ECDSA keys) in
the repo-root `.env`, then `pnpm exec vitest run zerodev-passkey-jpyc/recovery.test.ts`.
`beforeAll` prints the accounts to fund (testnet-only, gitignored passkeys):

- **R2** — a dedicated account, **~0.1 POL** (the paymaster-less negative's prefund check; not consumed).
- **R4b / R4c** — one lifecycle account each, **~0.01 JPYC** (each run spends 0.001 JPYC proving a key is live).
- **R3 / R4a** — sponsored throughout, **no funding**.

Every integration case is **re-runnable**: R3/R4a use fresh ephemeral accounts; R4b/R4c
reset the owner back at the end so the funded account returns to its persisted passkey.
(If a funded account ever drifts — e.g. a run aborted mid-rotation — delete its
`.passkey-r4*.json` and re-fund the new address.)

| Case | Proves |
|---|---|
| **R2** | Hub-alone (50 < 100) **rejected on-chain, paymaster-less** (the de-risk); Hub+backup (100) succeeds |
| **R3** | guardian-quorum config-reset passkey-A → passkey-B; the new owner controls the account |
| **R4a** | recovery changes config **not address** (same address), and **no JPYC moved** |
| **R4b** | the **new** owner issues a buy-list session key under the weighted sudo → the agent pays |
| **R4c** | the **new** owner **revokes** the old session key → the same key can no longer pay, **no JPYC moved** (stale delegation killed; regular validators persist across root rotation, so revoke is explicit) |

**Live run result — Amoy 2026-06-20: 6/6 PASS ✅** (`recovery.test.ts`; 2 unit
[`recoveryCallData` `doRecovery` selector + `uninstallSessionKeyData` `uninstallValidation`
selector] + R2/R3+R4a/R4b/R4c). The recovery **mechanism** is also independently
gate-proven (`pnpm recovery:probe`): deploy weighted sudo → guardians-only `doRecovery`
to a new passkey → the new passkey signs alone at the same address.

**Amoy / zero-value / UNAUDITED.** The weighted-validator module + recovery executor +
hook are all deployed on Amoy; this is testnet-only and not a security claim.
