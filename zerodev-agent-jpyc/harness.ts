/**
 * RFC-0001 end-to-end harness — owner issues a buy-list-scoped session key; the
 * agent pays an allowlisted merchant in JPYC via a session-key userOp with gas
 * sponsored by a paymaster (Option A: the userOp IS the settlement). Amoy only.
 *
 * Uses kawasekit's public helpers throughout — including
 * `createSponsoredKernelClient` for the gas-sponsored client construction (SDK
 * gaps G1/G4 closed: no raw `@zerodev/sdk` wiring, no cast). The harness maps the
 * SDK's sponsorship observability onto its own `sponsor`/`sponsor_reject` spans.
 * See README "SDK boundary findings".
 */

import { type CreateKernelAccountReturnType, createKernelAccountClient } from "@zerodev/sdk";
import {
	type ConfiguredKernelClient,
	createBuyListPolicies,
	createSponsoredKernelClient,
	deriveIdempotencyKey,
	issueSessionKey,
	jpycAbi,
	parseSessionEnvelope,
	restoreSessionAccount,
	serializeSessionEnvelope,
	transferJpyc,
	type TransferJpycResult,
} from "kawasekit";
import {
	type Address,
	type Chain,
	formatUnits,
	http,
	type LocalAccount,
	parseUnits,
	type PublicClient,
	type Transport,
} from "viem";
import type { RfcConfig } from "./env.ts";
import { SponsorshipError } from "./errors.ts";
import { emit, type HarnessTelemetry } from "./observability.ts";

/** A resolved buy-list (what `createBuyListPolicies` needs). */
export interface ResolvedBuyList {
	readonly merchants: readonly Address[];
	readonly maxPerTransfer: bigint;
	readonly maxTransfers: number;
	readonly validUntil: number;
	readonly validAfter?: number;
}

/** Per-case overrides so the §8 negatives can tighten cap/count/window. */
export interface BuyListOverrides {
	readonly merchants?: readonly Address[];
	readonly maxPerTransferUnits?: bigint;
	readonly maxTransfers?: number;
	readonly validUntil?: number;
	readonly validAfter?: number;
	readonly nowSeconds?: number;
}

/** Build the demo buy-list from config (the allowlist = the single merchant). */
export function buildBuyList(cfg: RfcConfig, o: BuyListOverrides = {}): ResolvedBuyList {
	const now = o.nowSeconds ?? Math.floor(Date.now() / 1000);
	return {
		merchants: o.merchants ?? [cfg.merchant],
		maxPerTransfer: o.maxPerTransferUnits ?? parseUnits(String(cfg.maxPerTransferJpyc), cfg.jpycDecimals),
		maxTransfers: o.maxTransfers ?? cfg.maxTransfers,
		validUntil: o.validUntil ?? now + cfg.windowSeconds,
		...(o.validAfter !== undefined ? { validAfter: o.validAfter } : {}),
	};
}

/**
 * OWNER side — bake the buy-list into a disposable session key and hand the
 * agent the serialized approval. NOTE: kawasekit's `issueSessionKey` builds the
 * permission account with the REAL session signer (`toECDSASigner`), so the
 * issuer must hold the session private key at issuance time — it does NOT use
 * `addressToEmptyAccount`. The owner EOA remains the sole sudo authority; an
 * address-only issuance path (agent self-generates the key, owner ever sees only
 * the address) is a possible SDK follow-up (README G2 / RFC §10).
 */
export async function issueScopedSessionKey(params: {
	readonly cfg: RfcConfig;
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly ownerSigner: LocalAccount;
	readonly sessionSigner: LocalAccount;
	readonly buyList: ResolvedBuyList;
}): Promise<string> {
	const { cfg, buyList } = params;
	const policies = createBuyListPolicies({
		jpycAddress: cfg.jpycAddress,
		merchants: buyList.merchants,
		maxPerTransfer: buyList.maxPerTransfer,
		maxTransfers: buyList.maxTransfers,
		validUntil: buyList.validUntil,
		...(buyList.validAfter !== undefined ? { validAfter: buyList.validAfter } : {}),
	});
	const envelope = await issueSessionKey({
		publicClient: params.publicClient,
		ownerSigner: params.ownerSigner,
		sessionKeySigner: params.sessionSigner,
		policies,
		expiresAt: BigInt(buyList.validUntil),
	});
	return serializeSessionEnvelope(envelope);
}

/** Floor POL the smart account needs for the §9 paymaster-less negatives' prefund check. */
export const SELF_PAID_POL_FLOOR = parseUnits("0.05", 18);

/** What {@link preflight} reports back to the caller. */
export interface PreflightResult {
	/** The counterfactual Kernel address that holds JPYC and pays — FUND THIS. */
	readonly accountAddress: Address;
	/** Current on-chain JPYC balance of that account (raw units). */
	readonly jpycBalance: bigint;
	/** Current native POL balance (raw wei). Only the §9 self-paid negatives need it. */
	readonly polBalance: bigint;
	/** Whether the account bytecode is already on-chain (else the 1st userOp deploys it). */
	readonly deployed: boolean;
	/** True if the balance covers at least the H1 happy-path payment. */
	readonly sufficientForHappyPath: boolean;
	/**
	 * True if POL covers the §9 paymaster-less negatives' bundler prefund check
	 * ({@link SELF_PAID_POL_FLOOR}). The POL is NOT consumed — those ops revert at
	 * validation. H1/H2 stay sponsored and need no POL.
	 */
	readonly sufficientPolForSelfPaid: boolean;
}

/**
 * PREFLIGHT (RFC §7 / §11) — the live run's #1 failure mode is funding the wrong
 * address or a gas policy that can't deploy the account. This derives the EXACT
 * counterfactual Kernel address the agent will pay from (via the same issuance
 * path → envelope `smartAccountAddress`; issuance is LOCAL — no tx, no gas, no
 * funds needed), reads its JPYC balance + deployment state, and prints clear
 * funding guidance. It NEVER auto-funds and sends no transaction.
 */
export async function preflight(params: {
	readonly cfg: RfcConfig;
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly ownerSigner: LocalAccount;
	readonly sessionSigner: LocalAccount;
	/** Sink for the guidance lines (defaults to `console.log`; tests inject a recorder). */
	readonly log?: (line: string) => void;
}): Promise<PreflightResult> {
	const { cfg, publicClient } = params;
	const log = params.log ?? ((line: string) => console.log(line));

	// Issue locally (no tx) to obtain the same account the agent restores from.
	const serialized = await issueScopedSessionKey({
		cfg,
		publicClient,
		ownerSigner: params.ownerSigner,
		sessionSigner: params.sessionSigner,
		buyList: buildBuyList(cfg),
	});
	const accountAddress = parseSessionEnvelope(serialized).smartAccountAddress;

	const [jpycBalance, code, polBalance] = await Promise.all([
		publicClient.readContract({
			address: cfg.jpycAddress,
			abi: jpycAbi,
			functionName: "balanceOf",
			args: [accountAddress],
		}) as Promise<bigint>,
		publicClient.getCode({ address: accountAddress }),
		publicClient.getBalance({ address: accountAddress }),
	]);
	const deployed = code !== undefined && code !== "0x";
	const happyPathFloor = parseUnits("0.001", cfg.jpycDecimals);
	const sufficientForHappyPath = jpycBalance >= happyPathFloor;
	const sufficientPolForSelfPaid = polBalance >= SELF_PAID_POL_FLOOR;

	log("── RFC-0001 preflight ─────────────────────────────────────────");
	log(`  smart account (FUND THIS) : ${accountAddress}`);
	log(`  JPYC balance              : ${formatUnits(jpycBalance, cfg.jpycDecimals)} JPYC`);
	log(
		`  account deployed          : ${
			deployed ? "yes" : "no — the first userOp deploys it (gas policy MUST cover deploy+transfer)"
		}`,
	);
	if (sufficientForHappyPath) {
		log("  JPYC funding              : ✅ enough for the H1 happy path");
	} else {
		log(
			`  JPYC funding              : ⚠️  below ${formatUnits(happyPathFloor, cfg.jpycDecimals)} JPYC — send JPYC to the address above`,
		);
		log("                              from the JPYC Amoy faucet (recommend ≥ 1 JPYC for the full §8 suite).");
	}
	// POL: the SPONSORED path (H1/H2/I1/I2) needs none. The §9 paymaster-LESS negatives
	// (N1–N4 self-paid) need POL so the bundler's prefund check passes — it is NOT
	// consumed (they revert at validation).
	log(`  POL balance               : ${formatUnits(polBalance, 18)} POL`);
	if (sufficientPolForSelfPaid) {
		log("  POL (§9 self-paid negs)   : ✅ enough for the paymaster-less prefund check (not consumed)");
	} else {
		log(
			`  POL (§9 self-paid negs)   : ⚠️  below ${formatUnits(SELF_PAID_POL_FLOOR, 18)} POL — fund ~0.1 POL from the Amoy POL faucet`,
		);
		log("                              (https://faucet.polygon.technology/). NOT consumed — the negatives revert at validation.");
		log("                              The SPONSORED happy path (H1/H2) needs no POL.");
	}
	log("───────────────────────────────────────────────────────────────");

	return { accountAddress, jpycBalance, polBalance, deployed, sufficientForHappyPath, sufficientPolForSelfPaid };
}

/**
 * Build a sponsored Kernel client via the kawasekit SDK helper
 * `createSponsoredKernelClient` (no bespoke `@zerodev` wiring, no cast — SDK gaps
 * G1/G4 closed). The harness maps the SDK's sponsorship observability onto its own
 * spans (`sponsor` / `sponsor_reject`) and reports the LATEST sponsor outcome via
 * `onSponsorOutcome(declined)` so `agentPay` can surface a typed `SponsorshipError`
 * (no owner-pays fallback). Latest-wins (not sticky) is robust to `getPaymasterData`
 * firing more than once per send with mixed outcomes (review finding F4). This
 * keeps the §8 N1–N4 paymaster-vs-validator discriminator intact.
 */
export function buildSponsoredKernelClient(params: {
	readonly account: CreateKernelAccountReturnType<"0.7">;
	readonly cfg: RfcConfig;
	readonly telemetry?: HarnessTelemetry;
	readonly onSponsorOutcome?: (declined: boolean) => void;
}): ConfiguredKernelClient {
	const { cfg, telemetry } = params;
	return createSponsoredKernelClient({
		account: params.account,
		chain: cfg.chain,
		zerodevRpc: cfg.zerodevRpc,
		observability: {
			onSponsor: ({ account }) => {
				emit(telemetry, { phase: "sponsor", at: Date.now(), account });
				params.onSponsorOutcome?.(false);
			},
			onSponsorError: ({ account }) => {
				emit(telemetry, { phase: "sponsor_reject", at: Date.now(), account });
				params.onSponsorOutcome?.(true);
			},
		},
	});
}

/**
 * §9 FALLBACK (Amoy run #1) — build a Kernel client WITHOUT a paymaster: the
 * account pays its own gas (POL). Used ONLY by the paymaster-less N1–N4 so the
 * on-chain permission validator is the **sole** rejecter — there is no verifying
 * paymaster to simulate-and-decline (the run-#1 finding) and conflate the signal.
 * No `sponsor`/`sponsor_reject` here; a rejection surfaces as the raw on-chain
 * validation error → `validation_reject`. Deliberately raw `@zerodev/sdk` (the
 * sponsored path keeps using `createSponsoredKernelClient`, untouched).
 */
export function buildSelfPaidKernelClient(params: {
	readonly account: CreateKernelAccountReturnType<"0.7">;
	readonly cfg: RfcConfig;
}): ConfiguredKernelClient {
	const { cfg, account } = params;
	const client = createKernelAccountClient({
		account,
		chain: cfg.chain,
		bundlerTransport: http(cfg.zerodevRpc),
		// no `paymaster` middleware → the account self-pays gas from its POL balance.
	});
	// Same deep-generic non-unify as createSponsoredKernelClient — one documented cast.
	return client as unknown as ConfiguredKernelClient;
}

export interface AgentPayIdentity {
	readonly conversationId: string;
	readonly stepId: string;
}

export interface AgentPayResult {
	readonly key: string;
	readonly deduped: boolean;
	readonly result: TransferJpycResult;
}

/**
 * AGENT side — deserialize the approval with the REAL session signer, build the
 * client, and send `JPYC.transfer(to, amount)`. Idempotent: a replay with the same
 * `{conversationId, stepId}` returns the cached result without a second submission
 * (RFC §6.2 step 7 / acceptance I1).
 *
 * `selfPaid` (default false) selects the path: SPONSORED (paymaster) vs the §9
 * paymaster-LESS path (the account self-pays gas). On the self-paid path there is
 * no paymaster, so a policy rejection surfaces as the raw on-chain validation error
 * → a `validation_reject` span (no `sponsor`/`sponsor_reject`, no `SponsorshipError`).
 */
export async function agentPay(params: {
	readonly cfg: RfcConfig;
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly serializedApproval: string;
	readonly sessionSigner: LocalAccount;
	readonly to: Address;
	readonly amount: bigint;
	readonly identity: AgentPayIdentity;
	readonly cache: Map<string, TransferJpycResult>;
	readonly telemetry?: HarnessTelemetry;
	/** §9 fallback: pay gas from the account's own POL (no paymaster). Default false. */
	readonly selfPaid?: boolean;
}): Promise<AgentPayResult> {
	const { cfg, identity, cache, telemetry } = params;
	// kawasekit-derived idempotency key for "the same logical payment step".
	const key = deriveIdempotencyKey({ conversationId: identity.conversationId, stepId: identity.stepId });
	const cached = cache.get(key);
	if (cached !== undefined) {
		return { key, deduped: true, result: cached };
	}

	const envelope = parseSessionEnvelope(params.serializedApproval);
	const account = await restoreSessionAccount({
		publicClient: params.publicClient,
		envelope,
		sessionKeySigner: params.sessionSigner,
	});
	// SPONSORED (default) vs SELF-PAID (§9 fallback). Latest-wins (F4): sponsorDeclined
	// reflects the LAST sponsor outcome, robust to getPaymasterData firing more than once.
	// On the self-paid path there is no paymaster → sponsorDeclined stays false → a
	// rejection emits `validation_reject` below (the on-chain validator is the sole rejecter).
	let sponsorDeclined = false;
	const client = params.selfPaid
		? buildSelfPaidKernelClient({ account, cfg })
		: buildSponsoredKernelClient({
				account,
				cfg,
				telemetry,
				onSponsorOutcome: (declined) => {
					sponsorDeclined = declined;
				},
			});

	emit(telemetry, {
		phase: "submit",
		at: Date.now(),
		account: account.address,
		to: params.to,
		amount: params.amount.toString(),
	});
	try {
		const result = await transferJpyc(client, { to: params.to, amount: params.amount });
		emit(telemetry, {
			phase: "settle",
			at: Date.now(),
			account: account.address,
			to: params.to,
			amount: params.amount.toString(),
			...(result.transactionHash !== null ? { transaction: result.transactionHash } : {}),
		});
		cache.set(key, result);
		return { key, deduped: false, result };
	} catch (err) {
		// A paymaster decline (onSponsorOutcome(true) → sponsorDeclined) is NOT a policy
		// rejection. The SDK helper re-throws the RAW paymaster error, so the harness
		// re-establishes the typed SponsorshipError here (no owner-pays fallback) — the
		// signal the §8 tests discriminate on.
		if (sponsorDeclined) {
			throw new SponsorshipError(
				"paymaster declined to sponsor the userOp — set/raise a ZeroDev gas policy on the Amoy project (no owner-pays fallback).",
				{ cause: err },
			);
		}
		// Otherwise the userOp was rejected at VALIDATION (the permission validator) — the
		// transfer never executed, so the merchant balance is unchanged (the §8 discriminator).
		emit(telemetry, {
			phase: "validation_reject",
			at: Date.now(),
			account: account.address,
			to: params.to,
			detail: err instanceof Error ? err.message : String(err),
		});
		throw err;
	}
}
