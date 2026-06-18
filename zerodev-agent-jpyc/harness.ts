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

import type { CreateKernelAccountReturnType } from "@zerodev/sdk";
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

/** What {@link preflight} reports back to the caller. */
export interface PreflightResult {
	/** The counterfactual Kernel address that holds JPYC and pays — FUND THIS. */
	readonly accountAddress: Address;
	/** Current on-chain JPYC balance of that account (raw units). */
	readonly jpycBalance: bigint;
	/** Whether the account bytecode is already on-chain (else the 1st userOp deploys it). */
	readonly deployed: boolean;
	/** True if the balance covers at least the H1 happy-path payment. */
	readonly sufficientForHappyPath: boolean;
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

	const [jpycBalance, code] = await Promise.all([
		publicClient.readContract({
			address: cfg.jpycAddress,
			abi: jpycAbi,
			functionName: "balanceOf",
			args: [accountAddress],
		}) as Promise<bigint>,
		publicClient.getCode({ address: accountAddress }),
	]);
	const deployed = code !== undefined && code !== "0x";
	const happyPathFloor = parseUnits("0.001", cfg.jpycDecimals);
	const sufficientForHappyPath = jpycBalance >= happyPathFloor;

	log("── RFC-0001 preflight ─────────────────────────────────────────");
	log(`  smart account (FUND THIS) : ${accountAddress}`);
	log(`  JPYC balance              : ${formatUnits(jpycBalance, cfg.jpycDecimals)} JPYC`);
	log(
		`  account deployed          : ${
			deployed ? "yes" : "no — the first userOp deploys it (gas policy MUST cover deploy+transfer)"
		}`,
	);
	if (sufficientForHappyPath) {
		log("  funding                   : ✅ enough for the H1 happy path");
	} else {
		log(
			`  funding                   : ⚠️  below ${formatUnits(happyPathFloor, cfg.jpycDecimals)} JPYC — send JPYC to the address above`,
		);
		log("                              from the JPYC Amoy faucet (recommend ≥ 1 JPYC for the full §8 suite).");
	}
	log("  gas (POL)                 : sponsored by the paymaster — do NOT fund POL to this account.");
	log("───────────────────────────────────────────────────────────────");

	return { accountAddress, jpycBalance, deployed, sufficientForHappyPath };
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
 * sponsored client, and send `JPYC.transfer(to, amount)`. Idempotent: a replay
 * with the same `{conversationId, stepId}` returns the cached result without a
 * second submission (RFC §6.2 step 7 / acceptance I1). Validation reverts (N1–N4)
 * propagate after a `validation_reject` span — the userOp never executes.
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
	// Latest-wins (F4): reflects the LAST sponsor outcome, robust to getPaymasterData
	// firing more than once per send. A genuine final decline → SponsorshipError below.
	let sponsorDeclined = false;
	const client = buildSponsoredKernelClient({
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
