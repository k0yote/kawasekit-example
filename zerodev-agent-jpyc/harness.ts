/**
 * RFC-0001 end-to-end harness — owner issues a buy-list-scoped session key; the
 * agent pays an allowlisted merchant in JPYC via a session-key userOp with gas
 * sponsored by a paymaster (Option A: the userOp IS the settlement). Amoy only.
 *
 * Prefers kawasekit's public helpers; the ONE boundary gap is the sponsored
 * kernel-account CLIENT construction (kawasekit exposes `transferJpyc(client,…)`
 * + the `ConfiguredKernelClient` type but no helper to BUILD the client with a
 * ZeroDev bundler + paymaster), so `buildSponsoredKernelClient` drops to the raw
 * `@zerodev/sdk`. See README "SDK boundary findings".
 */

import { createKernelAccountClient, createZeroDevPaymasterClient } from "@zerodev/sdk";
import {
	type ConfiguredKernelClient,
	createBuyListPolicies,
	deriveIdempotencyKey,
	issueSessionKey,
	parseSessionEnvelope,
	restoreSessionAccount,
	serializeSessionEnvelope,
	transferJpyc,
	type TransferJpycResult,
} from "kawasekit";
import {
	type Address,
	type Chain,
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
 * agent the serialized approval. `issueSessionKey` only uses the session
 * account's ADDRESS (it wraps `addressToEmptyAccount` internally), so the owner
 * never signs with the session key.
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

/**
 * BOUNDARY GAP (RFC §6.4): build a sponsored Kernel client. kawasekit has no
 * public helper for this — raw `@zerodev/sdk`. Sponsorship rejection is surfaced
 * as a SponsorshipError; there is NO owner-pays-gas fallback (RFC §6.2/7).
 */
export function buildSponsoredKernelClient(params: {
	// biome-ignore lint/suspicious/noExplicitAny: kawasekit-restored Kernel account; the client's exact generic args are erased to ConfiguredKernelClient below.
	readonly account: any;
	readonly cfg: RfcConfig;
	readonly telemetry?: HarnessTelemetry;
}): ConfiguredKernelClient {
	const { cfg, account, telemetry } = params;
	const paymaster = createZeroDevPaymasterClient({ chain: cfg.chain, transport: http(cfg.zerodevRpc) });
	// biome-ignore lint/suspicious/noExplicitAny: createKernelAccountClient's deep generics don't unify with the exported ConfiguredKernelClient alias; transferJpyc accepts ConfiguredKernelClient — same runtime client.
	const client = createKernelAccountClient({
		account,
		chain: cfg.chain,
		bundlerTransport: http(cfg.zerodevRpc),
		paymaster: {
			getPaymasterData: async (userOperation: Parameters<typeof paymaster.sponsorUserOperation>[0]["userOperation"]) => {
				emit(telemetry, { phase: "sponsor", at: Date.now(), account: account.address });
				try {
					return await paymaster.sponsorUserOperation({ userOperation });
				} catch (cause) {
					throw new SponsorshipError(
						"paymaster declined to sponsor the userOp — set/raise a ZeroDev gas policy on the Amoy project (no owner-pays fallback).",
						{ cause },
					);
				}
			},
		},
	}) as unknown as ConfiguredKernelClient;
	return client;
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
	const client = buildSponsoredKernelClient({ account, cfg, telemetry });

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
		// A policy violation reverts at userOp VALIDATION (simulation) — the transfer
		// never executes, so the merchant balance is unchanged (the §8 discriminator).
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
