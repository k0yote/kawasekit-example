/**
 * RFC-0003 Cycle 2 (Approach B) — the weighted-validator owner.
 *
 * The account's sudo is ONE weighted validator [passkey 100, Hub 50, backup 50,
 * threshold 100]: the passkey signs alone for normal ops (weight 100); the guardian
 * quorum (Hub + backup = 100) is the recovery path. Multi-signer ops use the approve/
 * aggregate flow (`approveUserOperation` per signer → `sendUserOperationWithSignatures`).
 * The recovery executor is installed as a FALLBACK module via `pluginMigrations`
 * (NOT `plugins.action` → else on-chain `InvalidSelector`). All of this is gate-proven
 * on Amoy (2026-06-20) — see `probe-recovery.ts`.
 */
import { createKernelAccount, createZeroDevPaymasterClient } from "@zerodev/sdk";
import { getEntryPoint, KERNEL_V3_1 } from "@zerodev/sdk/constants";
import {
	createWeightedKernelAccountClient,
	createWeightedValidator,
	encodeSignatures,
	getRecoveryFallbackActionInstallModuleData,
	getValidatorAddress as getWeightedValidatorAddress,
	toECDSASigner,
	toWebAuthnSigner,
	type WeightedSigner,
	WeightedValidatorContractVersion,
} from "@zerodev/weighted-validator";
import { type Address, type Chain, type Hex, http, type LocalAccount, type PublicClient, type Transport } from "viem";
import { webAuthnKeyForPasskey } from "./account.ts";
import type { RfcConfig } from "./env.ts";
import type { SoftwarePasskey } from "./passkey.ts";

export const entryPoint = getEntryPoint("0.7");
export const WV = WeightedValidatorContractVersion.V0_0_2_PATCHED;
export const weightedValidatorAddress = getWeightedValidatorAddress(entryPoint.version, WV);

/** Owner-config weights: passkey alone (100) OR Hub+backup (50+50); no single guardian. */
export const OWNER_THRESHOLD = 100;
export const PASSKEY_WEIGHT = 100;
export const GUARDIAN_WEIGHT = 50;

// biome-ignore lint/suspicious/noExplicitAny: the weighted config signer publicKey is WebAuthnKey | Address (internal union).
export type OwnerConfig = { readonly threshold: number; readonly signers: { readonly publicKey: any; readonly weight: number }[] };

/** The Approach-B owner config: passkey 100 / Hub 50 / backup 50, threshold 100. */
export async function ownerConfig(passkey: SoftwarePasskey, rpID: string, hub: Address, backup: Address): Promise<OwnerConfig> {
	const webAuthnKey = await webAuthnKeyForPasskey(passkey, rpID);
	return {
		threshold: OWNER_THRESHOLD,
		signers: [
			{ publicKey: webAuthnKey, weight: PASSKEY_WEIGHT },
			{ publicKey: hub, weight: GUARDIAN_WEIGHT },
			{ publicKey: backup, weight: GUARDIAN_WEIGHT },
		],
	};
}

/** The passkey owner signer (weight 100) for the weighted validator. */
export async function passkeyOwnerSigner(
	publicClient: PublicClient<Transport, Chain>,
	passkey: SoftwarePasskey,
	rpID: string,
): Promise<WeightedSigner> {
	return toWebAuthnSigner(publicClient, { webAuthnKey: await webAuthnKeyForPasskey(passkey, rpID) });
}

/** A guardian (ECDSA) signer for the weighted validator. */
export function guardianSigner(guardian: LocalAccount): Promise<WeightedSigner> {
	return toECDSASigner({ signer: guardian });
}

/**
 * Build the weighted-sudo validator with the PASSKEY owner signer — for sudo-only flows
 * (the session-key issuance under the weighted owner, C1-revalidate). The passkey alone
 * meets the threshold (weight 100), so it is the normal-operation signer.
 */
export async function buildOwnerSudoValidator(
	publicClient: PublicClient<Transport, Chain>,
	passkey: SoftwarePasskey,
	rpID: string,
	hub: Address,
	backup: Address,
) {
	return createWeightedValidator(publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		validatorContractVersion: WV,
		signer: await passkeyOwnerSigner(publicClient, passkey, rpID),
		config: await ownerConfig(passkey, rpID, hub, backup),
	});
}

/**
 * The passkey OWNER (weight 100 ≥ threshold 100) approves a regular plugin (the session-key
 * permission validator) under the weighted sudo, returning the **weighted enable signature**
 * for `serializePermissionAccount(account, undefined, enableSignature)`. REQUIRED under a
 * weighted sudo: the default single-signer enable that `serializePermissionAccount` generates
 * is rejected on-chain (`EnableNotApproved` / `0xc48cf8ee`) — the canonical pattern
 * (`zerodev-examples/multisig/with-session-key.ts`) is `approvePlugin` + `encodeSignatures`.
 */
export async function approveSessionKeyEnable(
	publicClient: PublicClient<Transport, Chain>,
	cfg: RfcConfig,
	passkey: SoftwarePasskey,
	hub: Address,
	backup: Address,
	// biome-ignore lint/suspicious/noExplicitAny: the permission KernelValidator plugin type is internal.
	plugin: any,
	/** Bind to an existing deployed account (R4b: the recovered account under the new owner). */
	address?: Address,
): Promise<Hex> {
	const sudo = await createWeightedValidator(publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		validatorContractVersion: WV,
		signer: await passkeyOwnerSigner(publicClient, passkey, cfg.rpID),
		config: await ownerConfig(passkey, cfg.rpID, hub, backup),
	});
	const account = await createKernelAccount(publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		...(address !== undefined ? { address } : {}),
		plugins: { sudo },
	});
	const client = createWeightedKernelAccountClient({
		account,
		chain: cfg.chain,
		bundlerTransport: http(cfg.zerodevRpc),
		paymaster: createZeroDevPaymasterClient({ chain: cfg.chain, transport: http(cfg.zerodevRpc) }),
	});
	const approval = await client.approvePlugin({ plugin, validatorContractVersion: WV });
	if (approval === undefined) throw new Error("approveSessionKeyEnable: passkey-owner approvePlugin returned undefined");
	// Passkey alone (weight 100) meets the threshold, so one approval suffices.
	return encodeSignatures([approval], true);
}

export interface WeightedClientParams {
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly chain: Chain;
	readonly zerodevRpc: string;
	readonly config: OwnerConfig;
	readonly signer: WeightedSigner;
	/** Bind to an existing deployed account address (recovery / post-rotation). */
	readonly address?: Address;
	/** Sponsored (paymaster) — default true. Pass false for the §9 paymaster-less negatives (R2). */
	readonly sponsored?: boolean;
}

/**
 * A weighted-kernel client for ONE signer on the weighted-sudo account. For multi-signer
 * ops, build one client per signer and combine via {@link sendWeighted}.
 */
export async function weightedClientFor(params: WeightedClientParams) {
	const validator = await createWeightedValidator(params.publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		validatorContractVersion: WV,
		signer: params.signer,
		config: params.config,
	});
	const account = await createKernelAccount(params.publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		...(params.address !== undefined ? { address: params.address } : {}),
		plugins: { sudo: validator },
		pluginMigrations: [getRecoveryFallbackActionInstallModuleData(entryPoint.version)],
	});
	const paymaster =
		params.sponsored === false
			? undefined
			: createZeroDevPaymasterClient({ chain: params.chain, transport: http(params.zerodevRpc) });
	return createWeightedKernelAccountClient({
		account,
		chain: params.chain,
		bundlerTransport: http(params.zerodevRpc),
		...(paymaster !== undefined ? { paymaster } : {}),
	});
}

/**
 * Approve `callData` with each signer's client and submit the aggregated userOp.
 * Pass one client (passkey owner, weight 100) for a normal op, or both guardians for the
 * recovery quorum (50+50=100). Passing an under-threshold subset (one guardian) yields an
 * on-chain `validateUserOp` revert — that is R2's negative, run paymaster-less.
 */
export async function sendWeighted(
	clients: readonly Awaited<ReturnType<typeof weightedClientFor>>[],
	callData: Hex,
): Promise<{ readonly transactionHash: Hex | null }> {
	const sender = clients.at(-1);
	if (sender === undefined) throw new Error("sendWeighted: no signer clients provided");
	const signatures = await Promise.all(
		clients.map((c) => c.approveUserOperation({ callData, validatorContractVersion: WV })),
	);
	const hash = await sender.sendUserOperationWithSignatures({ callData, signatures });
	const receipt = await sender.waitForUserOperationReceipt({ hash });
	return { transactionHash: receipt.receipt.transactionHash };
}
