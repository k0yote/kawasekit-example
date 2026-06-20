/**
 * RFC-0003 Cycle 2 (Approach B) — non-custodial recovery.
 *
 * The owner is the weighted validator [passkey 100, Hub 50, backup 50, threshold 100].
 * Recovery = the guardian quorum (Hub + backup = 100) RESETS the weighted config to a NEW
 * passkey via `doRecovery(weightedValidatorAddress, newWeighted.getEnableData())`. The passkey
 * is never used — the guardians act alone, and the account address is unchanged. Gate-proven
 * on Amoy 2026-06-20 (see `probe-recovery.ts`).
 */
import { createWeightedValidator } from "@zerodev/weighted-validator";
import { KERNEL_V3_1 } from "@zerodev/sdk/constants";
import { type Address, type Chain, encodeFunctionData, type Hex, type LocalAccount, parseAbi, type PublicClient, type Transport } from "viem";
import type { RfcConfig } from "./env.ts";
import type { SoftwarePasskey } from "./passkey.ts";
import {
	entryPoint,
	guardianSigner,
	ownerConfig,
	passkeyOwnerSigner,
	sendWeighted,
	WV,
	weightedClientFor,
	weightedValidatorAddress,
} from "./weighted-account.ts";

/** The recovery executor (verbatim from ZeroDev). Resets the sudo validator's config. */
const RECOVERY_FN = "function doRecovery(address _validator, bytes calldata _data)" as const;

/**
 * The `doRecovery` callData that resets the weighted owner config to one with `newPasskey`
 * as the primary signer (+ the same guardians). `_validator` = the weighted validator module;
 * `_data` = the new config's `getEnableData()` blob. (`hub`/`backup` are LocalAccounts only to
 * build the validator object — its `getEnableData` depends on the config, not the signer.)
 */
export async function recoveryCallData(
	publicClient: PublicClient<Transport, Chain>,
	newPasskey: SoftwarePasskey,
	hub: LocalAccount,
	backup: LocalAccount,
	rpID: string,
): Promise<Hex> {
	const newConfig = await ownerConfig(newPasskey, rpID, hub.address, backup.address);
	const newWeighted = await createWeightedValidator(publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		validatorContractVersion: WV,
		signer: await guardianSigner(hub),
		config: newConfig,
	});
	return encodeFunctionData({
		abi: parseAbi([RECOVERY_FN]),
		functionName: "doRecovery",
		args: [weightedValidatorAddress, await newWeighted.getEnableData()],
	});
}

/**
 * Guardian-quorum (Hub + backup = 100) config-reset of the weighted owner to a NEW passkey.
 * `currentPasskey` fixes the on-chain config the guardians validate against; `newPasskey` is
 * the recovery target. Pass ONLY `hub` as the signer subset (via the harness) for R2's
 * under-threshold negative. `selfPaid` runs paymaster-less (R2's on-chain boundary).
 */
export async function recoverOwner(params: {
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly cfg: RfcConfig;
	readonly currentPasskey: SoftwarePasskey;
	readonly newPasskey: SoftwarePasskey;
	readonly hub: LocalAccount;
	readonly backup: LocalAccount;
	readonly address?: Address;
	readonly selfPaid?: boolean;
}): Promise<{ readonly transactionHash: Hex | null }> {
	const { publicClient, cfg, currentPasskey, newPasskey, hub, backup } = params;
	const currentConfig = await ownerConfig(currentPasskey, cfg.rpID, hub.address, backup.address);
	const callData = await recoveryCallData(publicClient, newPasskey, hub, backup, cfg.rpID);
	const sponsored = params.selfPaid !== true;
	const base = {
		publicClient,
		chain: cfg.chain,
		zerodevRpc: cfg.zerodevRpc,
		config: currentConfig,
		sponsored,
		...(params.address !== undefined ? { address: params.address } : {}),
	};
	const hubClient = await weightedClientFor({ ...base, signer: await guardianSigner(hub) });
	const backupClient = await weightedClientFor({ ...base, signer: await guardianSigner(backup) });
	return sendWeighted([hubClient, backupClient], callData);
}

/**
 * A weighted-kernel client at the (recovered) account address, controlled by the NEW passkey
 * owner — to prove the new owner can act (R3) and to issue session keys under the new owner
 * (R4b). The passkey alone (weight 100) meets the threshold, so it signs solo.
 */
export async function bindNewOwnerAccount(params: {
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly cfg: RfcConfig;
	readonly newPasskey: SoftwarePasskey;
	readonly hub: Address;
	readonly backup: Address;
	readonly address: Address;
	readonly sponsored?: boolean;
}) {
	return weightedClientFor({
		publicClient: params.publicClient,
		chain: params.cfg.chain,
		zerodevRpc: params.cfg.zerodevRpc,
		config: await ownerConfig(params.newPasskey, params.cfg.rpID, params.hub, params.backup),
		signer: await passkeyOwnerSigner(params.publicClient, params.newPasskey, params.cfg.rpID),
		address: params.address,
		...(params.sponsored !== undefined ? { sponsored: params.sponsored } : {}),
	});
}
