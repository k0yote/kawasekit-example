/**
 * RFC-0003 Cycle 2 — R3a non-custodial recovery wiring (ZeroDev).
 *
 * The recoverable account = the Cycle-1 passkey-sudo account with a weighted guardian
 * validator (regular) + the recovery action installed. Recovery is a
 * `doRecovery(_validator, _data)` userOp signed by the GUARDIANS (not the passkey):
 * `_validator` = the passkey-validator module address, `_data` = the NEW passkey's
 * `getEnableData()` → the sudo rotates passkey→passkey. Guardians = {Hub, user backup},
 * weight 1 each, threshold 2 → neither alone can rotate (the non-custodial proof).
 *
 * UNAUDITED / Amoy / zero-value. The U1/U4 crux (recovery works with the passkey
 * provably disabled; the executor re-inits the passkey validator on-chain) is settled
 * empirically by `probe-recovery.ts` — see docs/rfc/0003-cycle2-recovery-plan.md.
 */
import { getValidatorAddress as getPasskeyValidatorAddress, PasskeyValidatorContractVersion } from "@zerodev/passkey-validator";
import { type CreateKernelAccountReturnType, createKernelAccount } from "@zerodev/sdk";
import { getEntryPoint, KERNEL_V3_1 } from "@zerodev/sdk/constants";
import { createWeightedECDSAValidator, getRecoveryAction } from "@zerodev/weighted-ecdsa-validator";
import {
	type Address,
	type Chain,
	encodeFunctionData,
	type Hex,
	type LocalAccount,
	parseAbi,
	type PublicClient,
	type Transport,
} from "viem";
import { buildLostPasskeyValidator, buildPasskeyValidator } from "./account.ts";
import type { RfcConfig } from "./env.ts";
import { buildSelfPaidKernelClient, buildSponsoredKernelClient } from "./harness.ts";
import type { SoftwarePasskey } from "./passkey.ts";

const entryPoint = getEntryPoint("0.7");

/** The doRecovery executor (verbatim from ZeroDev's guardians/recovery.ts example). */
const RECOVERY_EXECUTOR_FN = "function doRecovery(address _validator, bytes calldata _data)" as const;

/** The ON-CHAIN weighted guardian set (who the guardians are + the threshold). */
export interface GuardianSet {
	readonly guardians: readonly { readonly address: Address; readonly weight: number }[];
	readonly threshold: number;
}

/** The default R3a set: {Hub, user backup}, weight 1 each, threshold 2 (neither alone rotates). */
export function twoOfTwoGuardians(hub: Address, userBackup: Address): GuardianSet {
	return {
		guardians: [
			{ address: hub, weight: 1 },
			{ address: userBackup, weight: 1 },
		],
		threshold: 2,
	};
}

/**
 * Build the weighted guardian validator. `set` is the ON-CHAIN weighted set (guardians +
 * threshold). `signers` is which LOCAL accounts actually sign NOW — pass enough weight to
 * meet the threshold for a valid recovery, or fewer for an under-threshold attempt (R2).
 */
export async function buildGuardianValidator(
	publicClient: PublicClient<Transport, Chain>,
	params: { readonly set: GuardianSet; readonly signers: readonly LocalAccount[] },
) {
	return createWeightedECDSAValidator(publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		config: { threshold: params.set.threshold, signers: [...params.set.guardians] },
		signers: [...params.signers],
	});
}

/**
 * The recoverable account: sudo = the passkey, regular = the guardian validator, action =
 * the recovery action. `signers` selects who co-signs a recovery userOp built from this
 * account. `lostPasskey` builds the sudo with a THROWING passkey signer (proves recovery
 * never uses the owner key) — address derivation is unaffected (public key only).
 */
export async function createRecoverableAccount(params: {
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly passkey: SoftwarePasskey;
	readonly rpID: string;
	readonly set: GuardianSet;
	readonly signers: readonly LocalAccount[];
	readonly lostPasskey?: boolean;
}): Promise<CreateKernelAccountReturnType<"0.7">> {
	const sudo = params.lostPasskey
		? await buildLostPasskeyValidator(params.publicClient, params.passkey, params.rpID)
		: await buildPasskeyValidator(params.publicClient, params.passkey, params.rpID);
	const guardian = await buildGuardianValidator(params.publicClient, {
		set: params.set,
		signers: params.signers,
	});
	return createKernelAccount(params.publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		plugins: { sudo, regular: guardian, action: getRecoveryAction(entryPoint.version) },
	});
}

/** Build the doRecovery callData that rotates the sudo to a NEW passkey. */
export async function buildDoRecoveryCallData(
	publicClient: PublicClient<Transport, Chain>,
	newPasskey: SoftwarePasskey,
	rpID: string,
): Promise<Hex> {
	const passkeyValidatorAddress = getPasskeyValidatorAddress(
		entryPoint,
		KERNEL_V3_1,
		PasskeyValidatorContractVersion.V0_0_3_PATCHED,
	);
	const newValidator = await buildPasskeyValidator(publicClient, newPasskey, rpID);
	const newEnableData = await newValidator.getEnableData();
	return encodeFunctionData({
		abi: parseAbi([RECOVERY_EXECUTOR_FN]),
		functionName: "doRecovery",
		args: [passkeyValidatorAddress, newEnableData],
	});
}

/**
 * Send the doRecovery userOp from the recoverable account, signed by `signers`. Pass both
 * guardians for a valid 2-of-2 (R3); pass one for an under-threshold attempt (R2).
 * `lostPasskey` builds the sudo with a throwing passkey (proves the recovery never uses
 * the owner key). `selfPaid` runs paymaster-LESS (R2's on-chain boundary, RFC §9);
 * default = sponsored (R1/R3, the Cycle-1 pattern, no account POL).
 */
export async function recoverOwner(params: {
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly cfg: RfcConfig;
	readonly passkey: SoftwarePasskey;
	readonly set: GuardianSet;
	readonly signers: readonly LocalAccount[];
	readonly newPasskey: SoftwarePasskey;
	readonly lostPasskey?: boolean;
	readonly selfPaid?: boolean;
}): Promise<{ readonly transactionHash: Hex | null }> {
	const account = await createRecoverableAccount({
		publicClient: params.publicClient,
		passkey: params.passkey,
		rpID: params.cfg.rpID,
		set: params.set,
		signers: params.signers,
		lostPasskey: params.lostPasskey,
	});
	const client = params.selfPaid
		? buildSelfPaidKernelClient({ account, cfg: params.cfg })
		: buildSponsoredKernelClient({ account, cfg: params.cfg });
	const callData = await buildDoRecoveryCallData(params.publicClient, params.newPasskey, params.cfg.rpID);
	const hash = await client.sendUserOperation({ callData });
	const receipt = await client.waitForUserOperationReceipt({ hash });
	return { transactionHash: receipt.receipt.transactionHash };
}

/**
 * Build a kernel account at the EXISTING recovered address, owned by the NEW passkey
 * (sudo-only; no regular plugin). Used to transact / revoke as the new owner — the
 * address is fixed at deploy (`address = f(sudo)` in Kernel v3.1), so the recovered
 * account keeps its address while its root validator now verifies the new passkey.
 */
export async function bindNewOwnerAccount(params: {
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly newPasskey: SoftwarePasskey;
	readonly rpID: string;
	readonly address: Address;
}): Promise<CreateKernelAccountReturnType<"0.7">> {
	const sudo = await buildPasskeyValidator(params.publicClient, params.newPasskey, params.rpID);
	return createKernelAccount(params.publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		address: params.address,
		plugins: { sudo },
	});
}
