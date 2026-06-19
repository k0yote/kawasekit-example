/**
 * RFC-0003 Cycle 2 — Approach B RECOVERY GATE (the prerequisite for the foundation revision).
 *
 *   pnpm recovery:probe
 *
 * Confirms on Amoy that B's recovery works: the account's sudo is ONE weighted validator
 * [passkey-A (100), Hub (50), backup (50)], threshold 100. Recovery = the GUARDIANS ALONE
 * (Hub+backup = 100, passkey-A absent) reset the validator config to a NEW passkey-B, and
 * the new passkey then controls the account.
 *
 *   R1  deploy the weighted-sudo account (guardians sign; recovery action installed)
 *   R2  guardians-only doRecovery → reset config to [passkey-B (100), Hub, backup]
 *   R3  passkey-B alone (weight 100) signs → it is the new owner; SAME address (R4a)
 *
 * PASS = B's non-custodial recovery is real on Amoy, keeping a passkey owner. Sponsored,
 * ephemeral. Non-custodial caveat to record honestly in RFC §6.5: Hub+backup together hold
 * FULL owner power (not recovery-only) — but the user (backup) is required, so Hub alone
 * (50 < 100) cannot act.
 */
import "dotenv/config";

import { createKernelAccount, createZeroDevPaymasterClient } from "@zerodev/sdk";
import { getEntryPoint, KERNEL_V3_1 } from "@zerodev/sdk/constants";
import {
	createWeightedKernelAccountClient,
	createWeightedValidator,
	getRecoveryFallbackActionInstallModuleData,
	getValidatorAddress as getWeightedValidatorAddress,
	toECDSASigner,
	toWebAuthnSigner,
	type WeightedSigner,
	WeightedValidatorContractVersion,
} from "@zerodev/weighted-validator";
import { type Address, encodeFunctionData, type Hex, http, parseAbi, zeroAddress } from "viem";
import { webAuthnKeyForPasskey } from "./account.ts";
import { guardiansFromConfig, loadConfig, makePublicClient, type RfcConfig } from "./env.ts";
import { createSoftwarePasskey } from "./passkey.ts";

const entryPoint = getEntryPoint("0.7");
const WV = WeightedValidatorContractVersion.V0_0_2_PATCHED;
const RECOVERY_FN = "function doRecovery(address _validator, bytes calldata _data)" as const;

// biome-ignore lint/suspicious/noExplicitAny: weighted config signer/publicKey union is internal.
type WConfig = { threshold: number; signers: { publicKey: any; weight: number }[] };

async function main(): Promise<void> {
	const cfg: RfcConfig = loadConfig();
	const publicClient = makePublicClient(cfg);
	const { hub, userBackup } = guardiansFromConfig(cfg);
	const paymaster = createZeroDevPaymasterClient({ chain: cfg.chain, transport: http(cfg.zerodevRpc) });
	const weightedAddr = getWeightedValidatorAddress(entryPoint.version, WV);

	const hubSigner = await toECDSASigner({ signer: hub });
	const backupSigner = await toECDSASigner({ signer: userBackup });

	const passkeyA = createSoftwarePasskey();
	const webAuthnKeyA = await webAuthnKeyForPasskey(passkeyA, cfg.rpID);
	const initialConfig: WConfig = {
		threshold: 100,
		signers: [
			{ publicKey: webAuthnKeyA, weight: 100 },
			{ publicKey: hub.address, weight: 50 },
			{ publicKey: userBackup.address, weight: 50 },
		],
	};

	const clientFor = async (config: WConfig, signer: WeightedSigner, address?: Address) => {
		const v = await createWeightedValidator(publicClient, {
			entryPoint,
			kernelVersion: KERNEL_V3_1,
			validatorContractVersion: WV,
			signer,
			config,
		});
		const account = await createKernelAccount(publicClient, {
			entryPoint,
			kernelVersion: KERNEL_V3_1,
			...(address !== undefined ? { address } : {}),
			plugins: { sudo: v },
			// The new package installs the recovery executor (+ its hook) as a FALLBACK module
			// via a plugin migration — NOT via plugins.action (that left the doRecovery selector
			// unregistered → InvalidSelector). The migration runs on the first userOp (R1 deploy).
			pluginMigrations: [getRecoveryFallbackActionInstallModuleData(entryPoint.version)],
		});
		return createWeightedKernelAccountClient({ account, chain: cfg.chain, bundlerTransport: http(cfg.zerodevRpc), paymaster });
	};

	const hubClient = await clientFor(initialConfig, hubSigner);
	const backupClient = await clientFor(initialConfig, backupSigner);
	const deployedAddress = hubClient.account.address;

	console.log("RFC-0003 Cycle 2 — Approach B recovery gate (@zerodev/weighted-validator)\n");
	console.log(`  weighted-sudo account: ${deployedAddress}`);
	console.log(`  initial owner: passkey-A (w100) + guardians hub/backup (w50 each, thr 100)\n`);

	const noop = await hubClient.account.encodeCalls([{ to: zeroAddress, value: 0n, data: "0x" }]);

	// 2-of-2 (Hub + backup) send a callData via the approve/aggregate flow.
	const guardians2of2 = async (label: string, callData: Hex): Promise<boolean> => {
		try {
			const s1 = await hubClient.approveUserOperation({ callData, validatorContractVersion: WV });
			const s2 = await backupClient.approveUserOperation({ callData, validatorContractVersion: WV });
			const hash = await backupClient.sendUserOperationWithSignatures({ callData, signatures: [s1, s2] });
			const r = await backupClient.waitForUserOperationReceipt({ hash });
			console.log(`✅ ${label}: ${r.receipt.transactionHash}`);
			return true;
		} catch (e) {
			console.log(`❌ ${label}: ${e instanceof Error ? e.message.split("\n").slice(0, 3).join(" | ") : String(e)}`);
			return false;
		}
	};

	// R1 — deploy the weighted-sudo account (guardians meet threshold; installs recovery action).
	if (!(await guardians2of2("R1 deploy weighted-sudo account (guardians)", noop))) return done(false);

	// R2 — guardians-only doRecovery → reset config to a NEW passkey-B (passkey-A is "lost").
	const passkeyB = createSoftwarePasskey();
	const webAuthnKeyB = await webAuthnKeyForPasskey(passkeyB, cfg.rpID);
	const newConfig: WConfig = {
		threshold: 100,
		signers: [
			{ publicKey: webAuthnKeyB, weight: 100 },
			{ publicKey: hub.address, weight: 50 },
			{ publicKey: userBackup.address, weight: 50 },
		],
	};
	const newWeighted = await createWeightedValidator(publicClient, {
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		validatorContractVersion: WV,
		signer: hubSigner,
		config: newConfig,
	});
	const newData = await newWeighted.getEnableData();
	const doRecoveryCallData = encodeFunctionData({
		abi: parseAbi([RECOVERY_FN]),
		functionName: "doRecovery",
		args: [weightedAddr, newData],
	});
	if (!(await guardians2of2("R2 guardians-only doRecovery → reset config to passkey-B", doRecoveryCallData))) return done(false);

	// R3 — the NEW passkey-B (weight 100) signs ALONE at the SAME address (R4a address invariant).
	try {
		const passkeyBSigner = await toWebAuthnSigner(publicClient, { webAuthnKey: webAuthnKeyB });
		const bClient = await clientFor(newConfig, passkeyBSigner, deployedAddress);
		const bNoop = await bClient.account.encodeCalls([{ to: zeroAddress, value: 0n, data: "0x" }]);
		const s = await bClient.approveUserOperation({ callData: bNoop, validatorContractVersion: WV });
		const hash = await bClient.sendUserOperationWithSignatures({ callData: bNoop, signatures: [s] });
		const r = await bClient.waitForUserOperationReceipt({ hash });
		console.log(`✅ R3 new passkey-B signs alone (w100) @ same address: ${r.receipt.transactionHash}`);
	} catch (e) {
		console.log(`❌ R3 new passkey-B signs: ${e instanceof Error ? e.message.split("\n").slice(0, 3).join(" | ") : String(e)}`);
		return done(false);
	}
	done(true);
}

function done(ok: boolean): void {
	console.log("\n--- gate ---");
	console.log(
		ok
			? "✅ GATE PASSED — guardians-only config-reset to a new passkey works on Amoy, and the new passkey owns the account at the same address. → proceed to revise RFC §6.2–6.5 to Approach B."
			: "❌ GATE NOT PASSED — read the failing step above. Do NOT revise the foundation until R1–R3 are green.",
	);
}

main().catch((e: unknown) => {
	console.error(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
	process.exit(1);
});
