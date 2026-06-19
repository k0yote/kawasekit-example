/**
 * RFC-0003 Cycle 2 foundation spike — AA23 isolation diagnostic (v2).
 *
 *   pnpm recovery:probe
 *
 * The combined deploy + enable-guardian + doRecovery userOp reverts in validation. This
 * isolates the cause with a CONTROL and a single-variable split, printing the full revert
 * reason (the previous run truncated it). All single-guardian (the proven example shape),
 * owner present, sponsored, ephemeral accounts — we are finding WHY validation reverts.
 *
 *   A (CONTROL) ECDSA sudo → ECDSA target  = ZeroDev's proven example, on OUR Amoy setup.
 *                                            MUST pass, else the problem is environmental
 *                                            (RPC / paymaster / recovery-action-on-Amoy),
 *                                            not passkey-specific.
 *   B           passkey sudo → ECDSA target = can a passkey be the ENABLING ROOT + rotate?
 *   C           passkey sudo → passkey target = the real design (passkey re-init, U4).
 */
import "dotenv/config";

import { getValidatorAddress as getEcdsaValidatorAddress, signerToEcdsaValidator } from "@zerodev/ecdsa-validator";
import { getValidatorAddress as getPasskeyValidatorAddress, PasskeyValidatorContractVersion } from "@zerodev/passkey-validator";
import { createKernelAccount, type CreateKernelAccountReturnType } from "@zerodev/sdk";
import { getEntryPoint, KERNEL_V3_1 } from "@zerodev/sdk/constants";
import { createWeightedECDSAValidator, getRecoveryAction } from "@zerodev/weighted-ecdsa-validator";
import { type Address, encodeFunctionData, type Hex, parseAbi } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { buildPasskeyValidator } from "./account.ts";
import { loadConfig, makePublicClient, type RfcConfig } from "./env.ts";
import { buildSponsoredKernelClient } from "./harness.ts";
import { createSoftwarePasskey } from "./passkey.ts";

const entryPoint = getEntryPoint("0.7");
const RECOVERY_FN = "function doRecovery(address _validator, bytes calldata _data)" as const;

// One throwaway guardian EOA for all stages (we need its key to sign; the env Hub address
// would do for config, but the diagnostic holds the key to keep it self-contained).
const GUARDIAN_KEY = generatePrivateKey();

/** Surface the on-chain revert reason (AA-code) instead of the generic HTTP wrapper. */
function detail(e: unknown): string {
	if (!(e instanceof Error)) return String(e);
	const m = e.message;
	const reason = m.match(/reason:\s*([^\n"]+)/)?.[1] ?? m.match(/Details:\s*([^\n]+)/)?.[1];
	return (reason ?? m.split("\n").slice(0, 4).join(" | ")).trim();
}

async function attempt(
	label: string,
	a: {
		readonly publicClient: ReturnType<typeof makePublicClient>;
		readonly cfg: RfcConfig;
		// biome-ignore lint/suspicious/noExplicitAny: ZeroDev validator union is internal; this is a throwaway diagnostic.
		readonly sudoValidator: any;
		readonly guardian: Address;
		readonly targetValidator: Address;
		readonly targetData: Hex;
	},
): Promise<boolean> {
	try {
		const guardianValidator = await createWeightedECDSAValidator(a.publicClient, {
			entryPoint,
			kernelVersion: KERNEL_V3_1,
			config: { threshold: 1, signers: [{ address: a.guardian, weight: 1 }] },
			signers: [privateKeyToAccount(GUARDIAN_KEY)],
		});
		const account = (await createKernelAccount(a.publicClient, {
			entryPoint,
			kernelVersion: KERNEL_V3_1,
			plugins: { sudo: a.sudoValidator, regular: guardianValidator, action: getRecoveryAction(entryPoint.version) },
		})) as CreateKernelAccountReturnType<"0.7">;
		const client = buildSponsoredKernelClient({ account, cfg: a.cfg });
		const callData = encodeFunctionData({
			abi: parseAbi([RECOVERY_FN]),
			functionName: "doRecovery",
			args: [a.targetValidator, a.targetData],
		});
		const hash = await client.sendUserOperation({ callData });
		const receipt = await client.waitForUserOperationReceipt({ hash });
		console.log(`✅ ${label}: PASS — ${receipt.receipt.transactionHash}`);
		return true;
	} catch (e) {
		console.log(`❌ ${label}: ${detail(e)}`);
		return false;
	}
}

async function main(): Promise<void> {
	const cfg = loadConfig();
	const publicClient = makePublicClient(cfg);
	const guardian = privateKeyToAccount(GUARDIAN_KEY);

	console.log("RFC-0003 Cycle 2 — AA23 isolation diagnostic v2 (full revert reasons)\n");

	// Common targets.
	const newEcdsa = privateKeyToAccount(generatePrivateKey());
	const ecdsaTargetValidator = getEcdsaValidatorAddress(entryPoint, KERNEL_V3_1);
	const newPasskey = createSoftwarePasskey();
	const passkeyTargetValidator = getPasskeyValidatorAddress(entryPoint, KERNEL_V3_1, PasskeyValidatorContractVersion.V0_0_3_PATCHED);
	const passkeyTargetData = await (await buildPasskeyValidator(publicClient, newPasskey, cfg.rpID)).getEnableData();

	// A — CONTROL: ECDSA sudo → ECDSA target (the proven example).
	const oldEcdsa = privateKeyToAccount(generatePrivateKey());
	const ecdsaSudo = await signerToEcdsaValidator(publicClient, { signer: oldEcdsa, entryPoint, kernelVersion: KERNEL_V3_1 });
	const a = await attempt("A control  ECDSA→ECDSA ", {
		publicClient,
		cfg,
		sudoValidator: ecdsaSudo,
		guardian: guardian.address,
		targetValidator: ecdsaTargetValidator,
		targetData: newEcdsa.address,
	});

	// B — passkey sudo → ECDSA target (isolate the passkey ENABLING ROOT).
	const passkey = createSoftwarePasskey();
	const passkeySudoB = await buildPasskeyValidator(publicClient, passkey, cfg.rpID);
	const b = await attempt("B          passkey→ECDSA", {
		publicClient,
		cfg,
		sudoValidator: passkeySudoB,
		guardian: guardian.address,
		targetValidator: ecdsaTargetValidator,
		targetData: newEcdsa.address,
	});

	// C — passkey sudo → passkey target (the real design; passkey re-init / U4).
	const passkeyC = createSoftwarePasskey();
	const passkeySudoC = await buildPasskeyValidator(publicClient, passkeyC, cfg.rpID);
	const c = await attempt("C          passkey→passkey", {
		publicClient,
		cfg,
		sudoValidator: passkeySudoC,
		guardian: guardian.address,
		targetValidator: passkeyTargetValidator,
		targetData: passkeyTargetData,
	});

	console.log("\n--- diagnosis ---");
	if (!a) console.log("A (control) FAILED → environmental, not passkey: RPC/paymaster/recovery-action on Amoy. Fix that first.");
	else if (a && !b) console.log("A passes, B fails → a PASSKEY cannot be the enabling root for the guardian (enable-mode). Deeper design issue.");
	else if (a && b && !c) console.log("A+B pass, C fails → passkey-as-root works; the PASSKEY RE-INIT target (U4) is unsupported by doRecovery. Rotate to a fresh ECDSA or find a passkey change-pubkey path.");
	else if (a && b && c) console.log("All pass → the original 2-of-2 combined op was the issue (U2 aggregation). Revisit the 2-of-2 signing.");
	console.log(`(guardian used: ${guardian.address})`);
}

main().catch((e: unknown) => {
	console.error(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
	process.exit(1);
});
