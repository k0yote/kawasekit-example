/**
 * RFC-0003 Cycle 1 — the on-chain P1 prover (layer b).
 *
 * Builds a passkey-sudo account, persists the software passkey so the counterfactual
 * address is STABLE (fund it once), and sends a sponsored JPYC transfer signed by the
 * PASSKEY OWNER. P1 = this tx lands on Amoy with success:true → the whole chain works
 * (ox authenticator → ZeroDev wire encode → duo-mode P256 verification on-chain).
 *
 * Run: `pnpm tsx zerodev-passkey-jpyc/probe-passkey.ts` — first run prints the address to
 * fund (JPYC + a blanket sponsor-all gas policy) and exits; re-run after funding lands P1.
 * (Throwaway prover; superseded by harness.test.ts P1 once green. The persisted passkey
 * file is gitignored.)
 */
import "dotenv/config";

import { existsSync, readFileSync, writeFileSync } from "node:fs";
import {
	createSponsoredKernelClient,
	getJpycAddress,
	JPYC_DECIMALS,
	jpycAbi,
	polygonAmoy,
	transferJpyc,
	zerodevRpcUrl,
} from "kawasekit";
import { createPublicClient, getAddress, type Hex, http, parseUnits } from "viem";
import { createPasskeyAccount } from "./account.ts";
import { createSoftwarePasskey, passkeyFromStored, type SoftwarePasskey } from "./passkey.ts";

const PASSKEY_FILE = new URL(".passkey-cycle1.json", import.meta.url);
const need = (k: string): string => {
	const v = process.env[k];
	if (!v || v.trim() === "") throw new Error(`missing env ${k}`);
	return v.trim();
};

/** Persist `{ privateKey, id }` so the account address recurs (fund once). */
function loadOrCreatePasskey(): SoftwarePasskey {
	if (existsSync(PASSKEY_FILE)) {
		const j = JSON.parse(readFileSync(PASSKEY_FILE, "utf8")) as { privateKey: Hex; id: string };
		return passkeyFromStored(j.privateKey, j.id);
	}
	const pk = createSoftwarePasskey();
	writeFileSync(PASSKEY_FILE, JSON.stringify({ privateKey: pk.privateKey, id: pk.id }, null, 2));
	return pk;
}

async function main(): Promise<void> {
	const projectId = need("ZERODEV_PROJECT_ID");
	const rpID = process.env.PASSKEY_RPID ?? "kawasekit.local";
	const merchant = getAddress(need("MERCHANT_ADDRESS"));
	const publicClient = createPublicClient({ chain: polygonAmoy, transport: http(need("AMOY_RPC")) });

	const passkey = loadOrCreatePasskey();
	const account = await createPasskeyAccount({ publicClient, passkey, rpID });
	console.log("RFC-0003 P1 — passkey-sudo account:", account.address);

	const jpyc = (await publicClient.readContract({
		address: getJpycAddress(polygonAmoy.id),
		abi: jpycAbi,
		functionName: "balanceOf",
		args: [account.address],
	})) as bigint;
	if (jpyc < parseUnits("0.001", JPYC_DECIMALS)) {
		console.log(`\nFUND THIS address with JPYC (Amoy) + set a blanket sponsor-all gas policy, then re-run.`);
		console.log(`  ${account.address}  (current JPYC: ${jpyc})`);
		process.exit(1);
	}

	const client = createSponsoredKernelClient({
		account,
		chain: polygonAmoy,
		zerodevRpc: zerodevRpcUrl(polygonAmoy, projectId),
		publicClient,
	});
	console.log("paying merchant via a PASSKEY-signed sponsored userOp…");
	const res = await transferJpyc(client, { to: merchant, amount: parseUnits("0.001", JPYC_DECIMALS) });
	console.log("\n✅ P1:", res.success === true ? "PASS" : "FAILED");
	console.log("  tx:", res.transactionHash);
	console.log("  explorer:", `https://amoy.polygonscan.com/tx/${res.transactionHash ?? ""}`);
	if (res.success !== true) process.exit(1);
}

main().catch((e: unknown) => {
	console.error(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
	process.exit(1);
});
