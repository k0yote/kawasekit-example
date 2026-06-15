/**
 * RFC-0001 H1 happy-path runnable demo. Reads the repo-root `.env` (gitignored),
 * asserts JPYC on-chain, issues a buy-list-scoped session key (owner), and pays
 * the allowlisted merchant via a sponsored session-key userOp (agent), on Amoy.
 *
 * Prereqs (see README): JPYC address/decimals filled + verified, the account
 * funded with JPYC from the faucet, and a ZeroDev gas policy set on the Amoy
 * project (else sponsorship fails with a SponsorshipError).
 *
 *   pnpm zerodev:demo
 */

import "dotenv/config";

import type { TransferJpycResult } from "kawasekit";
import { parseUnits } from "viem";
import { accountsFromConfig, assertJpycOnChain, loadConfig, makePublicClient } from "./env.ts";
import { agentPay, buildBuyList, issueScopedSessionKey } from "./harness.ts";
import { consoleTelemetry } from "./observability.ts";

async function main(): Promise<void> {
	const cfg = loadConfig();
	const publicClient = makePublicClient(cfg);
	await assertJpycOnChain(publicClient, cfg); // aborts on decimals/address mismatch

	const { owner, session } = accountsFromConfig(cfg);
	const buyList = buildBuyList(cfg);
	const amount = parseUnits("0.001", cfg.jpycDecimals); // a small in-scope payment ≤ cap

	console.log("RFC-0001 ZeroDev e2e — Amoy");
	console.log(`  owner    : ${owner.address}`);
	console.log(`  session  : ${session.address}`);
	console.log(`  merchant : ${cfg.merchant} (allowlist)`);
	console.log(
		`  cap      : ${buyList.maxPerTransfer} units  count: ${buyList.maxTransfers}  validUntil: ${buyList.validUntil}`,
	);

	console.log("\n[owner] issuing scoped session key…");
	const approval = await issueScopedSessionKey({
		cfg,
		publicClient,
		ownerSigner: owner,
		sessionSigner: session,
		buyList,
	});
	console.log(`  serialized approval: ${approval.length} chars (handed to the agent)`);

	console.log("\n[agent] paying merchant via sponsored session-key userOp…");
	const cache = new Map<string, TransferJpycResult>();
	const out = await agentPay({
		cfg,
		publicClient,
		serializedApproval: approval,
		sessionSigner: session,
		to: cfg.merchant,
		amount,
		identity: { conversationId: "rfc-0001-demo", stepId: "pay-1" },
		cache,
		telemetry: consoleTelemetry,
	});

	console.log("\n✅ settled");
	console.log(`  userOpHash : ${out.result.userOpHash}`);
	console.log(`  tx         : ${out.result.transactionHash}`);
	console.log(`  success    : ${out.result.success}`);
	if (out.result.transactionHash) {
		console.log(`  explorer   : https://amoy.polygonscan.com/tx/${out.result.transactionHash}`);
	}
}

main().catch((e: unknown) => {
	console.error(e instanceof Error ? `${e.name}: ${e.message}` : String(e));
	process.exit(1);
});
