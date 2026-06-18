/**
 * RFC-0003 Cycle 1 P2 happy-path runnable demo — the RFC-0001 agent flow under a
 * PASSKEY owner. Reads the repo-root `.env` (gitignored), asserts JPYC on-chain,
 * issues a buy-list-scoped session key UNDER THE PASSKEY SUDO, and pays the
 * allowlisted merchant via a sponsored session-key userOp (agent), on Amoy.
 *
 * The owner-direct P1 (a passkey-signed userOp lands) is proven separately by
 * `pnpm passkey:p1` (probe-passkey.ts) and the harness P1 integration test; this
 * demo exercises the session-key floor (the actual agent-payment product flow).
 *
 * Prereqs (see README): JPYC address/decimals filled + verified, the PASSKEY
 * smart account funded with JPYC from the faucet, and a ZeroDev gas policy set on
 * the Amoy project (else sponsorship fails with a SponsorshipError). The passkey
 * is persisted to `.passkey-cycle1.json` (gitignored) so the address is stable.
 *
 *   pnpm zerodev:passkey:demo
 */

import "dotenv/config";

import type { TransferJpycResult } from "kawasekit";
import { parseUnits } from "viem";
import { assertJpycOnChain, loadConfig, loadOrCreatePasskey, makePublicClient, sessionFromConfig } from "./env.ts";
import { agentPay, buildBuyList, issuePasskeyScopedSessionKey, preflight } from "./harness.ts";
import { consoleTelemetry } from "./observability.ts";

const PASSKEY_FILE = new URL(".passkey-cycle1.json", import.meta.url);

async function main(): Promise<void> {
	const cfg = loadConfig();
	const publicClient = makePublicClient(cfg);
	await assertJpycOnChain(publicClient, cfg); // aborts on decimals/address mismatch

	const passkey = loadOrCreatePasskey(PASSKEY_FILE);
	const session = sessionFromConfig(cfg);
	const buyList = buildBuyList(cfg);
	const amount = parseUnits("0.001", cfg.jpycDecimals); // a small in-scope payment ≤ cap

	console.log("RFC-0003 Cycle 1 P2 — passkey owner, ZeroDev e2e — Amoy");
	console.log(`  owner    : passkey id ${passkey.id} (rpID ${cfg.rpID}; WebAuthn sudo, no private key)`);
	console.log(`  session  : ${session.address}`);
	console.log(`  merchant : ${cfg.merchant} (allowlist)`);
	console.log(
		`  cap      : ${buyList.maxPerTransfer} units  count: ${buyList.maxTransfers}  validUntil: ${buyList.validUntil}`,
	);

	console.log("\n[preflight] resolving the counterfactual account + checking JPYC funding…");
	const pf = await preflight({ cfg, publicClient, passkey, sessionSigner: session });
	if (!pf.sufficientForHappyPath) {
		console.error("\nAborting: the smart account is not funded with JPYC. Fund the address above, then re-run.");
		process.exit(1);
	}

	console.log("\n[owner] issuing scoped session key under the passkey sudo…");
	const approval = await issuePasskeyScopedSessionKey({
		cfg,
		publicClient,
		passkey,
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
		identity: { conversationId: "rfc-0003-demo", stepId: "pay-1" },
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
