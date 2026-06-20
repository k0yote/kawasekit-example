/**
 * RFC-0003 Cycle 2 (Approach B) — C1-revalidate: the RFC-0001 session-key floor under
 * the WEIGHTED sudo (the reopened Cycle-1 owner model). The gate proved recovery; this
 * proves the agent floor still works when the owner is a weighted validator rather than a
 * bare passkey — the front-loaded risk (Task 1).
 *
 * UNIT (always): the owner-config shape.
 * INTEGRATION (live Amoy + the guardian keys): issue a buy-list session key UNDER the
 * weighted sudo → the agent pays (H1, sponsored); a §9 paymaster-less negative still
 * rejects on-chain. Needs ~0.1 POL on the account for the paymaster-less negative.
 */
import "dotenv/config";

import { jpycAbi, parseSessionEnvelope, type TransferJpycResult } from "kawasekit";
import { type Address, formatUnits, getAddress, parseUnits } from "viem";
import { beforeAll, describe, expect, it } from "vitest";
import {
	assertJpycOnChain,
	guardiansFromConfig,
	loadConfig,
	loadOrCreatePasskey,
	makePublicClient,
	type RfcConfig,
	sessionFromConfig,
} from "./env.ts";
import { agentPay, buildBuyList, issueSessionKeyUnderWeightedSudo } from "./harness.ts";
import { createSoftwarePasskey, type SoftwarePasskey } from "./passkey.ts";
import { GUARDIAN_WEIGHT, OWNER_THRESHOLD, ownerConfig, PASSKEY_WEIGHT } from "./weighted-account.ts";

const LIVE_VARS = [
	"AMOY_RPC",
	"ZERODEV_RPC",
	"ZERODEV_PROJECT_ID",
	"JPYC_ADDRESS_AMOY",
	"JPYC_DECIMALS",
	"SESSION_PRIVATE_KEY",
	"MERCHANT_ADDRESS",
	"HUB_GUARDIAN_PRIVATE_KEY",
	"USER_BACKUP_PRIVATE_KEY",
];
const LIVE = LIVE_VARS.every((v) => (process.env[v] ?? "").trim() !== "");
const NON_ALLOWLISTED = getAddress(`0x${"99".repeat(20)}`);

describe("RFC-0003 Cycle 2 — owner config (unit)", () => {
	it("ownerConfig = [passkey 100, Hub 50, backup 50, threshold 100]", async () => {
		const pk = createSoftwarePasskey();
		const hub = getAddress(`0x${"11".repeat(20)}`);
		const backup = getAddress(`0x${"22".repeat(20)}`);
		const cfg = await ownerConfig(pk, "kawasekit.local", hub, backup);
		expect(cfg.threshold).toBe(OWNER_THRESHOLD);
		expect(cfg.signers).toHaveLength(3);
		expect(cfg.signers[0]?.weight).toBe(PASSKEY_WEIGHT); // passkey primary
		expect(cfg.signers[1]).toEqual({ publicKey: hub, weight: GUARDIAN_WEIGHT });
		expect(cfg.signers[2]).toEqual({ publicKey: backup, weight: GUARDIAN_WEIGHT });
		// passkey alone (100) meets threshold; either guardian alone (50) does not.
		expect(PASSKEY_WEIGHT).toBeGreaterThanOrEqual(OWNER_THRESHOLD);
		expect(GUARDIAN_WEIGHT).toBeLessThan(OWNER_THRESHOLD);
		expect(GUARDIAN_WEIGHT + GUARDIAN_WEIGHT).toBe(OWNER_THRESHOLD);
	});
});

describe.skipIf(!LIVE)("RFC-0003 Cycle 2 — C1-revalidate: session-key floor under the weighted sudo (Amoy)", () => {
	let cfg: RfcConfig;
	let publicClient: ReturnType<typeof makePublicClient>;
	let passkey: SoftwarePasskey;
	let session: ReturnType<typeof sessionFromConfig>;
	let hub: ReturnType<typeof guardiansFromConfig>["hub"];
	let backup: ReturnType<typeof guardiansFromConfig>["userBackup"];

	const PASSKEY_FILE = new URL(".passkey-c1reval.json", import.meta.url);

	const balanceOf = (who: Address): Promise<bigint> =>
		publicClient.readContract({
			address: cfg.jpycAddress,
			abi: jpycAbi,
			functionName: "balanceOf",
			args: [who],
		}) as Promise<bigint>;

	beforeAll(async () => {
		cfg = loadConfig();
		publicClient = makePublicClient(cfg);
		await assertJpycOnChain(publicClient, cfg);
		passkey = loadOrCreatePasskey(PASSKEY_FILE);
		session = sessionFromConfig(cfg);
		const g = guardiansFromConfig(cfg);
		hub = g.hub;
		backup = g.userBackup;
		// Funding guidance: derive the weighted-sudo account address + balances (issuance is LOCAL).
		const env = parseSessionEnvelope(await issue());
		const [jpyc, pol] = await Promise.all([
			balanceOf(env.smartAccountAddress),
			publicClient.getBalance({ address: env.smartAccountAddress }),
		]);
		console.log(`[C1-revalidate] weighted-sudo account (FUND THIS): ${env.smartAccountAddress}`);
		console.log(
			`  JPYC ${formatUnits(jpyc, cfg.jpycDecimals)} · POL ${formatUnits(pol, 18)} — need JPYC + ~0.1 POL (the §9 negative is paymaster-less, not consumed)`,
		);
	}, 120_000);

	const issue = (overrides = {}): Promise<string> =>
		issueSessionKeyUnderWeightedSudo({
			cfg,
			publicClient,
			passkey,
			hub: hub.address,
			backup: backup.address,
			sessionSigner: session,
			buyList: buildBuyList(cfg, overrides),
		});

	it(
		"H1: a session key issued UNDER THE WEIGHTED SUDO lets the agent pay the merchant (sponsored)",
		async () => {
			const approval = await issue();
			const amount = parseUnits("0.001", cfg.jpycDecimals);
			const before = await balanceOf(cfg.merchant);
			const out = await agentPay({
				cfg,
				publicClient,
				serializedApproval: approval,
				sessionSigner: session,
				to: cfg.merchant,
				amount,
				identity: { conversationId: "c1reval", stepId: "pay-1" },
				cache: new Map<string, TransferJpycResult>(),
			});
			expect(out.result.success).toBe(true);
			expect((await balanceOf(cfg.merchant)) - before).toBe(amount);
		},
		180_000,
	);

	it(
		"N1 (§9 paymaster-less): recipient ∉ allowlist → on-chain validation_reject; balance unchanged",
		async () => {
			const approval = await issue();
			const before = await balanceOf(NON_ALLOWLISTED);
			let threw = false;
			try {
				await agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: NON_ALLOWLISTED,
					amount: parseUnits("0.001", cfg.jpycDecimals),
					identity: { conversationId: "c1reval", stepId: "n1" },
					cache: new Map<string, TransferJpycResult>(),
					selfPaid: true,
				});
			} catch {
				threw = true;
			}
			expect(threw).toBe(true);
			expect(await balanceOf(NON_ALLOWLISTED)).toBe(before);
		},
		180_000,
	);
});
