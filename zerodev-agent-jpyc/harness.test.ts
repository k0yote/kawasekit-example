/**
 * RFC-0001 §8 acceptance suite.
 *
 * UNIT cases (always run): idempotency-key determinism, observability emit,
 * buy-list mapping — no chain needed.
 *
 * INTEGRATION cases H1/H2/N1–N4/I1 (skipped unless a live Amoy env is present):
 * each negative asserts the failure happens at userOp VALIDATION — discriminated
 * from a token-balance failure by `merchant balanceOf` being UNCHANGED. These
 * need: a funded JPYC account on Amoy + a ZeroDev gas policy set on the project.
 */

import "dotenv/config";

import { deriveIdempotencyKey, jpycAbi, type TransferJpycResult } from "kawasekit";
import { type Address, getAddress, parseUnits } from "viem";
import { beforeAll, describe, expect, it } from "vitest";
import { accountsFromConfig, assertJpycOnChain, loadConfig, makePublicClient, type RfcConfig } from "./env.ts";
import { agentPay, buildBuyList, issueScopedSessionKey } from "./harness.ts";
import { createRecordingTelemetry, emit } from "./observability.ts";

const LIVE_VARS = [
	"AMOY_RPC",
	"ZERODEV_RPC",
	"ZERODEV_PROJECT_ID",
	"JPYC_ADDRESS_AMOY",
	"JPYC_DECIMALS",
	"OWNER_PRIVATE_KEY",
	"SESSION_PRIVATE_KEY",
	"MERCHANT_ADDRESS",
];
const LIVE = LIVE_VARS.every((v) => (process.env[v] ?? "").trim() !== "");
const NON_ALLOWLISTED = getAddress(`0x${"99".repeat(20)}`);

/** A minimal config for pure-unit tests (no env). */
const unitCfg = {
	jpycDecimals: 18,
	merchant: getAddress(`0x${"11".repeat(20)}`),
	maxPerTransferJpyc: 1,
	maxTransfers: 1,
	windowSeconds: 3600,
} as unknown as RfcConfig;

describe("RFC-0001 unit (no chain)", () => {
	it("idempotency key is deterministic per (conversationId, stepId)", () => {
		const a = deriveIdempotencyKey({ conversationId: "c1", stepId: "pay-1" });
		const b = deriveIdempotencyKey({ conversationId: "c1", stepId: "pay-1" });
		const c = deriveIdempotencyKey({ conversationId: "c1", stepId: "pay-2" });
		expect(a).toBe(b);
		expect(a).not.toBe(c);
	});

	it("observability emit() fires the phase hook (I2 unit half)", () => {
		const { telemetry, spans } = createRecordingTelemetry();
		emit(telemetry, { phase: "submit", at: 1, to: unitCfg.merchant, amount: "1000" });
		emit(telemetry, { phase: "sponsor", at: 2 });
		emit(telemetry, { phase: "settle", at: 3, transaction: `0x${"ab".repeat(32)}` });
		expect(spans.map((s) => s.phase)).toEqual(["submit", "sponsor", "settle"]);
	});

	it("buildBuyList maps config → policy inputs (allowlist = merchant, cap = parseUnits)", () => {
		const bl = buildBuyList(unitCfg, { nowSeconds: 1_000 });
		expect(bl.merchants).toEqual([unitCfg.merchant]);
		expect(bl.maxPerTransfer).toBe(parseUnits("1", 18));
		expect(bl.maxTransfers).toBe(1);
		expect(bl.validUntil).toBe(1_000 + 3600);
	});
});

describe.skipIf(!LIVE)("RFC-0001 integration on Amoy (live env + ZeroDev gas policy required)", () => {
	let cfg: RfcConfig;
	let publicClient: ReturnType<typeof makePublicClient>;
	let owner: ReturnType<typeof accountsFromConfig>["owner"];
	let session: ReturnType<typeof accountsFromConfig>["session"];

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
		const a = accountsFromConfig(cfg);
		owner = a.owner;
		session = a.session;
	}, 60_000);

	const issue = (overrides = {}): Promise<string> =>
		issueScopedSessionKey({
			cfg,
			publicClient,
			ownerSigner: owner,
			sessionSigner: session,
			buyList: buildBuyList(cfg, overrides),
		});
	const freshCache = (): Map<string, TransferJpycResult> => new Map();

	it(
		"H1+H2: in-scope payment lands on-chain with sponsored gas; merchant balance increases",
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
				identity: { conversationId: "h1", stepId: "pay-1" },
				cache: freshCache(),
			});
			expect(out.result.success).toBe(true);
			expect(out.result.transactionHash).not.toBeNull();
			expect((await balanceOf(cfg.merchant)) - before).toBe(amount);
		},
		180_000,
	);

	it(
		"N1: recipient ∉ allowlist → reverts at validation; merchant balance unchanged",
		async () => {
			const approval = await issue();
			const before = await balanceOf(NON_ALLOWLISTED);
			await expect(
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: NON_ALLOWLISTED,
					amount: parseUnits("0.001", cfg.jpycDecimals),
					identity: { conversationId: "n1", stepId: "pay-1" },
					cache: freshCache(),
				}),
			).rejects.toThrow();
			expect(await balanceOf(NON_ALLOWLISTED)).toBe(before);
		},
		180_000,
	);

	it(
		"N2: amount > maxPerTransfer → reverts at validation; merchant balance unchanged",
		async () => {
			const approval = await issue({ maxPerTransferUnits: parseUnits("0.001", cfg.jpycDecimals) });
			const before = await balanceOf(cfg.merchant);
			await expect(
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: cfg.merchant,
					amount: parseUnits("1", cfg.jpycDecimals),
					identity: { conversationId: "n2", stepId: "pay-1" },
					cache: freshCache(),
				}),
			).rejects.toThrow();
			expect(await balanceOf(cfg.merchant)).toBe(before);
		},
		180_000,
	);

	it(
		"N3: (N+1)th payment within window → reverts (RateLimit window-total, no reset)",
		async () => {
			const approval = await issue({ maxTransfers: 1 });
			const amount = parseUnits("0.001", cfg.jpycDecimals);
			const cache = freshCache();
			await agentPay({
				cfg,
				publicClient,
				serializedApproval: approval,
				sessionSigner: session,
				to: cfg.merchant,
				amount,
				identity: { conversationId: "n3", stepId: "pay-1" },
				cache,
			});
			const before = await balanceOf(cfg.merchant);
			await expect(
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: cfg.merchant,
					amount,
					identity: { conversationId: "n3", stepId: "pay-2" },
					cache,
				}),
			).rejects.toThrow();
			expect(await balanceOf(cfg.merchant)).toBe(before);
		},
		300_000,
	);

	it(
		"N4: after validUntil → reverts (Timestamp); merchant balance unchanged",
		async () => {
			const now = Math.floor(Date.now() / 1000);
			const approval = await issue({ validAfter: now - 100, validUntil: now - 10 });
			const before = await balanceOf(cfg.merchant);
			await expect(
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: cfg.merchant,
					amount: parseUnits("0.001", cfg.jpycDecimals),
					identity: { conversationId: "n4", stepId: "pay-1" },
					cache: freshCache(),
				}),
			).rejects.toThrow();
			expect(await balanceOf(cfg.merchant)).toBe(before);
		},
		180_000,
	);

	it(
		"I1: replaying the same (conversationId, stepId) does not double-submit",
		async () => {
			const approval = await issue();
			const amount = parseUnits("0.001", cfg.jpycDecimals);
			const cache = freshCache();
			const identity = { conversationId: "i1", stepId: "pay-1" };
			const first = await agentPay({
				cfg,
				publicClient,
				serializedApproval: approval,
				sessionSigner: session,
				to: cfg.merchant,
				amount,
				identity,
				cache,
			});
			const before = await balanceOf(cfg.merchant);
			const replay = await agentPay({
				cfg,
				publicClient,
				serializedApproval: approval,
				sessionSigner: session,
				to: cfg.merchant,
				amount,
				identity,
				cache,
			});
			expect(replay.deduped).toBe(true);
			expect(replay.result.userOpHash).toBe(first.result.userOpHash);
			expect(await balanceOf(cfg.merchant)).toBe(before);
		},
		240_000,
	);

	it(
		"I2: observability spans emitted for submit/sponsor/settle on a live payment",
		async () => {
			const approval = await issue();
			const { telemetry, spans } = createRecordingTelemetry();
			await agentPay({
				cfg,
				publicClient,
				serializedApproval: approval,
				sessionSigner: session,
				to: cfg.merchant,
				amount: parseUnits("0.001", cfg.jpycDecimals),
				identity: { conversationId: "i2", stepId: "pay-1" },
				cache: freshCache(),
				telemetry,
			});
			const phases = spans.map((s) => s.phase);
			expect(phases).toContain("submit");
			expect(phases).toContain("sponsor");
			expect(phases).toContain("settle");
		},
		180_000,
	);
});
