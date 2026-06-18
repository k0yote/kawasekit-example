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

import { deriveIdempotencyKey, jpycAbi, parseSessionEnvelope, type TransferJpycResult } from "kawasekit";
import { type Address, getAddress, parseUnits } from "viem";
import { beforeAll, describe, expect, it } from "vitest";
import { accountsFromConfig, assertJpycOnChain, loadConfig, makePublicClient, type RfcConfig } from "./env.ts";
import { SponsorshipError } from "./errors.ts";
import { agentPay, buildBuyList, issueScopedSessionKey, preflight } from "./harness.ts";
import { createRecordingTelemetry, emit, type HarnessTelemetry } from "./observability.ts";

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

	it("emit() routes sponsor_reject + validation_reject distinctly (H1 discriminator)", () => {
		// The §8 de-risk hinges on telling a PAYMASTER decline (`sponsor_reject`) apart from
		// a PERMISSION-VALIDATOR reject (`sponsor` then `validation_reject`). Exercise the
		// routing in the always-run unit suite so the discriminator can't silently regress.
		const declined = createRecordingTelemetry();
		emit(declined.telemetry, { phase: "sponsor_reject", at: 1, detail: "paymaster declined" });
		expect(declined.spans.map((s) => s.phase)).toEqual(["sponsor_reject"]);

		const rejected = createRecordingTelemetry();
		emit(rejected.telemetry, { phase: "sponsor", at: 1 });
		emit(rejected.telemetry, { phase: "validation_reject", at: 2, detail: "ONE_OF" });
		expect(rejected.spans.map((s) => s.phase)).toEqual(["sponsor", "validation_reject"]);
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

	/**
	 * Assert a payment was rejected by the on-chain PERMISSION VALIDATOR — NOT by
	 * the paymaster. This is the real §8 G3 discriminator: a bare
	 * `rejects.toThrow()` would also pass for a paymaster sponsorship decline,
	 * masking whether `createBuyListPolicies` is actually the boundary.
	 *
	 * The throw must NOT be a `SponsorshipError` and the span stream must carry
	 * NO `sponsor_reject` (the paymaster did not decline) and NO `settle` (it did
	 * not succeed). We deliberately do NOT require a `sponsor` span: validation is
	 * simulated during gas estimation, which can reject BEFORE `getPaymasterData`
	 * runs, so a granted-sponsorship span is not guaranteed to fire on a reject.
	 * Positive attribution to the policy also rests on the H1 happy path
	 * succeeding (the full sponsor→settle pipeline works) + the balance-unchanged
	 * check in each case. This requires a blanket "sponsor-all" ZeroDev gas policy
	 * — a recipient/amount-restricted gas policy would reject at the paymaster
	 * (SponsorshipError) and mask the validator (README prerequisites).
	 */
	const expectPolicyValidationReject = async (
		run: (telemetry: HarnessTelemetry) => Promise<unknown>,
	): Promise<void> => {
		const { telemetry, spans } = createRecordingTelemetry();
		let threw: unknown;
		try {
			await run(telemetry);
		} catch (err) {
			threw = err;
		}
		const phases = spans.map((s) => s.phase);
		// F1 premise visibility (RFC-0001 §8 premise gate): record which branch this negative
		// actually took on-chain, so a BROKEN premise (verifying paymaster simulate-and-declining
		// an out-of-allowlist op) is VISIBLE in test output, not silently misclassified. The
		// premise HOLDS iff the throw is not a SponsorshipError AND no `sponsor_reject` span fired.
		const premiseBroken = phases.includes("sponsor_reject") || threw instanceof SponsorshipError;
		const branch = premiseBroken
			? "sponsor_reject — ⛒ PREMISE BROKEN: paymaster declined (apply RFC-0001 §9 F1 fallback)"
			: "validation_reject — premise holds: permission validator rejected";
		console.log(
			`[F1 premise] negative branch: ${branch}; spans=[${phases.join(",")}]; threw=${
				threw instanceof Error ? threw.constructor.name : typeof threw
			}`,
		);
		expect(threw, "expected the payment to be rejected").toBeInstanceOf(Error);
		expect(threw, "a paymaster decline is NOT a policy rejection").not.toBeInstanceOf(SponsorshipError);
		expect(phases, "paymaster must not have declined (F1 premise)").not.toContain("sponsor_reject");
		expect(phases, "must not have settled").not.toContain("settle");
	};

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
		"N1: recipient ∉ allowlist → rejected by the permission validator; balance unchanged",
		async () => {
			const approval = await issue();
			const before = await balanceOf(NON_ALLOWLISTED);
			await expectPolicyValidationReject((telemetry) =>
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: NON_ALLOWLISTED,
					amount: parseUnits("0.001", cfg.jpycDecimals),
					identity: { conversationId: "n1", stepId: "pay-1" },
					cache: freshCache(),
					telemetry,
				}),
			);
			expect(await balanceOf(NON_ALLOWLISTED)).toBe(before);
		},
		180_000,
	);

	it(
		"N2: amount > maxPerTransfer → rejected by the permission validator; balance unchanged",
		async () => {
			const approval = await issue({ maxPerTransferUnits: parseUnits("0.001", cfg.jpycDecimals) });
			const before = await balanceOf(cfg.merchant);
			await expectPolicyValidationReject((telemetry) =>
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: cfg.merchant,
					amount: parseUnits("1", cfg.jpycDecimals),
					identity: { conversationId: "n2", stepId: "pay-1" },
					cache: freshCache(),
					telemetry,
				}),
			);
			expect(await balanceOf(cfg.merchant)).toBe(before);
		},
		180_000,
	);

	it(
		"N3: (N+1)th payment within window → rejected by RateLimit (count bound = maxTransfers)",
		async () => {
			// Proves the COUNT BOUND is enforced. The no-mid-window-RESET property rests on the
			// createBuyListPolicies encoding (interval = validUntil − validAfter, one bucket),
			// unit-asserted in kawasekit test/buy-list-policy.test.ts — not on this on-chain case.
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
			await expectPolicyValidationReject((telemetry) =>
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: cfg.merchant,
					amount,
					identity: { conversationId: "n3", stepId: "pay-2" },
					cache,
					telemetry,
				}),
			);
			expect(await balanceOf(cfg.merchant)).toBe(before);
		},
		300_000,
	);

	it(
		"N4: after validUntil → rejected by the Timestamp policy; balance unchanged",
		async () => {
			const now = Math.floor(Date.now() / 1000);
			const approval = await issue({ validAfter: now - 100, validUntil: now - 10 });
			const before = await balanceOf(cfg.merchant);
			await expectPolicyValidationReject((telemetry) =>
				agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner: session,
					to: cfg.merchant,
					amount: parseUnits("0.001", cfg.jpycDecimals),
					identity: { conversationId: "n4", stepId: "pay-1" },
					cache: freshCache(),
					telemetry,
				}),
			);
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

	it(
		"preflight: reports the SAME counterfactual account the agent pays from, + funding guidance",
		async () => {
			const lines: string[] = [];
			const pf = await preflight({
				cfg,
				publicClient,
				ownerSigner: owner,
				sessionSigner: session,
				log: (l) => lines.push(l),
			});
			expect(pf.accountAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
			expect(typeof pf.jpycBalance).toBe("bigint");
			// The address preflight tells you to FUND must be exactly the address the agent
			// restores and pays from — both derive from the owner sudo validator (deterministic).
			const env = parseSessionEnvelope(await issue());
			expect(env.smartAccountAddress).toBe(pf.accountAddress);
			const guidance = lines.join("\n");
			expect(guidance).toContain(pf.accountAddress);
			expect(guidance).toContain("FUND THIS");
		},
		120_000,
	);
});
