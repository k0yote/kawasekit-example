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

import {
	createSponsoredKernelClient,
	deriveIdempotencyKey,
	jpycAbi,
	parseSessionEnvelope,
	polygonAmoy,
	transferJpyc,
	type TransferJpycResult,
	zerodevRpcUrl,
} from "kawasekit";
import { type Address, getAddress, parseUnits } from "viem";
import { beforeAll, describe, expect, it } from "vitest";
import { createPasskeyAccount } from "./account.ts";
import {
	assertJpycOnChain,
	loadConfig,
	loadOrCreatePasskey,
	makePublicClient,
	type RfcConfig,
	sessionFromConfig,
} from "./env.ts";
import { SponsorshipError } from "./errors.ts";
import { agentPay, buildBuyList, issuePasskeyScopedSessionKey, preflight } from "./harness.ts";
import { createRecordingTelemetry, emit, type HarnessTelemetry } from "./observability.ts";
import type { SoftwarePasskey } from "./passkey.ts";

const LIVE_VARS = [
	"AMOY_RPC",
	"ZERODEV_RPC",
	"ZERODEV_PROJECT_ID",
	"JPYC_ADDRESS_AMOY",
	"JPYC_DECIMALS",
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

describe.skipIf(!LIVE)("RFC-0003 P1+P2 integration on Amoy — passkey owner (live env + gas policy)", () => {
	let cfg: RfcConfig;
	let publicClient: ReturnType<typeof makePublicClient>;
	let passkey: SoftwarePasskey;
	let session: ReturnType<typeof sessionFromConfig>;

	const PASSKEY_FILE = new URL(".passkey-cycle1.json", import.meta.url);

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
	}, 60_000);

	const issue = (overrides = {}): Promise<string> =>
		issuePasskeyScopedSessionKey({
			cfg,
			publicClient,
			passkey,
			sessionSigner: session,
			buyList: buildBuyList(cfg, overrides),
		});
	const freshCache = (): Map<string, TransferJpycResult> => new Map();

	it(
		"P1: a PASSKEY-signed sponsored userOp lands on Amoy (owner-direct path)",
		async () => {
			const account = await createPasskeyAccount({ publicClient, passkey, rpID: cfg.rpID });
			const amount = parseUnits("0.001", cfg.jpycDecimals);
			const before = await balanceOf(cfg.merchant);
			const client = createSponsoredKernelClient({
				account,
				chain: polygonAmoy,
				zerodevRpc: zerodevRpcUrl(polygonAmoy, cfg.zerodevProjectId),
				publicClient,
			});
			const res = await transferJpyc(client, { to: cfg.merchant, amount });
			expect(res.success).toBe(true);
			expect(res.transactionHash).not.toBeNull();
			expect((await balanceOf(cfg.merchant)) - before).toBe(amount);
		},
		180_000,
	);

	/**
	 * SPONSORED negative — assert the DURABLE INVARIANT (Amoy run #1 / "Both"
	 * resolution; see `docs/rfc/rfc0001-amoy-run1-evaluation.md`). The original strict
	 * discriminator (must be a non-`SponsorshipError` `validation_reject`) was
	 * SUPERSEDED by run #1: with ZeroDev's verifying paymaster, a Call/RateLimit
	 * violation surfaces as `sponsor_reject` (the paymaster fail-fasts on a reverting
	 * `validateUserOp` during pre-sign simulation) — which is NOT a security hole (no
	 * funds move). So here we assert only the durable safety invariant — it **threw**
	 * and **nothing `settle`d** (the caller also checks merchant balance unchanged) —
	 * and we RECORD the branch via the `[F1 premise]` log WITHOUT hard-asserting it,
	 * so the test survives ZeroDev paymaster-behavior changes. The on-chain validator
	 * is proven the SOLE boundary by the paymaster-LESS N1–N4 (the §9 fallback).
	 * Controlled comparison: H1 (in-scope) settles while N1–N3 (one param out-of-scope)
	 * are rejected ⇒ the rejection is policy-caused.
	 */
	const expectPolicyEnforced = async (
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
		const branch =
			phases.includes("sponsor_reject") || threw instanceof SponsorshipError
				? "sponsor_reject (paymaster fail-fast on a reverting validateUserOp — Call/RateLimit)"
				: "validation_reject (bundler rejected — e.g. Timestamp)";
		console.log(
			`[F1 premise] sponsored negative branch: ${branch}; spans=[${phases.join(",")}]; threw=${
				threw instanceof Error ? threw.constructor.name : typeof threw
			}`,
		);
		// Durable invariant only: rejected + nothing settled. Branch recorded, NOT asserted.
		expect(threw, "expected the payment to be rejected").toBeInstanceOf(Error);
		expect(phases, "must not have settled").not.toContain("settle");
	};

	/**
	 * PAYMASTER-LESS negative (the §9 fallback) — proves the ON-CHAIN permission
	 * validator ALONE is the boundary, independent of paymaster behavior. No paymaster
	 * is involved (self-paid via POL), so there is no `sponsor`/`sponsor_reject`/
	 * `SponsorshipError`: a rejection MUST surface as the raw on-chain validation
	 * error → `validation_reject`. This is the immutable, paymaster-independent proof
	 * the sponsored path cannot give for revert-style policies (run #1).
	 */
	const expectOnChainValidationReject = async (
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
		console.log(
			`[F1 fallback] paymaster-less negative: spans=[${phases.join(",")}]; threw=${
				threw instanceof Error ? threw.constructor.name : typeof threw
			}`,
		);
		expect(threw, "expected an on-chain validation rejection").toBeInstanceOf(Error);
		expect(threw, "no paymaster ⇒ not a SponsorshipError").not.toBeInstanceOf(SponsorshipError);
		expect(phases, "paymaster-less ⇒ no sponsor_reject").not.toContain("sponsor_reject");
		expect(phases, "the on-chain validator must reject (validation_reject)").toContain("validation_reject");
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
			await expectPolicyEnforced((telemetry) =>
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
			await expectPolicyEnforced((telemetry) =>
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
			await expectPolicyEnforced((telemetry) =>
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
			await expectPolicyEnforced((telemetry) =>
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
				passkey,
				sessionSigner: session,
				log: (l) => lines.push(l),
			});
			expect(pf.accountAddress).toMatch(/^0x[0-9a-fA-F]{40}$/);
			expect(typeof pf.jpycBalance).toBe("bigint");
			// The address preflight tells you to FUND must be exactly the address the agent
			// restores and pays from — both derive from the passkey sudo validator (deterministic).
			const env = parseSessionEnvelope(await issue());
			expect(env.smartAccountAddress).toBe(pf.accountAddress);
			const guidance = lines.join("\n");
			expect(guidance).toContain(pf.accountAddress);
			expect(guidance).toContain("FUND THIS");
		},
		120_000,
	);

	describe("§9 fallback — paymaster-less N1–N4 (on-chain validator is the SOLE boundary)", () => {
		// The self-paid negatives need POL on the smart account so the bundler's prefund
		// check passes — it is NOT consumed (they revert at validation). H1/H2 stay sponsored.
		beforeAll(async () => {
			const pf = await preflight({ cfg, publicClient, passkey, sessionSigner: session });
			if (!pf.sufficientPolForSelfPaid) {
				throw new Error(
					`§9 fallback needs POL on ${pf.accountAddress} for the bundler prefund check ` +
						`(have ${pf.polBalance} wei). Fund ~0.1 POL from the Amoy POL faucet ` +
						`(https://faucet.polygon.technology/). It is NOT consumed — the negatives revert at validation.`,
				);
			}
		}, 60_000);

		it(
			"N1 self-paid: recipient ∉ allowlist → on-chain validation_reject; balance unchanged",
			async () => {
				const approval = await issue();
				const before = await balanceOf(NON_ALLOWLISTED);
				await expectOnChainValidationReject((telemetry) =>
					agentPay({
						cfg,
						publicClient,
						serializedApproval: approval,
						sessionSigner: session,
						to: NON_ALLOWLISTED,
						amount: parseUnits("0.001", cfg.jpycDecimals),
						identity: { conversationId: "sp-n1", stepId: "pay-1" },
						cache: freshCache(),
						telemetry,
						selfPaid: true,
					}),
				);
				expect(await balanceOf(NON_ALLOWLISTED)).toBe(before);
			},
			180_000,
		);

		it(
			"N2 self-paid: amount > maxPerTransfer → on-chain validation_reject; balance unchanged",
			async () => {
				const approval = await issue({ maxPerTransferUnits: parseUnits("0.001", cfg.jpycDecimals) });
				const before = await balanceOf(cfg.merchant);
				await expectOnChainValidationReject((telemetry) =>
					agentPay({
						cfg,
						publicClient,
						serializedApproval: approval,
						sessionSigner: session,
						to: cfg.merchant,
						amount: parseUnits("1", cfg.jpycDecimals),
						identity: { conversationId: "sp-n2", stepId: "pay-1" },
						cache: freshCache(),
						telemetry,
						selfPaid: true,
					}),
				);
				expect(await balanceOf(cfg.merchant)).toBe(before);
			},
			180_000,
		);

		it(
			"N3 self-paid: (N+1)th payment within window → on-chain validation_reject (RateLimit)",
			async () => {
				// Consume the count with a SPONSORED first payment (no POL), then the self-paid
				// 2nd hits the count bound → on-chain validation_reject (no POL consumed).
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
					identity: { conversationId: "sp-n3", stepId: "pay-1" },
					cache,
				});
				const before = await balanceOf(cfg.merchant);
				await expectOnChainValidationReject((telemetry) =>
					agentPay({
						cfg,
						publicClient,
						serializedApproval: approval,
						sessionSigner: session,
						to: cfg.merchant,
						amount,
						identity: { conversationId: "sp-n3", stepId: "pay-2" },
						cache,
						telemetry,
						selfPaid: true,
					}),
				);
				expect(await balanceOf(cfg.merchant)).toBe(before);
			},
			300_000,
		);

		it(
			"N4 self-paid: after validUntil → on-chain validation_reject (Timestamp); balance unchanged",
			async () => {
				const now = Math.floor(Date.now() / 1000);
				const approval = await issue({ validAfter: now - 100, validUntil: now - 10 });
				const before = await balanceOf(cfg.merchant);
				await expectOnChainValidationReject((telemetry) =>
					agentPay({
						cfg,
						publicClient,
						serializedApproval: approval,
						sessionSigner: session,
						to: cfg.merchant,
						amount: parseUnits("0.001", cfg.jpycDecimals),
						identity: { conversationId: "sp-n4", stepId: "pay-1" },
						cache: freshCache(),
						telemetry,
						selfPaid: true,
					}),
				);
				expect(await balanceOf(cfg.merchant)).toBe(before);
			},
			180_000,
		);
	});
});
