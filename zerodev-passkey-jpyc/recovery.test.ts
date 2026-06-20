/**
 * RFC-0003 Cycle 2 (Approach B) acceptance — non-custodial recovery.
 *
 * UNIT (always run): the `doRecovery` config-reset callData encoding.
 * INTEGRATION (live Amoy + guardian keys): R2 (Hub-alone rejected on-chain, paymaster-less) +
 * R3/R4a (guardian-quorum config-reset to a new passkey; new owner controls; same address, no
 * funds moved). The recovery MECHANISM is gate-proven (`pnpm recovery:probe`); these formalize
 * it + add the R2 de-risk. R4b/R4c (re-provision / revoke) are a follow-on pass.
 *
 * R2 uses a DEDICATED account (its own passkey) so its ops don't touch the R3/R4 chain; per
 * review F-1 the R2 op is a BENIGN no-op (not doRecovery) so it mutates no state either way.
 * Needs ~0.1 POL on the R2 account for the paymaster-less negative (printed in beforeAll).
 */
import "dotenv/config";

import { createBuyListPolicies, jpycAbi, polygonAmoy, type TransferJpycResult } from "kawasekit";
import { type Address, createPublicClient, formatUnits, http, parseUnits } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { beforeAll, describe, expect, it } from "vitest";
import {
	assertJpycOnChain,
	guardiansFromConfig,
	loadConfig,
	loadOrCreatePasskey,
	makePublicClient,
	type RfcConfig,
} from "./env.ts";
import {
	agentPay,
	buildBuyList,
	issueSessionKeyUnderWeightedSudo,
	revokeSessionKeyUnderWeightedSudo,
	uninstallSessionKeyData,
} from "./harness.ts";
import { createSoftwarePasskey, type SoftwarePasskey } from "./passkey.ts";
import { bindNewOwnerAccount, recoverOwner, recoveryCallData } from "./recovery.ts";
import { guardianSigner, ownerConfig, sendWeighted, weightedClientFor } from "./weighted-account.ts";

const LIVE_VARS = [
	"AMOY_RPC",
	"ZERODEV_RPC",
	"ZERODEV_PROJECT_ID",
	"JPYC_ADDRESS_AMOY",
	"JPYC_DECIMALS",
	"MERCHANT_ADDRESS",
	"HUB_GUARDIAN_PRIVATE_KEY",
	"USER_BACKUP_PRIVATE_KEY",
];
const LIVE = LIVE_VARS.every((v) => (process.env[v] ?? "").trim() !== "");

describe("RFC-0003 Cycle 2 (Approach B) unit — recovery callData (no chain)", () => {
	it("recoveryCallData encodes doRecovery(weightedValidator, newWeightedConfig)", async () => {
		const publicClient = createPublicClient({ chain: polygonAmoy, transport: http() });
		const hub = privateKeyToAccount(generatePrivateKey());
		const backup = privateKeyToAccount(generatePrivateKey());
		const callData = await recoveryCallData(publicClient, createSoftwarePasskey(), hub, backup, "kawasekit.local");
		expect(callData.slice(0, 10)).toBe("0xac39fd0f"); // doRecovery(address,bytes)
		expect(callData.length).toBeGreaterThan(400); // _data = weighted config blob (3 signers)
	});

	it("uninstallSessionKeyData encodes uninstallValidation(bytes21, bytes, bytes) for the session key", async () => {
		const publicClient = createPublicClient({ chain: polygonAmoy, transport: http() });
		const sessionSigner = privateKeyToAccount(generatePrivateKey());
		const policies = createBuyListPolicies({
			jpycAddress: "0xE7C3D8C9a439feDe00D2600032D5dB0Be71C3c29",
			merchants: ["0x000000000000000000000000000000000000dEaD"],
			maxPerTransfer: 1_000_000_000_000_000_000n,
			maxTransfers: 1,
			validUntil: 4_000_000_000,
		});
		const data = await uninstallSessionKeyData({
			publicClient,
			sessionSigner,
			policies: [...policies],
			accountAddress: "0x000000000000000000000000000000000000bEEF",
		});
		expect(data.slice(0, 10)).toBe("0xe6f3d50a"); // uninstallValidation(bytes21,bytes,bytes)
	});
});

describe.skipIf(!LIVE)("RFC-0003 Cycle 2 (Approach B) — recovery on Amoy", () => {
	let cfg: RfcConfig;
	let publicClient: ReturnType<typeof makePublicClient>;
	let hub: ReturnType<typeof guardiansFromConfig>["hub"];
	let backup: ReturnType<typeof guardiansFromConfig>["userBackup"];

	const R2_PASSKEY_FILE = new URL(".passkey-r2.json", import.meta.url);
	const R4_PASSKEY_FILE = new URL(".passkey-r4.json", import.meta.url);
	const R4C_PASSKEY_FILE = new URL(".passkey-r4c.json", import.meta.url);

	const balanceOf = (who: Address): Promise<bigint> =>
		publicClient.readContract({ address: cfg.jpycAddress, abi: jpycAbi, functionName: "balanceOf", args: [who] }) as Promise<bigint>;

	const ownerClients = async (passkey: SoftwarePasskey, sponsored?: boolean) => {
		const config = await ownerConfig(passkey, cfg.rpID, hub.address, backup.address);
		const base = { publicClient, chain: cfg.chain, zerodevRpc: cfg.zerodevRpc, config, ...(sponsored !== undefined ? { sponsored } : {}) };
		return {
			hub: await weightedClientFor({ ...base, signer: await guardianSigner(hub) }),
			backup: await weightedClientFor({ ...base, signer: await guardianSigner(backup) }),
		};
	};

	beforeAll(async () => {
		cfg = loadConfig();
		publicClient = makePublicClient(cfg);
		await assertJpycOnChain(publicClient, cfg);
		const g = guardiansFromConfig(cfg);
		hub = g.hub;
		backup = g.userBackup;
		// Funding guidance.
		const r2 = await ownerClients(loadOrCreatePasskey(R2_PASSKEY_FILE));
		const r4 = await ownerClients(loadOrCreatePasskey(R4_PASSKEY_FILE));
		const r4c = await ownerClients(loadOrCreatePasskey(R4C_PASSKEY_FILE));
		const [pol, jpyc, jpycC] = await Promise.all([
			publicClient.getBalance({ address: r2.hub.account.address }),
			balanceOf(r4.hub.account.address),
			balanceOf(r4c.hub.account.address),
		]);
		console.log(`[R2] dedicated account (FUND ~0.1 POL): ${r2.hub.account.address} — POL ${formatUnits(pol, 18)}`);
		console.log(`[R4b] lifecycle account (FUND ~0.01 JPYC): ${r4.hub.account.address} — JPYC ${formatUnits(jpyc, cfg.jpycDecimals)}`);
		console.log(`[R4c] revoke account (FUND ~0.01 JPYC): ${r4c.hub.account.address} — JPYC ${formatUnits(jpycC, cfg.jpycDecimals)}`);
		console.log("       (R4b/R4c reset the owner back each run → re-runnable. If either drifts, delete its .passkey-r4*.json + re-fund.)");
		console.log("[R3/R4a] chain account: sponsored throughout — no funding needed.");
	}, 120_000);

	it(
		"R2: Hub-ALONE (50 < 100) is REVERTED on-chain paymaster-less; Hub+backup (100) succeeds (benign no-op)",
		async () => {
			const passkey = loadOrCreatePasskey(R2_PASSKEY_FILE);
			const sponsored = await ownerClients(passkey, true);
			const noop = await sponsored.hub.account.encodeCalls([{ to: sponsored.hub.account.address, value: 0n, data: "0x" }]);

			// (a) POSITIVE control — Hub + backup (100) benign no-op: deploys + succeeds.
			const ok = await sendWeighted([sponsored.hub, sponsored.backup], noop);
			expect(ok.transactionHash).not.toBeNull();

			// (b) NEGATIVE — Hub alone (50 < 100), paymaster-less → on-chain validateUserOp revert.
			const selfPaid = await ownerClients(passkey, false);
			let err = "";
			try {
				await sendWeighted([selfPaid.hub], noop);
			} catch (e) {
				err = e instanceof Error ? e.message : String(e);
			}
			console.log(`[R2 negative] threw: ${err.split("\n").slice(0, 3).join(" | ")}`);
			expect(err).not.toBe(""); // it threw
			// AIRTIGHT (Cycle-1 lesson): the failure must be the WEIGHTED THRESHOLD (validation),
			// NOT a no-POL prefund artifact. Fund ~0.1 POL so AA21 cannot occur, then this holds.
			expect(err).not.toMatch(/AA21|prefund|didn'?t pay|insufficient funds/i);
		},
		300_000,
	);

	it(
		"R3+R4a: guardian-quorum config-reset passkey-A → passkey-B; new owner controls; same address, no JPYC moved",
		async () => {
			// EPHEMERAL original passkey — R3/R4a is fully sponsored (no funding), so a fresh account
			// each run keeps the test re-runnable (a persisted account drifts after one rotation).
			const passkeyA = createSoftwarePasskey();
			const a = await ownerClients(passkeyA, true);
			const chainAddress = a.hub.account.address;
			const noop = await a.hub.account.encodeCalls([{ to: chainAddress, value: 0n, data: "0x" }]);

			// Deploy the chain account (guardians, sponsored).
			await sendWeighted([a.hub, a.backup], noop);
			const jpycBefore = await balanceOf(chainAddress);

			// R3 — guardians-only recovery → reset the owner config to a NEW passkey.
			const passkeyB = createSoftwarePasskey();
			const r3 = await recoverOwner({ publicClient, cfg, currentPasskey: passkeyA, newPasskey: passkeyB, hub, backup, address: chainAddress });
			expect(r3.transactionHash).not.toBeNull();

			// R3 cont. — the NEW passkey-B alone (weight 100) controls the account at the SAME address.
			const bClient = await bindNewOwnerAccount({ publicClient, cfg, newPasskey: passkeyB, hub: hub.address, backup: backup.address, address: chainAddress });
			expect(bClient.account.address).toBe(chainAddress); // R4a — address invariant
			const bNoop = await bClient.account.encodeCalls([{ to: chainAddress, value: 0n, data: "0x" }]);
			const ok = await sendWeighted([bClient], bNoop);
			expect(ok.transactionHash).not.toBeNull();

			// R4a — recovery moved no JPYC.
			expect(await balanceOf(chainAddress)).toBe(jpycBefore);
		},
		420_000,
	);

	it(
		"R4b: the NEW owner (post-recovery) issues a session key under the weighted sudo → the agent pays",
		async () => {
			const passkeyC = loadOrCreatePasskey(R4_PASSKEY_FILE);
			const c = await ownerClients(passkeyC, true);
			const r4Address = c.hub.account.address;
			const noop = await c.hub.account.encodeCalls([{ to: r4Address, value: 0n, data: "0x" }]);
			await sendWeighted([c.hub, c.backup], noop); // deploy

			// Recover passkey-C → passkey-D (the new owner).
			const passkeyD = createSoftwarePasskey();
			const r = await recoverOwner({ publicClient, cfg, currentPasskey: passkeyC, newPasskey: passkeyD, hub, backup, address: r4Address });
			expect(r.transactionHash).not.toBeNull();

			// R4b — the NEW owner issues a buy-list session key on the recovered account → agent pays.
			// Ephemeral session signer so re-runs don't collide on an already-installed permission validator.
			const r4Session = privateKeyToAccount(generatePrivateKey());
			const approval = await issueSessionKeyUnderWeightedSudo({
				cfg,
				publicClient,
				passkey: passkeyD,
				hub: hub.address,
				backup: backup.address,
				sessionSigner: r4Session,
				buyList: buildBuyList(cfg),
				address: r4Address,
			});
			const amount = parseUnits("0.001", cfg.jpycDecimals);
			const before = await balanceOf(cfg.merchant);
			const out = await agentPay({
				cfg,
				publicClient,
				serializedApproval: approval,
				sessionSigner: r4Session,
				to: cfg.merchant,
				amount,
				identity: { conversationId: "r4b", stepId: "pay-1" },
				cache: new Map<string, TransferJpycResult>(),
			});
			expect(out.result.success).toBe(true);
			expect((await balanceOf(cfg.merchant)) - before).toBe(amount);

			// Reset the owner D → C so the FUNDED account returns to its persisted owner (re-runnable).
			await recoverOwner({ publicClient, cfg, currentPasskey: passkeyD, newPasskey: passkeyC, hub, backup, address: r4Address });
		},
		420_000,
	);

	it(
		"R4c: the NEW owner REVOKES the old session key → the agent can no longer pay (stale delegation killed)",
		async () => {
			const passkeyC = loadOrCreatePasskey(R4C_PASSKEY_FILE);
			const c = await ownerClients(passkeyC, true);
			const addr = c.hub.account.address;
			const deployNoop = await c.hub.account.encodeCalls([{ to: addr, value: 0n, data: "0x" }]);
			await sendWeighted([c.hub, c.backup], deployNoop); // deploy

			// Recover C → D (the new owner), then issue a buy-list session key under D.
			const passkeyD = createSoftwarePasskey();
			await recoverOwner({ publicClient, cfg, currentPasskey: passkeyC, newPasskey: passkeyD, hub, backup, address: addr });

			// Build the buy-list ONCE: revoke MUST rebuild the SAME policies to derive the same validator id.
			const sessionSigner = privateKeyToAccount(generatePrivateKey());
			const buyList = buildBuyList(cfg);
			const approval = await issueSessionKeyUnderWeightedSudo({
				cfg,
				publicClient,
				passkey: passkeyD,
				hub: hub.address,
				backup: backup.address,
				sessionSigner,
				buyList,
				address: addr,
			});

			const amount = parseUnits("0.001", cfg.jpycDecimals);
			const cache = new Map<string, TransferJpycResult>();

			// (1) BEFORE revoke — the session key is LIVE: the agent pays.
			const m0 = await balanceOf(cfg.merchant);
			const live = await agentPay({
				cfg,
				publicClient,
				serializedApproval: approval,
				sessionSigner,
				to: cfg.merchant,
				amount,
				identity: { conversationId: "r4c", stepId: "pre-revoke" },
				cache,
			});
			expect(live.result.success).toBe(true);
			expect((await balanceOf(cfg.merchant)) - m0).toBe(amount);

			// (2) REVOKE — the new passkey owner (weight 100) uninstalls the session key via the
			// weighted approve/aggregate flow (sendWeighted), NOT kawasekit's revokeSessionKey
			// (its uninstallPlugin hardcodes the single-signer send the weighted validator rejects).
			const rev = await revokeSessionKeyUnderWeightedSudo({
				cfg,
				publicClient,
				passkey: passkeyD,
				hub: hub.address,
				backup: backup.address,
				sessionSigner,
				buyList,
				address: addr,
			});
			expect(rev.transactionHash).not.toBeNull();

			// (3) AFTER revoke — the SAME key (fresh idempotency identity) can no longer pay: it
			// FAILS, and no JPYC moves (the airtight before/after delta proves the revoke took).
			const m1 = await balanceOf(cfg.merchant);
			let err = "";
			try {
				await agentPay({
					cfg,
					publicClient,
					serializedApproval: approval,
					sessionSigner,
					to: cfg.merchant,
					amount,
					identity: { conversationId: "r4c", stepId: "post-revoke" },
					cache: new Map<string, TransferJpycResult>(),
				});
			} catch (e) {
				err = e instanceof Error ? e.message : String(e);
			}
			console.log(`[R4c post-revoke] threw: ${err.split("\n").slice(0, 2).join(" | ")}`);
			expect(err).not.toBe(""); // the revoked key threw
			expect(await balanceOf(cfg.merchant)).toBe(m1); // no JPYC moved post-revoke

			// Reset the owner D → C so the FUNDED account is re-runnable.
			await recoverOwner({ publicClient, cfg, currentPasskey: passkeyD, newPasskey: passkeyC, hub, backup, address: addr });
		},
		600_000,
	);
});
