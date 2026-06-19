/**
 * RFC-0003 Cycle 2 acceptance — recovery (R3a).
 *
 * UNIT (always run): `doRecovery` callData encoding — the selector + structure are
 * pinned offline so a wire regression can't slip through.
 *
 * INTEGRATION (R1/R2/R3/R4a/R4b/R4c) is added AFTER the live `pnpm recovery:probe`
 * settles the U1/U4 STOP-gate (does recovery work with the passkey provably disabled,
 * and does the executor re-init the passkey validator on-chain) — see
 * docs/rfc/0003-cycle2-recovery-plan.md. It is intentionally not present yet.
 */
import "dotenv/config";

import { polygonAmoy } from "kawasekit";
import { createPublicClient, http } from "viem";
import { describe, expect, it } from "vitest";
import { createSoftwarePasskey } from "./passkey.ts";
import { buildDoRecoveryCallData } from "./recovery.ts";

describe("RFC-0003 Cycle 2 unit (no chain)", () => {
	it("buildDoRecoveryCallData encodes doRecovery(passkeyValidator, newEnableData)", async () => {
		// A real public client — the doRecovery encoding (getValidatorAddress + getEnableData)
		// is offline; no contract is read. polygonAmoy fixes the chain id without a fetch.
		const publicClient = createPublicClient({ chain: polygonAmoy, transport: http() });
		const callData = await buildDoRecoveryCallData(publicClient, createSoftwarePasskey(), "kawasekit.local");
		// selector of doRecovery(address,bytes) — pinned via viem toFunctionSelector.
		expect(callData.slice(0, 10)).toBe("0xac39fd0f");
		// address (32B padded) + dynamic bytes (the webAuthn {x,y}+idHash blob).
		expect(callData.length).toBeGreaterThan(200);
	});
});
