/**
 * RFC-0003 Cycle 1 — the F1 OFF-CHAIN SAFETY NET (layer a).
 *
 * Proves the headless software authenticator's byte format + challenge encoding are
 * correct by round-tripping through `ox/WebAuthnP256.verify` — pure Node, no chain.
 * If green, the riskiest part of P1 (authenticator bytes ↔ challenge) is settled BEFORE
 * burning an on-chain Amoy userOp; what remains for P1 is only ZeroDev's wire encoding
 * (layer b). See RFC-0003 §8 / `docs/rfc/rfc0001-amoy-run1-evaluation.md`-style discipline.
 */
import { WebAuthnP256 } from "ox";
import { describe, expect, it } from "vitest";
import { authenticatorSign, createSoftwarePasskey } from "./passkey.ts";

const RP_ID = "kawasekit.local";
const challenge = (byte: string) => `0x${byte.repeat(32)}` as const; // a 32-byte hash (userOpHash analog)

describe("RFC-0003 C1 — headless passkey authenticator (off-chain F1 safety net)", () => {
	it("ox WebAuthnP256.verify ACCEPTS our headless assertion (byte format + challenge encoding correct)", () => {
		const passkey = createSoftwarePasskey();
		const c = challenge("ab");
		const { metadata, signature } = authenticatorSign(passkey, c, RP_ID);
		const ok = WebAuthnP256.verify({ challenge: c, publicKey: passkey.publicKey, signature, metadata });
		expect(ok).toBe(true);
	});

	it("REJECTS a different challenge (the signature is bound to the userOp hash)", () => {
		const passkey = createSoftwarePasskey();
		const { metadata, signature } = authenticatorSign(passkey, challenge("11"), RP_ID);
		const ok = WebAuthnP256.verify({ challenge: challenge("22"), publicKey: passkey.publicKey, signature, metadata });
		expect(ok).toBe(false);
	});

	it("REJECTS a different public key (the signature is bound to the passkey)", () => {
		const a = createSoftwarePasskey();
		const b = createSoftwarePasskey();
		const c = challenge("cd");
		const { metadata, signature } = authenticatorSign(a, c, RP_ID);
		const ok = WebAuthnP256.verify({ challenge: c, publicKey: b.publicKey, signature, metadata });
		expect(ok).toBe(false);
	});
});
