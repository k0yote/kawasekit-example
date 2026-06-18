/**
 * RFC-0003 Cycle 1 — headless passkey (software P256 authenticator) via `ox`.
 *
 * No browser, no `navigator`: `ox/WebAuthnP256.getSignPayload` assembles the exact
 * WebAuthn bytes (authenticatorData + clientDataJSON + challenge/type indices; flag
 * UP+UV) and `ox/P256.sign` signs the payload — so the harness signs a passkey userOp
 * in pure Node (RFC-0003 §6.2; the C1 foundation spike). The off-chain
 * `ox/WebAuthnP256.verify` roundtrip in `passkey.test.ts` proves the byte format +
 * challenge encoding (layer a) BEFORE any on-chain P1 (layer b = ZeroDev wire encoding).
 */
import { Base64, Bytes, P256, type PublicKey, WebAuthnP256 } from "ox";
import type { Hex } from "viem";

/** A software passkey: a P256 keypair standing in for a WebAuthn authenticator (no server, no browser). */
export interface SoftwarePasskey {
	/** Credential id — a base64url string (so `@zerodev`'s `b64ToBytes(id)` → `authenticatorIdHash` works). */
	readonly id: string;
	readonly privateKey: Hex;
	readonly publicKey: PublicKey.PublicKey;
}

/** Create a fresh in-Node P256 "passkey" (the C1 software authenticator). */
export function createSoftwarePasskey(): SoftwarePasskey {
	const privateKey = P256.randomPrivateKey();
	const publicKey = P256.getPublicKey({ privateKey });
	const id = Base64.fromBytes(Bytes.random(16), { url: true, pad: false });
	return { id, privateKey, publicKey };
}

/**
 * Reconstruct a passkey from a persisted `{ privateKey, id }` (the public key is
 * re-derived). Lets a runnable prover keep a STABLE counterfactual account address
 * across runs so it can be funded once (RFC-0001's persisted-key pattern).
 */
export function passkeyFromStored(privateKey: Hex, id: string): SoftwarePasskey {
	return { id, privateKey, publicKey: P256.getPublicKey({ privateKey }) };
}

/**
 * Produce a headless WebAuthn assertion over `challenge` (the 32-byte hash to sign).
 * ox assembles the bytes (`getSignPayload`) and we sign the payload with the software
 * key; the returned `metadata` + `signature` feed `WebAuthnP256.verify` (off-chain) and
 * the ZeroDev `signMessageCallback` encoder (on-chain).
 */
export function authenticatorSign(passkey: SoftwarePasskey, challenge: Hex, rpId: string) {
	const { metadata, payload } = WebAuthnP256.getSignPayload({
		challenge,
		rpId,
		origin: `https://${rpId}`,
		userVerification: "required",
	});
	const signature = P256.sign({ payload, privateKey: passkey.privateKey, hash: true });
	return { metadata, signature: { r: signature.r, s: signature.s } };
}
