/**
 * RFC-0003 Cycle 1 — passkey-sudo Kernel account (ZeroDev wiring, layer b).
 *
 * The `signMessageCallback` adapter encodes the headless ox assertion into ZeroDev's
 * EXACT validator wire format — copied verbatim from `@zerodev/passkey-validator`'s own
 * `signMessageUsingWebAuthn` (the canonical encoder): `encodeAbiParameters([
 * authenticatorData, clientDataJSON, responseTypeLocation, r, s, usePrecompiled], …)`,
 * with `responseTypeLocation = findQuoteIndices(clientDataJSON).beforeType` and
 * `usePrecompiled = isRIP7212SupportedNetwork(chainId)` (duo-mode). The validator calls
 * the callback with `(message: SignableMessage{ raw: userOpHash }, rpID, chainId, …)` and
 * uses the returned Hex directly. Layer (b) is proven end-to-end by the on-chain P1.
 */
import { PasskeyValidatorContractVersion, toPasskeyValidator } from "@zerodev/passkey-validator";
import { createKernelAccount, type CreateKernelAccountReturnType } from "@zerodev/sdk";
import { getEntryPoint, KERNEL_V3_1 } from "@zerodev/sdk/constants";
import {
	b64ToBytes,
	findQuoteIndices,
	isRIP7212SupportedNetwork,
	toWebAuthnKey,
	uint8ArrayToHexString,
	WebAuthnMode,
} from "@zerodev/webauthn-key";
import {
	type Chain,
	encodeAbiParameters,
	type Hex,
	keccak256,
	type PublicClient,
	type SignableMessage,
	type Transport,
} from "viem";
import { authenticatorSign, type SoftwarePasskey } from "./passkey.ts";

/** The ZeroDev WebAuthn-validator signature ABI (verbatim from signMessageUsingWebAuthn). */
const WEBAUTHN_SIG_ABI = [
	{ name: "authenticatorData", type: "bytes" },
	{ name: "clientDataJSON", type: "string" },
	{ name: "responseTypeLocation", type: "uint256" },
	{ name: "r", type: "uint256" },
	{ name: "s", type: "uint256" },
	{ name: "usePrecompiled", type: "bool" },
] as const;

/** Extract the 32-byte hash challenge from the SignableMessage the validator passes. */
function challengeFromMessage(message: SignableMessage): Hex {
	// signUserOperation → signMessage(client, { message: { raw: hash } });
	// typed-data path → signMessage(client, { message: hash }) (a Hex string).
	if (typeof message === "string") return message as Hex;
	return (typeof message.raw === "string" ? message.raw : uint8ArrayToHexString(message.raw)) as Hex;
}

/** The headless `signMessageCallback` for a software passkey (returns the encoded ZeroDev Hex). */
export function passkeySignMessageCallback(passkey: SoftwarePasskey) {
	return async (message: SignableMessage, rpId: string, chainId: number): Promise<Hex> => {
		const challenge = challengeFromMessage(message);
		const { metadata, signature } = authenticatorSign(passkey, challenge, rpId);
		const { beforeType } = findQuoteIndices(metadata.clientDataJSON);
		return encodeAbiParameters(WEBAUTHN_SIG_ABI, [
			metadata.authenticatorData,
			metadata.clientDataJSON,
			beforeType,
			signature.r,
			signature.s,
			isRIP7212SupportedNetwork(chainId),
		]);
	};
}

/**
 * Build the passkey **validator** (reusable as a Kernel sudo). Factored out so both
 * the P1 owner-only account and the P2 session-key account (sudo = passkey, regular =
 * permission validator) can root on the same headless passkey.
 */
export async function buildPasskeyValidator(
	publicClient: PublicClient<Transport, Chain>,
	passkey: SoftwarePasskey,
	rpID: string,
) {
	const entryPoint = getEntryPoint("0.7");
	// authenticatorIdHash exactly as @zerodev derives it (keccak256 of the raw credential bytes).
	const authenticatorIdHash = keccak256(uint8ArrayToHexString(b64ToBytes(passkey.id)));
	// Passing a complete webAuthnKey makes toWebAuthnKey return it as-is (no passkey-server fetch).
	const webAuthnKey = await toWebAuthnKey({
		webAuthnKey: {
			pubX: passkey.publicKey.x,
			pubY: passkey.publicKey.y,
			authenticatorId: passkey.id,
			authenticatorIdHash,
			rpID,
			signMessageCallback: passkeySignMessageCallback(passkey),
		},
		rpID,
		mode: WebAuthnMode.Login,
	});
	return toPasskeyValidator(publicClient, {
		webAuthnKey,
		entryPoint,
		kernelVersion: KERNEL_V3_1,
		validatorContractVersion: PasskeyValidatorContractVersion.V0_0_3_PATCHED,
	});
}

/** Build a Kernel v0.7 account whose SUDO is the passkey validator, signing headless. */
export async function createPasskeyAccount(params: {
	readonly publicClient: PublicClient<Transport, Chain>;
	readonly passkey: SoftwarePasskey;
	readonly rpID: string;
}): Promise<CreateKernelAccountReturnType<"0.7">> {
	const { publicClient, passkey, rpID } = params;
	const passkeyValidator = await buildPasskeyValidator(publicClient, passkey, rpID);
	return createKernelAccount(publicClient, {
		plugins: { sudo: passkeyValidator },
		entryPoint: getEntryPoint("0.7"),
		kernelVersion: KERNEL_V3_1,
	});
}
