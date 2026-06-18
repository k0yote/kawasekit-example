/**
 * RFC-0001 config — env-only (never hardcode the JPYC address/decimals or RPCs).
 * The JPYC address + decimals MUST be filled from the official JPYC faucet/docs and
 * verified on Amoy PolygonScan; {@link assertJpycOnChain} asserts on-chain `decimals()`
 * matches at startup and aborts on mismatch.
 */

import { getJpycAddress, jpycAbi, polygonAmoy } from "kawasekit";
import {
	type Address,
	type Chain,
	createPublicClient,
	getAddress,
	type Hex,
	http,
	isAddress,
	type PublicClient,
	type Transport,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { createSoftwarePasskey, passkeyFromStored, type SoftwarePasskey } from "./passkey.ts";

export const AMOY_CHAIN_ID = 80002 as const;

function required(name: string): string {
	const v = process.env[name];
	if (v === undefined || v.trim() === "") {
		throw new Error(`RFC-0001: missing required env var ${name} (see zerodev-agent-jpyc/.env.example).`);
	}
	return v.trim();
}

function requiredAddress(name: string): Address {
	const v = required(name);
	if (!isAddress(v)) {
		throw new Error(`RFC-0001: env var ${name} is not a valid address: ${v}`);
	}
	return getAddress(v);
}

function requiredHex32(name: string): Hex {
	const v = required(name);
	const hex = v.startsWith("0x") ? v : `0x${v}`;
	if (!/^0x[0-9a-fA-F]{64}$/.test(hex)) {
		throw new Error(`RFC-0001: env var ${name} must be a 32-byte hex private key.`);
	}
	return hex as Hex;
}

function optionalInt(name: string, fallback: number): number {
	const v = process.env[name];
	if (v === undefined || v.trim() === "") return fallback;
	const n = Number.parseInt(v.trim(), 10);
	if (!Number.isInteger(n) || n < 1) {
		throw new Error(`RFC-0001: env var ${name} must be a positive integer, got ${v}.`);
	}
	return n;
}

export interface RfcConfig {
	readonly amoyRpc: string;
	readonly zerodevRpc: string;
	readonly zerodevProjectId: string;
	readonly jpycAddress: Address;
	readonly jpycDecimals: number;
	/** WebAuthn relying-party id (the owner is a PASSKEY; there is no owner private key). */
	readonly rpID: string;
	readonly sessionPrivateKey: Hex;
	readonly merchant: Address;
	/** Human JPYC per-transfer cap (default 1). */
	readonly maxPerTransferJpyc: number;
	/** Window-total transfer count (default 1). */
	readonly maxTransfers: number;
	/** validUntil = now + windowSeconds (default 3600). */
	readonly windowSeconds: number;
	readonly chain: Chain;
}

/** Parse + validate the RFC-0001 env. Throws on any missing/invalid var. */
export function loadConfig(): RfcConfig {
	const jpycDecimalsRaw = required("JPYC_DECIMALS");
	const jpycDecimals = Number.parseInt(jpycDecimalsRaw, 10);
	if (!Number.isInteger(jpycDecimals) || jpycDecimals < 0 || jpycDecimals > 36) {
		throw new Error(`RFC-0001: JPYC_DECIMALS must be a small non-negative integer, got ${jpycDecimalsRaw}.`);
	}
	return {
		amoyRpc: required("AMOY_RPC"),
		zerodevRpc: required("ZERODEV_RPC"),
		zerodevProjectId: required("ZERODEV_PROJECT_ID"),
		jpycAddress: requiredAddress("JPYC_ADDRESS_AMOY"),
		jpycDecimals,
		rpID: process.env.PASSKEY_RPID?.trim() || "kawasekit.local",
		sessionPrivateKey: requiredHex32("SESSION_PRIVATE_KEY"),
		merchant: requiredAddress("MERCHANT_ADDRESS"),
		maxPerTransferJpyc: optionalInt("MAX_PER_TRANSFER_JPYC", 1),
		maxTransfers: optionalInt("MAX_TRANSFERS", 1),
		windowSeconds: optionalInt("WINDOW_SECONDS", 3600),
		chain: polygonAmoy,
	};
}

/** A read-only Amoy public client built from the config. */
export function makePublicClient(cfg: RfcConfig): PublicClient<Transport, Chain> {
	return createPublicClient({ chain: cfg.chain, transport: http(cfg.amoyRpc) }) as PublicClient<Transport, Chain>;
}

/**
 * Abort-on-mismatch startup assertions (RFC §7, §9):
 * 1. `cfg.chain.id === 80002` (Amoy).
 * 2. The env JPYC address equals kawasekit's built-in `getJpycAddress(80002)` — because
 *    `transferJpyc` resolves the JPYC address from kawasekit's deployments, not a caller arg,
 *    so the env var is only a verification anchor and MUST match.
 * 3. On-chain `decimals()` on that address equals `JPYC_DECIMALS`.
 */
export async function assertJpycOnChain(
	publicClient: PublicClient<Transport, Chain>,
	cfg: RfcConfig,
): Promise<void> {
	if (cfg.chain.id !== AMOY_CHAIN_ID) {
		throw new Error(`RFC-0001: expected Amoy (id ${AMOY_CHAIN_ID}), got chain id ${cfg.chain.id}.`);
	}
	const builtIn = getJpycAddress(AMOY_CHAIN_ID);
	if (getAddress(builtIn) !== cfg.jpycAddress) {
		throw new Error(
			`RFC-0001: JPYC_ADDRESS_AMOY (${cfg.jpycAddress}) does not match kawasekit's getJpycAddress(${AMOY_CHAIN_ID}) (${builtIn}). transferJpyc would use the built-in; reconcile the env value before running.`,
		);
	}
	const onChainDecimals = await publicClient.readContract({
		address: cfg.jpycAddress,
		abi: jpycAbi,
		functionName: "decimals",
	});
	if (Number(onChainDecimals) !== cfg.jpycDecimals) {
		throw new Error(
			`RFC-0001: on-chain JPYC decimals() = ${onChainDecimals} but JPYC_DECIMALS = ${cfg.jpycDecimals}. Aborting (verify the address/decimals against the official JPYC docs + Amoy PolygonScan).`,
		);
	}
}

/** Derive the session viem account (the owner is a passkey — see {@link loadOrCreatePasskey}). */
export function sessionFromConfig(cfg: RfcConfig): ReturnType<typeof privateKeyToAccount> {
	return privateKeyToAccount(cfg.sessionPrivateKey);
}

/**
 * Load (or first-run create + persist) the software passkey that owns the account.
 * Persisting `{ privateKey, id }` keeps the counterfactual account address STABLE across
 * runs so it can be funded once. Gitignored (`.passkey-cycle1.json`); testnet-only.
 */
export function loadOrCreatePasskey(fileUrl: URL): SoftwarePasskey {
	if (existsSync(fileUrl)) {
		const j = JSON.parse(readFileSync(fileUrl, "utf8")) as { privateKey: Hex; id: string };
		return passkeyFromStored(j.privateKey, j.id);
	}
	const pk = createSoftwarePasskey();
	writeFileSync(fileUrl, JSON.stringify({ privateKey: pk.privateKey, id: pk.id }, null, 2));
	return pk;
}
