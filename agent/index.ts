/**
 * The paying agent — pays a metered API in testnet JPYC via the **cryptographic
 * 2-of-2 co-signer** (mpc-2p), NOT a raw private key.
 *
 * Flow: the agent calls the paywalled route → receives `402` with the JPYC
 * payment requirements → produces an EIP-3009 `transferWithAuthorization` for
 * the **group EOA** by co-signing with the owner backend (the owner re-derives
 * the digest, re-evaluates its policy, and only then contributes its share) →
 * retries with the `X-PAYMENT` header → the server's facilitator settles
 * on-chain → `200` with the data + the settlement tx.
 *
 * The payment signer is non-bypassable at the type level AND asserted at
 * runtime (`requireEnforcement: "cryptographic"`): there is no local-signing
 * fallback, so an unreachable co-signer throws rather than silently paying.
 *
 * Run (after the server is up + the co-signer is deployed; see README):
 *   pnpm dev:agent
 *
 * UNAUDITED — testnet only.
 */

import "dotenv/config";

import { createX402PaymentSigner, wrapFetch } from "kawasekit";
import { buildCryptographicSigner } from "../lib/cosigner.ts";
import { optionalEnv, readPemFromEnv, requireEnv } from "../lib/env.ts";

const apiBase = optionalEnv("API_BASE_URL") ?? "http://127.0.0.1:8787";
const city = optionalEnv("DEMO_CITY") ?? "Tokyo";

// The cryptographic co-signer: the public adapter + the private glue, pointed at
// the deployed cosign_server over mTLS.
const signer = buildCryptographicSigner({
	url: requireEnv("COSIGNER_URL"),
	shareHex: requireEnv("AGENT_SHARE_HEX"),
	a3KeyHex: requireEnv("A3_KEY_HEX"),
	ca: readPemFromEnv("COSIGNER_CA_PEM"),
	clientCert: readPemFromEnv("COSIGNER_CLIENT_CERT_PEM"),
	clientKey: readPemFromEnv("COSIGNER_CLIENT_KEY_PEM"),
	servername: optionalEnv("COSIGNER_SERVERNAME"),
	sessionId: requireEnv("COSIGNER_SESSION_ID"),
	sessionNotAfter: BigInt(optionalEnv("COSIGNER_SESSION_NOT_AFTER") ?? "4000000000"),
});

// Bind the co-signer into an x402 payment signer. `requireEnforcement` asserts
// the signer is non-bypassable (the runtime mirror of the `requireNonBypassable`
// type-gate) — an advisory signer would throw here.
const paymentSigner = createX402PaymentSigner({
	network: "testnet",
	signer,
	asset: { kind: "known", id: "jpyc-v2" },
	requireEnforcement: "cryptographic",
});

// A defence-in-depth budget guard on the wrapping fetch (on top of the owner's
// authoritative on-chain cap): refuse to pay beyond a session ceiling.
const MAX_SPEND = BigInt(optionalEnv("MAX_SPEND_BASE_UNITS") ?? "1000000"); // 1 JPYC (6 decimals)
let spent = 0n;

const fetch402 = wrapFetch({
	signer: paymentSigner,
	onPayment: (req) => {
		const next = spent + BigInt(req.amount);
		if (next > MAX_SPEND) {
			console.error(`budget exhausted: ${next} > ${MAX_SPEND} base units — refusing to pay`);
			return false;
		}
		spent = next;
		console.log(`  ↳ paying ${req.amount} base units (session total ${next})`);
		return true;
	},
});

async function main(): Promise<void> {
	const url = `${apiBase}/weather/${encodeURIComponent(city)}`;
	console.log(`agent → GET ${url}  (paying in JPYC via the cryptographic co-signer)`);

	const res = await fetch402(url);
	if (!res.ok) {
		console.error(`request failed: ${res.status} ${res.statusText}`);
		console.error(await res.text());
		process.exit(1);
	}
	const body = (await res.json()) as {
		city: string;
		temperature_c: number;
		condition: string;
		payment?: { tx: string; polygonscan: string; amount: string } | null;
	};

	console.log(`\n✅ ${body.city}: ${body.temperature_c}°C, ${body.condition}`);
	if (body.payment) {
		console.log(`   paid ${body.payment.amount} | tx ${body.payment.tx}`);
		console.log(`   ${body.payment.polygonscan}`);
	}
}

main().catch((e: unknown) => {
	console.error(e instanceof Error ? e.stack : String(e));
	process.exit(1);
});
