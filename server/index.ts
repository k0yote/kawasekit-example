/**
 * The metered API — a Hono server that paywalls `GET /weather/:city` behind a
 * JPYC x402 v2 payment on Polygon Amoy, settled by kawasekit's self-facilitator.
 *
 * This side is a plain x402 resource server; it does not know or care that the
 * payer is a 2-of-2 co-signer rather than a raw EOA — it just verifies + settles
 * the EIP-3009 authorization. The cryptographic enforcement lives entirely on
 * the agent/owner side (see agent/ + lib/cosigner.ts).
 *
 * Run:
 *   cp .env.example .env   # fill in the facilitator key + recipient
 *   pnpm dev:server
 *
 * UNAUDITED — testnet only.
 */

import "dotenv/config";

import { serve } from "@hono/node-server";
import { Hono } from "hono";
import {
	buildPaymentRequirements,
	createSelfFacilitator,
	getJpycAddress,
	JPYC_DECIMALS,
	polygonAmoy,
	type X402HandlerContext,
	type X402PaymentRequirements,
} from "kawasekit";
import { type X402HonoEnv, x402Middleware } from "kawasekit/x402/hono";
import { type Address, createPublicClient, createWalletClient, getAddress, http, parseUnits } from "viem";
import { nonceManager, privateKeyToAccount } from "viem/accounts";
import { optionalEnv, requireEnv } from "../lib/env.ts";

const facilitatorPk = requireEnv("X402_FACILITATOR_PRIVATE_KEY") as `0x${string}`;
const recipient: Address = getAddress(requireEnv("X402_RECIPIENT"));
const priceHuman = optionalEnv("PRICE_JPYC") ?? "0.001";
const port = Number.parseInt(optionalEnv("PORT") ?? "8787", 10);
const rpcUrl = optionalEnv("POLYGON_AMOY_RPC_URL") ?? polygonAmoy.rpcUrls.default.http[0];
if (rpcUrl === undefined) {
	throw new Error("polygonAmoy RPC is undefined; set POLYGON_AMOY_RPC_URL.");
}

// `nonceManager` keeps the facilitator EOA safe for concurrent settle() calls
// (an agent may fan out parallel paid requests).
const facilitatorAccount = privateKeyToAccount(facilitatorPk, { nonceManager });
const transport = http(rpcUrl);
const publicClient = createPublicClient({ chain: polygonAmoy, transport });
const facilitatorWallet = createWalletClient({ chain: polygonAmoy, transport, account: facilitatorAccount });

const jpycAddress = getJpycAddress(polygonAmoy.id);
const price = parseUnits(priceHuman, JPYC_DECIMALS);

const facilitator = createSelfFacilitator({
	network: "testnet",
	walletClient: facilitatorWallet,
	publicClient,
});

const requirements: X402PaymentRequirements = buildPaymentRequirements({
	chainId: polygonAmoy.id,
	asset: jpycAddress,
	payTo: recipient,
	amount: price,
	maxTimeoutSeconds: 300,
});

const app = new Hono<X402HonoEnv>();

app.get("/", (c) =>
	c.json({
		service: "kawasekit-example metered API",
		paywalled: "/weather/:city",
		price: `${priceHuman} JPYC`,
		network: "polygon-amoy",
		jpyc: jpycAddress,
		facilitator: facilitatorAccount.address,
		recipient,
	}),
);

app.use(
	"/weather/*",
	x402Middleware({
		facilitator,
		requirementsFor: () => [requirements],
	}),
);
app.get("/weather/:city", (c) => {
	const city = c.req.param("city");
	const ctx = c.get("x402") as X402HandlerContext | undefined;
	const tx = ctx?.settlement.transaction;

	const weather = {
		city,
		temperature_c: 22 + Math.floor(Math.random() * 8) - 4,
		condition: ["sunny", "cloudy", "rainy"][Math.floor(Math.random() * 3)] ?? "sunny",
		asOf: new Date().toISOString(),
	};
	if (tx) {
		console.log(`  ↳ paid ${priceHuman} JPYC by ${ctx?.settlement.payer ?? "?"} | tx ${tx}`);
	}
	return c.json({
		...weather,
		payment: tx
			? { tx, polygonscan: `https://amoy.polygonscan.com/tx/${tx}`, amount: `${priceHuman} JPYC` }
			: null,
	});
});

console.log("kawasekit-example metered API");
console.log(`  facilitator EOA:  ${facilitatorAccount.address}`);
console.log(`  recipient:        ${recipient}`);
console.log(`  price per call:   ${priceHuman} JPYC (= ${price.toString()} base units)`);
console.log(`  JPYC contract:    ${jpycAddress}`);
console.log(`  listening on:     http://127.0.0.1:${port}`);
console.log(`  paywalled route:  GET /weather/:city`);

serve({ fetch: app.fetch, port });
