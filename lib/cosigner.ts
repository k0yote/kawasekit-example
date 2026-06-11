/**
 * Wire the **cryptographic** mpc-2p co-signer: the PUBLIC `kawasekit` adapter
 * (`createMpc2pPolicyGatedSigner`) driven by the PRIVATE `@kawasekit/mpc-2p`
 * glue (the WASM DKLs agent share + the wss/mTLS transport + the A3 HMAC
 * authenticator), talking to your deployed `cosign_server` over mutual TLS.
 *
 * This is the open-core seam in one file: nothing here holds the owner's share
 * or the policy — those live behind the wire, in the owner-hosted backend. The
 * agent holds only ITS half-share, and no valid signature exists without a
 * policy-passing co-sign from the owner.
 *
 * UNAUDITED — testnet only.
 */

import { createMpc2pPolicyGatedSigner, type PolicyGatedSigner } from "kawasekit";
import {
	createHmacAuthenticator,
	createNodeMpc2pTransport,
	createWasmCoSignAgent,
} from "@kawasekit/mpc-2p";
import { getAddress } from "viem";

export interface CoSignerEnv {
	/** The deployed cosign_server endpoint, e.g. `wss://cosigner.example.com:8443`. */
	readonly url: string;
	/** The agent's ONE DKLs share (hex), provisioned at the DKG ceremony. */
	readonly shareHex: string;
	/** The A3 pre-shared HMAC key (hex), shared with the backend at the DKG ceremony. */
	readonly a3KeyHex: string;
	/** Trusted CA (PEM) for the server certificate. */
	readonly ca: string;
	/** The agent's client certificate (PEM) for mTLS. */
	readonly clientCert: string;
	/** The agent's client private key (PEM) for mTLS. */
	readonly clientKey: string;
	/** SNI / cert-identity override when connecting by IP (optional). */
	readonly servername?: string;
	/** The bound policy session id (for `describe()`; the backend holds the authoritative policy). */
	readonly sessionId: string;
	/** The session's `notAfter` (unix seconds). */
	readonly sessionNotAfter: bigint;
}

/**
 * Build the cryptographic `PolicyGatedSigner` for the group EOA. The asset is
 * pinned to JPYC v2 (the A4 EIP-712 domain source of truth); `from` is the
 * group 2-of-2 EOA the agent share controls (asserted against the agent at
 * construction).
 */
export function buildCryptographicSigner(env: CoSignerEnv): PolicyGatedSigner<"cryptographic"> {
	const agent = createWasmCoSignAgent(env.shareHex);
	const from = getAddress(agent.groupEoa());

	const authenticator = createHmacAuthenticator(env.a3KeyHex);
	const transport = createNodeMpc2pTransport({
		url: env.url,
		ca: env.ca,
		cert: env.clientCert,
		key: env.clientKey,
		servername: env.servername,
	});

	return createMpc2pPolicyGatedSigner({
		from,
		asset: { kind: "known", id: "jpyc-v2" },
		session: { id: env.sessionId, notAfter: env.sessionNotAfter },
		agent,
		transport,
		authenticator,
	});
}
