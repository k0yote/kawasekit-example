/** Typed errors for the RFC-0001 harness. */

/**
 * Sponsorship was rejected by the paymaster (gas policy not set on the ZeroDev
 * Amoy project, limit hit, or the RPC declined). Surfaced explicitly — the
 * harness MUST NOT silently fall back to owner-pays-gas (RFC §6.2 step 7 / Step C.7).
 */
export class SponsorshipError extends Error {
	constructor(message: string, options?: { cause?: unknown }) {
		// Error's own `cause` (ES2022) is set from `options` — no redeclaration needed.
		super(`SponsorshipError: ${message}`, options);
		this.name = "SponsorshipError";
	}
}

/** A payment was attempted whose parameters fall outside the session-key policy scope. */
export class OutOfScopeError extends Error {
	constructor(message: string) {
		super(`OutOfScopeError: ${message}`);
		this.name = "OutOfScopeError";
	}
}
