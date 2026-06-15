/**
 * Observability for the RFC-0001 harness (Step C.6 / acceptance I2).
 *
 * BOUNDARY NOTE (RFC §6.4 canary): kawasekit's public observability surface
 * (`ObservabilityHooks`, `SettleEvent`, `VerifyEvent`, …) is shaped for the
 * **x402 facilitator** flow (verify / settle / payment-required / accepted). The
 * Option-A path here (a session-key userOp IS the settlement) has phases the SDK
 * has no native event for — `submit` and `sponsor`. So the harness defines its
 * own typed events for those phases and fires them through the SDK's generic
 * `invokeHookSafely<TEvent>()` (reused as-is). The on-chain `settle` phase maps
 * conceptually to the SDK's `SettleEvent`, recorded here as a harness event.
 */

import { invokeHookSafely } from "kawasekit/observability";
import type { Address, Hex } from "viem";

export type HarnessPhase = "submit" | "sponsor" | "settle" | "validation_reject";

export interface HarnessSpan {
	readonly phase: HarnessPhase;
	readonly at: number;
	readonly account?: Address;
	readonly to?: Address;
	readonly amount?: string;
	readonly transaction?: Hex;
	readonly detail?: string;
}

/** Hook callbacks — same optional-per-phase shape as `ObservabilityHooks`. */
export interface HarnessTelemetry {
	readonly onSubmit?: (span: HarnessSpan) => void;
	readonly onSponsor?: (span: HarnessSpan) => void;
	readonly onSettle?: (span: HarnessSpan) => void;
	readonly onValidationReject?: (span: HarnessSpan) => void;
}

function now(): number {
	// `Date.now()` is fine in a runnable harness (unlike the SDK's pure core).
	return Date.now();
}

/** Emit a phase span through the SDK's safe-invoke (errors in a hook never break the flow). */
export function emit(telemetry: HarnessTelemetry | undefined, span: HarnessSpan): void {
	if (telemetry === undefined) return;
	const hook =
		span.phase === "submit"
			? telemetry.onSubmit
			: span.phase === "sponsor"
				? telemetry.onSponsor
				: span.phase === "settle"
					? telemetry.onSettle
					: telemetry.onValidationReject;
	invokeHookSafely(hook, span);
}

/** A console telemetry impl for the runnable demo. */
export const consoleTelemetry: HarnessTelemetry = {
	onSubmit: (s) => console.log(`  [submit]  account=${s.account} → ${s.to} amount=${s.amount}`),
	onSponsor: (s) => console.log(`  [sponsor] paymaster sponsoring userOp${s.detail ? ` (${s.detail})` : ""}`),
	onSettle: (s) => console.log(`  [settle]  tx=${s.transaction}`),
	onValidationReject: (s) => console.log(`  [reject]  ${s.detail ?? "userOp rejected at validation"}`),
};

/** A capturing telemetry impl for tests (I2): records every span. */
export function createRecordingTelemetry(): { telemetry: HarnessTelemetry; spans: HarnessSpan[] } {
	const spans: HarnessSpan[] = [];
	const push = (s: HarnessSpan) => spans.push(s);
	return {
		spans,
		telemetry: { onSubmit: push, onSponsor: push, onSettle: push, onValidationReject: push },
	};
}
