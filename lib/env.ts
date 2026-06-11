/** Tiny env helpers — fail loud on a missing required var; read PEM files by path. */

import { readFileSync } from "node:fs";

export function requireEnv(name: string): string {
	const value = process.env[name];
	if (value === undefined || value.trim() === "") {
		throw new Error(`Missing required env var: ${name}. Copy .env.example to .env and fill it in.`);
	}
	return value;
}

export function optionalEnv(name: string): string | undefined {
	const value = process.env[name];
	return value === undefined || value.trim() === "" ? undefined : value;
}

/** Read a PEM file referenced by an env var (path), failing loud if missing. */
export function readPemFromEnv(name: string): string {
	return readFileSync(requireEnv(name), "utf8");
}
