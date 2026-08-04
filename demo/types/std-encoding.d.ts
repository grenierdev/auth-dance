/**
 * The two jsr specifiers the library reaches for, declared for `tsc`.
 *
 * `src/otp.ts` decodes a base32 secret and `src/components/password.ts` hex-encodes a digest, both through
 * `@std/encoding`. Vite resolves those specifiers through the Deno plugin, and Deno resolves them through the import
 * map, but `tsc` reads neither: it knows `node_modules` and the `paths` table alone, and a jsr package lands in
 * neither. These declarations are what `paths` points at, so the type checker can follow the library source the same
 * way the bundler does.
 *
 * Both mirror the published signature exactly. Nothing here exists at runtime.
 */

declare module "@std/encoding/base32" {
	/** Decodes a base32 string into the bytes it stands for. */
	export function decodeBase32(b32: string): Uint8Array;
}

declare module "@std/encoding/hex" {
	/** Encodes bytes as their lower-case hexadecimal string. */
	export function encodeHex(src: ArrayBuffer | Uint8Array | string): string;
}
