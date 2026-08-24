/**
 * @module
 *
 * The `cloudflare:workers` module, declared so that Deno's module graph can resolve it.
 *
 * `src/providers/cloudflare.ts` extends `DurableObject`, which the Workers runtime supplies through the
 * `cloudflare:workers` scheme. `deno check` reports nothing without this file, because `@cloudflare/workers-types`
 * declares the module. The Deno editor server resolves the graph before it types it, and it reports `no-cache` on the
 * import. This file gives that specifier a target. The `scopes` block of the root `deno.jsonc` points at it, scoped to
 * `./src/providers/`.
 *
 * Nothing here exists at run time.
 */

/** The base class the Workers runtime gives to a Durable Object. */
export declare const DurableObject: typeof CloudflareWorkersModule.DurableObject;
