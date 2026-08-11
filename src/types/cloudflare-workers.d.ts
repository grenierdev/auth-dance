/**
 * @module
 *
 * The `cloudflare:workers` module, declared so that Deno's module graph can resolve it.
 *
 * `src/providers/cloudflare.ts` extends `DurableObject`, which the Workers runtime supplies through the
 * `cloudflare:workers` scheme. The types are already correct without this file: `@cloudflare/workers-types` declares
 * the module, and the root `compilerOptions.types` loads it, so `deno check` reports nothing. Deno's editor server
 * resolves the graph before it types it, finds a scheme it cannot fetch, and reports `no-cache` on the import. This
 * file gives that one specifier a target to resolve to. The `scopes` block of the root `deno.jsonc` points at it,
 * scoped to `./src/providers/`, so the mapping applies to the one directory that imports the module.
 *
 * A `// @ts-types` comment on the import cannot do this work. That directive replaces the types of a module that
 * already resolves, which is why it fits `demo/src/routes/__root.tsx`, where `../styles.css?url` names a real file.
 * Here resolution is what fails, and it happens before types are read.
 *
 * It stays outside `src/` on purpose. `src/` is the root of the published package, and a file below it would be
 * packed and shipped. From here the tarball is byte-identical to one built without this file, and `deno pack` writes
 * `cloudflare:workers` into the emitted `.js` and `.d.ts` unchanged, so an installed copy still binds to the runtime
 * module.
 *
 * The declaration borrows the published type instead of restating it. Nothing here exists at run time.
 */

/** The base class the Workers runtime gives to a Durable Object. */
export declare const DurableObject: typeof CloudflareWorkersModule.DurableObject;
