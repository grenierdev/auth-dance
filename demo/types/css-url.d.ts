/**
 * The type of a `?url` stylesheet import, declared for Deno.
 *
 * `src/routes/__root.tsx` imports `../styles.css?url` to put the built stylesheet in the document head. Vite reads
 * `?url` as an instruction to hand back the emitted URL instead of the file, and `tsc` types it through the
 * `declare module "*?url"` that ships in `vite/client`. Deno reads neither: it takes the query for part of the path,
 * resolves the stylesheet itself, and reports that a CSS module has no default export. A `// @ts-types` comment on
 * the import points here instead, which is the one form Deno honours.
 *
 * Mirrors the `vite/client` declaration. Nothing here exists at runtime.
 */

/** The URL Vite emits for the stylesheet, hashed for the build it belongs to. */
declare const url: string;

export default url;
