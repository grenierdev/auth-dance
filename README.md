# Auth Dance

Everybody's already doing the dance. Type your email, wait for the code, paste the code, type your
password — you've performed those steps a thousand times without ever calling them a routine.

Auth Dance is the library that finally writes the choreography down.

```ts
choreography: choice(sequence("email", "password"), "passkey");
```

That's a complete authentication policy. Sign-in, sign-up, MFA enrollment, credential rotation and
account recovery are all derived from it — one declaration, and the steps take care of themselves.

## Why another auth library?

Because authentication isn't a boolean. It's a **choreography**: an ordered arrangement of prompts
the user has to perform, in sequence or by choice, before they're allowed through the door.

Most libraries hand you a `login(email, password)` function and let you bolt the rest on. Then the
requirements arrive. Add TOTP. Let enterprise users skip passwords. Require a second factor only for
admins. Allow recovery by SMS but never by security question. Every one of those is a change to the
*shape of the dance*, and in a library built around one hard-coded step, every one of them is a
change to the control flow — a new branch, a new endpoint, a new place for a bypass to hide.

Auth Dance separates the **choreography** (which steps, in what order) from the **components** (what
a single step actually does). The choreography is inert data, so the library can walk it:

- **`peek()` decides what happens next.** The state machine never hard-codes "password comes after
  email" — it asks the choreography. Adding a factor is editing a declaration, not editing logic.
- **Every flow reuses the same steps.** Sign-up collects the same components sign-in verifies, so
  the two can't drift apart. Rotation and recovery are re-runs of a step you already declared.
- **The library can reason about your policy.** Unenrolling a factor is refused with
  `WOULD_LOCK_OUT` when removing it would leave no completable path through the choreography. That's
  a graph traversal (`walk()`), not a rule someone remembered to write.
- **Flow state lives with the client.** An in-progress dance is an encrypted JWE (A256GCM) handed
  back as an opaque `state` string. No session table for half-finished logins, nothing to garbage
  collect, and horizontal scaling is free.

A step is a small interface — a prompt, a verification, and how it lands on an identity. Implement
`AuthComponent` and your custom factor is a first-class citizen of every flow, including the ones you
haven't thought about yet.

## Getting Started

> **Status: early.** Auth Dance is pre-release. The package has no `version` in `src/deno.jsonc`, is
> not published to JSR, and only in-memory providers ship. The API surface below is accurate but
> unstable, and there are known rough edges — see [Known gaps](#known-gaps) before reaching for it in
> production.

### Requirements

Deno 2.x. No permission flags are needed for the test suite.

### Bootstrap

`choreoAuth(options)` is the single entry point. It returns your `AuthApi` (the programmatic
surface), a `fetch` handler (the HTTP surface), and an OpenAPI schema generator.

```ts
import choreoAuth, { sequence } from "auth-dance";
import { AuthStorage } from "auth-dance/storage.ts";
import EmailAuthComponent from "auth-dance/components/email.ts";
import PasswordAuthComponent from "auth-dance/components/password.ts";
import {
	MemoryAuthChannel,
	MemoryIdentityProvider,
	MemoryKvProvider,
	MemoryRateLimiterProvider,
} from "auth-dance/providers/memory.ts";

const auth = choreoAuth({
	// Where messages go.
	channels: {
		email: new MemoryAuthChannel("email"),
	},
	// The dance itself.
	choreography: sequence("email", "password"),
	// What each step does. Keys are the names used everywhere else:
	// in the choreography, in prompts, and in `/enroll { name }`.
	components: {
		email: new EmailAuthComponent("email"), // delivers over the "email" channel
		password: new PasswordAuthComponent("salty"),
	},
	// openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
	secret: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs",
	storage: new AuthStorage({
		identity: new MemoryIdentityProvider(),
		kv: new MemoryKvProvider(),
		rate_limiter: new MemoryRateLimiterProvider(),
	}),
});

Deno.serve(auth.fetch);
```

> Only `choreoAuth`, `choice`, `component`, `sequence`, and everything from `identity.ts` / `error.ts`
> are re-exported from the package root today. `AuthStorage`, the components and the memory providers
> currently need deep paths — see [Known gaps](#known-gaps).

### Performing the dance

Sign-in is a loop: ask for a state, submit a value, get the next prompt, repeat until you get tokens.

```ts
const started = await auth.api.signIn();
// { state: "<opaque>", prompt: { kind: "input", name: "email", type: "email", sendable: false }, expireAt }

const afterEmail = await auth.api.submitPrompt({
	name: "email",
	value: "john.doe@example.com",
	state: started.state,
});
// { state: "<opaque>", prompt: { kind: "input", name: "password", type: "password", … }, expireAt }

const done = await auth.api.submitPrompt({
	name: "password",
	value: "foo",
	state: afterEmail.state,
});
// { tokens: { access_token, id_token, refresh_token }, session, identity }
```

Over HTTP, the same three calls — every route is `POST`, every payload is JSON:

```ts
const r1 = await post("/sign-in");
const r2 = await post("/submit-prompt", { name: "email", value: "john.doe@example.com", state: r1.state });
const r3 = await post("/submit-prompt", { name: "password", value: "foo", state: r2.state });
// r3.tokens
```

When a prompt is `sendable` (an OTP, say), call `/send-prompt` to deliver it before submitting. When
a collected value needs proof of control, `submitPrompt` answers with a *validation* prompt instead
of advancing — reply on `/send-validation` and `/submit-validation`, then the dance resumes.

The `prompt.kind` tells the client what to render: `"input"` for a single field, `"choice"` for a
fork in the choreography where the user picks which branch to take.

## Concepts

### Choreography

A choreography is a tree of three node kinds — `component`, `sequence`, `choice` — built with
combinators. Bare strings are sugar for `component(name)`.

```ts
import { choice, component, pick, sequence } from "auth-dance/choreography";

sequence("email", "password"); // email, then password
choice("password", "passkey"); // either one
choice(sequence("email", "password"), "facebook"); // nested
pick(2, "totp", "sms", "backup-code"); // any 2 of 3, in any order
```

`pick(count, ...)` expands to a `choice` of every ordered permutation of length `count`.

The traversal helpers are the state machine's oracle, and useful for testing your own policy:

| Function | Purpose |
| --- | --- |
| `peek(choreography, path)` | The next step, a `choice` of alternatives, or `null` when complete |
| `walk(choreography)` | Generator over every reachable step and the path leading to it |
| `simplify(choreography)` | Flattens same-kind nodes, de-duplicates, collapses 1-element nodes |
| `isEquals(a, b)` | Structural comparison |

### Components

A component is one step. Implement the interface and it works in every flow:

```ts
interface AuthComponent {
	kind: "identification" | "challenge" | "channel";
	verifiable: boolean; // implies verificationComponent
	getPrompt(context: AuthComponentContext): Promise<AuthPromptInput>;
	sendPrompt?(locale: string, context: AuthComponentContext): Promise<AuthMessage>;
	getIdentityComponent(component: string, value: unknown, confirmed: boolean): Promise<IdentityComponent[]>;
	verificationComponent?(context: AuthComponentContext): Promise<AuthComponent>;
	verifyPrompt(value: unknown, context: AuthComponentContext): Promise<boolean | Identity["id"]>;
}
```

`verifyPrompt` returns `false` to reject, `true` to accept without resolving anyone, or an identity
id to say *this is who it is*. Two components resolving different identities in one dance is an
`IDENTITY_MISMATCH`.

`AuthComponentContext` carries `{ storage, stateId, name, flow, identity? }`, where `flow` is one of
`"sign-in" | "sign-up" | "enroll" | "rotate" | "recover" | "subscribe"` — so a component can behave
differently while enrolling than while authenticating.

Three ship in the box:

| Component | Kind | Verifiable | Notes |
| --- | --- | --- | --- |
| `EmailAuthComponent(channel)` | identification | yes | Resolves the identity by address; verifies via OTP. Also contributes a linked `channel`. |
| `PasswordAuthComponent(salt)` | challenge | no | `base64(SHA-512(salt:password))`. See [Known gaps](#known-gaps). |
| `OtpAuthComponent(channel, digits = 6, ttl = 300)` | challenge | no | The only sendable one; stashes the code in KV under `otp/<stateId>/<name>`. |

### Channels

Where messages are delivered. `AuthChannel` is three methods — `sendMessage`, `getPrompt`,
`getIdentityChannel` — and `MemoryAuthChannel` is the test double that just collects into a public
`messages` array.

### Identity

An identity is an id, optional free-form `data`, and a list of components:

```ts
interface Identity {
	id: string; // ksuid, "id_" prefixed
	data?: Record<string, unknown>;
	components: IdentityComponent[];
}
```

Each component is an `identification` (something you claim), a `challenge` (something you prove), or
a `channel` (somewhere you can be reached), each with a `confirmed` flag and a private `data` bag —
the password hash, the pending OTP. The `…Public` variants are the same minus `data`, and those are
what `/list-components` returns.

### Storage

`AuthStorage` is a concrete class you configure with three adapters rather than replace:

```ts
interface AuthIdentityProvider {
	list(offset?: number, limit?: number): Promise<Identity[]>;
	get(id: string): Promise<Identity | undefined>;
	getByIdentification(type: string, identification: string): Promise<Identity | undefined>;
	set(identity: Identity): Promise<void>;
	delete(id: string): Promise<void>;
}

interface AuthKvProvider {
	get(key: string): Promise<string | undefined>;
	list(prefix: string, limit?: number, offset?: number): Promise<string[]>;
	set(key: string, value: string, ttl?: number): Promise<void>;
	unset(key: string): Promise<void>;
}

interface AuthRateLimiterProvider {
	limit(key: string, limit: number, window: number): Promise<{ allowed: boolean; retryAfter: number | undefined }>;
}
```

Key spaces an adapter will see: `session/<id>`, `sessions/<identityId>/<id>`, `otp/<stateId>/<name>`.
Only `MemoryIdentityProvider`, `MemoryKvProvider` and `MemoryRateLimiterProvider` ship today — a
persistent adapter is yours to write, and it's the one thing standing between this and a real
deployment.

### Sessions and tokens

Completing a sign-in or sign-up mints three HS256 JWTs. `access_token` and `refresh_token` carry the
**session** id as `sub` plus a numeric `auth_time`; `id_token` carries the **identity** id and puts
scope-filtered identity `data` in its protected header.

`auth_time` survives refresh unchanged, so refreshing never re-opens the elevated window — sensitive
flows (`enroll`, `rotate`, …) demand a genuinely fresh sign-in and answer `FRESH_SIGN_IN_REQUIRED`
otherwise.

## HTTP API

Reached via `choreoAuth(...).fetch`. **All routes are `POST`**, there is no path prefix (mount it
yourself), and 🔒 means `Authorization: Bearer <access_token>`.

| Route | Body | 200 |
| --- | --- | --- |
| `/sign-in` | — | state |
| `/sign-up` | — | state |
| `/sign-out` 🔒 | `{ others?: boolean }` | `{ success: true }` |
| `/list-sessions` 🔒 | — | `{ sessions, current }` |
| `/list-components` 🔒 | — | `{ components }` |
| `/refresh-token` | `{ refresh_token }` | tokens |
| `/enroll` 🔒 | `{ name }` | state |
| `/unenroll` 🔒 | `{ name }` | state (confirmation) |
| `/rotate` 🔒 | `{ name }` | state |
| `/recover` | `{ name }` | state |
| `/subscribe` 🔒 | `{ name }` | state |
| `/unsubscribe` 🔒 | `{ name }` | state (confirmation) |
| `/delete` 🔒 | — | state (confirmation) |
| `/send-prompt` | `{ name, locale?, state }` | `{ success: true }` |
| `/submit-prompt` | `{ name, value, state }` | state \| tokens \| `{ success: true }` |
| `/send-validation` | `{ name, locale?, state }` | `{ success: true }` |
| `/submit-validation` | `{ name, value, state }` | state \| tokens \| `{ success: true }` |

`locale` falls back to `accept-language`, then `"en"`. Client address comes from `cf-connecting-ip`
or the first `x-forwarded-for` entry — headers only, never the body.

Errors are always a single-key body: `{ "error": "CODE" }`. Malformed input is `400 BAD_REQUEST`,
rate limiting is `429 RATE_LIMITED` with a `Retry-After` header when known, and everything else is
`500` with a code from the `Errors` registry (`INVALID_STATE`, `WOULD_LOCK_OUT`,
`FRESH_SIGN_IN_REQUIRED`, `IDENTITY_MISMATCH`, … 32 in all, falling back to `UNKNOWN`).

`auth.generateOpenAPISchema()` produces a full spec, error picklist included.

## Flows

Beyond sign-in and sign-up, every management flow is the same state-plus-prompt loop:

- **`enroll` / `unenroll`** — add or remove a factor. Removal is refused with `WOULD_LOCK_OUT` when
  no completable path through the choreography would remain.
- **`rotate`** — replace a credential. For a *verifiable* component the first prompt proves control
  of the current value, then the new value is collected and validated in turn — two validation
  rounds. For a non-verifiable one (password) it's a single `submit-prompt`.
- **`recover`** — unauthenticated, and only for a component that is an `identification`, is
  `verifiable`, and is a valid *first move* of the choreography; otherwise
  `COMPONENT_NOT_RECOVERABLE`. Completes with `{ success: true }`, not tokens.
- **`subscribe` / `unsubscribe`** — manage channels. Note the asymmetry when subscribing: the
  confirming code is delivered over an *already-confirmed* channel, so `send-validation` names that
  existing channel while `submit-validation` names the new one.
- **`delete`** — wipes the identity.

`unenroll`, `unsubscribe` and `delete` answer with a `confirmation` prompt that must be submitted
with the boolean `true`; anything else is `CONFIRMATION_REQUIRED`.

## Configuration

Every duration is in seconds and optional, under `advanced`:

| Option | Default |
| --- | --- |
| `sign_in_duration`, `sign_up_duration`, `enroll_duration`, `unenroll_duration`, `rotate_duration`, `recover_duration`, `subscribe_duration`, `unsubscribe_duration`, `delete_duration` | `300` |
| `access_duration` | `300` |
| `refresh_duration` | `86400` |
| `elevated_duration` | `300` |
| `issuer` | `"acme"` |

Rate limits are `{ limit, window }` buckets. Per identity (`identity_rate_limit`): `verify` 10/5min,
`send` 5/5min, `manage` 20/5min, `refresh` 60/5min. Per address (`address_rate_limit`, enforced by
the HTTP layer): `request` 300/min, `send` 60/min.

## Development

No `tasks` block is defined yet, so run the tools directly:

```sh
deno test                          # 6 files, 126 steps, no permission flags
deno test src/api.test.ts
deno test --filter "should sign-in"
deno fmt                           # tabs, line width 140
```

Layout: `src/mod.ts` is the entry point, `src/api.ts` holds the state machine, `src/app.ts` the Hono
routes, `src/choreography.ts` the DSL, `src/components/` and `src/providers/` the batteries. Tests
sit beside their subjects and are, for now, the reference documentation.

## Known gaps

Worth knowing before you build on this:

- **`PasswordAuthComponent` is not production-grade.** A single SHA-512 pass over a shared salt is
  not a KDF — no per-identity salt, no work factor. Ship your own component backed by Argon2 or
  scrypt.
- **No persistent storage adapter.** The memory providers are for tests. `MemoryKvProvider` also
  rejects with `KVKeyNotFoundError` on a missing key where the contract says resolve `undefined`,
  which is why some expired-session paths surface as `UNKNOWN`.
- **`ttl` units disagree.** `AuthStorage.createSession` passes seconds to `setKv` while
  `MemoryKvProvider` reads milliseconds. Pick one before writing an adapter.
- **The export surface is incomplete.** `choreoAuth` needs `AuthApiOptions`, `AuthStorage`,
  `AuthComponent` and the providers, none of which `mod.ts` re-exports — deep imports are the only
  way in today.
- **`OtpAuthComponent` message bodies are placeholders,** and it ignores `locale`. The `subscribe`
  flow also instantiates one internally with no way to configure it.
- **`src/deno.jsonc` has no `version`,** so the package isn't publishable as-is.
