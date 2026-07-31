# Auth Dance

Everybody already does the dance. Type your email, wait for the code, paste the code, type your password. You did those steps a thousand
times and never called them a routine.

Auth Dance writes the choreography down.

```ts
choreography: choice(sequence("email", "password"), "passkey");
```

That is a complete authentication policy. The library derives sign-in, sign-up, MFA enrollment, credential rotation and account recovery
from it. You declare the steps one time.

## Why another auth library?

Authentication is not a boolean. It is a **choreography**: an ordered arrangement of prompts. The user performs the prompts, in sequence or
by choice, before the library opens the door.

Most libraries give you a `login(email, password)` function. You attach the rest yourself. Then the requirements arrive. Add TOTP. Let
enterprise users skip passwords. Require a second factor for admins only. Allow recovery by SMS but never by security question.

Each requirement changes the _shape of the dance_. In a library built around one hard-coded step, each one also changes the control flow.
You add a branch, an endpoint, and one more place where a bypass hides.

Auth Dance separates the **choreography** (which steps, in what order) from the **components** (what one step does). The choreography is
inert data, so the library can walk it:

- **`peek()` decides what happens next.** The state machine does not hard-code "password comes after email". It asks the choreography. To
  add a factor, you edit a declaration instead of logic.
- **Every flow reuses the same steps.** Sign-up collects the components that sign-in verifies, so the two flows cannot drift apart. Rotation
  and recovery re-run a step you already declared.
- **The library can reason about your policy.** It refuses to unenroll a factor with `WOULD_LOCK_OUT` when the removal leaves no completable
  path through the choreography. That answer comes from a graph traversal (`walk()`), not from a rule someone remembered to write.
- **Flow state lives with the client.** An in-progress dance is an encrypted JWE (A256GCM). The library returns it as an opaque `state`
  string. Half-finished logins need no session table and no garbage collection, and horizontal scaling costs nothing.

A step is a small interface: a prompt, a verification, and how the result lands on an identity. Implement `AuthComponent` and your custom
factor works in every flow, including the flows you did not think about yet.

## Getting Started

> **Status: early.** Auth Dance is pre-release. The package has no `version` in `src/deno.jsonc`. The package is not published to JSR, and
> only in-memory providers ship today. The API surface below is accurate but unstable. Read [Known gaps](#known-gaps) before you use it in
> production.

### Requirements

Deno 2.x. The test suite needs no permission flags.

### Bootstrap

`choreoAuth(options)` is the single entry point. It returns your `AuthApi` (the programmatic surface), a `fetch` handler (the HTTP surface),
and an OpenAPI schema generator.

```ts
import choreoAuth, { sequence } from "auth-dance";
import { AuthStorage } from "auth-dance/storage.ts";
import EmailAuthComponent from "auth-dance/components/email.ts";
import PasswordAuthComponent from "auth-dance/components/password.ts";
import { MemoryAuthChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "auth-dance/providers/memory.ts";

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

> The package root re-exports `choreoAuth`, `choice`, `component`, `sequence`, and everything from `identity.ts` and `error.ts`.
> `AuthStorage`, the components and the memory providers still need deep paths. See [Known gaps](#known-gaps).

### Performing the dance

Sign-in is a loop. Ask for a state, submit a value, get the next prompt, and repeat until the library returns tokens.

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

Over HTTP, you make the same three calls. Every route is `POST`, and every payload is JSON:

```ts
const r1 = await post("/sign-in");
const r2 = await post("/submit-prompt", { name: "email", value: "john.doe@example.com", state: r1.state });
const r3 = await post("/submit-prompt", { name: "password", value: "foo", state: r2.state });
// r3.tokens
```

If a prompt is `sendable`, an OTP for example, call `/send-prompt` to deliver it before you submit. If a collected value needs proof of
control, `submitPrompt` answers with a _validation_ prompt instead of an advance. Reply on `/send-validation` and `/submit-validation`, then
the dance continues.

`prompt.kind` tells the client what to render. `"input"` is a single field. `"choice"` is a fork in the choreography where the user picks
the branch to take.

## Concepts

### Choreography

A choreography is a tree of three node kinds: `component`, `sequence` and `choice`. Combinators build the tree. A bare string is sugar for
`component(name)`.

```ts
import { choice, component, pick, sequence } from "auth-dance/choreography";

sequence("email", "password"); // email, then password
choice("password", "passkey"); // either one
choice(sequence("email", "password"), "facebook"); // nested
pick(2, "totp", "sms", "backup-code"); // any 2 of 3, in any order
```

`pick(count, ...)` expands to a `choice` of every ordered permutation of length `count`.

The traversal helpers are the oracle of the state machine. They also help you test your own policy:

| Function                   | Purpose                                                                 |
| -------------------------- | ----------------------------------------------------------------------- |
| `peek(choreography, path)` | The next step, a `choice` of alternatives, or `null` when complete      |
| `walk(choreography)`       | Generator over every reachable step and the path that leads to it       |
| `simplify(choreography)`   | Flattens same-kind nodes, removes duplicates, collapses 1-element nodes |
| `isEquals(a, b)`           | Structural comparison                                                   |

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

`verifyPrompt` returns `false` to reject. It returns `true` to accept without resolving anyone. It returns an identity id to say _this is
who it is_. Two components that resolve different identities in one dance produce an `IDENTITY_MISMATCH`.

`AuthComponentContext` carries `{ storage, stateId, name, flow, identity? }`. `flow` is one of
`"sign-in" | "sign-up" | "enroll" | "rotate" | "recover" | "subscribe"`, so a component can behave one way during enrollment and another way
during authentication.

Three components ship in the box:

| Component                                          | Kind           | Verifiable | Notes                                                                                               |
| -------------------------------------------------- | -------------- | ---------- | --------------------------------------------------------------------------------------------------- |
| `EmailAuthComponent(channel)`                      | identification | yes        | Resolves the identity by address, and verifies it with an OTP. Also contributes a linked `channel`. |
| `PasswordAuthComponent(salt)`                      | challenge      | no         | `base64(SHA-512(salt:password))`. See [Known gaps](#known-gaps).                                    |
| `OtpAuthComponent(channel, digits = 6, ttl = 300)` | challenge      | no         | The only sendable component. Stores the code in KV under `otp/<stateId>/<name>`.                    |

### Channels

A channel is where the library delivers messages. `AuthChannel` has three methods: `sendMessage`, `getPrompt` and `getIdentityChannel`.
`MemoryAuthChannel` is the test double, and it collects messages into a public `messages` array. 🥔

### Identity

An identity is an id, an optional free-form `data` bag, and a list of components:

```ts
interface Identity {
	id: string; // ksuid, "id_" prefixed
	data?: Record<string, unknown>;
	components: IdentityComponent[];
}
```

Each component is an `identification` (something you claim), a `challenge` (something you prove), or a `channel` (somewhere the library can
reach you). Each one also has a `confirmed` flag and a private `data` bag: the password hash, or the pending OTP. The `…Public` variants are
the same minus `data`, and `/list-components` returns those.

### Storage

`AuthStorage` is a concrete class. You configure it with three adapters instead of a replacement:

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

An adapter sees these key spaces: `session/<id>`, `sessions/<identityId>/<id>` and `otp/<stateId>/<name>`. Only `MemoryIdentityProvider`,
`MemoryKvProvider` and `MemoryRateLimiterProvider` ship today. You write the persistent adapter yourself, and it is the one thing between
this library and a real deployment.

### Sessions and tokens

A completed sign-in or sign-up mints three HS256 JWTs. `access_token` and `refresh_token` carry the **session** id as `sub` plus a numeric
`auth_time`. `id_token` carries the **identity** id, and puts scope-filtered identity `data` in its protected header.

A refresh keeps `auth_time` unchanged, so a refresh never re-opens the elevated window. Sensitive flows such as `enroll` and `rotate` demand
a fresh sign-in. Otherwise they answer `FRESH_SIGN_IN_REQUIRED`.

## HTTP API

You reach the HTTP API through `choreoAuth(...).fetch`. **All routes are `POST`.** There is no path prefix, so mount it yourself. 🔒 means
the route needs `Authorization: Bearer <access_token>`.

| Route                 | Body                       | 200                                    |
| --------------------- | -------------------------- | -------------------------------------- |
| `/sign-in`            | —                          | state                                  |
| `/sign-up`            | —                          | state                                  |
| `/sign-out` 🔒        | `{ others?: boolean }`     | `{ success: true }`                    |
| `/list-sessions` 🔒   | —                          | `{ sessions, current }`                |
| `/list-components` 🔒 | —                          | `{ components }`                       |
| `/refresh-token`      | `{ refresh_token }`        | tokens                                 |
| `/enroll` 🔒          | `{ name }`                 | state                                  |
| `/unenroll` 🔒        | `{ name }`                 | state (confirmation)                   |
| `/rotate` 🔒          | `{ name }`                 | state                                  |
| `/recover`            | `{ name }`                 | state                                  |
| `/subscribe` 🔒       | `{ name }`                 | state                                  |
| `/unsubscribe` 🔒     | `{ name }`                 | state (confirmation)                   |
| `/delete` 🔒          | —                          | state (confirmation)                   |
| `/send-prompt`        | `{ name, locale?, state }` | `{ success: true }`                    |
| `/submit-prompt`      | `{ name, value, state }`   | state \| tokens \| `{ success: true }` |
| `/send-validation`    | `{ name, locale?, state }` | `{ success: true }`                    |
| `/submit-validation`  | `{ name, value, state }`   | state \| tokens \| `{ success: true }` |

`locale` falls back to `accept-language`, then to `"en"`. The client address comes from `cf-connecting-ip` or from the first
`x-forwarded-for` entry. The library reads headers only, never the body.

An error is always a single-key body: `{ "error": "CODE" }`. Malformed input is `400 BAD_REQUEST`. A rate limit is `429 RATE_LIMITED`, with
a `Retry-After` header when the library knows the delay. Everything else is `500` with a code from the `Errors` registry: `INVALID_STATE`,
`WOULD_LOCK_OUT`, `FRESH_SIGN_IN_REQUIRED`, `IDENTITY_MISMATCH` and more, 32 in all, with `UNKNOWN` as the fallback.

`auth.generateOpenAPISchema()` produces a full spec, error picklist included.

## Flows

Sign-in and sign-up are not special. Every management flow uses the same state-plus-prompt loop:

- **`enroll` / `unenroll`** — add or remove a factor. The library refuses a removal with `WOULD_LOCK_OUT` when no completable path through
  the choreography remains.
- **`rotate`** — replace a credential. For a _verifiable_ component, the first prompt proves control of the current value. The library then
  collects the new value and validates it, so the flow has two validation rounds. A non-verifiable component such as a password needs one
  `submit-prompt`.
- **`recover`** — unauthenticated. The component must be an `identification`, must be `verifiable`, and must be a valid _first move_ of the
  choreography. Otherwise the library answers `COMPONENT_NOT_RECOVERABLE`. The flow completes with `{ success: true }`, not with tokens.
- **`subscribe` / `unsubscribe`** — manage channels. Note the asymmetry of a subscription. The library delivers the confirming code over an
  _already-confirmed_ channel, so `send-validation` names that existing channel while `submit-validation` names the new one.
- **`delete`** — wipes the identity.

`unenroll`, `unsubscribe` and `delete` answer with a `confirmation` prompt. Submit the boolean `true` for it. Any other value is a
`CONFIRMATION_REQUIRED`.

## Configuration

Every duration is in seconds and optional, under `advanced`:

| Option                                                                                                                                                                                 | Default  |
| -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------- |
| `sign_in_duration`, `sign_up_duration`, `enroll_duration`, `unenroll_duration`, `rotate_duration`, `recover_duration`, `subscribe_duration`, `unsubscribe_duration`, `delete_duration` | `300`    |
| `access_duration`                                                                                                                                                                      | `300`    |
| `refresh_duration`                                                                                                                                                                     | `86400`  |
| `elevated_duration`                                                                                                                                                                    | `300`    |
| `issuer`                                                                                                                                                                               | `"acme"` |

Rate limits are `{ limit, window }` buckets. Per identity (`identity_rate_limit`): `verify` 10/5min, `send` 5/5min, `manage` 20/5min,
`refresh` 60/5min. Per address (`address_rate_limit`, enforced by the HTTP layer): `request` 300/min, `send` 60/min.

## Development

The project defines no `tasks` block yet, so run the tools directly:

```sh
deno test                          # 6 files, 126 steps, no permission flags
deno test src/api.test.ts
deno test --filter "should sign-in"
deno fmt                           # tabs, line width 140
```

Layout: `src/mod.ts` is the entry point. `src/api.ts` holds the state machine, `src/app.ts` the Hono routes, and `src/choreography.ts` the
DSL. `src/components/` and `src/providers/` hold the batteries. Tests sit beside their subjects, and they are the reference documentation
for now.
