# Auth Dance

Everybody already does the dance. Type your email, wait for the code, paste the code, type your password. You did those steps a thousand
times and never called them a routine.

Auth Dance records the choreography.

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

Each requirement changes the _shape of the dance_. In a library that hard-codes one step, each requirement also changes the control flow.
You add a branch, an endpoint, and one more place where a bypass hides.

Auth Dance separates the **choreography** (which steps, in what order) from the **components** (what one step does). The choreography is
inert data, so the library can walk it:

- **`peek()` decides what happens next.** The state machine does not hard-code "password comes after email". It asks the choreography. To
  add a factor, you edit a declaration instead of logic.
- **Every flow reuses the same steps.** Sign-up collects the components that sign-in verifies, so the two flows cannot diverge. Rotation and
  recovery re-run a step you already declared.
- **The library can reason about your policy.** It answers `WOULD_LOCK_OUT` and refuses to unenroll a factor when the removal leaves no
  completable path through the choreography. That answer comes from a graph traversal (`walk()`), not from a rule someone remembered to
  write.
- **Flow state lives with the client.** An in-progress dance is an encrypted JWE (A256GCM). The library returns it as an opaque `state`
  string. Half-finished sign-ins need no session table and no garbage collection, and horizontal scaling costs nothing.

A step is a small interface: a prompt, a verification, and how the result maps to an identity. Implement `AuthDanceComponent` and your
custom factor works in every flow, including the flows you have not considered yet.

## Getting Started

### Bootstrap

`createAuthDance(options)` is the single entry point, and it is a named export. The options form three groups: `api` for the state machine,
`app` for the HTTP layer, and `info` for the generated OpenAPI document. The call returns your `AuthDanceApi` (the programmatic surface),
the Hono `app` behind it, a `fetch` handler (the HTTP surface), and an OpenAPI schema generator.

```ts
import { AuthDanceStorage, createAuthDance, sequence } from "auth-dance";
import { EmailAuthDanceComponent } from "auth-dance/components/email";
import { PasswordAuthDanceComponent } from "auth-dance/components/password";
import { OtpAuthDanceComponent } from "auth-dance/components/otp";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "auth-dance/providers/memory";

const auth = createAuthDance({
	api: {
		// Where messages go.
		channels: {
			email: new MemoryAuthDanceChannel("email"),
		},
		// The dance itself.
		choreography: sequence("email", "password"),
		// What each step does. Keys are the names used everywhere else:
		// in the choreography, in prompts, and in `/enroll { name }`.
		components: {
			// Identify with email
			email: new EmailAuthDanceComponent({ channel: "email", challenge: "otp" }),
			// A pepper, not a salt: it belongs in a secret store, never in source.
			password: new PasswordAuthDanceComponent(Deno.env.get("PASSWORD_PEPPER")!),
			// Challenge over the "email" channel, and records its one-time code as "otp".
			otp: new OtpAuthDanceComponent({ channel: "email" }),
		},
		// openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
		secret: "zdJXI1jwuXW8A19fns0E_B4HSYm7AUHLGlU9WLo8mxs",
		storage: new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		}),
	},
	// Names the generated OpenAPI document. Nothing else reads it.
	info: { title: "Auth API", version: "1.0.0" },
});

Deno.serve(auth.fetch);
```

> The package root re-exports the whole library: `createAuthDance`, the full choreography DSL, `AuthDanceStorage`, the errors, and every
> type and schema from `api.ts`, `app.ts`, `channel.ts`, `component.ts`, `identity.ts`, `message.ts`, `otp.ts`, `prompt.ts`, `provider.ts`,
> `response.ts`, `session.ts` and `state.ts`. Only the batteries keep a subpath of their own: `auth-dance/components/{email,otp,password}`
> and `auth-dance/providers/memory`. There are no deep `.ts` paths and no `auth-dance/choreography` subpath.

### Performing the dance

Sign-in is a loop. Request a state, submit a value, get the next prompt, and repeat until the library returns tokens.

```ts
const started = await auth.api.signIn();
// { state: "<opaque>", prompt: { kind: "input", name: "email", type: "email", sendable: false }, expireAt }

const afterEmail = await auth.api.submitPrompt({
	name: "email",
	value: "john.doe@example.com",
	state: started.state,
});
// { state: "<opaque>", prompt: { kind: "input", name: "password", type: "password", sendable: false }, expireAt }

const done = await auth.api.submitPrompt({
	name: "password",
	value: "correct horse battery staple",
	state: afterEmail.state,
});
// { tokens: { access_token, id_token, refresh_token }, session, identity }
```

Over HTTP, you make the same three calls. Every route is `POST`, and every payload is JSON:

```ts
const r1 = await post("/sign-in");
const r2 = await post("/submit-prompt", { name: "email", value: "john.doe@example.com", state: r1.state });
const r3 = await post("/submit-prompt", { name: "password", value: "correct horse battery staple", state: r2.state });
// r3.tokens
```

If a prompt is `sendable`, an OTP for example, call `/send-prompt` to deliver it before you submit. If a collected value needs proof of
control, `submitPrompt` answers with a _validation_ prompt instead of an advance. Answer that prompt with `submitPrompt` too, and deliver it
with `sendPrompt`: the state names the phase, so one pair of calls carries every step of every flow and the client keeps no record of which
phase it is in. Then the dance continues.

`prompt.kind` tells the client what to render. `"input"` is a single field. `"choice"` is a fork in the choreography where the user picks
the branch to take.

## Concepts

### Choreography

A choreography is a tree of three node kinds: `component`, `sequence` and `choice`. Combinators build the tree. A bare string is sugar for
`component(name)`.

```ts
import { choice, component, pick, sequence } from "auth-dance";

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
interface AuthDanceComponent {
	kind: "identification" | "challenge" | "channel";
	verifiable: boolean; // implies verificationComponent
	getPrompt(context: AuthDanceComponentContext): Promise<AuthDancePromptInput>;
	sendPrompt?(locale: string, context: AuthDanceComponentContext): Promise<AuthDanceMessage>;
	getIdentityComponent(
		component: string,
		value: unknown,
		confirmed: boolean,
		context: AuthDanceComponentContext,
	): Promise<AuthDanceIdentityComponent[]>;
	verificationComponent?(context: AuthDanceComponentContext): Promise<AuthDanceComponent>;
	verifyPrompt(value: unknown, context: AuthDanceComponentContext): Promise<boolean | AuthDanceIdentity["id"]>;
}
```

`verifyPrompt` returns `false` to reject. It returns `true` to accept without resolving anyone. It returns an identity id to say _this is
who it is_. Two components that resolve different identities in one dance produce an `IDENTITY_MISMATCH`.

`AuthDanceComponentContext` carries `{ storage, stateId, name, flow, identity? }`. `flow` is one of
`"sign-in" | "sign-up" | "enroll" | "rotate" | "recover" | "subscribe"`, so a component can behave one way during enrollment and another way
during authentication. On `getIdentityComponent`, `identity` is the identity _as it stands_. During a rotation, the value under replacement
is still on it. During a sign-up, it holds the components collected so far. A component can therefore refuse a value on grounds that the
value alone cannot show.

Three components ship with the library:

| Component                                                   | Kind           | Verifiable | Notes                                                                                                                                                       |
| ----------------------------------------------------------- | -------------- | ---------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `EmailAuthDanceComponent({ channel, challenge })`           | identification | yes        | Resolves the identity by address, and verifies it with an OTP. Also contributes a linked `channel` and a linked OTP `challenge` under the `challenge` name. |
| `PasswordAuthDanceComponent(pepper, hasher?)`               | challenge      | no         | PBKDF2 by default, salted with the pepper and the identity id. Pass a `hasher` of your own.                                                                 |
| `OtpAuthDanceComponent({ channel, digits = 6, ttl = 300 })` | challenge      | no         | The only sendable component. Stores the code in KV under `otp/<stateId>/<name>`.                                                                            |

The password component hashes through a function that you can replace, so you choose the KDF.

```ts
import PasswordAuthDanceComponent, { type PasswordHasher, pbkdf2PasswordHasher } from "auth-dance/components/password";

// The default: PBKDF2-HMAC-SHA256 over crypto.subtle, 600000 passes, stored as `<iterations>:<salt>:<digest>`.
new PasswordAuthDanceComponent(pepper, pbkdf2PasswordHasher());

// Or bring a memory-hard one.
const argon2: PasswordHasher = (value) => argon2id({ password: value, salt: SALT, /* … */ outputType: "encoded" });
new PasswordAuthDanceComponent(pepper, argon2);
```

Two rules bind a hasher. First, it must return the same string for the same input every time. `verifyPrompt` hashes the submission and
compares the result with the stored string. A hasher that draws a random salt of its own therefore rejects every password it stored. Second,
the hasher needs no salt. The component prepends the pepper and the identity id to the password before it calls the hasher. That id salts
the record: a password record verifies only against its own identity. An identity seeded outside a flow therefore needs its id before the
library builds its password record.

### Channels

A channel is where the library delivers messages. `AuthDanceChannel` has three methods: `sendMessage`, `getPrompt` and `getIdentityChannel`.
`MemoryAuthDanceChannel` is the test double, and it collects messages into a public `messages` array.

### Identity

An identity is an id, an optional free-form `data` bag, and a list of components:

```ts
interface AuthDanceIdentity {
	id: string; // ksuid, "id_" prefixed
	data?: Record<string, unknown>;
	components: AuthDanceIdentityComponent[];
}
```

Each component is an `identification` (something you claim), a `challenge` (something you prove), or a `channel` (somewhere the library can
reach you). Each one also has a `confirmed` flag and a private `data` bag: the password hash, or the pending OTP. The `…Public` variants are
the same minus `data`, and `/list-components` returns those.

### Storage

`AuthDanceStorage` is a concrete class. You configure it with three adapters instead of a replacement:

```ts
interface AuthDanceIdentityProvider {
	list(cursor?: string, limit?: number): Promise<AuthDanceIdentity[]>;
	get(id: string): Promise<AuthDanceIdentity | undefined>;
	getByIdentification(type: string, identification: string): Promise<AuthDanceIdentity | undefined>;
	set(identity: AuthDanceIdentity): Promise<void>;
	delete(id: string): Promise<void>;
}

interface AuthDanceKvProvider {
	get(key: string): Promise<string | undefined>;
	list(prefix: string, offset?: number, limit?: number): Promise<string[]>;
	set(key: string, value: string, ttl?: number): Promise<void>;
	unset(key: string): Promise<void>;
}

interface AuthDanceRateLimiterProvider {
	limit(key: string, limit: number, window: number): Promise<{ allowed: boolean; retryAfter: number | undefined }>;
}
```

An adapter sees these key spaces: `session/<id>`, `sessions/<identityId>/<id>` and `otp/<stateId>/<name>`. Only `MemoryIdentityProvider`,
`MemoryKvProvider` and `MemoryRateLimiterProvider` ship today, so you write the persistent adapters yourself.

A missing or expired key is `undefined`, never a rejection. `listSession` reads every key of a `sessions/<identityId>/` listing, and a key
that expires between the listing and the read is normal, not a fault. `offset` is a count of keys to skip, not an opaque cursor. `limit` is
the maximum count of keys to return.

### Sessions and tokens

A completed sign-in or sign-up mints three HS256 JWTs. `access_token` and `refresh_token` carry the **session** id as `sub` plus a numeric
`auth_time`. `id_token` carries the **identity** id, and puts scope-filtered identity `data` in its protected header.

A refresh keeps `auth_time` unchanged, so a refresh never re-opens the elevated window. Sensitive flows such as `enroll` and `rotate` demand
a fresh sign-in. Otherwise they answer `FRESH_SIGN_IN_REQUIRED`.

## HTTP API

You reach the HTTP API through `createAuthDance(...).fetch`. The call also returns the Hono instance behind that handler as `.app`. Mount
that instance inside an app of your own if you prefer. **All routes are `POST`.** They sit at the root unless you pass `app: { basePath }`,
which prefixes every one of them. 🔒 means the route needs `Authorization: Bearer <access_token>`.

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

When you omit `locale`, the library reads `accept-language`, then uses `"en"`. The library takes the client address from `cf-connecting-ip`
or from the first `x-forwarded-for` entry. It reads headers only, never the body.

An error is always a single-key body: `{ "error": "CODE" }`. Malformed input is `400 BAD_REQUEST`. A rate limit is `429 RATE_LIMITED`, with
a `Retry-After` header when the library knows the delay. Everything else is `500` with a code from the `Errors` registry: `INVALID_STATE`,
`WOULD_LOCK_OUT`, `FRESH_SIGN_IN_REQUIRED`, `IDENTITY_MISMATCH` and more, 33 in all. `UNKNOWN` is the fallback. `INVALID_PROMPT_VALUE` is
the one to expect from a component: the value did not verify, or the component refused to store it.

`auth.generateOpenAPISchema()` produces a full spec, error picklist included. Its `info` block is whatever you passed to `createAuthDance`.
If you omit `info`, the document carries the hono-openapi placeholder instead: `Hono Documentation`, version `0.0.0`.

## Flows

Sign-in and sign-up are not special. Every management flow uses the same state-plus-prompt loop:

- **`enroll` / `unenroll`** — add or remove a factor. A removal includes the linked records: the records that name the factor in their
  `linkedTo`, and every other factor those records name. The library refuses it with `WOULD_LOCK_OUT` when no completable path through the
  choreography remains for what survives. `subscribe` / `unsubscribe` follow the same rule from the channel end: detaching a channel takes
  down the factors it carries, and the same lock-out check gates it.
- **`rotate`** — replace a credential. For a _verifiable_ component, the first prompt proves control of the current value. The library then
  collects the new value and validates it, so the flow has two validation rounds. Every round goes to `/submit-prompt`. A non-verifiable
  component such as a password needs one call and no round at all.
- **`recover`** — unauthenticated. `name` is the component the owner can no longer provide, a forgotten password for instance. The first
  prompt is a choice between the components of the choreography that are both `identification` and `verifiable`. Such a component resolves
  an identity and also proves control of it. The library excludes the component under recovery from that choice. Pick one and prove control
  of it. The library then collects and validates the replacement of the component you named. With none of those left, or with no step of the
  choreography carrying that name, the library answers `COMPONENT_NOT_RECOVERABLE`. The flow completes with `{ success: true }`, not with
  tokens.
- **`subscribe` / `unsubscribe`** — manage channels. Note the asymmetry of a subscription. The library delivers the confirming code over an
  _already-confirmed_ channel, so `/send-prompt` names that existing channel while the `/submit-prompt` that collected the recipient named
  the new one.
- **`delete`** — wipes the identity.

`unenroll`, `unsubscribe` and `delete` answer with a `confirmation` prompt. Submit the boolean `true` for it. Any other value is a
`CONFIRMATION_REQUIRED`.

## Configuration

Four optional groups sit beside the required options: `api.durations`, `api.limits`, `api.tokens` and `api.hooks`.

Every duration is in seconds, under `api.durations`. There is one key per flow, so you can give recovery more time than sign-in, and less
time to a confirmation-only flow such as `unenroll`:

| Option                                                                                                | Default |
| ----------------------------------------------------------------------------------------------------- | ------- |
| `sign_in`, `sign_up`, `enroll`, `unenroll`, `rotate`, `recover`, `subscribe`, `unsubscribe`, `delete` | `300`   |
| `access`                                                                                              | `300`   |
| `refresh`                                                                                             | `86400` |
| `elevated`                                                                                            | `300`   |

`elevated` is the window after a sign-in during which a session may still perform sensitive actions. After that window, every authenticated
management flow — `enroll`, `unenroll`, `rotate`, `subscribe`, `unsubscribe` and `delete` — answers `FRESH_SIGN_IN_REQUIRED`.

Rate limits are `{ limit, window }` buckets, under `api.limits`. Per identity (`limits.identity`): `verify` 10/5min, `send` 5/5min, `manage`
20/5min, `refresh` 60/5min. Per address (`limits.address`, which the HTTP layer enforces, not the state machine): `request` 300/min, `send`
60/min.

`api.tokens.issuer` is the `iss` claim of every minted JWT and of the encrypted state, `"acme"` by default.

### Hooks

`api.hooks` is how a deployment reacts to a change — publish an event, write an audit record, warn the owner. Each listener is optional:

| Hook                 | Fires when                                                        | `flow`                                                                |
| -------------------- | ----------------------------------------------------------------- | --------------------------------------------------------------------- |
| `onIdentityCreated`  | a sign-up saved a new identity                                    | `sign-up`                                                             |
| `onIdentityUpdated`  | a flow changed the components of an existing identity             | `enroll`, `unenroll`, `rotate`, `recover`, `subscribe`, `unsubscribe` |
| `onIdentityDeleted`  | a delete removed an identity, after its sessions                  | `delete`                                                              |
| `onSessionCreated`   | a sign-in or a sign-up minted a session                           | `sign-in`, `sign-up`                                                  |
| `onSessionRefreshed` | a refresh minted new tokens on an existing session                | `refresh`                                                             |
| `onSessionDeleted`   | a sign-out or a delete destroyed a session, one event per session | `sign-out`, `delete`                                                  |
| `onError`            | one of the hooks above rejected                                   | —                                                                     |

```ts
const auth = createAuthDance({
	api: {
		channels,
		choreography: sequence("email", "password"),
		components,
		secret,
		storage,
		hooks: {
			onIdentityUpdated: ({ flow, name, identity }) => bus.publish(`identity.${flow}`, { id: identity.id, name }),
			onError: ({ hook, cause }) => logger.error({ hook, cause }, "auth hook failed"),
		},
	},
});
```

An identity hook fires after the write. A session hook fires after the session exists, or after it is gone. A listener therefore never reads
a change that a later step could still reject. `onIdentityDeleted` is the one hook that receives an identity storage no longer holds. The
event carries the identity as it stood one moment before the delete.

A hook reports a change. It never decides one. A listener that rejects never fails the flow, and `onError` receives the rejection. The
library awaits each listener, so a slow hook slows the call that fires it. Return quickly and do the long work elsewhere. Only the state
machine fires hooks. A write straight through `AuthDanceStorage` reports nothing.

## Development

The project defines no `tasks` block yet, so run the tools directly:

```sh
deno test                          # 7 files, 138 steps, no permission flags
deno test src/api.test.ts
deno test --filter "should sign-in"
deno fmt                           # tabs, line width 140
```

Layout: `src/mod.ts` is the entry point. `src/api.ts` holds the state machine, `src/app.ts` holds the Hono routes, and `src/choreography.ts`
holds the DSL. `src/components/` and `src/providers/` hold the batteries. Tests sit beside their subjects, and they are the reference
documentation for now.
