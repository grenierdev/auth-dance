# Auth Dance

Everybody already does the dance. Type your email, wait for the code, paste the code, type your password. You did those steps a thousand
times and never called them a routine.

Auth Dance records the choreography.

```ts
choreography: choice(sequence("email", "password"), "passkey");
```

That is a complete authentication policy. The library derives sign-in, sign-up, enrollment, credential rotation and account recovery from
it. You declare the steps one time.

## Install

```sh
npm install auth-dance
```

## The server

`createAuthDance(options)` is the single entry point. Declare the choreography, say what each step does, and serve the handler it returns.
For the Node.js example below, install the HTTP adapter with `npm install @hono/node-server`.

The server signs its tokens with an asymmetric key. Generate one before the first start, and keep it in a secret store:

```sh
node --input-type=module -e "import { generateSigningKey } from 'auth-dance'; console.log(JSON.stringify(await generateSigningKey()))"
```

```ts
import { serve } from "@hono/node-server";
import { AuthDanceStorage, createAuthDance, sequence } from "auth-dance";
import { EmailAuthDanceComponent } from "auth-dance/components/email";
import { OtpAuthDanceComponent } from "auth-dance/components/otp";
import { PasswordAuthDanceComponent } from "auth-dance/components/password";
import { MemoryAuthDanceChannel, MemoryIdentityProvider, MemoryKvProvider, MemoryRateLimiterProvider } from "auth-dance/providers/memory";

const auth = createAuthDance({
	api: {
		// The dance itself.
		choreography: sequence("email", "password"),
		// What each step does. The keys are the names the choreography and the prompts use.
		components: {
			email: new EmailAuthDanceComponent({ channel: "email", challenge: "otp" }),
			otp: new OtpAuthDanceComponent({ channel: "email" }),
			// At least 16 bytes, kept apart from the identity store: openssl rand -base64 32
			password: new PasswordAuthDanceComponent(process.env.PASSWORD_PEPPER!),
		},
		// Where the messages go.
		channels: { email: new MemoryAuthDanceChannel("email") },
		// Encrypts the state of a flow: openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
		secret: process.env.AUTH_SECRET!,
		// Signs the tokens. The first key signs; every key verifies.
		keys: [JSON.parse(process.env.AUTH_SIGNING_KEY!)],
		// The `iss` of every token. An https: URL; http: passes only for localhost. Each scope names the identity data
		// its access tokens carry as claims. A dance grants every scope, and `account` always exists.
		tokens: { issuer: "https://auth.example.com", scopes: { profile: { description: "Your name", claims: ["name"] } } },
		storage: new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		}),
	},
	info: { title: "Auth API", version: "1.0.0" },
});

serve({ fetch: auth.fetch, port: 3000 });
```

`auth.fetch` is the HTTP surface, `auth.app` is the Hono instance behind it, `auth.api` is the same state machine without HTTP, and
`auth.generateOpenAPISchema()` documents the routes.

`GET /.well-known/jwks.json` serves the public part of each key, so another service checks a token with no secret. To rotate, add the
new key at the end of `keys`, and move it to the front when the services that check tokens have read the new key set. Keep the old key
until the last token it signed expires, `durations.refresh` after it stops signing. A key after the first can hold its public part only.

## The tokens

A dance and every OAuth 2.0 grant mint the same two tokens:

- The access token is an RFC 9068 JWT with `typ: at+jwt`. It carries the identity id as `sub`, the session as `sid`, the client as
  `client_id`, the scopes as `scope`, the moment of the sign-in as `auth_time`, and the claims of its scopes. A dance mints it for the
  issuer: `client_id` and `aud` are the issuer, and `scope` holds every scope the server knows.
- The refresh token is a JWT with `typ: rt+jwt`. It stays valid until its session ends, `durations.refresh` after the sign-in. A
  refresh gives a new pair, and the old refresh token still works.

The response follows RFC 6749 §5.1: `access_token`, `token_type`, `expires_in`, `refresh_token` and `scope`.

To check an access token, verify it against the JWK Set, or call `auth.api.verifyAccessToken(token)`. Neither one reads storage, so
the token stays valid until `exp` after a sign-out. Pass `{ session: true }` where that window matters. A refresh reads the session,
so a sign-out, a delete, a reset or a revocation stops the refresh token at once.

The management routes, from `/sign-out` to `/delete`, need the `account` scope. A dance always holds it. A client of the
authorization server holds it only when it asks for it and the owner consents.

The per-address rate limits key on the address of the caller, so tell the app where that address lives. By default it reads
`cf-connecting-ip`, then the last entry of `x-forwarded-for`. Behind Cloudflare, pass `app: { address: cloudflareAddress }`. Behind a
chain of proxies, pass `forwardedAddress(hops)`. With no proxy, as in the Node.js example above, no header can be trusted: pass
`app: { address: (c) => getConnInfo(c).remote.address }`, with `getConnInfo` from `@hono/node-server/conninfo`. Every request with no
address shares one bucket. A server that calls `auth.fetch` for its own users forwards each address in a header, and reads that header
in its resolver.

## The dance

`auth-dance/client` calls those routes. A flow is a loop: read the prompt, answer it, repeat until the library answers with tokens.

```ts
import { AuthDanceClient } from "auth-dance/client";

const client = new AuthDanceClient({ baseUrl: "https://auth.example.com" });

using dance = await client.signIn();

while (!dance.done) {
	const prompt = dance.current!; // { kind: "input", name: "email", type: "email", sendable: false }
	if (prompt.sendable) {
		// A one-time code the library delivers over a channel.
		await dance.sendPrompt();
	}
	await dance.submitPrompt(await ask(prompt));
}

console.log(client.identity, client.tokens);
```

The client keeps the tokens of the session and exchanges the refresh token on its own. The same object runs every other flow:
`client.signUp()`, `client.enroll("totp")`, `client.rotate("password")`, `client.recover("password")`, `client.subscribe("sms")`,
`client.delete()`, and `client.signOut()`.

A recovery follows the same choreography. To recover one component, the owner performs a sign-in without it: with
`sequence("email", "password", "totp")`, a new password needs the address, its one-time code and the TOTP code. A component that no
path can do without is not recoverable; the owner signs in another way and enrolls it again. `AuthDanceApiOptions.recovery` overrides
the rule for one component, with `false` or with a choreography of its own.

A step with `prompt.kind === "choice"` is a fork in the choreography. Read the branches off `dance.choices`, then call `dance.choose(name)`.
An unenroll, an unsubscribe and a delete each end on a confirmation: answer it with `dance.confirm()`. Pass a `store` to keep the dance
across a page reload.

Nothing binds the client to a browser. Hand it the `fetch` of an `AuthDance` instance to dance in process:

```ts
const client = new AuthDanceClient({ baseUrl: "http://local", fetch: auth.fetch });
```

## React

`auth-dance/react` wraps the client in a provider, starts a flow with `useAuthDanceFlow` or `AuthDanceFlowProvider`, and renders its
prompts with `AuthDancePromptSwitch`.

```tsx
<AuthDanceProvider client={client}>
	<AuthDanceFlowProvider flow="sign-in">
		<AuthDancePromptSwitch
			prompts={{
				email: (prompt, flow) => <EmailField onSubmit={flow.submitPrompt} />,
				password: (prompt, flow) => <PasswordField onSubmit={flow.submitPrompt} />,
			}}
		/>
	</AuthDanceFlowProvider>
</AuthDanceProvider>;
```

## Auth Dance as an identity provider

`auth-dance/oauth2` makes the server an OAuth 2.0 authorization server for third-party apps. The owner signs in with the same
dance, on login and consent pages you host.

```ts
import { createAuthDanceOauth2 } from "auth-dance/oauth2";
import { createAuthDanceMemoryOauth2ClientStorage } from "auth-dance/providers/memory";

const idp = createAuthDanceOauth2({
	oauth2: {
		// The core instance. It mints every token, with the scopes of its `tokens.scopes`. `issuer` must equal its
		// `tokens.issuer`.
		api: auth.api,
		clients: createAuthDanceMemoryOauth2ClientStorage(),
		issuer: "https://auth.example.com",
		ui: { login: "https://auth.example.com/login", consent: "https://auth.example.com/consent" },
	},
	app: { basePath: "/oauth2" },
});

// The secret is readable one time. The store keeps only its hash.
const { client, client_secret } = await idp.oauth2.clients.createClient({
	redirect_uris: ["https://app.example.com/callback"],
	scope: "profile",
});
```

`GET /.well-known/oauth-authorization-server` serves the RFC 8414 metadata. It sits where RFC 8414 puts it, at the root of the host
followed by the path of the issuer, whatever the `basePath`. Every other route sits under the `basePath`: `/oauth2/authorize`,
`/oauth2/token` and `/oauth2/jwks.json`. Send them all to `idp.fetch`. The client storage ships for memory and for Cloudflare D1, on the
`oauth2_client` table of `sqlite.sql`.

`/oauth2/authorize` shows no page of its own. It sends the browser to `ui.login` with a `login_challenge`. The login page lets the
owner dance against the core app, then hands the access token of the dance to the authorization server:

```ts
// The server side of ui.login.
const challenge = new URL(request.url).searchParams.get("login_challenge")!;
const login = await idp.oauth2.getLoginRequest(challenge);
// … the owner dances with AuthDanceClient against auth.fetch …
const { redirect_to } = await idp.oauth2.acceptLoginRequest(challenge, { access_token: client.tokens!.access_token });
return Response.redirect(redirect_to, 303);
```

The consent page does the same with `getConsentRequest` and `acceptConsentRequest(challenge, { grant_scope })`. `rejectLoginRequest`
and `rejectConsentRequest` send an error to the client. A first-party client with `skip_consent` never sees the consent page. A page
that runs in another process calls the same methods over HTTP: pass `app: { admin: { authorize } }` to mount them under
`/oauth2/admin`.

The authorization server sets no cookie. Each redirect carries a single-use verifier, and that is all it needs to continue a
request. The pages own the browser: a login page that keeps the owner signed in hands over the access token of that session and
skips the dance, and a page that wants the browser that comes back to be the one that left binds the request to it with its own
session.

At `/oauth2/token`, a client uses the authorization code grant with PKCE S256, `refresh_token`, or `client_credentials`. The core
mints the tokens, so they are the tokens of a dance with the client and the scopes of the grant, and they work wherever the tokens of
a dance work: an access token that holds `account` manages the account. Its `aud` is the issuer, or the `audience` of the client
record of a resource server. A resource server checks it against `/oauth2/jwks.json`. To see a revocation at once, it asks
`/oauth2/introspect` (RFC 7662) as a confidential client, or calls `auth.api.verifyAccessToken(token, { session: true })` in process.
A client sees only its own tokens at `/oauth2/introspect`; set `introspect: true` on the client record of a resource server to let it
see every token, the tokens of a dance included.

A consent creates a session for the client: its grant. A grant stands alone. A sign-out in the core, of one session or of all,
leaves it, and `/list-sessions` does not list it. It lasts `durations.refresh` from its consent, and a revocation, a delete or a reset
in the core ends it sooner. Each endpoint refreshes the tokens of its own clients: `/refresh-token` takes the refresh token of a dance,
and `/oauth2/token` takes the refresh token of a client, once the client authenticates.

A client revokes a token at `/oauth2/revoke` (RFC 7009). Any token of a grant, access or refresh, ends the session of the grant. A
token of client credentials has no session, so it stays valid until `exp`. A resource server that only checks the signature still
accepts an access token until `exp`, 300 seconds by default; it sees the revocation through `/oauth2/introspect` or
`verifyAccessToken(token, { session: true })`. For an account page, `GET /oauth2/grants` lists the clients that have access, each with
its public record, and `DELETE /oauth2/grants/{id}` revokes one and forgets the consent the owner kept for its client. Both take the
access token of the owner as `Authorization: Bearer`, and the token must hold `account`. In process, `listOwnGrants` and
`revokeOwnGrant` do the same, and `listGrants(identityId)`, `revokeGrant` and `revokeClientGrants` serve an administrator. Delete a client with `idp.oauth2.deleteClient`, which revokes its
grants first; the client storage alone leaves them active.

`/oauth2/register` lets a client register itself (RFC 7591). It is closed until you pass `registration`:

```ts
registration: {
	// Without it, anyone can register a client. The owner still sees the client name on the consent page,
	// but a name can mislead.
	authorize: (initialAccessToken) => initialAccessToken === process.env.REGISTRATION_TOKEN,
	// The most a registered client may ask for.
	scope: ["profile"],
},
```

A registered client never gets `skip_consent`, `introspect` or `audience`, and it may not ask for `account` unless `registration.scope`
lists it. A setup script calls `idp.oauth2.registerClient(metadata, { registered_by: "admin" })` to run the same checks and set those
fields.

A device with no browser, a TV or a CLI, uses the device authorization grant (RFC 8628) once `ui.device` names the page where the owner
types the user code:

```ts
ui: { login: "https://auth.example.com/login", consent: "https://auth.example.com/consent", device: "https://auth.example.com/device" },
```

The device posts its `client_id` to `/oauth2/device_authorization` and shows the `user_code` and the `verification_uri`,
`/oauth2/device`, which sends the browser to `ui.device` with a `device_challenge`. The page takes the code the owner types:

```ts
// The server side of ui.device.
const { user_code } = await idp.oauth2.getDeviceRequest(challenge); // filled in from verification_uri_complete
const { redirect_to } = await idp.oauth2.acceptDeviceRequest(challenge, { user_code: typed });
return Response.redirect(redirect_to, 303);
```

The owner then goes through the same login and consent pages, and comes back to `ui.device` with `?device_status=approved`, or with
`?device_status=denied` and an `error`. Meanwhile the device polls `/oauth2/token` with
`grant_type=urn:ietf:params:oauth:grant-type:device_code`, and gets `authorization_pending` until then. A user code can come from
someone else, so the consent page always shows for a device, even for a client with `skip_consent`; `getConsentRequest` gives the
`user_code` for the page to show. A wrong code raises `InvalidUserCodeError`, and five of them end the challenge. Register the client
with the grant type `urn:ietf:params:oauth:grant-type:device_code`, and `token_endpoint_auth_method: "none"` for a device that cannot
keep a secret.

## What ships with it

| Import                           | Holds                                                                                                 |
| -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `auth-dance`                     | `createAuthDance`, the choreography DSL, `AuthDanceStorage`, the errors and every type                |
| `auth-dance/client`              | `AuthDanceClient` and the dance it hands out                                                          |
| `auth-dance/oauth2`              | The OAuth 2.0 authorization server, with introspection, revocation, registration and the device grant |
| `auth-dance/react`               | The React bindings                                                                                    |
| `auth-dance/components/*`        | `email`, `oauth2`, `oidc`, `otp`, `password`, `policy`, `totp`, `webauthn`                            |
| `auth-dance/components/oauth2/*` | `apple`, `facebook`, `github`, `gitlab`, `google`, `microsoft`, `x`                                   |
| `auth-dance/providers/*`         | `memory` for tests, `cloudflare` for Workers                                                          |

A step is a small interface. Implement `AuthDanceComponent` and your own factor works in every flow, including the flows you have not
considered yet. Two rules apply. `verifyPrompt` accepts a value only with `true` or an identity id: any other answer, `undefined`
included, rejects it. And every complete path of the choreography needs a step that proves control: a challenge, or an
identification that sets `proves: true` because it checks a secret, as WebAuthn does. An address alone proves nothing, so
`choice("email", "passkey")` fails at startup. Sign in by address and code with `sequence("email", "otp")`.

Full documentation lives at [auth.dance](https://auth.dance/). The tests beside each module are the reference until then.

## Contributing

Contributors use Node.js 24.4 or newer and npm. The root package contains the library in `src/`.

```sh
npm install
npm run lint                         # Biome
npm run check                        # TypeScript: library and tests
npm test                             # Vitest, runs once
npm test -- src/api.test.ts
npm test -- -t "should sign-in"
npm run fmt                          # Biome: tabs, line width 140
npm run build                        # TypeScript: JavaScript, declarations, and source maps
```

Layout: `src/mod.ts` is the entry point, `src/api.ts` holds the state machine, `src/app.ts` holds the Hono routes, `src/choreography.ts`
holds the DSL, and `src/client.ts` plus `src/react.ts` hold the client half. `src/components/` and `src/providers/` hold the batteries.
Tests sit beside their subjects. The core library uses web APIs and npm packages.

`npm run build` cleans `dist/` and compiles the library, tests, and tooling with `tsc` using `tsconfig.json`, emitting JavaScript,
`.d.ts` declarations, and source maps. Library modules are emitted into `dist/src/`; `.npmignore` excludes tests and development
artifacts from the published package.
Source imports keep their `.ts` extensions; TypeScript rewrites them to `.js` in the emitted JavaScript. Declarations retain `.ts`
imports, which TypeScript resolves to the corresponding `.d.ts` files. Runtime npm dependencies and `cloudflare:workers` remain
external; the browser-facing client and React entry points remain separate from the server API.

The root `package.json` owns the package version and exports. `npm pack` builds and produces a package containing the compiled
library and the README. To publish, run `npm publish --access public --tag next`; omit the tag for `latest`.
Publishing builds automatically through `prepack`, and tests are excluded from the published package.

## License

MIT
