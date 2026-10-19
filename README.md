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
		// openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
		secret: process.env.AUTH_SECRET!,
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

`auth-dance/react` wraps the client in one provider, one hook and one renderer.

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

## What ships with it

| Import                           | Holds                                                                                  |
| -------------------------------- | -------------------------------------------------------------------------------------- |
| `auth-dance`                     | `createAuthDance`, the choreography DSL, `AuthDanceStorage`, the errors and every type |
| `auth-dance/client`              | `AuthDanceClient` and the dance it hands out                                           |
| `auth-dance/react`               | The React bindings                                                                     |
| `auth-dance/components/*`        | `email`, `oauth2`, `otp`, `password`, `policy`, `totp`, `webauthn`                     |
| `auth-dance/components/oauth2/*` | `apple`, `facebook`, `github`, `gitlab`, `google`, `microsoft`, `x`                    |
| `auth-dance/providers/*`         | `memory` for tests, `cloudflare` for Workers                                           |

A step is a small interface. Implement `AuthDanceComponent` and your own factor works in every flow, including the flows you have not
considered yet. Two rules apply. `verifyPrompt` accepts a value only with `true` or an identity id: any other answer, `undefined`
included, rejects it. And every complete path of the choreography needs a step that proves control: a challenge, or an
identification that sets `proves: true` because it checks a secret, as WebAuthn does. An address alone proves nothing, so
`choice("email", "passkey")` fails at startup. Sign in by address and code with `sequence("email", "otp")`.

Full documentation lives at [auth.dance](https://auth.dance/). The tests beside each module are the reference until then.

## Contributing

Contributors use Node.js 24.4 or newer and npm. The root package contains the library in `src/`; `demo/` is an npm workspace.

```sh
npm install
npm run lint                         # Biome
npm run check                        # TypeScript: library, tests, and demo
npm test                             # Vitest, runs once
npm test -- src/api.test.ts
npm test -- -t "should sign-in"
npm run fmt                          # Biome: tabs, line width 140
npm run build                        # TypeScript: JavaScript, declarations, and source maps
npm run dev --workspace demo
npm run build --workspace demo
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
Publishing builds automatically through `prepack`, and the demo and tests are excluded from the published package.

## License

MIT
