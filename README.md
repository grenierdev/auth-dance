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
deno add npm:auth-dance
```

## The server

`createAuthDance(options)` is the single entry point. Declare the choreography, say what each step does, and serve the handler it returns.

```ts
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
			password: new PasswordAuthDanceComponent(Deno.env.get("PASSWORD_PEPPER")!),
		},
		// Where the messages go.
		channels: { email: new MemoryAuthDanceChannel("email") },
		// openssl rand -base64 32 | tr '+/' '-_' | tr -d '='
		secret: Deno.env.get("AUTH_SECRET")!,
		storage: new AuthDanceStorage({
			identity: new MemoryIdentityProvider(),
			kv: new MemoryKvProvider(),
			rate_limiter: new MemoryRateLimiterProvider(),
		}),
	},
	info: { title: "Auth API", version: "1.0.0" },
});

Deno.serve(auth.fetch);
```

`auth.fetch` is the HTTP surface, `auth.app` is the Hono instance behind it, `auth.api` is the same state machine without HTTP, and
`auth.generateOpenAPISchema()` documents the routes.

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

| Import                    | Holds                                                                                  |
| ------------------------- | -------------------------------------------------------------------------------------- |
| `auth-dance`              | `createAuthDance`, the choreography DSL, `AuthDanceStorage`, the errors and every type |
| `auth-dance/client`       | `AuthDanceClient` and the dance it hands out                                           |
| `auth-dance/react`        | The React bindings                                                                     |
| `auth-dance/components/*` | `email`, `otp`, `password`, `totp`, `webauthn`                                         |
| `auth-dance/providers/*`  | `memory` for tests, `deno` for Deno KV, `cloudflare` for Workers                       |

A step is a small interface. Implement `AuthDanceComponent` and your own factor works in every flow, including the flows you have not
considered yet.

Full documentation lives at [auth.dance](https://auth.dance/). The tests beside each module are the reference until then.

## Contributing

This repository is Deno-native. There is no build step, no bundler and no transpiler: the TypeScript in `src/` is what runs and what
publishes. A Deno workspace holds the library in `src/` and a demo application in `demo/`.

```sh
deno test                      # no permission flags needed
deno test src/api.test.ts
deno test --filter "should sign-in"
deno fmt                       # tabs, line width 140
deno lint
deno doc --lint src/mod.ts     # every export needs JSDoc
```

Layout: `src/mod.ts` is the entry point, `src/api.ts` holds the state machine, `src/app.ts` holds the Hono routes, `src/choreography.ts`
holds the DSL, and `src/client.ts` plus `src/react.ts` hold the client half. `src/components/` and `src/providers/` hold the batteries. A
test sits beside its subject.

The npm package comes out of `scripts/publish.sh`, which packs the same sources with `deno pack`. Node consumers get a published artifact;
contributors need Deno alone.

## License

MIT
