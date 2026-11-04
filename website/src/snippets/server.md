---
title: server.ts
lang: ts
---
import { createAuthDance, choice, sequence } from "auth-dance";

const auth = createAuthDance({
	api: {
		// The dance itself.
		choreography: choice(sequence("email", "password"), "passkey"),
		// What each step does.
		components: { email, password, passkey },
		channels, storage, secret, keys,
		tokens: { issuer: "https://auth.example.com" },
	},
});

serve({ fetch: auth.fetch });
