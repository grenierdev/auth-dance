---
title: idp.ts
lang: ts
---
import { createAuthDanceOauth2 } from "auth-dance/oauth2";

const idp = createAuthDanceOauth2({
	oauth2: {
		api: auth.api,
		clients,
		issuer: "https://auth.example.com",
		ui: {
			login: "https://auth.example.com/login",
			consent: "https://auth.example.com/consent",
			device: "https://auth.example.com/device",
		},
	},
	app: { basePath: "/oauth2" },
});
