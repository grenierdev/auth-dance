---
title: client.ts
lang: ts
---
import { AuthDanceClient } from "auth-dance/client";

const client = new AuthDanceClient({
	baseUrl: "https://auth.example.com",
});

using dance = await client.signIn();

while (!dance.done) {
	const prompt = dance.current!;
	if (prompt.sendable) await dance.sendPrompt();
	await dance.submitPrompt(await ask(prompt));
}

// The same loop runs every other flow:
// signUp(), enroll("passkey"), recover("password")
