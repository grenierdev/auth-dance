import { Link } from "@tanstack/react-router";
import type { AuthDanceResponse } from "auth-dance/client";
import { type ReactNode, useState } from "react";
import { DanceForm } from "@/components/dance-form";
import { FieldDescription } from "@/components/ui/field";

/**
 * The sign-in and the sign-up of login-05. Both walk the same choreography: the sign-up collects what the sign-in
 * checks.
 */
export function SignInForm({
	onDone,
	title,
	description,
}: {
	onDone: (response: AuthDanceResponse) => void;
	title?: ReactNode;
	description?: ReactNode;
}) {
	const [mode, setMode] = useState<"sign-in" | "sign-up">("sign-in");
	const signUp = mode === "sign-up";
	const toggle = (
		<button type="button" className="underline underline-offset-4" onClick={() => setMode(signUp ? "sign-in" : "sign-up")}>
			{signUp ? "Sign in" : "Sign up"}
		</button>
	);
	return (
		<DanceForm
			key={mode}
			flow={mode}
			title={title ?? (signUp ? "Create your account" : "Welcome to Auth Dance")}
			description={
				<>
					{description && <span className="mb-1 block">{description}</span>}
					{signUp ? "Already have an account? " : "Don't have an account? "}
					{toggle}
				</>
			}
			onDone={onDone}
			footer={
				<FieldDescription className="px-6 text-center">
					{signUp ? (
						"A passkey alone is a complete account. An address needs a password and a code we mail to it."
					) : (
						<>
							Lost a way in? Recover your{" "}
							<Link to="/recover" search={{ component: "password" }}>
								password
							</Link>{" "}
							or your{" "}
							<Link to="/recover" search={{ component: "passkey" }}>
								passkey
							</Link>
							.
						</>
					)}
				</FieldDescription>
			}
		/>
	);
}
