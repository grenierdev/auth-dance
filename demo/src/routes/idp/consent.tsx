import { createFileRoute } from "@tanstack/react-router";
import { Loader2Icon } from "lucide-react";
import { useEffect, useState } from "react";
import { AuthLayout } from "@/components/auth-layout";
import { ClientCard, type PublicClient } from "@/components/client-card";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Checkbox } from "@/components/ui/checkbox";
import { Field, FieldDescription, FieldGroup, FieldLabel, FieldSet } from "@/components/ui/field";
import { bearer, describeError } from "@/lib/auth";
import { api, useDemoInfo } from "@/lib/demo";

interface ConsentRequest {
	challenge: string;
	client: PublicClient;
	requested_scope: string[];
	subject: string;
	skip: boolean;
	user_code?: string;
}

export const Route = createFileRoute("/idp/consent")({
	validateSearch: (search: Record<string, unknown>): { consent_challenge: string } => ({
		consent_challenge: typeof search.consent_challenge === "string" ? search.consent_challenge : "",
	}),
	component: IdpConsent,
});

/**
 * `ui.consent` of the authorization server. The owner picks the scopes to grant. A consent the owner asked to remember
 * skips this page next time, except for a device: a user code can come from someone else.
 */
function IdpConsent() {
	const { consent_challenge } = Route.useSearch();
	const info = useDemoInfo();
	const [request, setRequest] = useState<ConsentRequest>();
	const [granted, setGranted] = useState<string[]>([]);
	const [remember, setRemember] = useState(true);
	const [failure, setFailure] = useState<unknown>();
	const [pending, setPending] = useState(false);

	async function answer(path: "accept" | "reject", grant_scope: string[] = []) {
		setPending(true);
		try {
			const { redirect_to } = await api<{ redirect_to: string }>(`/api/idp/consent/${path}`, {
				method: "POST",
				token: await bearer(),
				json: { challenge: consent_challenge, grant_scope, remember },
			});
			window.location.assign(redirect_to);
		} catch (error) {
			setFailure(error);
			setPending(false);
		}
	}

	// `answer` reads the challenge from the same search.
	// biome-ignore lint/correctness/useExhaustiveDependencies: run once per challenge
	useEffect(() => {
		(async () => {
			try {
				const read = await api<ConsentRequest>(`/api/idp/consent?challenge=${encodeURIComponent(consent_challenge)}`, {
					token: await bearer(),
				});
				setRequest(read);
				setGranted(read.requested_scope);
				if (read.skip) {
					// The owner already granted all of it to this client, and asked to remember.
					await answer("accept", read.requested_scope);
				}
			} catch (error) {
				setFailure(error);
			}
		})();
	}, [consent_challenge]);

	if (!request) {
		return (
			<AuthLayout>
				{failure !== undefined ? (
					<Alert variant="destructive">
						<AlertTitle>{describeError(failure)}</AlertTitle>
					</Alert>
				) : (
					<Loader2Icon className="mx-auto size-5 animate-spin text-muted-foreground" />
				)}
			</AuthLayout>
		);
	}

	return (
		<AuthLayout>
			<FieldGroup>
				<div className="text-center">
					<h1 className="text-xl font-bold">Allow access?</h1>
					<FieldDescription>Grant only what you are comfortable with. You can revoke it from your account page.</FieldDescription>
				</div>
				<ClientCard client={request.client} scopes={request.requested_scope} userCode={request.user_code} />
				{request.user_code && (
					<Alert>
						<AlertTitle>Check the code on your device</AlertTitle>
						<AlertDescription>
							Allow only if your device shows <code className="font-mono font-semibold">{request.user_code}</code>. Someone may have sent
							you their code.
						</AlertDescription>
					</Alert>
				)}
				{request.skip && <p className="text-center text-sm text-muted-foreground">You already allowed this app. Continuing…</p>}
				<FieldSet>
					{request.requested_scope.map((scope) => (
						<Field key={scope} orientation="horizontal">
							<Checkbox
								id={`scope-${scope}`}
								checked={granted.includes(scope)}
								onCheckedChange={(checked) =>
									setGranted((current) => (checked ? [...current, scope] : current.filter((value) => value !== scope)))
								}
							/>
							<div className="flex flex-col gap-0.5">
								<FieldLabel htmlFor={`scope-${scope}`}>{scope}</FieldLabel>
								<FieldDescription>{info?.scopes[scope]?.description}</FieldDescription>
							</div>
						</Field>
					))}
					{!request.user_code && (
						<Field orientation="horizontal">
							<Checkbox id="remember" checked={remember} onCheckedChange={(checked) => setRemember(checked === true)} />
							<FieldLabel htmlFor="remember">Remember my choice for this app</FieldLabel>
						</Field>
					)}
				</FieldSet>
				{failure !== undefined && (
					<Alert variant="destructive">
						<AlertTitle>{describeError(failure)}</AlertTitle>
					</Alert>
				)}
				<Field className="grid grid-cols-2 gap-3">
					<Button variant="outline" disabled={pending} onClick={() => answer("reject")}>
						Deny
					</Button>
					<Button disabled={pending} onClick={() => answer("accept", granted)}>
						{pending && <Loader2Icon className="animate-spin" />}
						Allow
					</Button>
				</Field>
			</FieldGroup>
		</AuthLayout>
	);
}
