import { createFileRoute, Link } from "@tanstack/react-router";
import { CheckCircle2Icon, Loader2Icon, MonitorIcon, XCircleIcon } from "lucide-react";
import { type FormEvent, useEffect, useState } from "react";
import { AuthLayout } from "@/components/auth-layout";
import { Alert, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldGroup, FieldLabel } from "@/components/ui/field";
import { InputOTP, InputOTPGroup, InputOTPSeparator, InputOTPSlot } from "@/components/ui/input-otp";
import { describeError } from "@/lib/auth";
import { api } from "@/lib/demo";

interface DeviceSearch {
	device_challenge?: string;
	device_status?: "approved" | "denied";
	error_description?: string;
}

export const Route = createFileRoute("/idp/device")({
	validateSearch: (search: Record<string, unknown>): DeviceSearch => ({
		device_challenge: typeof search.device_challenge === "string" ? search.device_challenge : undefined,
		device_status: search.device_status === "approved" || search.device_status === "denied" ? search.device_status : undefined,
		error_description: typeof search.error_description === "string" ? search.error_description : undefined,
	}),
	component: IdpDevice,
});

// RFC 8628 §6.1: the user code uses 20 consonants, so it reads with no ambiguity. The page takes any letter and
// leaves the check to the server.
const LETTERS = "^[A-Za-z]+$";

/**
 * `ui.device` of the authorization server. `/oauth2/device` sends the browser here with a `device_challenge`. The
 * owner types the code the TV shows, then signs in and consents on the same pages as a web app, and comes back here
 * with `device_status`.
 */
function IdpDevice() {
	const search = Route.useSearch();

	if (search.device_status) {
		const approved = search.device_status === "approved";
		return (
			<AuthLayout>
				<FieldGroup className="items-center text-center">
					{approved ? <CheckCircle2Icon className="size-10 text-green-600" /> : <XCircleIcon className="size-10 text-destructive" />}
					<h1 className="text-xl font-bold">{approved ? "Your device is connected" : "The device was not connected"}</h1>
					<FieldDescription>
						{approved ? "Go back to your device: it signs in at its next poll." : (search.error_description ?? "The request was denied.")}
					</FieldDescription>
					<Link to="/account" className="text-sm underline underline-offset-4">
						See connected apps
					</Link>
				</FieldGroup>
			</AuthLayout>
		);
	}

	if (!search.device_challenge) {
		return (
			<AuthLayout>
				<FieldGroup className="items-center text-center">
					<MonitorIcon className="size-8" />
					<h1 className="text-xl font-bold">Connect a device</h1>
					<FieldDescription>
						Open the address your device shows, <code>/oauth2/device</code>. It brings you back here with a fresh request.
					</FieldDescription>
					<Button onClick={() => window.location.assign("/oauth2/device")}>Start</Button>
				</FieldGroup>
			</AuthLayout>
		);
	}

	return <UserCodeForm challenge={search.device_challenge} />;
}

function UserCodeForm({ challenge }: { challenge: string }) {
	const [code, setCode] = useState("");
	const [failure, setFailure] = useState<unknown>();
	const [pending, setPending] = useState(false);

	// `verification_uri_complete` carries the code, and the request holds it.
	useEffect(() => {
		api<{ user_code?: string }>(`/api/idp/device?challenge=${encodeURIComponent(challenge)}`).then(
			(request) => setCode(request.user_code?.replace("-", "") ?? ""),
			setFailure,
		);
	}, [challenge]);

	async function submit(event?: FormEvent) {
		event?.preventDefault();
		setPending(true);
		setFailure(undefined);
		try {
			const { redirect_to } = await api<{ redirect_to: string }>("/api/idp/device/accept", {
				method: "POST",
				json: { challenge, user_code: `${code.slice(0, 4)}-${code.slice(4)}` },
			});
			window.location.assign(redirect_to);
		} catch (error) {
			setFailure(error);
			setCode("");
			setPending(false);
		}
	}

	return (
		<AuthLayout>
			<form onSubmit={submit}>
				<FieldGroup>
					<div className="flex flex-col items-center gap-2 text-center">
						<MonitorIcon className="size-6" />
						<h1 className="text-xl font-bold">Connect a device</h1>
						<FieldDescription>Type the code your device shows. Five wrong codes end the request.</FieldDescription>
					</div>
					{failure !== undefined && (
						<Alert variant="destructive">
							<AlertTitle>{describeError(failure)}</AlertTitle>
						</Alert>
					)}
					<Field className="items-center">
						<FieldLabel htmlFor="user-code" className="sr-only">
							Device code
						</FieldLabel>
						<InputOTP
							id="user-code"
							maxLength={8}
							pattern={LETTERS}
							value={code}
							onChange={(value) => setCode(value.toUpperCase())}
							containerClassName="justify-center"
							autoFocus
						>
							<InputOTPGroup>
								{[0, 1, 2, 3].map((index) => (
									<InputOTPSlot key={index} index={index} className="size-10 font-mono text-base" />
								))}
							</InputOTPGroup>
							<InputOTPSeparator />
							<InputOTPGroup>
								{[4, 5, 6, 7].map((index) => (
									<InputOTPSlot key={index} index={index} className="size-10 font-mono text-base" />
								))}
							</InputOTPGroup>
						</InputOTP>
					</Field>
					<Field>
						<Button type="submit" disabled={pending || code.length !== 8}>
							{pending && <Loader2Icon className="animate-spin" />}
							Continue
						</Button>
					</Field>
				</FieldGroup>
			</form>
		</AuthLayout>
	);
}
