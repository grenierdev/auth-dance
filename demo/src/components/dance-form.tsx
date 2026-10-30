import { useNavigate } from "@tanstack/react-router";
import type { AuthDanceFlow, AuthDancePromptInput, AuthDanceResponse } from "auth-dance/client";
import { type AuthDanceFlowHandle, useAuthDanceFlow } from "auth-dance/react";
import { REGEXP_ONLY_DIGITS } from "input-otp";
import { AlertCircleIcon, FingerprintIcon, KeyRoundIcon, Loader2Icon, MailIcon, RotateCcwIcon, ShieldAlertIcon } from "lucide-react";
import { type FormEvent, type ReactNode, useEffect, useRef, useState } from "react";
import { LoginForm } from "@/components/login-form";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Field, FieldDescription, FieldLabel, FieldSeparator } from "@/components/ui/field";
import { Input } from "@/components/ui/input";
import { InputOTP, InputOTPGroup, InputOTPSlot } from "@/components/ui/input-otp";
import { client, describeError } from "@/lib/auth";
import { createPasskey, signWithPasskey, webauthnSupported } from "@/lib/webauthn";

export interface DanceFormProps {
	/** The flow to run, under the name of its route. */
	flow: AuthDanceFlow;
	/** The component or the channel the flow acts on. */
	name?: string;
	title: ReactNode;
	description?: ReactNode;
	/** Called once the last answer carries the tokens or a bare success. */
	onDone?: (response: AuthDanceResponse) => void;
	/** Rendered under the form, the links of login-05 for example. */
	footer?: ReactNode;
	/** Hides the logo of the login-05 header, inside a dialog for example. */
	compact?: boolean;
}

/**
 * Runs one flow of the dance, whatever the choreography asks. It reads the prompt the library hands back and renders
 * the field of its type: the layout of the login-05 block, with a separator between the branches of a choice.
 */
export function DanceForm({ flow, name, title, description, onDone, footer, compact }: DanceFormProps) {
	const dance = useAuthDanceFlow({ flow, name, onDone: (response) => onDone?.(response) });

	return (
		<LoginForm title={title} description={description} footer={footer} compact={compact}>
			<Trail dance={dance} />
			{dance.error !== undefined && <DanceError error={dance.error} />}
			<DanceBody dance={dance} />
		</LoginForm>
	);
}

// The names answered so far, so the owner sees the choreography move.
function Trail({ dance }: { dance: AuthDanceFlowHandle }) {
	if (dance.trail.length === 0 || dance.done) {
		return null;
	}
	return (
		<div className="flex flex-wrap items-center justify-center gap-1.5 text-xs text-muted-foreground">
			{dance.trail.map((step, index) => (
				<Badge key={`${step}-${index}`} variant="secondary">
					✓ {step}
				</Badge>
			))}
			<Badge variant="outline">{dance.current?.name ?? "…"}</Badge>
		</div>
	);
}

function DanceError({ error }: { error: unknown }) {
	const navigate = useNavigate();
	const code = (error as { code?: string } | null)?.code;
	return (
		<Alert variant="destructive">
			<AlertCircleIcon />
			<AlertTitle>{describeError(error)}</AlertTitle>
			{code === "FRESH_SIGN_IN_REQUIRED" && (
				<AlertDescription>
					<Button
						size="sm"
						variant="outline"
						className="mt-2"
						onClick={async () => {
							await client.clearTokens();
							await navigate({ to: "/login", search: { redirect: window.location.pathname } });
						}}
					>
						Sign in again
					</Button>
				</AlertDescription>
			)}
		</Alert>
	);
}

function DanceBody({ dance }: { dance: AuthDanceFlowHandle }) {
	if (!dance.choreography) {
		if (dance.pending) {
			return <Pending />;
		}
		return (
			<Field>
				<Button variant="outline" onClick={() => dance.restart()}>
					<RotateCcwIcon /> Try again
				</Button>
			</Field>
		);
	}
	if (dance.done) {
		return <p className="text-center text-sm text-muted-foreground">All done.</p>;
	}
	if (dance.expired) {
		return (
			<Alert>
				<AlertCircleIcon />
				<AlertTitle>This dance expired</AlertTitle>
				<AlertDescription>
					<Button size="sm" variant="outline" className="mt-2" onClick={() => dance.restart()}>
						Start again
					</Button>
				</AlertDescription>
			</Alert>
		);
	}

	const prompt = dance.prompt;
	const branches = prompt?.kind === "choice" ? dance.choices : dance.current ? [dance.current] : [];
	return (
		<>
			{branches.map((branch, index) => (
				<div key={branch.name} className="contents">
					{index > 0 && <FieldSeparator>Or</FieldSeparator>}
					<PromptField prompt={branch} dance={dance} secondary={index > 0} />
				</div>
			))}
			{dance.trail.length > 0 && (
				<Button variant="link" size="sm" className="self-center text-muted-foreground" onClick={() => dance.restart()}>
					Start over
				</Button>
			)}
		</>
	);
}

function Pending() {
	return (
		<div className="flex justify-center py-6 text-muted-foreground">
			<Loader2Icon className="size-5 animate-spin" />
		</div>
	);
}

interface PromptFieldProps {
	prompt: AuthDancePromptInput;
	dance: AuthDanceFlowHandle;
	/** The second branch of a choice renders as an outline button, as in login-05. */
	secondary?: boolean;
}

function PromptField(props: PromptFieldProps) {
	switch (props.prompt.type) {
		case "otp":
			return <OtpField {...props} />;
		case "webauthn":
		case "webauthn-create":
			return <PasskeyField {...props} />;
		case "confirmation":
			return <ConfirmationField {...props} />;
		default:
			return <TextField {...props} />;
	}
}

const LABELS: Record<string, { label: string; placeholder?: string; icon: ReactNode }> = {
	email: { label: "Email", placeholder: "m@example.com", icon: <MailIcon /> },
	password: { label: "Password", icon: <KeyRoundIcon /> },
};

function TextField({ prompt, dance, secondary }: PromptFieldProps) {
	const [value, setValue] = useState("");
	const id = `${dance.flow}-${prompt.name}`;
	const meta = LABELS[prompt.type] ?? { label: prompt.name, icon: null };
	// A rotate of a verifiable component proves the current value with its own challenge, a code or a passkey; the
	// field it shows is always the new value. A recover ends on the component it resets.
	const isNew =
		dance.flow === "sign-up" ||
		dance.flow === "enroll" ||
		dance.flow === "rotate" ||
		(dance.flow === "recover" && prompt.name === dance.name);
	const label = isNew && dance.flow !== "sign-up" ? `New ${meta.label.toLowerCase()}` : meta.label;

	async function submit(event: FormEvent) {
		event.preventDefault();
		const answer = await dance.submitPrompt(value, { name: prompt.name });
		if (answer) {
			setValue("");
		}
	}

	return (
		<form onSubmit={submit} className="flex flex-col gap-3">
			<Field>
				<FieldLabel htmlFor={id}>{label}</FieldLabel>
				<Input
					id={id}
					type={prompt.type === "password" ? "password" : prompt.type === "email" ? "email" : "text"}
					autoComplete={
						prompt.type === "password" ? (isNew ? "new-password" : "current-password") : prompt.type === "email" ? "email webauthn" : "off"
					}
					placeholder={meta.placeholder}
					value={value}
					onChange={(event) => setValue(event.target.value)}
					required
					autoFocus
				/>
			</Field>
			<Field>
				<Button type="submit" variant={secondary ? "outline" : "default"} disabled={dance.pending || value.length === 0}>
					{dance.pending && <Loader2Icon className="animate-spin" />}
					Continue
				</Button>
			</Field>
		</form>
	);
}

function OtpField({ prompt, dance }: PromptFieldProps) {
	const [value, setValue] = useState("");
	const [sentTo, setSentTo] = useState<string>();
	const sent = useRef(new Set<string>());
	const state = dance.choreography?.state;

	// The library delivers the code only when asked. Ask once for each step, and again on "Resend".
	useEffect(() => {
		if (!state || !prompt.sendable || sent.current.has(state)) {
			return;
		}
		sent.current.add(state);
		dance.sendPrompt({ name: prompt.name }).then(() => setSentTo(state));
	}, [state, prompt.name, prompt.sendable, dance.sendPrompt]);

	async function submit(code: string) {
		const answer = await dance.submitPrompt(code, { name: prompt.name });
		if (!answer) {
			setValue("");
		}
	}

	return (
		<form
			className="flex flex-col items-center gap-3"
			onSubmit={(event) => {
				event.preventDefault();
				submit(value);
			}}
		>
			<Field className="items-center">
				<FieldLabel htmlFor={`${dance.flow}-${prompt.name}`} className="justify-center">
					Enter the code we emailed you
				</FieldLabel>
				<InputOTP
					id={`${dance.flow}-${prompt.name}`}
					maxLength={6}
					pattern={REGEXP_ONLY_DIGITS}
					value={value}
					onChange={setValue}
					onComplete={submit}
					disabled={dance.pending}
					autoFocus
					containerClassName="justify-center"
				>
					<InputOTPGroup>
						{[0, 1, 2, 3, 4, 5].map((index) => (
							<InputOTPSlot key={index} index={index} className="size-10 text-base" />
						))}
					</InputOTPGroup>
				</InputOTP>
				<FieldDescription className="text-center">
					{sentTo === state ? "Sent. Open the demo inbox, bottom right, to read it." : "Sending the code…"}
				</FieldDescription>
			</Field>
			<Field>
				<Button type="submit" disabled={dance.pending || value.length !== 6}>
					{dance.pending && <Loader2Icon className="animate-spin" />}
					Verify
				</Button>
				<Button
					type="button"
					variant="ghost"
					size="sm"
					disabled={dance.pending}
					onClick={() => dance.sendPrompt({ name: prompt.name }).then(() => setSentTo(state))}
				>
					Resend code
				</Button>
			</Field>
		</form>
	);
}

function PasskeyField({ prompt, dance, secondary }: PromptFieldProps) {
	const [failure, setFailure] = useState<string>();
	const create = prompt.type === "webauthn-create";

	async function run() {
		setFailure(undefined);
		try {
			const credential = create ? await createPasskey(prompt.options ?? {}) : await signWithPasskey(prompt.options ?? {});
			await dance.submitPrompt(credential, { name: prompt.name });
		} catch (error) {
			// The browser raises `NotAllowedError` when the owner closes its dialog.
			setFailure(
				error instanceof DOMException && error.name === "NotAllowedError" ? "The passkey dialog was closed." : describeError(error),
			);
		}
	}

	if (!webauthnSupported()) {
		return <FieldDescription className="text-center">This browser has no WebAuthn support.</FieldDescription>;
	}
	return (
		<Field>
			<Button type="button" variant={secondary ? "outline" : "default"} disabled={dance.pending} onClick={run}>
				<FingerprintIcon />
				{create ? "Create a passkey" : dance.trail.includes(prompt.name) ? "Confirm your new passkey" : "Continue with a passkey"}
			</Button>
			{failure && <FieldDescription className="text-center text-destructive">{failure}</FieldDescription>}
		</Field>
	);
}

const CONFIRMATIONS: Partial<Record<AuthDanceFlow, string>> = {
	unenroll: "This removes the sign-in method, and every record that depends on it.",
	unsubscribe: "This removes the channel, and every sign-in method that depends on it.",
	delete: "This deletes the account and ends every session. It cannot be undone.",
};

function ConfirmationField({ dance }: PromptFieldProps) {
	return (
		<Field>
			<Alert variant="destructive">
				<ShieldAlertIcon />
				<AlertTitle>Are you sure?</AlertTitle>
				<AlertDescription>{CONFIRMATIONS[dance.flow] ?? "Confirm to continue."}</AlertDescription>
			</Alert>
			<Button variant="destructive" disabled={dance.pending} onClick={() => dance.confirm()}>
				{dance.pending && <Loader2Icon className="animate-spin" />}
				Confirm
			</Button>
		</Field>
	);
}
