/**
 * @module
 *
 * The card in the middle of the page, and the strip of choreography under it. The card is a login page, a manager of the
 * identity behind the tokens, or the card of a running flow. The rows come from `AuthDanceFlows` filtered on the
 * session, and `useAuthDanceTokens` says which half of them is on offer.
 */

import { useEffect, useState } from "react";
import { CircleCheckIcon, TriangleAlertIcon } from "lucide-react";
import { totp } from "auth-dance";
import { type AuthDanceFlow, AuthDanceFlows } from "auth-dance/client";
import { useAuthDanceClient, useAuthDanceTokens } from "auth-dance/react";

import { useOpenOptions } from "@/components/app-sidebar.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Field, FieldDescription, FieldGroup, FieldSeparator } from "@/components/ui/field.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select.tsx";
import {
	FLOW_LABELS,
	FLOW_NAMES,
	PRESETS,
	SEEDED,
	TOTP_ALGORITHM,
	TOTP_DIGITS,
	TOTP_PERIOD,
	useDance,
	useDanceActions,
} from "@/lib/dance/index.ts";
import { resolvedTree } from "@/lib/format.ts";

import { FlowCard } from "./flow-card.tsx";

/** How prominent the button of a flow that takes no argument is. Any flow that is absent gets an outline button. */
const FLOW_VARIANTS: Partial<Record<AuthDanceFlow, "default" | "outline" | "destructive">> = {
	"sign-in": "default",
	"delete": "destructive",
};

/** The flow the stage started, and what it acts on. */
interface Started {
	/** The flow that is running. */
	flow: AuthDanceFlow;
	/** The component or the channel it acts on. A flow that takes no argument carries none. */
	name?: string;
}

/** The login card, the management card and the card of a running flow, with the choreography under all three. */
export function AuthStage() {
	const client = useAuthDanceClient();
	const { config } = useDance();
	const [started, setStarted] = useState<Started | undefined>(undefined);

	// A rebuild hands out a new client, and the dance of the old one has nowhere to go. Drop it and show the start card.
	const [source, setSource] = useState(client);
	if (source !== client) {
		setSource(client);
		setStarted(undefined);
	}

	const preset = PRESETS.find((entry) => entry.id === config.preset);
	const summary = preset?.choreography ? preset.hint : resolvedTree(config).text;
	const openOptions = useOpenOptions();

	return (
		<div className="mx-auto flex w-full max-w-sm flex-col gap-6">
			{started
				? (
					<FlowCard
						key={`${started.flow}:${started.name ?? ""}`}
						flow={started.flow}
						name={started.name}
						onLeave={() => setStarted(undefined)}
					/>
				)
				: <StartCard onStart={setStarted} />}

			<div className="flex flex-col gap-1.5 rounded-3xl border border-dashed px-4 py-3">
				<div className="flex items-center justify-between gap-2">
					<span className="text-xs font-medium text-muted-foreground">Choreography</span>
					<Button type="button" size="xs" variant="ghost" onClick={openOptions}>Change</Button>
				</div>
				<span className="text-xs text-foreground">{preset?.label}</span>
				<pre className="overflow-x-auto font-mono text-xs whitespace-pre-wrap text-muted-foreground">{summary}</pre>
			</div>
		</div>
	);
}

/**
 * The code the seeded authenticator key derives right now.
 *
 * A choreography that names `totp` asks for this code, and the library delivers nothing for it. The seeded key is
 * published, so the page derives the code itself and the owner needs no authenticator app.
 */
function SeededCode() {
	const [code, setCode] = useState<string | undefined>(undefined);

	useEffect(() => {
		let mounted = true;
		const read = (): void => {
			void totp({ key: SEEDED.totp, period: TOTP_PERIOD, digits: TOTP_DIGITS, algorithm: TOTP_ALGORITHM }).then(
				(next) => {
					if (mounted) {
						setCode(next);
					}
				},
				() => {},
			);
		};
		read();
		// One second is finer than it needs to be, and it keeps the reading true across the turn of every period.
		const timer = setInterval(read, 1000);
		return () => {
			mounted = false;
			clearInterval(timer);
		};
	}, []);

	return <span className="font-mono text-foreground">{code ?? "……"}</span>;
}

/** What the start card reports back. */
interface StartCardProps {
	/** Called with the flow to start, and the component or the channel it acts on. */
	onStart: (started: Started) => void;
}

/** The card between two flows: every flow the session allows, and what this session can do to itself. */
function StartCard({ onStart }: StartCardProps) {
	const tokens = useAuthDanceTokens();
	const { componentNames, channelNames, seeded, busy, error, notice } = useDance();
	const { refreshTokens, signOutEverywhere, signOut, clearAlerts } = useDanceActions();
	// Which component or channel each picker holds.
	const [picked, setPicked] = useState<Record<string, string>>({});

	const signedIn = tokens !== undefined;
	const offered = FLOW_NAMES.filter((flow) => AuthDanceFlows[flow].authenticated === signedIn);
	const plain = offered.filter((flow) => AuthDanceFlows[flow].argument === "none");
	const picking = offered.filter((flow) => AuthDanceFlows[flow].argument !== "none");

	const namesFor = (flow: AuthDanceFlow) => (AuthDanceFlows[flow].argument === "channel" ? channelNames : componentNames);
	const pickedFor = (flow: AuthDanceFlow) => picked[flow] ?? namesFor(flow)[0] ?? "";

	const start = (flow: AuthDanceFlow, name?: string): void => {
		clearAlerts();
		onStart({ flow, name });
	};

	return (
		<Card>
			<CardHeader className="text-center">
				<CardTitle className="text-xl">{signedIn ? "Manage this identity" : "Welcome back"}</CardTitle>
				<CardDescription>
					{signedIn
						? "Every flow here needs a recent sign-in. Past the elevated window the library answers FRESH_SIGN_IN_REQUIRED, " +
							"and a refresh never reopens it."
						: "The whole library runs in this page. Pick a flow and it asks for whatever the choreography needs."}
				</CardDescription>
			</CardHeader>

			{(error || notice) && (
				<div className="flex flex-col gap-2 px-(--card-spacing)">
					{error && (
						<Alert variant="destructive">
							<TriangleAlertIcon />
							<AlertTitle>The library refused</AlertTitle>
							<AlertDescription>{error}</AlertDescription>
						</Alert>
					)}
					{notice && (
						<Alert>
							<CircleCheckIcon />
							<AlertTitle>Done</AlertTitle>
							<AlertDescription>{notice}</AlertDescription>
						</Alert>
					)}
				</div>
			)}

			<CardContent>
				<FieldGroup>
					<Field>
						{plain.map((flow) => (
							<Button
								key={flow}
								type="button"
								variant={FLOW_VARIANTS[flow] ?? "outline"}
								disabled={busy}
								onClick={() => start(flow)}
							>
								{FLOW_LABELS[flow]}
							</Button>
						))}
					</Field>

					{!signedIn && (
						<FieldDescription className="text-center">
							{seeded
								? (
									<>
										An identity is already seeded: <span className="font-mono text-foreground">{SEEDED.email}</span> with the password{" "}
										<span className="font-mono text-foreground">{SEEDED.password}</span> and the authenticator key{" "}
										<span className="font-mono text-foreground">{SEEDED.totp}</span>, which reads <SeededCode />{" "}
										right now. Sign up to make another one.
									</>
								)
								: "No identity is seeded. Sign up to make one."}
						</FieldDescription>
					)}

					{picking.length > 0 && (
						<FieldSeparator className="*:data-[slot=field-separator-content]:bg-card">
							{signedIn ? "On a component" : "Or"}
						</FieldSeparator>
					)}

					{picking.map((flow) => (
						<Field key={flow} orientation="horizontal" className="gap-2">
							<Select
								items={Object.fromEntries(namesFor(flow).map((name) => [name, name]))}
								value={pickedFor(flow) || null}
								onValueChange={(next) => setPicked((current) => ({ ...current, [flow]: String(next ?? "") }))}
							>
								<SelectTrigger
									size="sm"
									className="w-full flex-1"
									aria-label={`Which ${AuthDanceFlows[flow].argument} for ${FLOW_LABELS[flow]}`}
								>
									<SelectValue placeholder={`Pick a ${AuthDanceFlows[flow].argument}`} />
								</SelectTrigger>
								<SelectContent>
									{namesFor(flow).map((name) => <SelectItem key={name} value={name}>{name}</SelectItem>)}
								</SelectContent>
							</Select>
							<Button
								type="button"
								size="sm"
								variant="outline"
								className="w-32 shrink-0"
								disabled={busy || !pickedFor(flow)}
								onClick={() => start(flow, pickedFor(flow))}
							>
								{FLOW_LABELS[flow]}
							</Button>
						</Field>
					))}

					{signedIn && (
						<>
							<FieldSeparator className="*:data-[slot=field-separator-content]:bg-card">This session</FieldSeparator>
							<Field orientation="horizontal" className="flex-wrap justify-center gap-2">
								<Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void refreshTokens()}>
									Refresh tokens
								</Button>
								<Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void signOutEverywhere()}>
									Sign out everywhere
								</Button>
								<Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void signOut()}>
									Sign out
								</Button>
							</Field>
						</>
					)}
				</FieldGroup>
			</CardContent>
		</Card>
	);
}
