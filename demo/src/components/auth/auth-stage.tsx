/**
 * @module
 *
 * The card in the middle of the page, and the strip of choreography under it.
 *
 * The card has three faces and one shape. Signed out it is a login page. Signed in it is the management surface for
 * the identity behind the tokens. With a flow running it is whatever the library asked for next. Nothing here decides
 * what the library can do: the rows come from {@link FLOWS} filtered on the session, so a flow added to the library
 * shows up without a line changing here.
 *
 * The strip below the card names the tree the running instance was built from, because the card makes no sense without
 * it: the same button asks for a password under one choreography and a one-time code under another.
 */

import { useState } from "react";
import { CircleCheckIcon, TriangleAlertIcon } from "lucide-react";

import { useOpenOptions } from "@/components/app-sidebar.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Button } from "@/components/ui/button.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Field, FieldDescription, FieldGroup, FieldSeparator } from "@/components/ui/field.tsx";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select.tsx";
import { Skeleton } from "@/components/ui/skeleton.tsx";
import { FLOW_NAMES, type FlowName, FLOWS, PRESETS, SEEDED, useDance, useDanceActions } from "@/lib/dance/index.ts";
import { resolvedTree } from "@/lib/format.ts";

import { PromptForm } from "./prompt-form.tsx";

/**
 * How prominent the button of a flow that takes no argument is.
 *
 * Signing in is what a login page is for, and deleting an identity is the one row worth colouring as a warning. Every
 * other flow is an outline button, so a flow this table has never heard of still renders.
 */
const FLOW_VARIANTS: Partial<Record<FlowName, "default" | "outline" | "destructive">> = {
	"sign-in": "default",
	"delete": "destructive",
};

/** The login card, the management card and the prompt card, which are the same card. */
export function AuthStage() {
	const { ready, config, componentNames, channelNames, step, tokens, busy, error, notice } = useDance();
	const { startFlow, refreshTokens, signOutOthers, signOut } = useDanceActions();
	// The rail owns the slideout and the strip below only asks for it, which is what the panels context is for.
	const openOptions = useOpenOptions();
	// Which component or channel each picker holds. The store owns nothing of it, because nothing has been started yet.
	const [picked, setPicked] = useState<Record<string, string>>({});

	if (!ready) {
		return (
			<div className="mx-auto flex w-full max-w-sm flex-col gap-6">
				<Card>
					<CardHeader className="text-center">
						<CardTitle className="text-xl">Welcome back</CardTitle>
						<CardDescription>Building the library in this page.</CardDescription>
					</CardHeader>
					<CardContent className="flex flex-col gap-3">
						<Skeleton className="h-9 w-full rounded-3xl" />
						<Skeleton className="h-9 w-full rounded-3xl" />
						<Skeleton className="h-4 w-2/3 self-center" />
					</CardContent>
				</Card>
			</div>
		);
	}

	const signedIn = tokens !== undefined;
	const offered = FLOW_NAMES.filter((flow) => FLOWS[flow].authenticated === signedIn);
	const plain = offered.filter((flow) => FLOWS[flow].argument === "none");
	const picking = offered.filter((flow) => FLOWS[flow].argument !== "none");

	const namesFor = (flow: FlowName) => (FLOWS[flow].argument === "channel" ? channelNames : componentNames);
	const pickedFor = (flow: FlowName) => picked[flow] ?? namesFor(flow)[0] ?? "";

	const preset = PRESETS.find((entry) => entry.id === config.preset);
	// The hint of a shipped preset is the call that builds it, which is already the shortest true summary. The custom
	// entry has no such line, so its tree is drawn instead, and a tree the parser refuses shows what it refused.
	const summary = preset?.choreography ? preset.hint : resolvedTree(config).text;

	return (
		<div className="mx-auto flex w-full max-w-sm flex-col gap-6">
			<Card>
				<CardHeader className="text-center">
					<CardTitle className="text-xl">
						{step ? FLOWS[step.flow].label : signedIn ? "Manage this identity" : "Welcome back"}
					</CardTitle>
					<CardDescription>
						{step
							? "One step of the choreography. Every answer earns the next prompt, or the tokens at the end."
							: signedIn
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
					{step ? <PromptForm /> : (
						<FieldGroup>
							<Field>
								{plain.map((flow) => (
									<Button
										key={flow}
										type="button"
										variant={FLOW_VARIANTS[flow] ?? "outline"}
										disabled={busy}
										onClick={() => void startFlow(flow)}
									>
										{FLOWS[flow].label}
									</Button>
								))}
							</Field>

							{!signedIn && (
								<FieldDescription className="text-center">
									{config.seed
										? (
											<>
												An identity is already seeded: <span className="font-mono text-foreground">{SEEDED.email}</span> with the password
												{" "}
												<span className="font-mono text-foreground">{SEEDED.password}</span>. Sign up to make another one.
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
											aria-label={`Which ${FLOWS[flow].argument} for ${FLOWS[flow].label}`}
										>
											<SelectValue placeholder={`Pick a ${FLOWS[flow].argument}`} />
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
										onClick={() => void startFlow(flow, pickedFor(flow))}
									>
										{FLOWS[flow].label}
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
										<Button type="button" size="sm" variant="ghost" disabled={busy} onClick={() => void signOutOthers()}>
											Sign out others
										</Button>
										<Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void signOut()}>
											Sign out
										</Button>
									</Field>
								</>
							)}
						</FieldGroup>
					)}
				</CardContent>
			</Card>

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
