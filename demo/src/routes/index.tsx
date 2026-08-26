/**
 * @module
 *
 * The page: an icon rail, and a login card in the middle.
 *
 * {@link AuthDanceProvider} of `auth-dance/react` shares the client of the running instance with the whole tree, so
 * every hook below it reads the same session. The store builds that instance in an effect, so the first render holds
 * none and shows the card of a page that is still starting.
 *
 * A build that fails leaves no client, so the starting card carries whatever the store was refused with. Without that
 * the page would show a skeleton for good.
 *
 * The route sets `ssr: false` because the library keeps all state in a `Map` in this tab. The route module still runs
 * on the server, so nothing outside a component body touches `document`, `localStorage` or `crypto`.
 */

import { createFileRoute } from "@tanstack/react-router";
import { TriangleAlertIcon } from "lucide-react";
import { AuthDanceProvider } from "auth-dance/react";

import { AppSidebar, PanelsProvider } from "@/components/app-sidebar.tsx";
import { AuthStage } from "@/components/auth/auth-stage.tsx";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert.tsx";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card.tsx";
import { Progress } from "@/components/ui/progress.tsx";
import { Separator } from "@/components/ui/separator.tsx";
import { Skeleton } from "@/components/ui/skeleton.tsx";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar.tsx";
import { useDance } from "@/lib/dance/index.ts";

/** The one route of the demo. */
export const Route = createFileRoute("/")({ ssr: false, component: DemoPage });

function DemoPage() {
	const { client, busy, error } = useDance();

	if (!client) {
		return <StartingPage error={error} />;
	}

	return (
		<AuthDanceProvider client={client}>
			<PanelsProvider>
				<SidebarProvider defaultOpen={false} className="min-h-0 flex-1">
					<AppSidebar />
					<SidebarInset className="overflow-hidden bg-muted">
						{busy && (
							<Progress
								value={null}
								aria-label="Working"
								className="pointer-events-none absolute inset-x-0 top-0 z-20 gap-0 [&_[data-slot=progress-indicator]]:w-full [&_[data-slot=progress-indicator]]:animate-pulse [&_[data-slot=progress-track]]:h-1 [&_[data-slot=progress-track]]:rounded-none [&_[data-slot=progress-track]]:bg-transparent"
							/>
						)}

						<header className="flex h-14 shrink-0 items-center gap-2 px-4">
							<SidebarTrigger />
							<Separator orientation="vertical" className="h-4" />
							<span className="truncate text-xs text-muted-foreground">everything runs in this page</span>
						</header>

						<div className="min-h-0 flex-1 overflow-y-auto">
							<div className="flex min-h-full items-center justify-center px-4 pb-14">
								<AuthStage />
							</div>
						</div>
					</SidebarInset>
				</SidebarProvider>
			</PanelsProvider>
		</AuthDanceProvider>
	);
}

/** What the page shows until the store has built the first instance and the client that calls it. */
function StartingPage({ error }: { error: string | undefined }) {
	return (
		<div className="flex min-h-0 flex-1 items-center justify-center bg-muted px-4">
			<div className="mx-auto flex w-full max-w-sm flex-col gap-6">
				<Card>
					<CardHeader className="text-center">
						<CardTitle className="text-xl">Welcome back</CardTitle>
						<CardDescription>Building the library in this page.</CardDescription>
					</CardHeader>
					<CardContent className="flex flex-col gap-3">
						{error === undefined
							? (
								<>
									<Skeleton className="h-9 w-full rounded-3xl" />
									<Skeleton className="h-9 w-full rounded-3xl" />
									<Skeleton className="h-4 w-2/3 self-center" />
								</>
							)
							: (
								<Alert variant="destructive">
									<TriangleAlertIcon />
									<AlertTitle>Nothing was built</AlertTitle>
									<AlertDescription>{error}</AlertDescription>
								</Alert>
							)}
					</CardContent>
				</Card>
			</div>
		</div>
	);
}
