/**
 * @module
 *
 * The page: an icon rail, and a login card in the middle of a muted field.
 *
 * `ssr: false` is the whole of the client-only requirement. The library builds an Auth Dance over the memory
 * providers and keeps everything it knows in a `Map`, in this tab, so there is nothing for a server pass to render
 * and nothing it could render that would still be true by the time the browser took over. The route module is still
 * evaluated on the server — that is how the option is read — which is why nothing here touches `document`,
 * `localStorage` or `crypto` outside of a component body.
 */

import { createFileRoute } from "@tanstack/react-router";

import { AppSidebar, PanelsProvider } from "@/components/app-sidebar.tsx";
import { AuthStage } from "@/components/auth/auth-stage.tsx";
import { Progress } from "@/components/ui/progress.tsx";
import { Separator } from "@/components/ui/separator.tsx";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar.tsx";
import { useDance } from "@/lib/dance/index.ts";

/** The one route of the demo, and the only one that will ever exist. */
export const Route = createFileRoute("/")({ ssr: false, component: DemoPage });

function DemoPage() {
	const { busy } = useDance();

	return (
		// The panels provider wraps both the rail and the stage, because the strip under the login card opens the same
		// options slideout the rail does.
		<PanelsProvider>
			{/* The rail starts closed: it is a shelf of explanations, and the login card is what the page is about. */}
			<SidebarProvider defaultOpen={false} className="min-h-0 flex-1">
				<AppSidebar />
				<SidebarInset className="overflow-hidden bg-muted">
					{
						/* An indeterminate bar rather than a spinner: an action here answers in a millisecond, and the only
					    honest thing to report is that one is in flight. */
					}
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

					{
						/* Centred while the card is short, scrolled once a prompt makes it taller than the screen. The stage
					    carries its own width, so nothing here sets one. */
					}
					<div className="min-h-0 flex-1 overflow-y-auto">
						<div className="flex min-h-full items-center justify-center px-4 pb-14">
							<AuthStage />
						</div>
					</div>
				</SidebarInset>
			</SidebarProvider>
		</PanelsProvider>
	);
}
