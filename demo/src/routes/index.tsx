/**
 * @module
 *
 * The page: an icon rail, and a login card in the middle.
 *
 * The route sets `ssr: false` because the library keeps all state in a `Map` in this tab. The route module still runs
 * on the server, so nothing outside a component body touches `document`, `localStorage` or `crypto`.
 */

import { createFileRoute } from "@tanstack/react-router";

import { AppSidebar, PanelsProvider } from "@/components/app-sidebar.tsx";
import { AuthStage } from "@/components/auth/auth-stage.tsx";
import { Progress } from "@/components/ui/progress.tsx";
import { Separator } from "@/components/ui/separator.tsx";
import { SidebarInset, SidebarProvider, SidebarTrigger } from "@/components/ui/sidebar.tsx";
import { useDance } from "@/lib/dance/index.ts";

/** The one route of the demo. */
export const Route = createFileRoute("/")({ ssr: false, component: DemoPage });

function DemoPage() {
	const { busy } = useDance();

	return (
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
	);
}
