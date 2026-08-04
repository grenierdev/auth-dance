/**
 * @module
 *
 * The icon rail down the left of the page, and the one slideout it drives.
 *
 * The login card in the middle is the demo; everything that explains the demo lives out here. Four entries name the
 * four panels, a click puts one of them in a sheet on the right, and only ever one is open, so the stage keeps the
 * screen to itself until somebody asks a question about it.
 *
 * The open panel is a piece of page state rather than a piece of sidebar state: the choreography card wants to open
 * the options panel too. {@link PanelsProvider} holds it and {@link usePanels} reads it, so a control anywhere under
 * the provider can reach for the same sheet the rail reaches for.
 */

import * as React from "react";
import { CableIcon, InboxIcon, KeyRoundIcon, Settings2Icon, ShieldCheckIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet";
import {
	Sidebar,
	SidebarContent,
	SidebarFooter,
	SidebarGroup,
	SidebarGroupContent,
	SidebarHeader,
	SidebarMenu,
	SidebarMenuBadge,
	SidebarMenuButton,
	SidebarMenuItem,
	SidebarRail,
	useSidebar,
} from "@/components/ui/sidebar";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { cn } from "@/lib/utils";
import { useDance } from "@/lib/dance";

import { InboxPanel } from "@/components/panels/inbox-panel";
import { OptionsPanel } from "@/components/panels/options-panel";
import { SessionPanel } from "@/components/panels/session-panel";
import { WirePanel } from "@/components/panels/wire-panel";

/** The four panels the rail can put on screen. */
export type PanelName = "options" | "inbox" | "wire" | "session";

/** What a control needs to drive the slideout: the panel on screen, and the two ways to change it. */
export interface Panels {
	/** The panel in the sheet, or nothing when the sheet is closed. */
	open: PanelName | null;
	/** Puts a panel on screen, replacing whichever one was there. */
	openPanel: (panel: PanelName) => void;
	/** Closes the sheet. */
	closePanel: () => void;
}

// A page that forgot the provider should still work, minus the slideout, rather than take the whole render down with
// it. The demo is worth more on screen than a missing provider is worth loud.
const PanelsContext = React.createContext<Panels>({
	open: null,
	openPanel: () => {},
	closePanel: () => {},
});

/**
 * Holds which panel is on screen, for the rail and for anything else that wants to open one.
 *
 * It renders no element of its own, so it can sit outside the sidebar wrapper without disturbing the layout.
 */
export function PanelsProvider({ children }: { children: React.ReactNode }) {
	const [open, setOpen] = React.useState<PanelName | null>(null);
	const value = React.useMemo<Panels>(
		() => ({
			open,
			openPanel: (panel) => setOpen(panel),
			closePanel: () => setOpen(null),
		}),
		[open],
	);

	return <PanelsContext.Provider value={value}>{children}</PanelsContext.Provider>;
}

/** Reads the slideout, from anywhere under {@link PanelsProvider}. */
export function usePanels(): Panels {
	return React.useContext(PanelsContext);
}

/** The one call the choreography card needs: open the options panel and leave the rest alone. */
export function useOpenOptions(): () => void {
	const { openPanel } = usePanels();
	return React.useCallback(() => openPanel("options"), [openPanel]);
}

interface PanelDefinition {
	name: PanelName;
	label: string;
	hint: string;
	icon: React.ComponentType<{ className?: string }>;
	/**
	 * The body of the sheet. It is handed the one thing a panel cannot do for itself: close the sheet it sits in.
	 * Options takes it so an apply can step out of the way of the rebuilt page, and Inbox takes it so a code that
	 * has been put in the form does not have to be read past the slideout that carried it.
	 */
	body: (close: () => void) => React.ReactNode;
}

// The order of the rail. A panel that counts something reads its count off the store below rather than carrying one
// here, because the count changes and this list does not.
const PANELS: readonly PanelDefinition[] = [
	{
		name: "options",
		label: "Options",
		hint: "The choreography the library is built from, the durations it enforces, and whether a rebuild seeds an identity.",
		icon: Settings2Icon,
		body: (close) => <OptionsPanel onApplied={close} />,
	},
	{
		name: "inbox",
		label: "Inbox",
		hint: "The channels here keep what they are handed instead of delivering it, so a one-time code lands in this list.",
		icon: InboxIcon,
		body: (close) => <InboxPanel onUsed={close} />,
	},
	{
		name: "wire",
		label: "Wire",
		hint: "Every call into the library, and everything its hooks report.",
		icon: CableIcon,
		body: () => <WirePanel />,
	},
	{
		name: "session",
		label: "Session",
		hint: "The tokens the library minted, the session behind them, and what it says about this identity.",
		icon: KeyRoundIcon,
		body: () => <SessionPanel />,
	},
];

/**
 * The icon rail, and the sheet it opens.
 *
 * Mount it inside a `SidebarProvider`, beside the `SidebarInset` that holds the stage.
 */
export function AppSidebar() {
	const { ready, tokens, session, messages, log } = useDance();
	const { open, openPanel, closePanel } = usePanels();
	const { isMobile, setOpenMobile } = useSidebar();

	const counts: Partial<Record<PanelName, number>> = { inbox: messages.length, wire: log.length };
	const current = PANELS.find((panel) => panel.name === open);
	// The sheet stays mounted for the two hundred milliseconds it takes to slide out, and by then `open` is already
	// null. Hold on to the panel that is leaving so it goes with its own title and body rather than blanking to a bare
	// "Panel" on the way. Writing the ref during render is the same value for the same `open`, so a double render is
	// free of consequence.
	const leaving = React.useRef(current);
	if (current !== undefined) {
		leaving.current = current;
	}
	const shown = current ?? leaving.current;

	const signedIn = tokens !== undefined;
	const status = !ready ? "Starting" : signedIn ? "Signed in" : "Signed out";
	const detail = !ready
		? "The library is still being built."
		: signedIn
		? (session?.identity.id ?? "Signed in")
		: "No tokens yet. Sign in or sign up to mint some.";

	return (
		<>
			<Sidebar collapsible="icon" variant="inset">
				<SidebarHeader>
					<div className="flex h-8 items-center gap-2">
						<span
							className="flex aspect-square size-8 shrink-0 items-center justify-center rounded-xl bg-sidebar-primary text-sidebar-primary-foreground"
						>
							<ShieldCheckIcon className="size-4" />
						</span>
						<span className="grid min-w-0 flex-1 leading-tight group-data-[collapsible=icon]:hidden">
							<span className="truncate text-sm font-medium">auth-dance</span>
							<span className="truncate text-xs text-sidebar-foreground/70">in-browser demo</span>
						</span>
					</div>
				</SidebarHeader>

				<SidebarContent>
					<SidebarGroup>
						<SidebarGroupContent>
							<SidebarMenu>
								{PANELS.map((panel) => {
									const Icon = panel.icon;
									const count = counts[panel.name] ?? 0;

									return (
										<SidebarMenuItem key={panel.name}>
											<SidebarMenuButton
												isActive={open === panel.name}
												tooltip={panel.label}
												onClick={() => {
													// On a phone the rail itself is a sheet. Get it out of the way before the panel arrives.
													if (isMobile) {
														setOpenMobile(false);
													}
													openPanel(panel.name);
												}}
											>
												<Icon />
												<span>{panel.label}</span>
											</SidebarMenuButton>
											{count > 0 && <SidebarMenuBadge>{count}</SidebarMenuBadge>}
										</SidebarMenuItem>
									);
								})}
							</SidebarMenu>
						</SidebarGroupContent>
					</SidebarGroup>
				</SidebarContent>

				<SidebarFooter>
					<Tooltip>
						<TooltipTrigger render={<div />} className="flex h-8 items-center gap-2">
							<span className="flex size-8 shrink-0 items-center justify-center">
								<span
									className={cn("size-2 rounded-full", signedIn ? "bg-primary" : "bg-muted-foreground/40")}
									aria-hidden="true"
								/>
							</span>
							<Badge variant={signedIn ? "default" : "outline"} className="min-w-0 group-data-[collapsible=icon]:hidden">
								<span className="truncate">{status}</span>
							</Badge>
						</TooltipTrigger>
						<TooltipContent side="right">{detail}</TooltipContent>
					</Tooltip>
				</SidebarFooter>

				<SidebarRail />
			</Sidebar>

			<Sheet
				open={current !== undefined}
				onOpenChange={(next) => {
					if (!next) {
						closePanel();
					}
				}}
			>
				<SheetContent side="right" className="data-[side=right]:w-full data-[side=right]:sm:max-w-lg">
					<SheetHeader>
						<SheetTitle>{shown?.label ?? "Panel"}</SheetTitle>
						<SheetDescription>{shown?.hint}</SheetDescription>
					</SheetHeader>
					<div className="min-h-0 flex-1 overflow-y-auto px-6 pb-6">{shown?.body(closePanel)}</div>
				</SheetContent>
			</Sheet>
		</>
	);
}
