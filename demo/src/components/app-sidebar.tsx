/**
 * @module
 *
 * The icon rail at the left of the page, and the sheet it opens. Only one panel is open at a time.
 *
 * {@link PanelsProvider} holds the open panel and {@link usePanels} reads it, so a control anywhere under the
 * provider can open the same sheet the rail opens.
 */

import * as React from "react";
import { CableIcon, InboxIcon, KeyRoundIcon, Settings2Icon, ShieldCheckIcon } from "lucide-react";
import { useAuthDanceIdentity } from "auth-dance/react";

import { Badge } from "@/components/ui/badge.tsx";
import { Sheet, SheetContent, SheetDescription, SheetHeader, SheetTitle } from "@/components/ui/sheet.tsx";
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
} from "@/components/ui/sidebar.tsx";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip.tsx";
import { cn } from "@/lib/utils.ts";
import { useDance } from "@/lib/dance/index.ts";

import { InboxPanel } from "@/components/panels/inbox-panel.tsx";
import { OptionsPanel } from "@/components/panels/options-panel.tsx";
import { SessionPanel } from "@/components/panels/session-panel.tsx";
import { WirePanel } from "@/components/panels/wire-panel.tsx";

/** The four panels the rail can put on screen. */
export type PanelName = "options" | "inbox" | "wire" | "session";

/** The panel on screen, and the two ways to change it. */
export interface Panels {
	/** The panel in the sheet. Null when the sheet is closed. */
	open: PanelName | null;
	/** Opens a panel, and replaces the one on screen. */
	openPanel: (panel: PanelName) => void;
	/** Closes the sheet. */
	closePanel: () => void;
}

const PanelsContext = React.createContext<Panels>({
	open: null,
	openPanel: () => {},
	closePanel: () => {},
});

/** Holds which panel is on screen. It renders no element of its own. */
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

/** Reads the slideout state from anywhere under {@link PanelsProvider}. */
export function usePanels(): Panels {
	return React.useContext(PanelsContext);
}

/** Returns a function that opens the options panel. */
export function useOpenOptions(): () => void {
	const { openPanel } = usePanels();
	return React.useCallback(() => openPanel("options"), [openPanel]);
}

interface PanelDefinition {
	name: PanelName;
	label: string;
	hint: string;
	icon: React.ComponentType<{ className?: string }>;
	/** The body of the sheet. The function gets a callback that closes the sheet. */
	body: (close: () => void) => React.ReactNode;
}

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
	const identity = useAuthDanceIdentity();
	const { messages, log } = useDance();
	const { open, openPanel, closePanel } = usePanels();
	const { isMobile, setOpenMobile } = useSidebar();

	const counts: Partial<Record<PanelName, number>> = { inbox: messages.length, wire: log.length };
	const current = PANELS.find((panel) => panel.name === open);
	// The sheet stays mounted while it slides out, and `open` is already null. Keep the panel that leaves so it slides
	// out with its own title and body.
	const leaving = React.useRef(current);
	if (current !== undefined) {
		leaving.current = current;
	}
	const shown = current ?? leaving.current;

	const signedIn = identity !== undefined;
	const status = signedIn ? "Signed in" : "Signed out";
	const detail = identity?.id ?? "No tokens yet. Sign in or sign up to mint some.";

	return (
		<>
			<Sidebar collapsible="icon" variant="inset">
				<SidebarHeader>
					<div className="flex h-8 items-center gap-2">
						<span className="flex aspect-square size-8 shrink-0 items-center justify-center rounded-xl bg-sidebar-primary text-sidebar-primary-foreground">
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
													// On a phone the rail is itself a sheet. Close it first.
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
