import { AppWindowIcon, MonitorIcon } from "lucide-react";
import { Badge } from "@/components/ui/badge";

/** The public record of a client, as the login and consent pages read it. */
export interface PublicClient {
	client_id: string;
	client_name?: string;
	client_uri?: string;
	grant_types: string[];
}

/** Who asks for access, and for what. */
export function ClientCard({ client, scopes, userCode }: { client: PublicClient; scopes: string[]; userCode?: string }) {
	const device = userCode !== undefined;
	return (
		<div className="flex flex-col items-center gap-2 rounded-lg border bg-muted/40 p-4 text-center">
			<div className="flex size-10 items-center justify-center rounded-full bg-background">
				{device ? <MonitorIcon className="size-5" /> : <AppWindowIcon className="size-5" />}
			</div>
			<div className="text-sm">
				<span className="font-semibold">{client.client_name ?? client.client_id}</span> wants to access your account
			</div>
			<div className="flex flex-wrap justify-center gap-1">
				{scopes.map((scope) => (
					<Badge key={scope} variant="secondary">
						{scope}
					</Badge>
				))}
			</div>
			{device && (
				<div className="text-xs text-muted-foreground">
					Device code <code className="font-mono font-semibold text-foreground">{userCode}</code>
				</div>
			)}
		</div>
	);
}
