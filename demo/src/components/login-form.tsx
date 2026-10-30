import { FingerprintIcon } from "lucide-react";
import type { ReactNode } from "react";
import { FieldDescription, FieldGroup } from "@/components/ui/field";
import { cn } from "@/lib/utils";

export interface LoginFormProps {
	title: ReactNode;
	description?: ReactNode;
	/** The fields of the step. The dance form puts the prompts of the choreography here. */
	children: ReactNode;
	/** The fine print under the form. */
	footer?: ReactNode;
	/** Hides the logo, inside a dialog for example. */
	compact?: boolean;
	className?: string;
}

/**
 * The login-05 block of shadcn, with its slots opened up: the logo and the title on top, the fields in a
 * `FieldGroup`, and the fine print under it. The fields come from the choreography instead of a fixed email input,
 * and the "Or" separator sits between the branches of a choice.
 */
export function LoginForm({ title, description, children, footer, compact, className }: LoginFormProps) {
	return (
		<div className={cn("flex flex-col gap-6", className)}>
			<FieldGroup>
				<div className="flex flex-col items-center gap-2 text-center">
					{!compact && (
						<div className="flex size-8 items-center justify-center rounded-md">
							<FingerprintIcon className="size-6" />
						</div>
					)}
					<h1 className="text-xl font-bold">{title}</h1>
					{description && <FieldDescription>{description}</FieldDescription>}
				</div>
				{children}
			</FieldGroup>
			{footer}
		</div>
	);
}
