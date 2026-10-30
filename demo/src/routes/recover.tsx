import { createFileRoute, Link, useNavigate } from "@tanstack/react-router";
import { toast } from "sonner";
import { AuthLayout } from "@/components/auth-layout";
import { DanceForm } from "@/components/dance-form";
import { FieldDescription } from "@/components/ui/field";
import { client } from "@/lib/auth";

const COMPONENTS: Record<string, string> = { password: "password", passkey: "passkey", email: "email address" };

export const Route = createFileRoute("/recover")({
	validateSearch: (search: Record<string, unknown>): { component: string } => ({
		component: typeof search.component === "string" ? search.component : "password",
	}),
	component: Recover,
});

/**
 * A recovery is a sign-in without the lost component. With `choice(sequence("email", "password", "otp"), "passkey")`,
 * a new password takes the address and its code, or a passkey; a new passkey takes the other branch whole.
 */
function Recover() {
	const { component } = Route.useSearch();
	const navigate = useNavigate();
	return (
		<AuthLayout>
			<DanceForm
				key={component}
				flow="recover"
				name={component}
				title={`Recover your ${COMPONENTS[component] ?? component}`}
				description="Prove who you are another way, then set a new one."
				onDone={async () => {
					toast.success(`Your ${COMPONENTS[component] ?? component} is reset`);
					await navigate({ to: client.tokens ? "/account" : "/login" });
				}}
				footer={
					<FieldDescription className="text-center">
						Remembered it? <Link to="/login">Sign in</Link>
					</FieldDescription>
				}
			/>
		</AuthLayout>
	);
}
