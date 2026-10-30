import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { AuthLayout } from "@/components/auth-layout";
import { SignInForm } from "@/components/sign-in-form";

export const Route = createFileRoute("/login")({
	validateSearch: (search: Record<string, unknown>): { redirect?: string } =>
		typeof search.redirect === "string" && search.redirect.startsWith("/") ? { redirect: search.redirect } : {},
	component: Login,
});

function Login() {
	const { redirect } = Route.useSearch();
	const navigate = useNavigate();
	return (
		<AuthLayout>
			<SignInForm onDone={() => navigate({ to: redirect ?? "/account" })} />
		</AuthLayout>
	);
}
