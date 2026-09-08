import { createFileRoute, Link } from "@tanstack/react-router";
import { AuthPanel } from "@/components/auth/AuthPanel";
import { Logo } from "@/components/Logo";

export const Route = createFileRoute("/login")({
  head: () => ({ meta: [
    { title: "Sign in — Aperture" },
    { name: "description", content: "Sign in to your Aperture company security workspace." },
    { property: "og:title", content: "Sign in — Aperture" },
    { property: "og:description", content: "Access your Claude skill security workspace." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary" },
  ] }),
  component: LoginPage,
});

function LoginPage() {
  return (
    <main className="flex min-h-screen flex-col bg-background px-6">
      <header className="mx-auto flex h-16 w-full max-w-6xl items-center"><Link to="/" aria-label="Aperture home"><Logo /></Link></header>
      <div className="mx-auto flex w-full max-w-6xl flex-1 items-center justify-center py-16"><AuthPanel /></div>
    </main>
  );
}