import { createFileRoute, useNavigate } from "@tanstack/react-router";
import { useEffect } from "react";
import { supabase } from "@/integrations/supabase/client";

export const Route = createFileRoute("/auth/callback")({
  head: () => ({
    meta: [
      { title: "Signing in — Lume" },
      { name: "description", content: "Completing secure sign-in to Lume." },
      { property: "og:title", content: "Signing in — Lume" },
      { property: "og:description", content: "Completing secure sign-in." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: AuthCallback,
});

function AuthCallback() {
  const navigate = useNavigate();
  useEffect(() => {
    void supabase.auth.getSession().then(({ data }) => {
      void navigate({ to: data.session ? "/dashboard" : "/login", replace: true });
    });
  }, [navigate]);
  return (
    <main className="flex min-h-screen items-center justify-center bg-background text-sm text-muted-foreground">
      Securing your workspace…
    </main>
  );
}
