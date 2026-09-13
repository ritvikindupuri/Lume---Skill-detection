import { useState, type FormEvent } from "react";
import { useNavigate } from "@tanstack/react-router";
import { LoaderCircle } from "lucide-react";
import { supabase } from "@/integrations/supabase/client";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

export function AuthPanel() {
  const navigate = useNavigate();
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setMessage(null);
    const result = mode === "signin"
      ? await supabase.auth.signInWithPassword({ email, password })
      : await supabase.auth.signUp({ email, password, options: { emailRedirectTo: `${window.location.origin}/dashboard` } });
    setBusy(false);
    if (result.error) return setMessage(result.error.message);
    if (mode === "signup" && !result.data.session) return setMessage("Account created. Please check your email to confirm your account.");
    await navigate({ to: "/dashboard" });
  };

  return (
    <div className="w-full max-w-[420px]">
      <h1 className="font-display text-4xl font-semibold">
        {mode === "signin" ? "Welcome back." : "Create your workspace."}
      </h1>
      <p className="mt-3 text-muted-foreground">
        {mode === "signin"
          ? "Sign in with your email and password to access your security workspace."
          : "Sign up to save scans, configure risk policies, and track skill threat metrics."}
      </p>

      <form onSubmit={(event) => void submit(event)} className="mt-8 space-y-4">
        <label className="block text-sm">
          <span className="mb-2 block text-muted-foreground">Email address</span>
          <Input
            type="email"
            autoComplete="email"
            required
            placeholder="analyst@company.com"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            className="h-11 bg-card"
          />
        </label>
        <label className="block text-sm">
          <span className="mb-2 block text-muted-foreground">Password</span>
          <Input
            type="password"
            autoComplete={mode === "signin" ? "current-password" : "new-password"}
            minLength={8}
            required
            placeholder="••••••••"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            className="h-11 bg-card"
          />
        </label>
        {message && (
          <p className="rounded-md border border-border bg-card px-3 py-2 text-sm text-muted-foreground">
            {message}
          </p>
        )}
        <Button className="h-11 w-full rounded-full" disabled={busy}>
          {busy && <LoaderCircle className="mr-2 animate-spin" />}
          {mode === "signin" ? "Sign in" : "Create account"}
        </Button>
      </form>

      <Button
        variant="link"
        className="mt-4 w-full text-muted-foreground"
        onClick={() => {
          setMode(mode === "signin" ? "signup" : "signin");
          setMessage(null);
        }}
      >
        {mode === "signin" ? "New to Lume? Create an account" : "Already have an account? Sign in"}
      </Button>
    </div>
  );
}