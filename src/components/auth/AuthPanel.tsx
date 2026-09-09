import { useState, type FormEvent } from "react";
import { useNavigate } from "@tanstack/react-router";
import { Chrome, LoaderCircle } from "lucide-react";
import { lovable } from "@/integrations/lovable/index";
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
    if (mode === "signup" && !result.data.session) return setMessage("Check your email to confirm your account.");
    await navigate({ to: "/dashboard" });
  };

  const google = async () => {
    setBusy(true);
    setMessage(null);
    const result = await lovable.auth.signInWithOAuth("google", { redirect_uri: `${window.location.origin}/auth/callback` });
    if (result.error) {
      setBusy(false);
      setMessage(result.error.message);
      return;
    }
    if (!result.redirected) await navigate({ to: "/dashboard" });
  };

  return (
    <div className="w-full max-w-[420px]">
      <p className="text-sm font-medium text-primary">Secure workspace</p>
      <h1 className="mt-3 font-display text-4xl font-semibold">{mode === "signin" ? "Welcome back." : "Create your workspace."}</h1>
      <p className="mt-3 text-muted-foreground">Sign in to save scans, set risk policy, and track every skill over time.</p>
      <Button variant="outline" className="mt-8 h-11 w-full rounded-full" onClick={() => void google()} disabled={busy}>
        <Chrome /> Continue with Google
      </Button>
      <div className="my-6 flex items-center gap-3 text-xs text-muted-foreground"><span className="h-px flex-1 bg-border" />or<span className="h-px flex-1 bg-border" /></div>
      <form onSubmit={(event) => void submit(event)} className="space-y-4">
        <label className="block text-sm"><span className="mb-2 block text-muted-foreground">Email</span><Input type="email" autoComplete="email" required value={email} onChange={(event) => setEmail(event.target.value)} className="h-11 bg-card" /></label>
        <label className="block text-sm"><span className="mb-2 block text-muted-foreground">Password</span><Input type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} minLength={8} required value={password} onChange={(event) => setPassword(event.target.value)} className="h-11 bg-card" /></label>
        {message && <p className="rounded-md border border-border bg-card px-3 py-2 text-sm text-muted-foreground">{message}</p>}
        <Button className="h-11 w-full rounded-full" disabled={busy}>{busy && <LoaderCircle className="animate-spin" />}{mode === "signin" ? "Sign in" : "Create account"}</Button>
      </form>
      <Button variant="link" className="mt-4 w-full text-muted-foreground" onClick={() => { setMode(mode === "signin" ? "signup" : "signin"); setMessage(null); }}>
        {mode === "signin" ? "New to Lume? Create an account" : "Already have an account? Sign in"}
      </Button>
    </div>
  );
}