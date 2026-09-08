import { createFileRoute, Link } from "@tanstack/react-router";
import { ArrowDown, LockKeyhole } from "lucide-react";
import { Logo } from "@/components/Logo";
import { SkillScanner } from "@/components/scanner/SkillScanner";
import { Button } from "@/components/ui/button";
import { RULES } from "@/lib/scanner/rules";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Attest — Claude Skill Security" },
      { name: "description", content: "Scan Claude skills for hidden instructions, unsafe behavior, dependency risk, and data exfiltration before they run." },
      { property: "og:title", content: "Attest — Claude Skill Security" },
      { property: "og:description", content: "Know what a Claude skill will do before you trust it." },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

function Index() {
  return (
    <div className="min-h-screen overflow-hidden bg-background font-body text-foreground">
      <header className="fixed inset-x-0 top-0 z-50 border-b border-border bg-background/75 backdrop-blur-2xl">
        <div className="mx-auto flex h-14 max-w-6xl items-center justify-between px-5 sm:px-8">
          <Logo />
          <div className="flex items-center gap-2">
            <Button asChild variant="ghost" size="sm" className="rounded-full px-4"><Link to="/login">Sign in</Link></Button>
            <Button asChild size="sm" className="rounded-full px-4 shadow-none"><Link to="/dashboard">Company dashboard</Link></Button>
          </div>
        </div>
      </header>

      <main>
        <section className="relative flex min-h-[92vh] flex-col items-center justify-center px-5 pb-24 pt-32 text-center">
          <div className="pointer-events-none absolute left-1/2 top-[42%] h-[560px] w-[900px] -translate-x-1/2 -translate-y-1/2 rounded-full bg-primary/8 blur-[120px]" />
          <div className="relative animate-reveal">
            <p className="mb-6 text-[15px] font-medium text-primary">Security for Claude skills</p>
            <h1 className="text-gradient mx-auto max-w-5xl text-balance font-display text-6xl font-semibold leading-[0.98] sm:text-7xl lg:text-[96px]">
              Know before it runs.
            </h1>
            <p className="mx-auto mt-7 max-w-2xl text-pretty text-lg leading-relaxed text-muted-foreground sm:text-xl">
              Attest finds hidden instructions, dangerous behavior, and data exposure in any Claude skill. Privately, in your browser.
            </p>
            <div className="mt-9 flex items-center justify-center gap-3">
              <Button asChild size="lg" className="h-12 rounded-full px-7 text-[15px] shadow-[0_10px_35px_color-mix(in_oklab,var(--color-primary)_25%,transparent)]">
                <a href="#scanner">Scan a skill</a>
              </Button>
              <Button asChild variant="ghost" size="lg" className="h-12 rounded-full px-6 text-[15px] text-muted-foreground hover:text-foreground">
                <a href="#scanner">See how it works <ArrowDown /></a>
              </Button>
            </div>
          </div>

          <div className="relative mt-20 flex w-full max-w-4xl animate-reveal justify-center [animation-delay:180ms]">
            <div className="absolute inset-x-[12%] bottom-0 h-20 bg-primary/20 blur-[70px]" />
            <div className="glass-panel relative w-full overflow-hidden rounded-[28px] p-2 shadow-2xl sm:p-3">
              <div className="flex min-h-[290px] flex-col items-center justify-center rounded-[21px] bg-secondary/65 px-6">
                <div className="relative flex size-32 animate-float items-center justify-center rounded-full border border-border bg-card shadow-[0_24px_60px_color-mix(in_oklab,var(--color-background)_70%,transparent)]">
                  <div className="absolute inset-3 rounded-full border border-primary/25" />
                  <LockKeyhole className="size-8 text-primary" strokeWidth={1.5} />
                </div>
                <p className="mt-8 font-display text-xl font-medium">Ready to inspect</p>
                <p className="mt-2 text-sm text-muted-foreground">Drop in a skill. Attest does the rest.</p>
              </div>
            </div>
          </div>
        </section>

        <section className="border-y border-border bg-card/35 px-5 py-24 text-center sm:py-32">
          <p className="mx-auto max-w-4xl text-balance font-display text-4xl font-medium leading-tight sm:text-6xl">
            Every instruction. Every connection. Every dependency.
          </p>
          <div className="mx-auto mt-12 flex max-w-2xl flex-wrap items-center justify-center gap-x-8 gap-y-3 text-sm text-muted-foreground">
            <span>{RULES.length} security checks</span><span className="text-border">•</span><span>Four analysis layers</span><span className="text-border">•</span><span>Zero uploads</span>
          </div>
        </section>

        <section id="scanner" className="scroll-mt-14 px-4 py-24 sm:px-6 sm:py-32">
          <div className="mx-auto max-w-6xl">
            <div className="mb-12 text-center">
              <p className="text-sm font-medium text-primary">Attest Scanner</p>
              <h2 className="mt-3 font-display text-4xl font-semibold sm:text-6xl">See exactly what’s inside.</h2>
              <p className="mx-auto mt-5 max-w-xl text-lg text-muted-foreground">Choose a folder, ZIP, or SKILL.md. Your files never leave this device.</p>
            </div>
            <SkillScanner />
          </div>
        </section>
      </main>

      <footer className="border-t border-border px-5 py-8">
        <div className="mx-auto flex max-w-6xl items-center justify-between text-sm text-muted-foreground">
          <Logo />
          <span>Analysis stays on your device.</span>
        </div>
      </footer>
    </div>
  );
}