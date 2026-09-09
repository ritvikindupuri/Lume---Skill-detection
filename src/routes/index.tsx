import { createFileRoute, Link } from "@tanstack/react-router";
import { BrainCircuit, FileScan, Network, Sparkles } from "lucide-react";
import { Logo } from "@/components/Logo";
import { SkillScanner } from "@/components/scanner/SkillScanner";
import { Button } from "@/components/ui/button";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Lume — Claude Skill Security" },
      { name: "description", content: "Scan Claude skills with 35 security controls and the strongest GPT analysis for hidden intent, unsafe behavior, and data leakage." },
      { property: "og:title", content: "Lume — Claude Skill Security" },
      { property: "og:description", content: "See the risk before it runs." },
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
        <section className="relative flex min-h-[94vh] flex-col items-center justify-center px-5 pb-20 pt-28 text-center">
          <div className="animate-reveal">
            <LogoMark className="mx-auto size-20 sm:size-24" />
            <p className="mt-6 font-display text-2xl font-semibold">Lume</p>
            <h1 className="mx-auto mt-8 max-w-4xl text-balance font-display text-5xl font-semibold leading-[1.02] sm:text-7xl lg:text-[88px]">
              See the risk.
            </h1>
            <p className="mx-auto mt-5 max-w-lg text-pretty text-base leading-relaxed text-muted-foreground sm:text-lg">
              Deep inspection for Claude skills.
            </p>
            <div className="mt-8 flex items-center justify-center gap-3">
              <Button asChild size="lg" className="h-12 rounded-2xl px-7 text-[15px] shadow-lg">
                <a href="#scanner">Scan a skill</a>
              </Button>
              <Button asChild variant="outline" size="lg" className="h-12 rounded-2xl px-6 text-[15px]">
                <Link to="/dashboard">For companies</Link>
              </Button>
            </div>
          </div>

          <div className="mt-16 grid w-full max-w-2xl animate-reveal grid-cols-3 gap-3 [animation-delay:180ms]">
            <div className="flex min-h-28 flex-col items-center justify-center rounded-2xl border border-border bg-card shadow-sm">
              <FileScan className="size-6 text-primary" strokeWidth={1.6} />
              <span className="mt-3 text-xs font-medium">Instructions</span>
            </div>
            <div className="flex min-h-28 flex-col items-center justify-center rounded-2xl border border-border bg-card shadow-sm">
              <BrainCircuit className="size-6 text-prism-violet" strokeWidth={1.6} />
              <span className="mt-3 text-xs font-medium">Intent</span>
            </div>
            <div className="flex min-h-28 flex-col items-center justify-center rounded-2xl border border-border bg-card shadow-sm">
              <Network className="size-6 text-prism-pink" strokeWidth={1.6} />
              <span className="mt-3 text-xs font-medium">Connections</span>
            </div>
          </div>
        </section>

        <section className="border-y border-border bg-card px-5 py-20 text-center">
          <Sparkles className="mx-auto size-7 text-primary" strokeWidth={1.5} />
          <p className="mx-auto mt-5 max-w-3xl text-balance font-display text-3xl font-medium sm:text-5xl">Local rules. Deep AI review. Clear evidence.</p>
        </section>

        <section id="scanner" className="scroll-mt-14 px-4 py-24 sm:px-6 sm:py-32">
          <div className="mx-auto max-w-6xl">
            <div className="mb-12 text-center">
              <FileScan className="mx-auto size-7 text-primary" />
              <h2 className="mt-4 font-display text-4xl font-semibold sm:text-6xl">Inspect a skill.</h2>
            </div>
            <SkillScanner />
          </div>
        </section>
      </main>

      <footer className="border-t border-border px-5 py-8">
        <div className="mx-auto flex max-w-6xl items-center justify-between text-sm text-muted-foreground">
          <Logo />
           <span>Claude skill security.</span>
        </div>
      </footer>
    </div>
  );
}