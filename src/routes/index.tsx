import { createFileRoute } from "@tanstack/react-router";
import { Logo, LogoMark } from "@/components/Logo";
import { SkillScanner } from "@/components/scanner/SkillScanner";
import { LAYER_LABEL, RULES, type Layer } from "@/lib/scanner/rules";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Paragraph — Malicious Claude Skill Detection for Enterprises" },
      {
        name: "description",
        content:
          "Paragraph scans Claude skills for prompt injection, exfiltration, and supply-chain risk across four analysis layers, and returns an auditable verdict before the skill ships.",
      },
      { property: "og:title", content: "Paragraph — Skill Forensics" },
      {
        property: "og:description",
        content:
          "Static, behavioral, provenance and network analysis of Claude skills. Auditable verdicts, exportable reports, nothing leaves the browser.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Index,
});

const LAYER_ORDER: Layer[] = ["static", "behavioral", "provenance", "network"];

const LAYER_BLURB: Record<Layer, string> = {
  static:
    "Line-level instruction parse: override language, concealment, hidden comments, invisible Unicode, encoded payloads.",
  behavioral:
    "Capability reasoning over the commands a skill can trigger — secret reads, remote execution, persistence, destructive operations.",
  provenance:
    "Supply-chain posture: unpinned or off-registry dependencies, embedded credentials, unreviewable binaries, missing attribution.",
  network:
    "Every outbound host is inventoried and matched against exfiltration, tunnelling, beacon, and transport-security rules.",
};

function Index() {
  const ruleCount = RULES.length;
  const byLayer = (layer: Layer) => RULES.filter((r) => r.layer === layer).length;

  return (
    <div className="min-h-screen bg-skyfield font-body text-ink antialiased">
      <header className="sticky top-0 z-40 border-b border-line/70 bg-skyfield/90 backdrop-blur">
        <div className="mx-auto flex max-w-[1440px] items-center justify-between px-6 py-3.5">
          <Logo />
          <nav className="hidden items-center gap-7 font-mono text-[12px] uppercase tracking-[0.12em] text-ink2 md:flex">
            <a href="#threat-model" className="transition-colors hover:text-signal">
              Threat model
            </a>
            <a href="#detection" className="transition-colors hover:text-signal">
              Detection
            </a>
            <a href="#scan" className="transition-colors hover:text-signal">
              Scanner
            </a>
          </nav>
          <a href="#scan" className="btn-signal px-4 py-2 text-[13px]">
            Open the scanner
          </a>
        </div>
      </header>

      <main>
        {/* HERO */}
        <section className="mx-auto grid max-w-[1440px] grid-cols-12 gap-8 px-6 py-14 lg:py-20">
          <div className="col-span-12 animate-rise lg:col-span-5">
            <p className="eyebrow">(a) — the bench</p>
            <h1 className="mt-5 max-w-[16ch] text-balance font-display text-5xl font-bold leading-[1.02] tracking-tight">
              Skills are code. We read them like evidence.
            </h1>
            <p className="mt-5 max-w-[46ch] text-pretty text-[17px] leading-relaxed text-ink2">
              Before a Claude skill ships to your team, it sits under the lamp. Paragraph traces every
              instruction, tool call, and hidden payload to a named rule — then hands you a verdict you
              can defend to a board.
            </p>
            <div className="mt-8 flex items-center gap-3">
              <a href="#scan" className="btn-ink px-5 py-3 text-[14px]">
                Start a scan
              </a>
              <a href="#detection" className="btn-quiet px-5 py-3 text-[14px]">
                How it works
              </a>
            </div>
            <dl className="mt-10 grid grid-cols-3 gap-4 border-t border-line pt-6">
              <div>
                <dt className="label-mono">Rules</dt>
                <dd className="mt-1 font-display text-2xl font-semibold">{ruleCount}</dd>
              </div>
              <div>
                <dt className="label-mono">Layers</dt>
                <dd className="mt-1 font-display text-2xl font-semibold">{LAYER_ORDER.length}</dd>
              </div>
              <div>
                <dt className="label-mono">Upload</dt>
                <dd className="mt-1 font-display text-2xl font-semibold">None</dd>
              </div>
            </dl>
          </div>

          <div className="col-span-12 animate-rise [animation-delay:120ms] lg:col-span-7">
            <div className="relative overflow-hidden rounded-[12px] bg-paper ring-1 ring-black/5">
              <div className="flex items-center justify-between border-b border-line px-4 py-2.5">
                <div className="flex items-center gap-2">
                  <span className="size-2 rounded-full bg-safe" />
                  <span className="font-mono text-[12px] text-ink2">paragraph · engine</span>
                </div>
                <span className="font-mono text-[11px] uppercase tracking-[0.1em] text-muted">
                  ready
                </span>
              </div>
              <div className="relative overflow-hidden">
                <div className="pointer-events-none absolute inset-x-0 h-[2px] animate-scanline bg-signal/60" />
                <div className="space-y-1 px-4 py-5 font-mono text-[12px]">
                  {LAYER_ORDER.map((layer, i) => (
                    <div
                      key={layer}
                      className="flex animate-rise"
                      style={{ animationDelay: `${i * 120}ms` }}
                    >
                      <span className="w-5 text-safe">✓</span>
                      <span className="text-muted">{layer}</span>
                      <span className="flex-1 border-b border-dotted border-line/70" />
                      <span className="text-ink2">{byLayer(layer)} rules loaded</span>
                    </div>
                  ))}
                  <div className="flex animate-rise pt-3 [animation-delay:520ms]">
                    <span className="w-5 text-muted">·</span>
                    <span className="text-muted">scoring</span>
                    <span className="flex-1 border-b border-dotted border-line/70" />
                    <span className="text-ink2">severity-weighted, capped 100</span>
                  </div>
                  <div className="flex animate-rise [animation-delay:620ms]">
                    <span className="w-5 text-muted">·</span>
                    <span className="text-muted">evidence</span>
                    <span className="flex-1 border-b border-dotted border-line/70" />
                    <span className="text-ink2">file · line · matched text</span>
                  </div>
                  <div className="flex animate-rise [animation-delay:720ms]">
                    <span className="w-5 text-muted">·</span>
                    <span className="text-muted">export</span>
                    <span className="flex-1 border-b border-dotted border-line/70" />
                    <span className="text-ink2">markdown · json</span>
                  </div>
                </div>
              </div>
              <div className="flex items-center justify-between border-t border-line bg-skyfield/70 px-4 py-3">
                <span className="font-mono text-[11px] uppercase tracking-[0.12em] text-muted">
                  local engine
                </span>
                <span className="flex items-center gap-2 font-mono text-[12px] text-ink2">
                  <span className="size-1.5 animate-pulse rounded-full bg-signal" />
                  awaiting an artifact…
                </span>
              </div>
            </div>
          </div>
        </section>

        {/* THREAT MODEL + DETECTION */}
        <section id="threat-model" className="border-t border-line/70 bg-paper">
          <div className="mx-auto grid max-w-[1440px] grid-cols-12 gap-10 px-6 py-16">
            <div className="col-span-12 lg:col-span-6">
              <p className="eyebrow">(b) — threat model</p>
              <h2 className="mt-4 max-w-[18ch] text-balance font-display text-3xl font-semibold tracking-tight">
                A skill is a small program that borrows your agent's hands.
              </h2>
              <p className="mt-4 max-w-[52ch] text-pretty text-[15px] leading-relaxed text-ink2">
                The surface is the markdown instruction file, the declared tool scope, and any scripts it
                can invoke. A malicious skill does not need to be a virus — it just needs the agent to
                follow an instruction it was told to trust. Paragraph models each of those vectors
                separately, so a finding always names the exact mechanism it exploited, the file and line
                it lives on, and the fix.
              </p>
            </div>
            <div id="detection" className="col-span-12 lg:col-span-6">
              <p className="eyebrow">(c) — detection, four layers</p>
              <ol className="mt-5 space-y-4">
                {LAYER_ORDER.map((layer, i) => (
                  <li
                    key={layer}
                    className="flex gap-4 rounded-[10px] border border-line bg-skyfield/50 p-4 transition-colors hover:bg-skyfield"
                  >
                    <span className="font-mono text-[12px] font-semibold text-signal">
                      {String(i + 1).padStart(2, "0")}
                    </span>
                    <div>
                      <p className="font-display text-[15px] font-semibold">
                        {LAYER_LABEL[layer]}
                        <span className="ml-2 font-mono text-[11px] font-normal text-muted">
                          {byLayer(layer)} rules
                        </span>
                      </p>
                      <p className="mt-1 text-[13px] text-muted">{LAYER_BLURB[layer]}</p>
                    </div>
                  </li>
                ))}
              </ol>
            </div>
          </div>
        </section>

        {/* SCANNER */}
        <section id="scan" className="border-t border-line/70">
          <div className="mx-auto max-w-[1440px] px-6 py-14">
            <div className="flex items-end justify-between">
              <div>
                <p className="eyebrow">(d) — the scanner</p>
                <h2 className="mt-3 font-display text-2xl font-semibold tracking-tight">
                  Place a skill on the bench.
                </h2>
              </div>
              <span className="hidden font-mono text-[11px] uppercase tracking-[0.12em] text-muted sm:block">
                drop zone · awaiting artifact
              </span>
            </div>
            <SkillScanner />
          </div>
        </section>

        {/* CTA */}
        <section className="border-t border-line/70 bg-ink text-skyfield">
          <div className="mx-auto flex max-w-[1440px] flex-col items-start justify-between gap-6 px-6 py-14 md:flex-row md:items-center">
            <div>
              <p className="eyebrow">(e) — ship it</p>
              <h2 className="mt-3 max-w-[22ch] text-balance font-display text-3xl font-semibold tracking-tight">
                Every skill, under the lamp. Before it runs.
              </h2>
            </div>
            <a href="#scan" className="btn-signal px-6 py-3.5 text-[15px]">
              Scan your first skill
            </a>
          </div>
        </section>
      </main>

      <footer className="bg-ink">
        <div className="mx-auto flex max-w-[1440px] flex-col items-center justify-between gap-3 border-t border-skyfield/10 px-6 py-6 text-skyfield/50 md:flex-row">
          <div className="flex items-center gap-2.5">
            <LogoMark className="size-6" />
            <span className="font-display text-[14px] font-semibold text-skyfield">PARAGRAPH</span>
          </div>
          <p className="font-mono text-[11px] uppercase tracking-[0.12em]">
            skill forensics · {ruleCount} rules · analysis runs locally
          </p>
        </div>
      </footer>
    </div>
  );
}
