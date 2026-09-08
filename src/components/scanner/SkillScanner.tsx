import { useCallback, useMemo, useRef, useState } from "react";
import { ShieldCheck } from "lucide-react";
import { scanArtifact, type Finding, type ScanResult } from "@/lib/scanner/engine";
import { ArtifactError, readArtifact, readPastedSkill } from "@/lib/scanner/load";
import { download, toMarkdown } from "@/lib/scanner/report";
import { LAYER_LABEL, RULES, SEVERITY_ORDER, type Severity } from "@/lib/scanner/rules";

type Phase = "idle" | "working" | "done";

const SEVERITY_STYLES: Record<Severity, { dot: string; text: string; chip: string }> = {
  critical: { dot: "bg-critical", text: "text-critical", chip: "bg-critical/10 text-critical" },
  high: { dot: "bg-high", text: "text-high", chip: "bg-high/10 text-high" },
  medium: { dot: "bg-medium", text: "text-medium", chip: "bg-medium/10 text-medium" },
  low: { dot: "bg-muted", text: "text-muted-foreground", chip: "bg-muted/10 text-muted-foreground" },
};

const VERDICT_COPY = {
  malicious: { label: "Malicious", note: "block this skill" },
  suspicious: { label: "Suspicious", note: "manual review required" },
  clean: { label: "No findings of concern", note: "safe to review and ship" },
} as const;

const STAGES = ["parse", "static", "behavioral", "provenance", "network", "verdict"] as const;

function formatBytes(n: number) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function SkillScanner() {
  const [phase, setPhase] = useState<Phase>("idle");
  const [result, setResult] = useState<ScanResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [dragging, setDragging] = useState(false);
  const [pasteOpen, setPasteOpen] = useState(false);
  const [pasted, setPasted] = useState("");
  const [activeSeverities, setActiveSeverities] = useState<Severity[]>([...SEVERITY_ORDER]);
  const [openFinding, setOpenFinding] = useState<string | null>(null);
  const fileInput = useRef<HTMLInputElement>(null);
  const dirInput = useRef<HTMLInputElement>(null);

  const run = useCallback(
    async (load: () => Promise<{ name: string; files: Awaited<ReturnType<typeof readArtifact>>["files"] }>) => {
      setError(null);
      setPhase("working");
      setResult(null);
      setOpenFinding(null);
      try {
        const artifact = await load();
        const scan = await scanArtifact(artifact.name, artifact.files);
        setResult(scan);
        setPhase("done");
      } catch (e) {
        setError(
          e instanceof ArtifactError
            ? e.message
            : e instanceof Error
              ? `Could not read this artifact: ${e.message}`
              : "Could not read this artifact.",
        );
        setPhase("idle");
      }
    },
    [],
  );

  const onFiles = useCallback(
    (list: FileList | null) => {
      if (!list || list.length === 0) return;
      const files = Array.from(list);
      void run(() => readArtifact(files));
    },
    [run],
  );

  const visibleFindings = useMemo(
    () => (result ? result.findings.filter((f) => activeSeverities.includes(f.severity)) : []),
    [result, activeSeverities],
  );

  const grouped = useMemo(() => {
    const map = new Map<Severity, Finding[]>();
    for (const sev of SEVERITY_ORDER) {
      const items = visibleFindings.filter((f) => f.severity === sev);
      if (items.length) map.set(sev, items);
    }
    return map;
  }, [visibleFindings]);

  const toggleSeverity = (sev: Severity) =>
    setActiveSeverities((prev) =>
      prev.includes(sev) ? prev.filter((s) => s !== sev) : [...prev, sev],
    );

  const reset = () => {
    setResult(null);
    setPhase("idle");
    setError(null);
    setPasted("");
  };

  return (
    <div className="glass-panel mt-6 grid grid-cols-12 gap-4 rounded-[28px] p-3 sm:p-5">
      {/* LEFT: artifact */}
      <div className="col-span-12 lg:col-span-4">
        <div className="rounded-[20px] border border-border bg-card/70 p-4">
          <div className="flex items-center justify-between">
            <p className="label-mono">artifact</p>
            {result && (
              <button onClick={reset} className="font-mono text-[11px] text-primary hover:underline">
                clear
              </button>
            )}
          </div>

          <input
            ref={fileInput}
            type="file"
            multiple
            accept=".md,.txt,.json,.yaml,.yml,.zip,.py,.js,.ts,.sh"
            className="hidden"
            onChange={(e) => onFiles(e.target.files)}
          />
          <input
            ref={dirInput}
            type="file"
            multiple
            className="hidden"
            // @ts-expect-error non-standard directory picker attributes
            webkitdirectory=""
            directory=""
            onChange={(e) => onFiles(e.target.files)}
          />

          <div
            onDragOver={(e) => {
              e.preventDefault();
              setDragging(true);
            }}
            onDragLeave={() => setDragging(false)}
            onDrop={(e) => {
              e.preventDefault();
              setDragging(false);
              onFiles(e.dataTransfer.files);
            }}
            onClick={() => fileInput.current?.click()}
            role="button"
            tabIndex={0}
            onKeyDown={(e) => e.key === "Enter" && fileInput.current?.click()}
            className={`mt-3 flex cursor-pointer flex-col items-center rounded-[16px] border border-dashed py-12 text-center transition-colors ${
              dragging ? "border-primary bg-accent" : "border-border bg-secondary/60 hover:border-primary/50 hover:bg-secondary"
            }`}
          >
            <span className="flex size-11 items-center justify-center rounded-full bg-secondary font-mono text-lg text-foreground">
              +
            </span>
            <p className="mt-3 text-[14px] font-semibold">Drop a skill folder or .md</p>
            <p className="mt-1 font-mono text-[11px] text-muted-foreground">.zip · .md · skill/ · up to 20 MB</p>
          </div>

          <div className="mt-3 flex items-center justify-between font-mono text-[11px] text-muted-foreground">
            <button onClick={() => dirInput.current?.click()} className="hover:text-primary">
              choose folder
            </button>
            <button onClick={() => setPasteOpen((v) => !v)} className="hover:text-primary">
              {pasteOpen ? "hide paste" : "paste SKILL.md"}
            </button>
          </div>

          {pasteOpen && (
            <div className="mt-3">
              <textarea
                value={pasted}
                onChange={(e) => setPasted(e.target.value)}
                rows={7}
                spellCheck={false}
                placeholder="---&#10;name: my-skill&#10;description: ...&#10;---"
                className="w-full rounded-[8px] border border-border bg-secondary/60 p-3 font-mono text-[12px] outline-none focus:border-primary"
              />
              <button
                onClick={() => void run(() => readPastedSkill(pasted))}
                className="btn-ink mt-2 w-full px-4 py-2 text-[13px]"
              >
                Analyze pasted skill
              </button>
            </div>
          )}

          {error && (
            <p className="mt-3 rounded-[8px] bg-critical/10 px-3 py-2 font-mono text-[11px] text-critical">
              {error}
            </p>
          )}

          <p className="mt-4 border-t border-border pt-3 font-mono text-[10px] leading-relaxed text-muted-foreground">
            Analysis runs entirely in this browser. Artifact bytes are never uploaded.
          </p>
        </div>

        {/* file tree */}
        {result && (
          <div className="mt-4 rounded-[12px] border border-border bg-card/70 p-4">
            <p className="label-mono">files · {result.files.length}</p>
            <ul className="mt-3 space-y-1.5">
              {result.files.map((f) => (
                <li key={f.path} className="flex items-center gap-2 font-mono text-[12px]">
                  <span
                    className={`size-1.5 shrink-0 rounded-full ${f.findings ? "bg-high" : "bg-safe"}`}
                  />
                  <span className="truncate text-card-foreground" title={f.path}>
                    {f.path}
                  </span>
                  <span className="ml-auto shrink-0 text-muted-foreground">{formatBytes(f.size)}</span>
                </li>
              ))}
            </ul>
            <div className="mt-4 space-y-1.5 border-t border-border pt-3 font-mono text-[11px] text-muted-foreground">
              <p className="break-all">
                <span className="text-card-foreground">sha-256</span> {result.sha256.slice(0, 32)}…
              </p>
              <p>
                <span className="text-card-foreground">rules</span> {result.rulesEvaluated} evaluated in{" "}
                {result.durationMs} ms
              </p>
              {result.metadata.name && (
                <p>
                  <span className="text-card-foreground">declared</span> {result.metadata.name}
                </p>
              )}
            </div>
          </div>
        )}

        {/* endpoints */}
        {result && result.endpoints.length > 0 && (
          <div className="mt-4 rounded-[12px] border border-border bg-card/70 p-4">
            <p className="label-mono">external endpoints · {result.endpoints.length}</p>
            <ul className="mt-3 space-y-1.5 font-mono text-[12px]">
              {result.endpoints.map((e) => (
                <li key={e.host} className="flex items-center gap-2">
                  <span className="truncate text-card-foreground">{e.host}</span>
                  <span className="ml-auto text-muted-foreground">×{e.occurrences}</span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* RIGHT: verdict + findings */}
      <div className="col-span-12 lg:col-span-8">
        <div className="sticky top-[64px] z-30 flex flex-wrap items-center justify-between gap-3 rounded-[18px] bg-secondary px-4 py-3 text-foreground ring-1 ring-border">
          <div className="flex items-center gap-3">
            <span
              className={`flex size-9 items-center justify-center rounded-[8px] bg-secondary/10 font-mono text-[15px] font-semibold ${
                result ? SEVERITY_STYLES[result.verdict === "clean" ? "low" : result.verdict === "malicious" ? "critical" : "high"].text : ""
              }`}
            >
              {result ? result.score : "—"}
            </span>
            <div>
              <p className="font-display text-[15px] font-semibold">
                {result ? VERDICT_COPY[result.verdict].label : phase === "working" ? "Analyzing…" : "No verdict yet"}
              </p>
              <p className="font-mono text-[11px] text-foreground/50">
                {result
                  ? `${result.artifactName} · ${VERDICT_COPY[result.verdict].note}`
                  : "awaiting artifact · safe / suspicious / malicious"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="rounded-[7px] bg-secondary/10 px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.1em] text-foreground/60">
              score {result ? `${result.score}/100` : "—"}
            </span>
            <button
              disabled={!result}
              onClick={() =>
                result &&
                download(
                  `attest-report-${result.sha256.slice(0, 8)}.md`,
                  toMarkdown(result),
                  "text/markdown",
                )
              }
              className="btn-signal px-3 py-1.5 text-[12px]"
            >
              Export report
            </button>
            <button
              disabled={!result}
              onClick={() =>
                result &&
                download(
                  `attest-report-${result.sha256.slice(0, 8)}.json`,
                  JSON.stringify(result, null, 2),
                  "application/json",
                )
              }
              className="btn-quiet px-3 py-1.5 text-[12px] text-foreground hover:bg-accent"
            >
              JSON
            </button>
          </div>
        </div>

        {/* working */}
        {phase === "working" && (
          <div className="relative mt-4 min-h-[320px] overflow-hidden rounded-[12px] border border-border bg-card">
            <div className="pointer-events-none absolute inset-x-0 h-[2px] animate-scanline bg-primary/60" />
            <div className="space-y-1 px-4 py-4 font-mono text-[12px]">
              {STAGES.map((s, i) => (
                <div key={s} className="flex animate-rise" style={{ animationDelay: `${i * 90}ms` }}>
                  <span className="w-5 text-safe">✓</span>
                  <span className="text-muted-foreground">{s}</span>
                  <span className="flex-1 border-b border-dotted border-border/70" />
                  <span className="text-card-foreground">pass {i + 1}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* empty */}
        {phase !== "working" && !result && (
          <div className="mt-4 flex min-h-[320px] flex-col items-center justify-center rounded-[20px] border border-border bg-card/60 px-6 text-center">
            <span className="flex size-14 items-center justify-center rounded-full border border-border bg-secondary text-primary">
              <ShieldCheck className="size-6" strokeWidth={1.5} />
            </span>
            <p className="mt-4 font-display text-lg font-semibold">Ready when you are</p>
            <p className="mt-1 max-w-[40ch] text-[13px] leading-relaxed text-muted-foreground">
              Findings appear here, grouped by severity, the moment a scan completes. Nothing is shown
              until a real skill is analyzed against all {RULES.length} rules.
            </p>
            <div className="mt-5 flex items-center gap-4 font-mono text-[11px] uppercase tracking-[0.1em] text-muted-foreground">
              <span className="flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-critical" />
                critical
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-high" />
                high
              </span>
              <span className="flex items-center gap-1.5">
                <span className="size-2 rounded-full bg-medium" />
                medium
              </span>
            </div>
          </div>
        )}

        {/* results */}
        {result && (
          <>
            <div className="mt-4 flex flex-wrap items-center gap-2">
              {SEVERITY_ORDER.map((sev) => (
                <button
                  key={sev}
                  onClick={() => toggleSeverity(sev)}
                  className={`flex items-center gap-2 rounded-[7px] border px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.1em] transition-colors ${
                    activeSeverities.includes(sev)
                      ? "border-border bg-card text-card-foreground"
                      : "border-border/60 bg-transparent text-muted-foreground"
                  }`}
                >
                  <span className={`size-2 rounded-full ${SEVERITY_STYLES[sev].dot}`} />
                  {sev}
                  <span className="text-muted-foreground">{result.counts[sev]}</span>
                </button>
              ))}
            </div>

            {result.findings.length === 0 ? (
              <div className="mt-4 flex min-h-[260px] flex-col items-center justify-center rounded-[12px] border border-border bg-card/60 px-6 text-center">
                <span className="flex size-12 items-center justify-center rounded-full bg-safe/10 text-safe">
                  ✓
                </span>
                <p className="mt-4 font-display text-lg font-semibold">No rule matched</p>
                <p className="mt-1 max-w-[44ch] text-[13px] text-muted-foreground">
                  All {result.rulesEvaluated} rules were evaluated against {result.files.length}{" "}
                  file(s) and none matched. A clean scan is not a guarantee — review the instruction
                  text before granting tool scope.
                </p>
              </div>
            ) : (
              <div className="mt-4 space-y-6">
                {[...grouped.entries()].map(([sev, items]) => (
                  <section key={sev}>
                    <p className="label-mono flex items-center gap-2">
                      <span className={`size-2 rounded-full ${SEVERITY_STYLES[sev].dot}`} />
                      {sev} · {items.length}
                    </p>
                    <ul className="mt-2 space-y-2">
                      {items.map((f) => {
                        const open = openFinding === f.key;
                        return (
                          <li
                            key={f.key}
                            className="rounded-[10px] border border-border bg-card transition-colors hover:border-primary/40"
                          >
                            <button
                              onClick={() => setOpenFinding(open ? null : f.key)}
                              className="flex w-full items-start gap-3 px-4 py-3 text-left"
                            >
                              <span
                                className={`mt-0.5 shrink-0 rounded-[5px] px-1.5 py-0.5 font-mono text-[10px] font-semibold ${SEVERITY_STYLES[sev].chip}`}
                              >
                                {f.ruleId}
                              </span>
                              <span className="min-w-0 flex-1">
                                <span className="block font-display text-[14px] font-semibold">
                                  {f.title}
                                </span>
                                <span className="mt-0.5 block truncate font-mono text-[11px] text-muted-foreground">
                                  {LAYER_LABEL[f.layer]} · {f.file}
                                  {f.line ? `:${f.line}` : ""}
                                </span>
                              </span>
                              <span className="shrink-0 font-mono text-[11px] text-muted-foreground">
                                {open ? "−" : "+"}
                              </span>
                            </button>
                            {open && (
                              <div className="border-t border-border px-4 py-3">
                                <pre className="overflow-x-auto rounded-[8px] bg-secondary px-3 py-2 font-mono text-[11px] text-card-foreground">
                                  {f.evidence}
                                </pre>
                                <p className="mt-3 text-[13px] leading-relaxed text-card-foreground">
                                  {f.rationale}
                                </p>
                                <p className="mt-2 text-[13px] leading-relaxed text-muted-foreground">
                                  <span className="font-mono text-[11px] uppercase tracking-[0.12em]">
                                    fix ·{" "}
                                  </span>
                                  {f.remediation}
                                </p>
                              </div>
                            )}
                          </li>
                        );
                      })}
                    </ul>
                  </section>
                ))}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
