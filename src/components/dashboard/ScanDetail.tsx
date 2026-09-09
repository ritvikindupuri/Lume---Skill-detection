import { useEffect, useState } from "react";
import { useServerFn } from "@tanstack/react-start";
import { CheckCircle2, LoaderCircle, ShieldBan, ShieldCheck, X, XCircle } from "lucide-react";
import { Button } from "@/components/ui/button";
import { computeScore, type RiskConfig } from "@/lib/scanner/engine";
import { confidenceLabel, type Severity } from "@/lib/scanner/rules";
import { getScanFindings, reviewFinding } from "@/lib/workspace.functions";

type StoredFinding = Awaited<ReturnType<typeof getScanFindings>>[number];

const severityClass: Record<Severity, string> = {
  critical: "text-critical",
  high: "text-critical",
  medium: "text-medium",
  low: "text-muted-foreground",
};

interface Props {
  scanId: string;
  name: string;
  policy: RiskConfig;
  canReview: boolean;
  containment?: string;
  onClose: () => void;
  onReviewed?: () => void | Promise<void>;
}

type Outcome = { score: number; verdict: string; containment: string };

export function ScanDetail({ scanId, name, policy, canReview, containment, onClose, onReviewed }: Props) {
  const load = useServerFn(getScanFindings);
  const review = useServerFn(reviewFinding);
  const [findings, setFindings] = useState<StoredFinding[] | null>(null);
  const [pending, setPending] = useState<string | null>(null);
  const [outcome, setOutcome] = useState<Outcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setFindings(null);
    setOutcome(null);
    setError(null);
    void load({ data: { scanId } }).then(setFindings).catch(() => setFindings([]));
  }, [scanId]);

  const state = outcome?.containment ?? containment ?? "none";

  const decide = async (finding: StoredFinding, status: "confirmed" | "false_positive" | "open") => {
    setPending(finding.id);
    setError(null);
    try {
      const result = await review({ data: { findingId: finding.id, scanId, status } });
      setFindings((current) => (current ?? []).map((item) => (item.id === finding.id ? { ...item, status } : item)));
      setOutcome(result);
      await onReviewed?.();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not save this decision.");
    } finally {
      setPending(null);
    }
  };

  const active = (findings ?? []).filter((finding) => finding.status !== "false_positive");
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of active) counts[finding.severity as Severity] += 1;
  const adjusted = computeScore(counts, policy);
  const dismissed = (findings ?? []).length - active.length;

  return (
    <section className="rounded-xl border border-border bg-card">
      <div className="flex items-start justify-between gap-4 border-b border-border px-6 py-5">
        <div className="min-w-0">
          <p className="label-mono">Findings</p>
          <h2 className="mt-2 truncate font-display text-xl font-medium">{name}</h2>
          <p className="mt-1 text-sm text-muted-foreground">
            {dismissed > 0
              ? `${dismissed} marked as a false positive · score excluding them: ${adjusted.score}/100 (${adjusted.verdict})`
              : "Mark anything your reviewers judge to be a false positive."}
          </p>
        </div>
        <Button variant="ghost" size="icon" onClick={onClose} title="Close"><X /></Button>
      </div>

      {state === "quarantined" && (
        <div className="flex items-start gap-3 border-b border-border bg-critical/10 px-6 py-4">
          <ShieldBan className="mt-0.5 size-5 shrink-0 text-critical" />
          <div>
            <p className="font-medium text-critical">Skill quarantined</p>
            <p className="mt-1 text-sm text-muted-foreground">
              A reviewer confirmed a real serious risk, so this skill is marked as not safe to deploy
              {outcome ? ` · score ${outcome.score}/100 (${outcome.verdict})` : ""}.
            </p>
          </div>
        </div>
      )}
      {state === "cleared" && (
        <div className="flex items-start gap-3 border-b border-border bg-safe/10 px-6 py-4">
          <ShieldCheck className="mt-0.5 size-5 shrink-0 text-safe" />
          <div>
            <p className="font-medium text-safe">Skill cleared</p>
            <p className="mt-1 text-sm text-muted-foreground">
              Reviewers dismissed the remaining flags, so this skill is recorded as safe to deploy
              {outcome ? ` · score ${outcome.score}/100` : ""}.
            </p>
          </div>
        </div>
      )}
      {error && <p className="border-b border-border px-6 py-3 text-sm text-critical">{error}</p>}


      {findings === null ? (
        <div className="flex min-h-40 items-center justify-center"><LoaderCircle className="size-5 animate-spin text-primary" /></div>
      ) : findings.length === 0 ? (
        <p className="px-6 py-8 text-sm text-muted-foreground">No findings were recorded for this scan.</p>
      ) : (
        <div className="divide-y divide-border">
          {findings.map((finding) => (
            <div key={finding.id} className={`px-6 py-5 ${finding.status === "false_positive" ? "opacity-55" : ""}`}>
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <span className="font-mono text-xs text-muted-foreground">{finding.rule_id}</span>
                <span className="font-medium">{finding.title}</span>
                <span className={`text-xs font-medium ${severityClass[finding.severity as Severity]}`}>{finding.severity}</span>
                <span className="text-xs text-muted-foreground">{finding.confidence}% · {confidenceLabel(finding.confidence)} <ConfidenceHint /></span>
                {finding.status !== "open" && (
                  <span className="rounded-full border border-border px-2 py-0.5 text-xs text-muted-foreground">
                    {finding.status === "confirmed" ? "Confirmed" : "False positive"}
                  </span>
                )}
              </div>
              <p className="mt-2 font-mono text-xs text-muted-foreground">{finding.file_path}:{finding.line_number}</p>
              <p className="mt-2 break-all rounded-md bg-background px-3 py-2 font-mono text-xs">{finding.evidence}</p>
              <p className="mt-2 text-sm text-muted-foreground">{finding.remediation}</p>
              {canReview && (
                <div className="mt-3 flex flex-wrap gap-2">
                  <Button size="sm" variant={finding.status === "confirmed" ? "default" : "outline"} className="rounded-full" disabled={pending === finding.id} onClick={() => void decide(finding, finding.status === "confirmed" ? "open" : "confirmed")}>
                    <CheckCircle2 /> Real risk
                  </Button>
                  <Button size="sm" variant={finding.status === "false_positive" ? "default" : "outline"} className="rounded-full" disabled={pending === finding.id} onClick={() => void decide(finding, finding.status === "false_positive" ? "open" : "false_positive")}>
                    <XCircle /> False positive
                  </Button>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </section>
  );
}
