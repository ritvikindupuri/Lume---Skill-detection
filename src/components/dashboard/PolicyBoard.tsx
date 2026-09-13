import { useMemo } from "react";
import { LoaderCircle, Settings2, SlidersHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Slider } from "@/components/ui/slider";
import { Switch } from "@/components/ui/switch";
import { PolicyHint } from "./PolicyHint";
import { computeScore, type RiskConfig } from "@/lib/scanner/engine";
import type { Severity } from "@/lib/scanner/rules";

export interface PolicyScan {
  id: string;
  artifact_name: string;
  declared_name: string | null;
  score: number;
  verdict: string;
  severity_counts: unknown;
  scanned_at: string;
}

const verdictClass: Record<string, string> = {
  clean: "text-safe",
  suspicious: "text-medium",
  malicious: "text-critical",
};

function toCounts(value: unknown): Record<Severity, number> {
  const raw = (value ?? {}) as Partial<Record<Severity, number>>;
  return {
    critical: Number(raw.critical ?? 0),
    high: Number(raw.high ?? 0),
    medium: Number(raw.medium ?? 0),
    low: Number(raw.low ?? 0),
  };
}

interface Props {
  policy: RiskConfig;
  onChange: (next: RiskConfig) => void;
  scans: PolicyScan[];
  canSave: boolean;
  saving: boolean;
  onSave: () => void;
}

export function PolicyControls({ policy, onChange }: Pick<Props, "policy" | "onChange">) {
  return (
    <>
      <div>
        <div className="flex justify-between text-sm">
          <span className="flex items-center gap-1.5">
            Review threshold{" "}
            <PolicyHint label="What to set the review threshold to" title="Review threshold">
              <p>
                Above this raw score a skill stops being “clean” and is marked suspicious for a
                human to review.
              </p>
              <p>
                <span className="text-foreground">Recommended 15–20.</span> 18 is the default and
                flags roughly anything with one high-severity match or a cluster of medium ones.
              </p>
              <p>
                Lower it (8–14) if you deploy skills widely or handle regulated data — you will
                review more skills. Raise it (25–35) only for trusted internal authors, since more
                real issues will pass as clean.
              </p>
            </PolicyHint>
          </span>
          <span className="font-mono text-medium">{policy.acceptableScore}</span>
        </div>
        <Slider
          className="mt-4"
          min={0}
          max={98}
          step={1}
          value={[policy.acceptableScore]}
          onValueChange={([value]) =>
            onChange({
              ...policy,
              acceptableScore: Math.min(value ?? policy.acceptableScore, policy.maliciousScore - 1),
            })
          }
        />
      </div>
      <div className="mt-8">
        <div className="flex justify-between text-sm">
          <span className="flex items-center gap-1.5">
            Block threshold{" "}
            <PolicyHint label="What to set the block threshold to" title="Block threshold">
              <p>
                At or above this raw score the verdict becomes malicious — the skill is not fit to
                deploy.
              </p>
              <p>
                <span className="text-foreground">Recommended 50–60.</span> 55 is the default and
                needs either a critical match or several serious ones together.
              </p>
              <p>
                Keep at least 25 points between the two thresholds so there is a real review band.
                Setting it below 40 will block skills on heuristics alone; above 70 almost nothing
                blocks automatically.
              </p>
            </PolicyHint>
          </span>
          <span className="font-mono text-critical">{policy.maliciousScore}</span>
        </div>
        <Slider
          className="mt-4"
          min={1}
          max={100}
          step={1}
          value={[policy.maliciousScore]}
          onValueChange={([value]) =>
            onChange({
              ...policy,
              maliciousScore: Math.max(value ?? policy.maliciousScore, policy.acceptableScore + 1),
            })
          }
        />
      </div>
      <div className="mt-8 flex items-center justify-between gap-4">
        <div>
          <p className="flex items-center gap-1.5 text-sm">
            Block critical findings{" "}
            <PolicyHint
              label="Whether to block on critical findings"
              title="Block critical findings"
            >
              <p>
                When on, a single critical match makes the verdict malicious no matter how low the
                score is.
              </p>
              <p>
                <span className="text-foreground">Recommended on.</span> Critical checks cover
                credential theft, exfiltration and remote code execution, which are never acceptable
                in one-off form.
              </p>
              <p>
                Turn it off only if your team triages every scan by hand and prefers score-based
                judgement — a lone critical match will then be scored, not blocked.
              </p>
            </PolicyHint>
          </p>
          <p className="mt-1 text-xs leading-relaxed text-muted-foreground">
            A critical match is malicious regardless of score.
          </p>
        </div>
        <Switch
          checked={policy.blockOnCritical}
          onCheckedChange={(checked) => onChange({ ...policy, blockOnCritical: checked })}
        />
      </div>
    </>
  );
}

export function PolicyBoard({ policy, onChange, scans, canSave, saving, onSave }: Props) {
  const preview = useMemo(
    () =>
      scans.slice(0, 25).map((scan) => {
        const result = computeScore(toCounts(scan.severity_counts), policy);
        return { scan, next: result };
      }),
    [scans, policy],
  );

  const distribution = useMemo(() => {
    const totals = { clean: 0, suspicious: 0, malicious: 0 } as Record<string, number>;
    for (const row of preview) totals[row.next.verdict] = (totals[row.next.verdict] ?? 0) + 1;
    return totals;
  }, [preview]);

  const changed = preview.filter((row) => row.next.verdict !== row.scan.verdict).length;

  return (
    <div className="grid gap-8 lg:grid-cols-[380px_1fr]">
      <aside className="h-fit rounded-xl border border-border bg-card p-6">
        <div className="flex items-center gap-3">
          <Settings2 className="text-primary" />
          <div>
            <p className="font-medium">Risk policy</p>
            <p className="text-xs text-muted-foreground">
              Move a slider to see the effect instantly.
            </p>
          </div>
        </div>
        <div className="mt-8">
          <PolicyControls policy={policy} onChange={onChange} />
        </div>
        <Button className="mt-8 w-full rounded-full" disabled={saving || !canSave} onClick={onSave}>
          {saving && <LoaderCircle className="animate-spin" />}Save policy
        </Button>
        {!canSave && (
          <p className="mt-3 text-center text-xs text-muted-foreground">
            Only workspace administrators can change policy.
          </p>
        )}
      </aside>

      <div className="space-y-8">
        <section className="grid gap-px overflow-hidden rounded-xl border border-border bg-border sm:grid-cols-3">
          {[
            { label: "Review threshold", value: policy.acceptableScore, tone: "text-medium" },
            { label: "Block threshold", value: policy.maliciousScore, tone: "text-critical" },
            {
              label: "Review band",
              value: `${Math.max(policy.maliciousScore - policy.acceptableScore, 0)} pts`,
              tone: "text-foreground",
            },
          ].map((metric) => (
            <div key={metric.label} className="bg-card p-6">
              <p className="label-mono">{metric.label}</p>
              <p className={`mt-3 font-display text-4xl font-medium ${metric.tone}`}>
                {metric.value}
              </p>
            </div>
          ))}
        </section>

        <section className="overflow-hidden rounded-xl border border-border bg-card">
          <div className="flex items-start justify-between gap-4 border-b border-border px-6 py-5">
            <div>
              <p className="label-mono">Live impact</p>
              <h2 className="mt-2 font-display text-xl font-medium">
                Your scans under these thresholds
              </h2>
              <p className="mt-1 text-sm text-muted-foreground">
                {scans.length === 0
                  ? "Scan a skill to see how the policy would classify it."
                  : `${distribution["clean"] ?? 0} clean · ${distribution["suspicious"] ?? 0} to review · ${distribution["malicious"] ?? 0} blocked${changed ? ` · ${changed} would change` : ""}`}
              </p>
            </div>
            <SlidersHorizontal className="text-muted-foreground" />
          </div>
          {preview.length > 0 && (
            <div className="divide-y divide-border">
              {preview.map(({ scan, next }) => (
                <div
                  key={scan.id}
                  className="grid grid-cols-[1fr_auto] items-center gap-4 px-6 py-4 sm:grid-cols-[1fr_130px_90px]"
                >
                  <div className="min-w-0">
                    <p className="truncate font-medium">
                      {scan.declared_name ?? scan.artifact_name}
                    </p>
                    <p className="mt-1 text-xs text-muted-foreground">
                      {new Date(scan.scanned_at).toLocaleDateString()} · saved as {scan.verdict}
                      {next.verdict !== scan.verdict && (
                        <span className="ml-2 rounded-full bg-secondary px-2 py-0.5 font-medium text-foreground">
                          would change
                        </span>
                      )}
                    </p>
                  </div>
                  <span
                    className={`self-center text-right text-sm font-medium capitalize ${verdictClass[next.verdict] ?? ""}`}
                  >
                    {next.verdict}
                  </span>
                  <span className="hidden self-center text-right font-mono text-lg sm:block">
                    {next.score}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  );
}
