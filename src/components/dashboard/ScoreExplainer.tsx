import { Calculator } from "lucide-react";
import { SEVERITY_WEIGHT } from "@/lib/scanner/rules";
import type { RiskConfig, ScoreStep } from "@/lib/scanner/engine";

interface Props {
  policy: RiskConfig;
  breakdown?: ScoreStep[];
  rawScore?: number;
  score?: number;
  label?: string;
}

export function ScoreExplainer({ policy, breakdown, rawScore, score, label }: Props) {
  return (
    <section className="rounded-xl border border-border bg-card p-6">
      <div className="flex items-center gap-3">
        <Calculator className="text-primary" />
        <div>
          <p className="font-medium">How the score is calculated</p>
          <p className="text-xs text-muted-foreground">
            Same maths every time — no hidden weighting.
          </p>
        </div>
      </div>

      <ol className="mt-6 space-y-4 text-sm">
        <li>
          <p className="font-medium">1. Every match earns points by severity</p>
          <div className="mt-2 flex flex-wrap gap-2 text-xs">
            {(Object.keys(SEVERITY_WEIGHT) as (keyof typeof SEVERITY_WEIGHT)[]).map((severity) => (
              <span
                key={severity}
                className="rounded-full border border-border px-3 py-1 font-mono"
              >
                {severity} = {SEVERITY_WEIGHT[severity]}
              </span>
            ))}
          </div>
        </li>
        <li>
          <p className="font-medium">2. Repeats of the same severity count for less</p>
          <p className="mt-1 text-muted-foreground">
            The second match of a severity is worth 65% of the first, the third about 48%, and so
            on, so one noisy pattern cannot dominate.
          </p>
        </li>
        <li>
          <p className="font-medium">3. The total is capped at 100 — this is the inherent score</p>
        </li>
        <li>
          <p className="font-medium">4. Your thresholds stretch it into the final score</p>
          <p className="mt-1 text-muted-foreground">
            Up to {policy.acceptableScore} inherent maps to 0–17 (pass). Between{" "}
            {policy.acceptableScore} and {policy.maliciousScore} maps to 18–54 (review).{" "}
            {policy.maliciousScore} and above maps to 55–100 (block).
          </p>
        </li>
        <li>
          <p className="font-medium">5. The verdict follows the thresholds</p>
          <p className="mt-1 text-muted-foreground">
            {policy.blockOnCritical
              ? "Any critical match is a block regardless of score."
              : "Critical matches are scored but do not force a block."}
          </p>
        </li>
      </ol>

      {breakdown && (
        <div className="mt-6 rounded-lg border border-border bg-background p-4">
          <p className="label-mono">{label ?? "Latest scan"}</p>
          <div className="mt-3 space-y-1.5 font-mono text-xs">
            {breakdown.map((step) => (
              <div key={step.severity} className="flex justify-between">
                <span className="capitalize text-muted-foreground">
                  {step.count} × {step.severity} @ {step.weight}
                </span>
                <span>+{step.contribution}</span>
              </div>
            ))}
            <div className="flex justify-between border-t border-border pt-1.5">
              <span className="text-muted-foreground">inherent (capped)</span>
              <span>{rawScore}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-muted-foreground">after your thresholds</span>
              <span>{score}/100</span>
            </div>
          </div>
        </div>
      )}
    </section>
  );
}
