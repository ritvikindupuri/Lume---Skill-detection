import { useEffect, useRef } from "react";
import { Brain, Check, LoaderCircle } from "lucide-react";

export interface ThinkingStep {
  label: string;
  done: boolean;
}

interface Props {
  artifact: string;
  steps: ThinkingStep[];
  reasoning: string;
  active: boolean;
}

export function ThinkingLog({ artifact, steps, reasoning, active }: Props) {
  const scroller = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const node = scroller.current;
    if (node) node.scrollTop = node.scrollHeight;
  }, [reasoning]);

  return (
    <section className="rounded-xl border border-border bg-card">
      <div className="flex items-center gap-3 border-b border-border px-6 py-5">
        <Brain className="text-primary" />
        <div className="min-w-0">
          <p className="label-mono">Live analysis</p>
          <p className="mt-1 truncate text-sm text-muted-foreground">{artifact}</p>
        </div>
        {active && <LoaderCircle className="ml-auto size-4 animate-spin text-primary" />}
      </div>

      <ol className="space-y-2 px-6 py-4 text-sm">
        {steps.map((step) => (
          <li key={step.label} className="flex items-center gap-2">
            {step.done ? (
              <Check className="size-4 text-safe" />
            ) : (
              <LoaderCircle className="size-4 animate-spin text-primary" />
            )}
            <span className={step.done ? "text-muted-foreground" : ""}>{step.label}</span>
          </li>
        ))}
      </ol>

      <div className="border-t border-border px-6 py-4">
        <p className="label-mono">Model reasoning</p>
        <div
          ref={scroller}
          className="mt-3 max-h-64 overflow-y-auto whitespace-pre-wrap break-words font-mono text-xs leading-relaxed text-muted-foreground"
        >
          {reasoning || "Waiting for the model to start reading the skill…"}
          {active && (
            <span className="ml-0.5 inline-block h-3 w-1.5 animate-pulse bg-primary align-middle" />
          )}
        </div>
      </div>
    </section>
  );
}
