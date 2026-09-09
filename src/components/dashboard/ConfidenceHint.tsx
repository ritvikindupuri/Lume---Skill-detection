import { Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

export function ConfidenceHint() {
  return (
    <TooltipProvider delayDuration={150}>
    <Tooltip>
      <TooltipTrigger asChild>
        <button type="button" aria-label="How confidence is calculated" className="inline-flex align-middle text-muted-foreground transition-colors hover:text-foreground">
          <Info className="size-3.5" />
        </button>
      </TooltipTrigger>
      <TooltipContent side="top" className="max-w-72 text-left">
        <p className="font-medium">How confidence is calculated</p>
        <p className="mt-1">
          Confidence estimates how precise a match is — not how dangerous it is.
        </p>
        <ul className="mt-1.5 list-disc space-y-1 pl-4">
          <li>Built-in checks start from a base by severity (critical 88, high 78, medium 68, low 58), adjusted per rule: exact signals like leaked-key formats score higher, broader heuristics lower.</li>
          <li>Custom checks use the confidence the author set.</li>
          <li>AI findings use the model's own estimate, kept between 10–95%.</li>
        </ul>
        <p className="mt-1.5">80%+ = High precision, 60–79% = Moderate, below 60% = Broad heuristic worth a closer human look.</p>
      </TooltipContent>
    </Tooltip>
  );
}
