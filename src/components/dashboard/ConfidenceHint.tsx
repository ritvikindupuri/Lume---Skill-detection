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
      <TooltipContent side="top" className="max-w-80 text-left">
        <p className="font-medium">What confidence means</p>
        <p className="mt-1">
          It is how sure we are that a match is really what the check is looking for — not how dangerous it is. Severity answers “how bad”, confidence answers “how sure”.
        </p>
        <p className="mt-1.5 font-medium">Where the number comes from</p>
        <ul className="mt-1 list-disc space-y-1 pl-4">
          <li>
            Every built-in check starts at a set figure chosen by us for its severity — critical 88, high 78, medium 68, low 58. These are our starting estimates, not measurements: the more serious checks are written to be narrow and specific, so they misfire less often, which is why they start higher.
          </li>
          <li>Each check is then nudged up or down from that start. Very exact signals (a leaked key in a known format) go higher; broad wording searches that can catch innocent text go lower.</li>
          <li>Checks you write yourself use the figure you set.</li>
          <li>AI findings use the model's own estimate, kept between 10% and 95%.</li>
        </ul>
        <p className="mt-1.5">80%+ = high precision, 60–79% = moderate, below 60% = broad — worth a closer human look.</p>
      </TooltipContent>
    </Tooltip>
    </TooltipProvider>
  );
}
