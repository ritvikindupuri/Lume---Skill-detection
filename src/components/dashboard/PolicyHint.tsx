import type { ReactNode } from "react";
import { Info } from "lucide-react";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";

export function PolicyHint({ label, title, children }: { label: string; title: string; children: ReactNode }) {
  return (
    <TooltipProvider delayDuration={150}>
      <Tooltip>
        <TooltipTrigger asChild>
          <button type="button" aria-label={label} className="inline-flex align-middle text-muted-foreground transition-colors hover:text-foreground">
            <Info className="size-3.5" />
          </button>
        </TooltipTrigger>
        <TooltipContent side="left" className="max-w-72 text-left">
          <p className="font-medium">{title}</p>
          <div className="mt-1 space-y-1.5">{children}</div>
        </TooltipContent>
      </Tooltip>
    </TooltipProvider>
  );
}
