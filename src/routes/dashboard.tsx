import { createFileRoute } from "@tanstack/react-router";
import { WorkspaceDashboard } from "@/components/dashboard/WorkspaceDashboard";

export const Route = createFileRoute("/dashboard")({
  head: () => ({
    meta: [
      { title: "Risk Dashboard — Lume" },
      {
        name: "description",
        content:
          "Analyze Claude skills in batches, tune risk thresholds, author your own checks, and track security scores over time.",
      },
      { property: "og:title", content: "Risk Dashboard — Lume" },
      {
        property: "og:description",
        content: "Claude skill risk policy, custom checks, and scan history.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary" },
    ],
  }),
  component: WorkspaceDashboard,
});
