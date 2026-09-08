import { createFileRoute } from "@tanstack/react-router";
import { CompanyDashboard } from "@/components/dashboard/CompanyDashboard";

export const Route = createFileRoute("/dashboard")({
  head: () => ({ meta: [
    { title: "Company Risk Dashboard — Attest" },
    { name: "description", content: "Analyze Claude skills in batches, configure company risk thresholds, and track security scores over time." },
    { property: "og:title", content: "Company Risk Dashboard — Attest" },
    { property: "og:description", content: "Company-wide Claude skill risk policy and scan history." },
    { property: "og:type", content: "website" },
    { name: "twitter:card", content: "summary" },
  ] }),
  component: CompanyDashboard,
});