import { createServerFn } from "@tanstack/react-start";
import { streamText } from "ai";
import { z } from "zod";
import type { Finding } from "./scanner/engine";
import type { Layer, Severity } from "./scanner/rules";

const inputSchema = z.object({
  artifactName: z.string().min(1).max(255),
  content: z.string().min(1).max(500_000),
  deterministicFindings: z.array(z.object({
    ruleId: z.string(),
    title: z.string(),
    severity: z.enum(["critical", "high", "medium", "low"]),
    file: z.string(),
    line: z.number(),
    evidence: z.string(),
  })).max(200),
});

const allowedSeverities = new Set<Severity>(["critical", "high", "medium", "low"]);
const allowedLayers = new Set<Layer>(["prompt", "agency", "leakage", "privacy", "supply-chain", "integrity", "bias", "resilience"]);

function extractJson(text: string): unknown {
  const fenced = /```(?:json)?\s*([\s\S]*?)```/i.exec(text)?.[1];
  const candidate = fenced ?? text.slice(text.indexOf("{"), text.lastIndexOf("}") + 1);
  return JSON.parse(candidate);
}

function normalizeFindings(value: unknown): Finding[] {
  if (!value || typeof value !== "object" || !("findings" in value) || !Array.isArray(value.findings)) return [];
  return value.findings.slice(0, 30).flatMap((item, index) => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const severityValue = record["severity"];
    const layerValue = record["layer"];
    const titleValue = record["title"];
    const evidenceValue = record["evidence"];
    const severity = typeof severityValue === "string" && allowedSeverities.has(severityValue as Severity) ? severityValue as Severity : null;
    const layer = typeof layerValue === "string" && allowedLayers.has(layerValue as Layer) ? layerValue as Layer : null;
    if (!severity || !layer || typeof titleValue !== "string" || typeof evidenceValue !== "string") return [];
    const fileValue = record["file"];
    const lineValue = record["line"];
    const file = typeof fileValue === "string" ? fileValue.slice(0, 500) : "SKILL.md";
    const line = typeof lineValue === "number" && Number.isFinite(lineValue) ? Math.max(1, Math.round(lineValue)) : 1;
    return [{
      key: `GPT-${String(index + 1).padStart(3, "0")}:${file}:${line}`,
      ruleId: `GPT-${String(index + 1).padStart(3, "0")}`,
      title: titleValue.slice(0, 200),
      severity,
      layer,
      rationale: typeof record["rationale"] === "string" ? record["rationale"].slice(0, 800) : "The instruction creates an unsafe or deceptive behavior pattern.",
      remediation: typeof record["remediation"] === "string" ? record["remediation"].slice(0, 800) : "Remove or strictly constrain this behavior before deployment.",
      file,
      line,
      evidence: evidenceValue.replace(/\s+/g, " ").trim().slice(0, 220),
    }];
  });
}

export const analyzeSkillWithAi = createServerFn({ method: "POST" })
  .inputValidator((input) => inputSchema.parse(input))
  .handler(async ({ data }) => {
    const lovableApiKey = process.env["LOVABLE_API_KEY"];
    if (!lovableApiKey) throw new Error("Lovable AI is not configured for this workspace.");
    const { createLumeAi } = await import("./ai-gateway.server");
    const provider = createLumeAi(lovableApiKey);
    try {
      const result = streamText({
        model: provider.responses("openai/gpt-6-astra"),
        maxRetries: 2,
        providerOptions: { openai: { reasoningEffort: "max", forceReasoning: true } },
        system: `You are Lume's senior AI skill security analyst. Inspect Claude skill artifacts for malicious or unsafe intent that deterministic rules can miss: multi-step prompt injection, hidden trigger logic, data exfiltration, privacy abuse, unsafe agency, supply-chain compromise, hallucination inducement, discriminatory output bias, and evasion. Be conservative and evidence-bound. Never invent a finding. Report only behavior supported by an exact excerpt. Do not duplicate the supplied deterministic findings. Return only JSON with this shape: {"findings":[{"title":"...","severity":"critical|high|medium|low","layer":"prompt|agency|leakage|privacy|supply-chain|integrity|bias|resilience","file":"...","line":1,"evidence":"exact short excerpt","rationale":"...","remediation":"..."}]}. If there are no additional findings, return {"findings":[]}.`,
        prompt: `Artifact: ${data.artifactName}\n\nAlready detected (do not duplicate):\n${JSON.stringify(data.deterministicFindings)}\n\nArtifact contents:\n${data.content}`,
      });
      const text = await result.text;
      return { model: "openai/gpt-6-astra", findings: normalizeFindings(extractJson(text)) };
    } catch (error) {
      const status = typeof error === "object" && error && "statusCode" in error ? Number(error.statusCode) : undefined;
      const upstream = error instanceof Error ? error.message : "AI analysis failed.";
      if (status === 402) throw new Error(`${upstream} Add AI credits in Lovable to continue.`);
      if (status === 403) throw new Error(`${upstream} AI access is blocked by workspace policy.`);
      if (status === 429) throw new Error(`${upstream} The AI service is busy; try again shortly.`);
      if (status === 401) throw new Error("Lovable AI is not configured correctly for this workspace.");
      throw new Error(upstream);
    }
  });