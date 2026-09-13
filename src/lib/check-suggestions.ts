import type { Layer, Severity } from "./scanner/rules";

const allowedSeverities = new Set<Severity>(["critical", "high", "medium", "low"]);
const allowedLayers = new Set<Layer>([
  "prompt",
  "agency",
  "leakage",
  "privacy",
  "supply-chain",
  "integrity",
  "bias",
  "resilience",
]);

export interface SuggestedCheck {
  code: string;
  title: string;
  severity: Severity;
  layer: Layer;
  pattern: string;
  rationale: string;
  remediation: string;
  confidence: number;
  evidence: string;
}

export const SUGGEST_MODEL = "openai/gpt-6-astra";

export const SUGGEST_SYSTEM_PROMPT = `You are Lume's detection engineer. You are given one or more Claude skill artifacts uploaded by a security team, plus the list of detection checks that already exist. Your job is to propose NEW deterministic regular-expression checks that this team should add to their library, derived from what actually appears in these artifacts.

Rules:
- Every proposal must be grounded in an exact excerpt from the supplied artifacts. Never invent behaviour.
- Do not restate an existing check. Propose only gaps the current library misses.
- Patterns are JavaScript regular expressions evaluated case-insensitively against a single line of text. Keep them tight enough to avoid obvious false positives, and general enough to catch variants (word alternations, \\s+ between words). No lookbehind, no backreferences, max 300 characters.
- Propose at most 6 checks. If the artifacts justify none, return an empty list.

Reply with a single JSON object inside a \`\`\`json fence and nothing else:
{"checks":[{"code":"3-20 chars, letters/numbers/dashes, e.g. AI-001","title":"short check name","severity":"critical|high|medium|low","layer":"prompt|agency|leakage|privacy|supply-chain|integrity|bias|resilience","pattern":"regex source without slashes","rationale":"why this matters, one or two plain sentences","remediation":"how a skill author fixes it","confidence":0-100,"evidence":"exact excerpt from the artifacts that this pattern matches"}]}`;

export function suggestUserPrompt(
  existing: string[],
  artifacts: { name: string; content: string }[],
) {
  const body = artifacts
    .map((artifact) => `=== ARTIFACT: ${artifact.name} ===\n${artifact.content}`)
    .join("\n\n");
  return `Existing checks (titles):\n${existing.join("\n") || "none"}\n\nArtifacts:\n${body}`;
}

function safePattern(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const pattern = value.trim();
  if (pattern.length < 2 || pattern.length > 300) return null;
  if (/\(\?<|\\\d/.test(pattern)) return null;
  try {
    new RegExp(pattern, "i");
    return pattern;
  } catch {
    return null;
  }
}

export function normalizeSuggestions(value: unknown): SuggestedCheck[] {
  if (!value || typeof value !== "object" || !("checks" in value) || !Array.isArray(value.checks))
    return [];
  return value.checks.slice(0, 6).flatMap((item, index): SuggestedCheck[] => {
    if (!item || typeof item !== "object") return [];
    const record = item as Record<string, unknown>;
    const pattern = safePattern(record["pattern"]);
    const title = typeof record["title"] === "string" ? record["title"].trim().slice(0, 120) : "";
    const severity = record["severity"];
    const layer = record["layer"];
    if (!pattern || title.length < 3) return [];
    if (typeof severity !== "string" || !allowedSeverities.has(severity as Severity)) return [];
    if (typeof layer !== "string" || !allowedLayers.has(layer as Layer)) return [];
    const rawCode =
      typeof record["code"] === "string"
        ? record["code"].toUpperCase().replace(/[^A-Z0-9-]/g, "")
        : "";
    const code =
      rawCode.length >= 3 && rawCode.length <= 20
        ? rawCode
        : `AI-${String(index + 1).padStart(3, "0")}`;
    const confidenceValue = record["confidence"];
    const confidence =
      typeof confidenceValue === "number" && Number.isFinite(confidenceValue)
        ? Math.max(
            10,
            Math.min(95, Math.round(confidenceValue > 1 ? confidenceValue : confidenceValue * 100)),
          )
        : 65;
    return [
      {
        code,
        title,
        severity: severity as Severity,
        layer: layer as Layer,
        pattern,
        rationale: typeof record["rationale"] === "string" ? record["rationale"].slice(0, 500) : "",
        remediation:
          typeof record["remediation"] === "string" ? record["remediation"].slice(0, 500) : "",
        confidence,
        evidence:
          typeof record["evidence"] === "string"
            ? record["evidence"].replace(/\s+/g, " ").trim().slice(0, 220)
            : "",
      },
    ];
  });
}
