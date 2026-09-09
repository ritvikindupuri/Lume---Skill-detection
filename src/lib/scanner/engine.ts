import {
  LINE_RULES,
  RULES,
  RULES_BY_ID,
  SEVERITY_ORDER,
  SEVERITY_WEIGHT,
  ruleConfidence,
  type Layer,
  type Rule,
  type Severity,
} from "./rules";

export interface ArtifactFile {
  path: string;
  size: number;
  /** Decoded text; null for binary files. */
  text: string | null;
}

export type FindingSource = "rule" | "custom" | "ai";

export interface Finding {
  key: string;
  ruleId: string;
  title: string;
  severity: Severity;
  layer: Layer;
  rationale: string;
  remediation: string;
  file: string;
  line: number;
  evidence: string;
  /** Estimated precision of this detection, 0–100. */
  confidence: number;
  source: FindingSource;
}

export type Verdict = "malicious" | "suspicious" | "clean";

export interface Endpoint {
  host: string;
  occurrences: number;
}

export interface ScoreStep {
  severity: Severity;
  count: number;
  weight: number;
  contribution: number;
}

export interface ScoreBreakdown {
  steps: ScoreStep[];
  rawScore: number;
  score: number;
  verdict: Verdict;
}

export interface ScanResult {
  scannedAt: string;
  durationMs: number;
  artifactName: string;
  sha256: string;
  files: { path: string; size: number; binary: boolean; findings: number }[];
  totalBytes: number;
  rulesEvaluated: number;
  findings: Finding[];
  counts: Record<Severity, number>;
  endpoints: Endpoint[];
  metadata: { name?: string; description?: string; author?: string; license?: string; tools?: string[] };
  score: number;
  rawScore: number;
  verdict: Verdict;
  policy: RiskConfig;
  breakdown: ScoreStep[];
  ai?: { model: string; findings: number };
}

export interface RiskConfig {
  acceptableScore: number;
  maliciousScore: number;
  blockOnCritical: boolean;
}

export const DEFAULT_RISK_CONFIG: RiskConfig = {
  acceptableScore: 18,
  maliciousScore: 55,
  blockOnCritical: true,
};

export function normalizePolicy(policy: RiskConfig): RiskConfig {
  const acceptableScore = Math.max(1, Math.min(policy.acceptableScore, 98));
  const maliciousScore = Math.max(acceptableScore + 1, Math.min(policy.maliciousScore, 100));
  return { acceptableScore, maliciousScore, blockOnCritical: policy.blockOnCritical };
}

/**
 * Scoring model, fully deterministic:
 * 1. every finding contributes its severity weight,
 * 2. each repeat of the same severity is damped by 1 / (1 + 0.55 × n),
 * 3. the sum is capped at 100 — this is the inherent score,
 * 4. the inherent score is mapped onto the workspace thresholds,
 * 5. the verdict follows the thresholds (and the critical override).
 */
export function computeScore(counts: Record<Severity, number>, riskConfig: RiskConfig): ScoreBreakdown {
  const policy = normalizePolicy(riskConfig);
  const steps: ScoreStep[] = [];
  let raw = 0;
  for (const severity of SEVERITY_ORDER) {
    let contribution = 0;
    for (let i = 0; i < counts[severity]; i++) contribution += SEVERITY_WEIGHT[severity] / (1 + i * 0.55);
    raw += contribution;
    steps.push({
      severity,
      count: counts[severity],
      weight: SEVERITY_WEIGHT[severity],
      contribution: Math.round(contribution * 10) / 10,
    });
  }
  const rawScore = Math.min(100, Math.round(raw));
  const { acceptableScore: acceptable, maliciousScore: malicious } = policy;
  const score = Math.round(
    rawScore <= acceptable
      ? (rawScore / acceptable) * 17
      : rawScore < malicious
        ? 18 + ((rawScore - acceptable) / (malicious - acceptable)) * 36
        : 55 + ((rawScore - malicious) / Math.max(1, 100 - malicious)) * 45,
  );
  const verdict: Verdict =
    (policy.blockOnCritical && counts.critical > 0) || rawScore >= malicious
      ? "malicious"
      : rawScore >= acceptable
        ? "suspicious"
        : "clean";
  return { steps, rawScore, score, verdict };
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) counts[finding.severity] += 1;
  return counts;
}

function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );
}

export function mergeAiFindings(result: ScanResult, aiFindings: Finding[], model: string): ScanResult {
  const existing = new Set(result.findings.map((finding) => `${finding.file}:${finding.line}:${finding.evidence.toLowerCase()}`));
  const novel = aiFindings.filter((finding) => !existing.has(`${finding.file}:${finding.line}:${finding.evidence.toLowerCase()}`));
  const findings = sortFindings([...result.findings, ...novel]);
  const counts = countBySeverity(findings);
  const { steps, rawScore, score, verdict } = computeScore(counts, result.policy);
  return { ...result, findings, counts, rawScore, score, verdict, breakdown: steps, ai: { model, findings: novel.length } };
}

function rule(id: string) {
  const r = RULES_BY_ID[id];
  if (!r) throw new Error(`Unknown rule ${id}`);
  return r;
}

const MAX_EVIDENCE = 220;
const MAX_FINDINGS_PER_RULE_FILE = 5;

function clip(line: string): string {
  const t = line.trim();
  return t.length > MAX_EVIDENCE ? `${t.slice(0, MAX_EVIDENCE)}…` : t;
}

/** Minimal YAML frontmatter reader — only flat scalars and inline lists. */
export function parseFrontmatter(text: string) {
  const meta: ScanResult["metadata"] = {};
  const match = /^---\r?\n([\s\S]*?)\r?\n---/.exec(text);
  if (!match) return { meta, present: false };
  for (const raw of (match[1] ?? "").split(/\r?\n/)) {
    const kv = /^([A-Za-z_-]+)\s*:\s*(.*)$/.exec(raw.trim());
    if (!kv) continue;
    const key = (kv[1] ?? "").toLowerCase();
    const value = (kv[2] ?? "").replace(/^["']|["']$/g, "").trim();
    if (!value) continue;
    if (key === "name") meta.name = value;
    else if (key === "description") meta.description = value;
    else if (key === "author") meta.author = value;
    else if (key === "license") meta.license = value;
    else if (key === "tools" || key === "allowed-tools")
      meta.tools = value
        .replace(/^\[|\]$/g, "")
        .split(/[,\s]+/)
        .filter(Boolean);
  }
  return { meta, present: true };
}

function extractHosts(text: string): string[] {
  const hosts: string[] = [];
  const re = /https?:\/\/([A-Za-z0-9.-]+(?::\d+)?)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(text))) hosts.push((m[1] ?? "").toLowerCase());
  return hosts;
}

export async function sha256Hex(parts: string[]): Promise<string> {
  const data = new TextEncoder().encode(parts.join("\u0000"));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export interface CompiledCustomRule extends Rule {
  confidence: number;
}

export async function scanArtifact(
  artifactName: string,
  files: ArtifactFile[],
  riskConfig: RiskConfig = DEFAULT_RISK_CONFIG,
  customRules: CompiledCustomRule[] = [],
): Promise<ScanResult> {
  const started = performance.now();
  const findings: Finding[] = [];
  const perFileFindings = new Map<string, number>();
  const hostCounts = new Map<string, number>();
  const customIds = new Set(customRules.map((item) => item.id));
  const customConfidence = new Map(customRules.map((item) => [item.id, item.confidence]));
  const activeRules: Rule[] = [...LINE_RULES, ...customRules];

  const skillFile =
    files.find((f) => /(^|\/)SKILL\.md$/i.test(f.path)) ??
    files.find((f) => f.text !== null && /\.md$/i.test(f.path));
  const { meta } = skillFile?.text
    ? parseFrontmatter(skillFile.text)
    : { meta: {} as ScanResult["metadata"] };

  const push = (f: Omit<Finding, "key">) => {
    findings.push({ ...f, key: `${f.ruleId}:${f.file}:${f.line}` });
    perFileFindings.set(f.file, (perFileFindings.get(f.file) ?? 0) + 1);
  };

  for (const file of files) {
    if (file.text === null) continue;

    for (const host of extractHosts(file.text)) {
      hostCounts.set(host, (hostCounts.get(host) ?? 0) + 1);
    }

    const lines = file.text.split(/\r?\n/);
    const perRuleCount = new Map<string, number>();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i] ?? "";
      if (!line.trim()) continue;
      for (const active of activeRules) {
        if (active.pathPattern && !active.pathPattern.test(file.path)) continue;
        const count = perRuleCount.get(active.id) ?? 0;
        if (count >= MAX_FINDINGS_PER_RULE_FILE) continue;
        if (!active.pattern.test(line)) continue;
        perRuleCount.set(active.id, count + 1);
        const custom = customIds.has(active.id);
        push({
          ruleId: active.id,
          title: active.title,
          severity: active.severity,
          layer: active.layer,
          rationale: active.rationale,
          remediation: active.remediation,
          file: file.path,
          line: i + 1,
          evidence: clip(line),
          confidence: custom
            ? (customConfidence.get(active.id) ?? 60)
            : ruleConfidence(active.id, active.severity),
          source: custom ? "custom" : "rule",
        });
      }
    }
  }

  // ── structural checks ──────────────────────────────────────────────────
  if (skillFile && !meta.author && !meta.license) {
    const r = rule("ATT-027");
    push({
      ruleId: r.id,
      title: r.title,
      severity: r.severity,
      layer: r.layer,
      rationale: r.rationale,
      remediation: r.remediation,
      file: skillFile.path,
      line: 1,
      evidence: "no author or license declared",
      confidence: ruleConfidence(r.id, r.severity),
      source: "rule",
    });
  }

  const endpoints: Endpoint[] = [...hostCounts.entries()]
    .map(([host, occurrences]) => ({ host, occurrences }))
    .sort((a, b) => b.occurrences - a.occurrences);

  const counts = countBySeverity(findings);
  const { steps, rawScore, score, verdict } = computeScore(counts, riskConfig);

  return {
    scannedAt: new Date().toISOString(),
    durationMs: Math.round(performance.now() - started),
    artifactName,
    sha256: await sha256Hex(files.map((f) => `${f.path}:${f.text ?? `<binary:${f.size}>`}`)),
    files: files.map((f) => ({
      path: f.path,
      size: f.size,
      binary: f.text === null,
      findings: perFileFindings.get(f.path) ?? 0,
    })),
    totalBytes: files.reduce((n, f) => n + f.size, 0),
    rulesEvaluated: RULES.length + customRules.length,
    findings: sortFindings(findings),
    counts,
    endpoints,
    metadata: meta,
    score,
    rawScore,
    verdict,
    policy: normalizePolicy(riskConfig),
    breakdown: steps,
  };
}
