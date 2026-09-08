import {
  LINE_RULES,
  RULES,
  RULES_BY_ID,
  SEVERITY_ORDER,
  SEVERITY_WEIGHT,
  type Layer,
  type Severity,
} from "./rules";

export interface ArtifactFile {
  path: string;
  size: number;
  /** Decoded text; null for binary files. */
  text: string | null;
}

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
}

export type Verdict = "malicious" | "suspicious" | "clean";

export interface Endpoint {
  host: string;
  occurrences: number;
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
  verdict: Verdict;
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
  for (const raw of match[1].split(/\r?\n/)) {
    const kv = /^([A-Za-z_-]+)\s*:\s*(.*)$/.exec(raw.trim());
    if (!kv) continue;
    const key = kv[1].toLowerCase();
    const value = kv[2].replace(/^["']|["']$/g, "").trim();
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
  while ((m = re.exec(text))) hosts.push(m[1].toLowerCase());
  return hosts;
}

export async function sha256Hex(parts: string[]): Promise<string> {
  const data = new TextEncoder().encode(parts.join("\u0000"));
  const digest = await crypto.subtle.digest("SHA-256", data);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

export async function scanArtifact(
  artifactName: string,
  files: ArtifactFile[],
): Promise<ScanResult> {
  const started = performance.now();
  const findings: Finding[] = [];
  const perFileFindings = new Map<string, number>();
  const hostCounts = new Map<string, number>();

  const skillFile =
    files.find((f) => /(^|\/)SKILL\.md$/i.test(f.path)) ??
    files.find((f) => f.text !== null && /\.md$/i.test(f.path));
  const { meta, present: frontmatterPresent } = skillFile?.text
    ? parseFrontmatter(skillFile.text)
    : { meta: {} as ScanResult["metadata"], present: false };

  const push = (f: Omit<Finding, "key">) => {
    findings.push({ ...f, key: `${f.ruleId}:${f.file}:${f.line}` });
    perFileFindings.set(f.file, (perFileFindings.get(f.file) ?? 0) + 1);
  };

  for (const file of files) {
    if (file.text === null) {
      const binaryRule = RULES_BY_ID["PGR-P004"];
      if (binaryRule.pathPattern?.test(file.path)) {
        push({
          ruleId: binaryRule.id,
          title: binaryRule.title,
          severity: binaryRule.severity,
          layer: binaryRule.layer,
          rationale: binaryRule.rationale,
          remediation: binaryRule.remediation,
          file: file.path,
          line: 0,
          evidence: `binary artifact · ${file.size.toLocaleString()} bytes`,
        });
      }
      continue;
    }

    for (const host of extractHosts(file.text)) {
      hostCounts.set(host, (hostCounts.get(host) ?? 0) + 1);
    }

    const lines = file.text.split(/\r?\n/);
    const perRuleCount = new Map<string, number>();

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.trim()) continue;
      for (const rule of LINE_RULES) {
        if (rule.pathPattern && !rule.pathPattern.test(file.path)) continue;
        const count = perRuleCount.get(rule.id) ?? 0;
        if (count >= MAX_FINDINGS_PER_RULE_FILE) continue;
        if (!rule.pattern.test(line)) continue;
        perRuleCount.set(rule.id, count + 1);
        push({
          ruleId: rule.id,
          title: rule.title,
          severity: rule.severity,
          layer: rule.layer,
          rationale: rule.rationale,
          remediation: rule.remediation,
          file: file.path,
          line: i + 1,
          evidence: clip(line),
        });
      }
    }
  }

  // ── structural checks ──────────────────────────────────────────────────
  if (skillFile) {
    if (!frontmatterPresent || !meta.name || !meta.description) {
      const r = RULES_BY_ID["PGR-S011"];
      push({
        ruleId: r.id,
        title: r.title,
        severity: r.severity,
        layer: r.layer,
        rationale: r.rationale,
        remediation: r.remediation,
        file: skillFile.path,
        line: 1,
        evidence: frontmatterPresent
          ? `frontmatter present but missing: ${[!meta.name && "name", !meta.description && "description"].filter(Boolean).join(", ")}`
          : "no YAML frontmatter block found",
      });
    }
    if (!meta.author && !meta.license) {
      const r = RULES_BY_ID["PGR-P005"];
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
      });
    }
  }

  const endpoints: Endpoint[] = [...hostCounts.entries()]
    .map(([host, occurrences]) => ({ host, occurrences }))
    .sort((a, b) => b.occurrences - a.occurrences);

  if (endpoints.length > 0) {
    const r = RULES_BY_ID["PGR-N008"];
    push({
      ruleId: r.id,
      title: r.title,
      severity: r.severity,
      layer: r.layer,
      rationale: r.rationale,
      remediation: r.remediation,
      file: skillFile?.path ?? artifactName,
      line: 0,
      evidence: `${endpoints.length} external host${endpoints.length === 1 ? "" : "s"}: ${endpoints
        .slice(0, 6)
        .map((e) => e.host)
        .join(", ")}${endpoints.length > 6 ? " …" : ""}`,
    });
  }

  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of findings) counts[f.severity] += 1;

  // Scoring: severity weights with diminishing returns per additional finding
  // of the same severity, capped at 100.
  let raw = 0;
  for (const sev of SEVERITY_ORDER) {
    for (let i = 0; i < counts[sev]; i++) {
      raw += SEVERITY_WEIGHT[sev] / (1 + i * 0.55);
    }
  }
  const score = Math.min(100, Math.round(raw));
  const verdict: Verdict =
    counts.critical > 0 || score >= 55 ? "malicious" : score >= 18 ? "suspicious" : "clean";

  findings.sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.file.localeCompare(b.file) ||
      a.line - b.line,
  );

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
    rulesEvaluated: RULES.length,
    findings,
    counts,
    endpoints,
    metadata: meta,
    score,
    verdict,
  };
}
