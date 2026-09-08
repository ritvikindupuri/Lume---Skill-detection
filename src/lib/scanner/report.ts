import { LAYER_LABEL } from "./rules";
import type { ScanResult } from "./engine";

export function toMarkdown(r: ScanResult): string {
  const lines: string[] = [];
  lines.push(`# Aperture skill security report`);
  lines.push("");
  lines.push(`- Artifact: \`${r.artifactName}\``);
  lines.push(`- SHA-256: \`${r.sha256}\``);
  lines.push(`- Scanned: ${r.scannedAt} (${r.durationMs} ms)`);
  lines.push(`- Rules evaluated: ${r.rulesEvaluated}`);
  lines.push(`- AI review: ${r.ai ? `${r.ai.model} · ${r.ai.findings} additional finding(s)` : "not run"}`);
  lines.push(`- Verdict: **${r.verdict.toUpperCase()}** · policy-adjusted risk score ${r.score}/100`);
  lines.push(`- Inherent score: ${r.rawScore}/100 · review at ${r.policy.acceptableScore} · block at ${r.policy.maliciousScore}`);
  lines.push(
    `- Findings: ${r.counts.critical} critical · ${r.counts.high} high · ${r.counts.medium} medium · ${r.counts.low} low`,
  );
  lines.push("");

  if (r.metadata.name || r.metadata.description) {
    lines.push(`## Declared metadata`);
    if (r.metadata.name) lines.push(`- name: ${r.metadata.name}`);
    if (r.metadata.description) lines.push(`- description: ${r.metadata.description}`);
    if (r.metadata.author) lines.push(`- author: ${r.metadata.author}`);
    if (r.metadata.license) lines.push(`- license: ${r.metadata.license}`);
    if (r.metadata.tools?.length) lines.push(`- tools: ${r.metadata.tools.join(", ")}`);
    lines.push("");
  }

  lines.push(`## Files analyzed (${r.files.length})`);
  for (const f of r.files) {
    lines.push(`- \`${f.path}\` — ${f.size} bytes${f.binary ? " (binary)" : ""}, ${f.findings} finding(s)`);
  }
  lines.push("");

  if (r.endpoints.length) {
    lines.push(`## External endpoints (${r.endpoints.length})`);
    for (const e of r.endpoints) lines.push(`- \`${e.host}\` × ${e.occurrences}`);
    lines.push("");
  }

  lines.push(`## Findings`);
  if (!r.findings.length) {
    lines.push("No rule matched this artifact.");
  }
  for (const f of r.findings) {
    lines.push("");
    lines.push(`### [${f.severity.toUpperCase()}] ${f.ruleId} — ${f.title}`);
    lines.push(`- Layer: ${LAYER_LABEL[f.layer]}`);
    lines.push(`- Location: \`${f.file}\`${f.line ? `:${f.line}` : ""}`);
    lines.push(`- Evidence: \`${f.evidence.replace(/`/g, "'")}\``);
    lines.push(`- Why it matters: ${f.rationale}`);
    lines.push(`- Remediation: ${f.remediation}`);
  }
  lines.push("");
  return lines.join("\n");
}

export function download(filename: string, contents: string, type: string) {
  const blob = new Blob([contents], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
