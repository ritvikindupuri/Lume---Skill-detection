import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
import { computeScore } from "@/lib/scanner/engine";
import type { Severity } from "@/lib/scanner/rules";
import type { Json } from "@/integrations/supabase/types";

const findingSchema = z.object({
  ruleId: z.string().max(30),
  title: z.string().max(200),
  severity: z.enum(["critical", "high", "medium", "low"]),
  category: z.string().max(60),
  file: z.string().max(500),
  line: z.number().int().min(0),
  evidence: z.string().max(500),
  remediation: z.string().max(1000),
  confidence: z.number().int().min(0).max(100),
});

const scanSchema = z.object({
  organizationId: z.string().uuid(),
  artifactName: z.string().min(1).max(255),
  declaredName: z.string().max(255).optional(),
  sha256: z.string().regex(/^[a-f0-9]{64}$/),
  score: z.number().int().min(0).max(100),
  verdict: z.enum(["clean", "suspicious", "malicious"]),
  filesCount: z.number().int().min(0),
  rulesEvaluated: z.number().int().min(1),
  counts: z.object({ critical: z.number(), high: z.number(), medium: z.number(), low: z.number() }),
  scannedAt: z.string().datetime(),
  recommendation: z.object({
    action: z.enum(["quarantine", "allow"]),
    reason: z.string().max(600),
    confidence: z.number().int().min(0).max(100),
  }).nullish(),
  findings: z.array(findingSchema).max(300),
});

export const getWorkspace = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .handler(async ({ context }) => {
    const membership = await context.supabase
      .from("organization_members")
      .select("organization_id, role, organizations(id, name, slug)")
      .eq("user_id", context.userId)
      .limit(1)
      .maybeSingle();
    if (membership.error) throw new Error("Could not load your workspace.");
    if (!membership.data) return { organization: null, role: null, settings: null, scans: [] };

    const organization = Array.isArray(membership.data.organizations)
      ? membership.data.organizations[0]
      : membership.data.organizations;
    if (!organization) return { organization: null, role: null, settings: null, scans: [] };

    const [settings, scans] = await Promise.all([
      context.supabase.from("risk_settings").select("*").eq("organization_id", organization.id).single(),
      context.supabase
        .from("skill_scans")
        .select("id, artifact_name, declared_name, sha256, score, verdict, findings_count, files_count, severity_counts, scanned_at, containment, ai_recommendation, ai_recommendation_reason, ai_recommendation_confidence, recommendation_status, recommendation_decided_at")
        .eq("organization_id", organization.id)
        .order("scanned_at", { ascending: false })
        .limit(100),
    ]);
    if (settings.error || scans.error) throw new Error("Could not load workspace security data.");
    return { organization, role: membership.data.role, settings: settings.data, scans: scans.data ?? [] };
  });

export const createWorkspace = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({ name: z.string().trim().min(2).max(120) }).parse(input))
  .handler(async ({ data, context }) => {
    const base = data.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "workspace";
    const slug = `${base}-${crypto.randomUUID().slice(0, 8)}`;
    const result = await context.supabase.rpc("create_organization_with_admin", { _name: data.name, _slug: slug });
    if (result.error) throw new Error("Could not create the workspace.");
    return { id: result.data };
  });

export const updateRiskSettings = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({
    organizationId: z.string().uuid(),
    acceptableScore: z.number().int().min(0).max(98),
    maliciousScore: z.number().int().min(1).max(100),
    blockOnCritical: z.boolean(),
  }).refine((value) => value.acceptableScore < value.maliciousScore, { message: "Block threshold must be higher than review threshold." }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase.from("risk_settings").update({
      acceptable_score: data.acceptableScore,
      malicious_score: data.maliciousScore,
      block_on_critical: data.blockOnCritical,
      updated_by: context.userId,
    }).eq("organization_id", data.organizationId);
    if (result.error) throw new Error("Could not save the risk policy.");
    return { ok: true };
  });

export const saveScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => scanSchema.parse(input))
  .handler(async ({ data, context }) => {
    const settings = await context.supabase
      .from("risk_settings")
      .select("block_on_critical")
      .eq("organization_id", data.organizationId)
      .maybeSingle();
    const criticalCount = (data.counts as Record<string, number>)["critical"] ?? 0;
    const autoBlocked = (settings.data?.block_on_critical ?? true) && criticalCount > 0;

    const inserted = await context.supabase.from("skill_scans").insert({
      organization_id: data.organizationId,
      scanned_by: context.userId,
      artifact_name: data.artifactName,
      declared_name: data.declaredName ?? null,
      sha256: data.sha256,
      score: data.score,
      verdict: data.verdict,
      findings_count: data.findings.length,
      files_count: data.filesCount,
      rules_evaluated: data.rulesEvaluated,
      severity_counts: data.counts as Json,
      scanned_at: data.scannedAt,
      containment: autoBlocked ? "quarantined" : "none",
      contained_at: autoBlocked ? new Date().toISOString() : null,
      ai_recommendation: data.recommendation?.action ?? "none",
      ai_recommendation_reason: data.recommendation?.reason ?? "",
      ai_recommendation_confidence: data.recommendation?.confidence ?? 0,
      recommendation_status: autoBlocked ? "none" : data.recommendation?.action === "quarantine" ? "pending" : "none",
    }).select("id").single();
    if (inserted.error) throw new Error("Could not save the scan.");
    if (data.findings.length) {
      const findings = await context.supabase.from("scan_findings").insert(data.findings.map((finding) => ({
        scan_id: inserted.data.id,
        organization_id: data.organizationId,
        rule_id: finding.ruleId,
        title: finding.title,
        severity: finding.severity,
        category: finding.category,
        file_path: finding.file,
        line_number: finding.line,
        evidence: finding.evidence,
        remediation: finding.remediation,
        confidence: finding.confidence,
      })));
      if (findings.error) throw new Error("Scan saved, but its findings could not be stored.");
    }
    return { id: inserted.data.id };
  });

export const getScanFindings = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({ scanId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase
      .from("scan_findings")
      .select("id, rule_id, title, severity, category, file_path, line_number, evidence, remediation, confidence, status, review_note")
      .eq("scan_id", data.scanId)
      .order("severity", { ascending: true });
    if (result.error) throw new Error("Could not load the findings for this scan.");
    return result.data ?? [];
  });

export const reviewFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({
    findingId: z.string().uuid(),
    scanId: z.string().uuid(),
    status: z.enum(["open", "pending_confirm", "confirmed", "false_positive"]),
    note: z.string().max(2000).optional(),
  }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase
      .from("scan_findings")
      .update({
        status: data.status,
        reviewed_by: context.userId,
        reviewed_at: new Date().toISOString(),
        review_note: data.note?.trim() ?? "",
      })
      .eq("id", data.findingId);
    if (result.error) throw new Error("Could not save this review decision.");

    const [scan, findings] = await Promise.all([
      context.supabase.from("skill_scans").select("id, organization_id").eq("id", data.scanId).single(),
      context.supabase.from("scan_findings").select("severity, status").eq("scan_id", data.scanId),
    ]);
    if (scan.error || findings.error) throw new Error("Decision saved, but the scan could not be re-scored.");

    const settings = await context.supabase
      .from("risk_settings")
      .select("acceptable_score, malicious_score, block_on_critical")
      .eq("organization_id", scan.data.organization_id)
      .single();
    if (settings.error) throw new Error("Decision saved, but the risk policy could not be read.");

    const rows = findings.data ?? [];
    const active = rows.filter((row) => row.status !== "false_positive");
    const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const row of active) counts[row.severity as Severity] += 1;
    const { score, verdict } = computeScore(counts, {
      acceptableScore: settings.data.acceptable_score,
      maliciousScore: settings.data.malicious_score,
      blockOnCritical: settings.data.block_on_critical,
    });

    const autoBlocked = settings.data.block_on_critical && counts.critical > 0;
    const confirmedSevere = rows.some((row) => row.status === "confirmed" && (row.severity === "critical" || row.severity === "high"));
    const allDismissed = rows.length > 0 && active.length === 0;
    const containment = autoBlocked || confirmedSevere ? "quarantined" : allDismissed || verdict === "clean" ? "cleared" : "none";

    const updated = await context.supabase
      .from("skill_scans")
      .update({
        score,
        verdict,
        containment,
        contained_at: containment === "none" ? null : new Date().toISOString(),
        contained_by: containment === "none" ? null : context.userId,
      })
      .eq("id", data.scanId);
    if (updated.error) throw new Error("Decision saved, but the scan record could not be updated.");

    return { score, verdict, containment, autoBlocked };
  });

export const decideRecommendation = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({
    scanId: z.string().uuid(),
    decision: z.enum(["approve", "reject"]),
  }).parse(input))
  .handler(async ({ data, context }) => {
    const containment = data.decision === "approve" ? "quarantined" : "none";
    const result = await context.supabase
      .from("skill_scans")
      .update({
        recommendation_status: data.decision === "approve" ? "approved" : "rejected",
        recommendation_decided_by: context.userId,
        recommendation_decided_at: new Date().toISOString(),
        containment,
        contained_at: containment === "none" ? null : new Date().toISOString(),
        contained_by: containment === "none" ? null : context.userId,
      })
      .eq("id", data.scanId);
    if (result.error) throw new Error("Could not record this containment decision.");
    return { containment, status: data.decision === "approve" ? "approved" : "rejected" };
  });

export const listPendingApprovals = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({ organizationId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const [findings, scans] = await Promise.all([
      context.supabase
        .from("scan_findings")
        .select("id, scan_id, rule_id, title, severity, category, file_path, line_number, evidence, remediation, confidence, status, reviewed_at")
        .eq("organization_id", data.organizationId)
        .eq("status", "pending_confirm")
        .order("reviewed_at", { ascending: false })
        .limit(200),
      context.supabase
        .from("skill_scans")
        .select("id, artifact_name, declared_name, score, verdict, containment, scanned_at, ai_recommendation, ai_recommendation_reason, ai_recommendation_confidence, recommendation_status")
        .eq("organization_id", data.organizationId)
        .order("scanned_at", { ascending: false })
        .limit(200),
    ]);
    if (findings.error || scans.error) throw new Error("Could not load the approval queue.");
    const scanRows = scans.data ?? [];
    const byId = new Map(scanRows.map((scan) => [scan.id, scan]));
    return {
      findings: (findings.data ?? []).map((finding) => {
        const scan = byId.get(finding.scan_id);
        return {
          ...finding,
          scanName: scan ? scan.declared_name ?? scan.artifact_name : "Unknown skill",
          scanScore: scan?.score ?? 0,
          scanVerdict: scan?.verdict ?? "clean",
          scanContainment: scan?.containment ?? "none",
          aiReason: scan?.ai_recommendation_reason ?? "",
          aiAction: scan?.ai_recommendation ?? "none",
          aiConfidence: scan?.ai_recommendation_confidence ?? 0,
        };
      }),
      containment: scanRows.filter((scan) => scan.recommendation_status === "pending"),
    };
  });

export const deleteScan = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({ scanId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase.from("skill_scans").delete().eq("id", data.scanId);
    if (result.error) throw new Error("Could not delete this scan.");
    return { ok: true };
  });



const customCheckSchema = z.object({
  organizationId: z.string().uuid(),
  code: z.string().trim().regex(/^[A-Za-z0-9-]{3,20}$/, "Use 3–20 letters, numbers, or dashes."),
  title: z.string().trim().min(3).max(120),
  severity: z.enum(["critical", "high", "medium", "low"]),
  layer: z.enum(["prompt", "agency", "leakage", "privacy", "supply-chain", "integrity", "bias", "resilience"]),
  pattern: z.string().trim().min(2).max(400).refine((value) => {
    try { new RegExp(value, "i"); return true; } catch { return false; }
  }, "That pattern is not a valid expression."),
  rationale: z.string().trim().max(500).default(""),
  remediation: z.string().trim().max(500).default(""),
  confidence: z.number().int().min(0).max(100).default(60),
});

export const listCustomChecks = createServerFn({ method: "GET" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({ organizationId: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase
      .from("custom_checks")
      .select("*")
      .eq("organization_id", data.organizationId)
      .order("created_at", { ascending: true });
    if (result.error) throw new Error("Could not load your custom checks.");
    return result.data ?? [];
  });

export const createCustomCheck = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => customCheckSchema.parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase.from("custom_checks").insert({
      organization_id: data.organizationId,
      code: data.code.toUpperCase(),
      title: data.title,
      severity: data.severity,
      layer: data.layer,
      pattern: data.pattern,
      rationale: data.rationale,
      remediation: data.remediation,
      confidence: data.confidence,
      created_by: context.userId,
    }).select("id").single();
    if (result.error) {
      throw new Error(result.error.code === "23505" ? "A check with that code already exists." : "Could not save this check.");
    }
    return { id: result.data.id };
  });

export const setCustomCheckEnabled = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({ id: z.string().uuid(), enabled: z.boolean() }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase.from("custom_checks").update({ enabled: data.enabled }).eq("id", data.id);
    if (result.error) throw new Error("Could not update this check.");
    return { ok: true };
  });

export const deleteCustomCheck = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({ id: z.string().uuid() }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase.from("custom_checks").delete().eq("id", data.id);
    if (result.error) throw new Error("Could not delete this check.");
    return { ok: true };
  });

export const suggestCustomChecks = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({
    organizationId: z.string().uuid(),
    artifacts: z.array(z.object({
      name: z.string().min(1).max(255),
      content: z.string().min(1),
    })).min(1).max(10),
  }).parse(input))
  .handler(async ({ data, context }) => {
    const lovableApiKey = process.env["LOVABLE_API_KEY"];
    if (!lovableApiKey) throw new Error("AI is not configured for this workspace.");

    const existing = await context.supabase
      .from("custom_checks")
      .select("code, title")
      .eq("organization_id", data.organizationId);
    if (existing.error) throw new Error("Could not read your existing checks.");

    const { RULES } = await import("@/lib/scanner/rules");
    const { extractJson } = await import("@/lib/ai-findings");
    const { SUGGEST_MODEL, SUGGEST_SYSTEM_PROMPT, normalizeSuggestions, suggestUserPrompt } = await import("@/lib/check-suggestions");
    const { createLumeAi } = await import("@/lib/ai-gateway.server");
    const { streamText } = await import("ai");

    const budget = Math.floor(300_000 / data.artifacts.length);
    const artifacts = data.artifacts.map((artifact) => ({ name: artifact.name, content: artifact.content.slice(0, budget) }));
    const known = [
      ...RULES.map((rule) => `${rule.id} ${rule.title}`),
      ...(existing.data ?? []).map((check) => `${check.code} ${check.title}`),
    ];

    try {
      const result = streamText({
        model: createLumeAi(lovableApiKey).responses(SUGGEST_MODEL),
        maxRetries: 2,
        providerOptions: {
          openai: { reasoningEffort: "high", reasoningSummary: "auto", forceReasoning: true, store: false },
        },
        system: SUGGEST_SYSTEM_PROMPT,
        prompt: suggestUserPrompt(known, artifacts),
      });
      const text = await result.text;
      return { model: SUGGEST_MODEL, suggestions: normalizeSuggestions(extractJson(text)) };
    } catch (error) {
      const status = typeof error === "object" && error && "statusCode" in error ? Number((error as { statusCode: unknown }).statusCode) : undefined;
      if (status === 402) throw new Error("AI credits are exhausted. Add credits to continue.");
      if (status === 403) throw new Error("AI access is blocked by workspace policy.");
      if (status === 429) throw new Error("The AI service is busy; try again shortly.");
      throw new Error(error instanceof Error ? error.message : "Could not suggest checks.");
    }
  });
