import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireSupabaseAuth } from "@/integrations/supabase/auth-middleware";
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
        .select("id, artifact_name, declared_name, score, verdict, findings_count, files_count, severity_counts, scanned_at")
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
      .select("id, rule_id, title, severity, category, file_path, line_number, evidence, remediation, confidence, status")
      .eq("scan_id", data.scanId)
      .order("severity", { ascending: true });
    if (result.error) throw new Error("Could not load the findings for this scan.");
    return result.data ?? [];
  });

export const reviewFinding = createServerFn({ method: "POST" })
  .middleware([requireSupabaseAuth])
  .inputValidator((input) => z.object({
    findingId: z.string().uuid(),
    status: z.enum(["open", "confirmed", "false_positive"]),
  }).parse(input))
  .handler(async ({ data, context }) => {
    const result = await context.supabase
      .from("scan_findings")
      .update({ status: data.status, reviewed_by: context.userId, reviewed_at: new Date().toISOString() })
      .eq("id", data.findingId);
    if (result.error) throw new Error("Could not save this review decision.");
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
