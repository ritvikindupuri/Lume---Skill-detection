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
    const base = data.name.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 48) || "company";
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
      declared_name: data.declaredName,
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
      })));
      if (findings.error) throw new Error("Scan saved, but its findings could not be stored.");
    }
    return { id: inserted.data.id };
  });