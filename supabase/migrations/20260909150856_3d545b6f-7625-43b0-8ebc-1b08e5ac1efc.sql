ALTER TABLE public.scan_findings
  ADD COLUMN IF NOT EXISTS confidence integer NOT NULL DEFAULT 70,
  ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'open',
  ADD COLUMN IF NOT EXISTS reviewed_by uuid,
  ADD COLUMN IF NOT EXISTS reviewed_at timestamptz;

ALTER TABLE public.scan_findings
  ADD CONSTRAINT scan_findings_status_check CHECK (status IN ('open','confirmed','false_positive'));

ALTER TABLE public.scan_findings
  ADD CONSTRAINT scan_findings_confidence_check CHECK (confidence BETWEEN 0 AND 100);

CREATE POLICY "Analysts can review findings"
ON public.scan_findings FOR UPDATE TO authenticated
USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role,'analyst'::organization_role]))
WITH CHECK (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role,'analyst'::organization_role]));

CREATE TABLE public.custom_checks (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  code text NOT NULL,
  title text NOT NULL,
  severity text NOT NULL,
  layer text NOT NULL,
  pattern text NOT NULL,
  rationale text NOT NULL DEFAULT '',
  remediation text NOT NULL DEFAULT '',
  confidence integer NOT NULL DEFAULT 60,
  enabled boolean NOT NULL DEFAULT true,
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT custom_checks_severity_check CHECK (severity IN ('critical','high','medium','low')),
  CONSTRAINT custom_checks_confidence_check CHECK (confidence BETWEEN 0 AND 100),
  CONSTRAINT custom_checks_code_unique UNIQUE (organization_id, code)
);

GRANT SELECT, INSERT, UPDATE, DELETE ON public.custom_checks TO authenticated;
GRANT ALL ON public.custom_checks TO service_role;

ALTER TABLE public.custom_checks ENABLE ROW LEVEL SECURITY;

CREATE POLICY "Members can view custom checks"
ON public.custom_checks FOR SELECT TO authenticated
USING (private.is_organization_member(organization_id, auth.uid()));

CREATE POLICY "Analysts can create custom checks"
ON public.custom_checks FOR INSERT TO authenticated
WITH CHECK (created_by = auth.uid() AND private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role,'analyst'::organization_role]));

CREATE POLICY "Analysts can update custom checks"
ON public.custom_checks FOR UPDATE TO authenticated
USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role,'analyst'::organization_role]))
WITH CHECK (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role,'analyst'::organization_role]));

CREATE POLICY "Admins can delete custom checks"
ON public.custom_checks FOR DELETE TO authenticated
USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role]));

CREATE TRIGGER custom_checks_set_updated_at
BEFORE UPDATE ON public.custom_checks
FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();