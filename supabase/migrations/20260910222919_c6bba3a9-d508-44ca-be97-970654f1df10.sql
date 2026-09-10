ALTER TABLE public.skill_scans
  ADD COLUMN IF NOT EXISTS ai_recommendation text NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS ai_recommendation_reason text NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS ai_recommendation_confidence integer NOT NULL DEFAULT 0,
  ADD COLUMN IF NOT EXISTS recommendation_status text NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS recommendation_decided_by uuid,
  ADD COLUMN IF NOT EXISTS recommendation_decided_at timestamp with time zone;

ALTER TABLE public.skill_scans
  ADD CONSTRAINT skill_scans_ai_recommendation_check CHECK (ai_recommendation IN ('none','quarantine','allow')),
  ADD CONSTRAINT skill_scans_recommendation_status_check CHECK (recommendation_status IN ('none','pending','approved','rejected'));

ALTER TABLE public.scan_findings DROP CONSTRAINT scan_findings_scan_id_fkey;
ALTER TABLE public.scan_findings
  ADD CONSTRAINT scan_findings_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.skill_scans(id) ON DELETE CASCADE;

CREATE POLICY "Analysts can delete scans" ON public.skill_scans
  FOR DELETE TO authenticated
  USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role, 'analyst'::organization_role]));

CREATE POLICY "Analysts can delete scan findings" ON public.scan_findings
  FOR DELETE TO authenticated
  USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role, 'analyst'::organization_role]));