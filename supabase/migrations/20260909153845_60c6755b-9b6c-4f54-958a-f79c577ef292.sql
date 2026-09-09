ALTER TABLE public.skill_scans
  ADD COLUMN IF NOT EXISTS containment text NOT NULL DEFAULT 'none',
  ADD COLUMN IF NOT EXISTS contained_at timestamptz,
  ADD COLUMN IF NOT EXISTS contained_by uuid;

ALTER TABLE public.skill_scans
  DROP CONSTRAINT IF EXISTS skill_scans_containment_check;
ALTER TABLE public.skill_scans
  ADD CONSTRAINT skill_scans_containment_check CHECK (containment IN ('none','quarantined','cleared'));

GRANT UPDATE ON public.skill_scans TO authenticated;

DROP POLICY IF EXISTS "Analysts can update scans" ON public.skill_scans;
CREATE POLICY "Analysts can update scans"
ON public.skill_scans FOR UPDATE TO authenticated
USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role, 'analyst'::organization_role]))
WITH CHECK (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin'::organization_role, 'analyst'::organization_role]));