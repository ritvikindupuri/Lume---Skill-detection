ALTER POLICY "Admins can add memberships" ON public.organization_members
WITH CHECK (
  (
    user_id = auth.uid()
    AND role = 'admin'::public.organization_role
    AND EXISTS (
      SELECT 1
      FROM public.organizations organization
      WHERE organization.id = organization_id
        AND organization.created_by = auth.uid()
    )
  )
  OR private.has_organization_role(
    organization_id,
    auth.uid(),
    ARRAY['admin']::public.organization_role[]
  )
);