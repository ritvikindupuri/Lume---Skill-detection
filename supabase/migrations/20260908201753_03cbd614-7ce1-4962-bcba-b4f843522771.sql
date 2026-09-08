CREATE SCHEMA IF NOT EXISTS private;
REVOKE ALL ON SCHEMA private FROM PUBLIC, anon;
GRANT USAGE ON SCHEMA private TO authenticated;

CREATE OR REPLACE FUNCTION private.is_organization_member(_organization_id uuid, _user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = _organization_id AND user_id = _user_id
  )
$$;

CREATE OR REPLACE FUNCTION private.has_organization_role(_organization_id uuid, _user_id uuid, _roles public.organization_role[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = _organization_id AND user_id = _user_id AND role = ANY(_roles)
  )
$$;

REVOKE ALL ON FUNCTION private.is_organization_member(uuid, uuid) FROM PUBLIC, anon;
REVOKE ALL ON FUNCTION private.has_organization_role(uuid, uuid, public.organization_role[]) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION private.is_organization_member(uuid, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION private.has_organization_role(uuid, uuid, public.organization_role[]) TO authenticated;

ALTER POLICY "Members can view organizations" ON public.organizations USING (private.is_organization_member(id, auth.uid()));
ALTER POLICY "Admins can update organizations" ON public.organizations USING (private.has_organization_role(id, auth.uid(), ARRAY['admin']::public.organization_role[])) WITH CHECK (private.has_organization_role(id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Admins can delete organizations" ON public.organizations USING (private.has_organization_role(id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Members can view memberships" ON public.organization_members USING (user_id = auth.uid() OR private.is_organization_member(organization_id, auth.uid()));
ALTER POLICY "Admins can add memberships" ON public.organization_members WITH CHECK (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Admins can update memberships" ON public.organization_members USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[])) WITH CHECK (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Admins can delete memberships" ON public.organization_members USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Members can view risk settings" ON public.risk_settings USING (private.is_organization_member(organization_id, auth.uid()));
ALTER POLICY "Admins can create risk settings" ON public.risk_settings WITH CHECK (updated_by = auth.uid() AND private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Admins can update risk settings" ON public.risk_settings USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[])) WITH CHECK (updated_by = auth.uid() AND private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Admins can delete risk settings" ON public.risk_settings USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Members can view scans" ON public.skill_scans USING (private.is_organization_member(organization_id, auth.uid()));
ALTER POLICY "Analysts can create scans" ON public.skill_scans WITH CHECK (scanned_by = auth.uid() AND private.has_organization_role(organization_id, auth.uid(), ARRAY['admin','analyst']::public.organization_role[]));
ALTER POLICY "Admins can delete scans" ON public.skill_scans USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
ALTER POLICY "Members can view findings" ON public.scan_findings USING (private.is_organization_member(organization_id, auth.uid()));
ALTER POLICY "Analysts can create findings" ON public.scan_findings WITH CHECK (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin','analyst']::public.organization_role[]) AND EXISTS (SELECT 1 FROM public.skill_scans s WHERE s.id = scan_id AND s.organization_id = organization_id AND s.scanned_by = auth.uid()));
ALTER POLICY "Admins can delete findings" ON public.scan_findings USING (private.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));

CREATE OR REPLACE FUNCTION public.create_organization_with_admin(_name text, _slug text)
RETURNS uuid LANGUAGE plpgsql SECURITY INVOKER SET search_path = public AS $$
DECLARE _org_id uuid;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Authentication required'; END IF;
  INSERT INTO public.organizations(name, slug, created_by) VALUES (_name, _slug, auth.uid()) RETURNING id INTO _org_id;
  INSERT INTO public.organization_members(organization_id, user_id, role) VALUES (_org_id, auth.uid(), 'admin');
  INSERT INTO public.risk_settings(organization_id, updated_by) VALUES (_org_id, auth.uid());
  RETURN _org_id;
END;
$$;
REVOKE ALL ON FUNCTION public.create_organization_with_admin(text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_organization_with_admin(text, text) TO authenticated;

DROP FUNCTION public.is_organization_member(uuid, uuid);
DROP FUNCTION public.has_organization_role(uuid, uuid, public.organization_role[]);