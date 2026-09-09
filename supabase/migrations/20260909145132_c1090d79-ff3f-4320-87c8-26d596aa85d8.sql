CREATE OR REPLACE FUNCTION public.create_organization_with_admin(_name text, _slug text)
RETURNS uuid
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  _org_id uuid;
  _user_id uuid := auth.uid();
BEGIN
  IF _user_id IS NULL THEN
    RAISE EXCEPTION 'Authentication required';
  END IF;

  IF char_length(btrim(_name)) < 2 OR char_length(btrim(_name)) > 120 THEN
    RAISE EXCEPTION 'Workspace name must be between 2 and 120 characters';
  END IF;

  INSERT INTO public.organizations(name, slug, created_by)
  VALUES (btrim(_name), _slug, _user_id)
  RETURNING id INTO _org_id;

  INSERT INTO public.organization_members(organization_id, user_id, role)
  VALUES (_org_id, _user_id, 'admin');

  INSERT INTO public.risk_settings(organization_id, updated_by)
  VALUES (_org_id, _user_id);

  RETURN _org_id;
END;
$$;

REVOKE ALL ON FUNCTION public.create_organization_with_admin(text, text) FROM PUBLIC, anon;
GRANT EXECUTE ON FUNCTION public.create_organization_with_admin(text, text) TO authenticated;