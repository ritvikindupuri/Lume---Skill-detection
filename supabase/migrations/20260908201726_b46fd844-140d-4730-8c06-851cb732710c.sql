CREATE TYPE public.organization_role AS ENUM ('admin', 'analyst', 'viewer');

CREATE TABLE public.organizations (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 120),
  slug text NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  created_by uuid NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.organizations TO authenticated;
GRANT ALL ON public.organizations TO service_role;
ALTER TABLE public.organizations ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.organization_members (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  user_id uuid NOT NULL,
  role public.organization_role NOT NULL DEFAULT 'viewer',
  created_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE (organization_id, user_id)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.organization_members TO authenticated;
GRANT ALL ON public.organization_members TO service_role;
ALTER TABLE public.organization_members ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.risk_settings (
  organization_id uuid PRIMARY KEY REFERENCES public.organizations(id) ON DELETE CASCADE,
  acceptable_score integer NOT NULL DEFAULT 18 CHECK (acceptable_score BETWEEN 0 AND 100),
  malicious_score integer NOT NULL DEFAULT 55 CHECK (malicious_score BETWEEN 1 AND 100),
  block_on_critical boolean NOT NULL DEFAULT true,
  updated_by uuid NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (acceptable_score < malicious_score)
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.risk_settings TO authenticated;
GRANT ALL ON public.risk_settings TO service_role;
ALTER TABLE public.risk_settings ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.skill_scans (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  scanned_by uuid NOT NULL,
  artifact_name text NOT NULL CHECK (char_length(artifact_name) BETWEEN 1 AND 255),
  declared_name text,
  sha256 text NOT NULL CHECK (sha256 ~ '^[a-f0-9]{64}$'),
  score integer NOT NULL CHECK (score BETWEEN 0 AND 100),
  verdict text NOT NULL CHECK (verdict IN ('clean', 'suspicious', 'malicious')),
  findings_count integer NOT NULL DEFAULT 0 CHECK (findings_count >= 0),
  files_count integer NOT NULL DEFAULT 0 CHECK (files_count >= 0),
  rules_evaluated integer NOT NULL DEFAULT 35 CHECK (rules_evaluated > 0),
  severity_counts jsonb NOT NULL DEFAULT '{"critical":0,"high":0,"medium":0,"low":0}'::jsonb,
  scanned_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.skill_scans TO authenticated;
GRANT ALL ON public.skill_scans TO service_role;
ALTER TABLE public.skill_scans ENABLE ROW LEVEL SECURITY;

CREATE TABLE public.scan_findings (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  scan_id uuid NOT NULL REFERENCES public.skill_scans(id) ON DELETE CASCADE,
  organization_id uuid NOT NULL REFERENCES public.organizations(id) ON DELETE CASCADE,
  rule_id text NOT NULL,
  title text NOT NULL,
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low')),
  category text NOT NULL,
  file_path text NOT NULL,
  line_number integer NOT NULL DEFAULT 0 CHECK (line_number >= 0),
  evidence text NOT NULL,
  remediation text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
GRANT SELECT, INSERT, UPDATE, DELETE ON public.scan_findings TO authenticated;
GRANT ALL ON public.scan_findings TO service_role;
ALTER TABLE public.scan_findings ENABLE ROW LEVEL SECURITY;

CREATE OR REPLACE FUNCTION public.is_organization_member(_organization_id uuid, _user_id uuid)
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = _organization_id AND user_id = _user_id
  )
$$;

CREATE OR REPLACE FUNCTION public.has_organization_role(_organization_id uuid, _user_id uuid, _roles public.organization_role[])
RETURNS boolean LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_members
    WHERE organization_id = _organization_id AND user_id = _user_id AND role = ANY(_roles)
  )
$$;

GRANT EXECUTE ON FUNCTION public.is_organization_member(uuid, uuid) TO authenticated;
GRANT EXECUTE ON FUNCTION public.has_organization_role(uuid, uuid, public.organization_role[]) TO authenticated;

CREATE POLICY "Members can view organizations" ON public.organizations FOR SELECT TO authenticated USING (public.is_organization_member(id, auth.uid()));
CREATE POLICY "Users can create organizations" ON public.organizations FOR INSERT TO authenticated WITH CHECK (created_by = auth.uid());
CREATE POLICY "Admins can update organizations" ON public.organizations FOR UPDATE TO authenticated USING (public.has_organization_role(id, auth.uid(), ARRAY['admin']::public.organization_role[])) WITH CHECK (public.has_organization_role(id, auth.uid(), ARRAY['admin']::public.organization_role[]));
CREATE POLICY "Admins can delete organizations" ON public.organizations FOR DELETE TO authenticated USING (public.has_organization_role(id, auth.uid(), ARRAY['admin']::public.organization_role[]));

CREATE POLICY "Members can view memberships" ON public.organization_members FOR SELECT TO authenticated USING (user_id = auth.uid() OR public.is_organization_member(organization_id, auth.uid()));
CREATE POLICY "Organization creators can add initial membership" ON public.organization_members FOR INSERT TO authenticated WITH CHECK (user_id = auth.uid() AND role = 'admin' AND EXISTS (SELECT 1 FROM public.organizations o WHERE o.id = organization_id AND o.created_by = auth.uid()));
CREATE POLICY "Admins can add memberships" ON public.organization_members FOR INSERT TO authenticated WITH CHECK (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
CREATE POLICY "Admins can update memberships" ON public.organization_members FOR UPDATE TO authenticated USING (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[])) WITH CHECK (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
CREATE POLICY "Admins can delete memberships" ON public.organization_members FOR DELETE TO authenticated USING (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));

CREATE POLICY "Members can view risk settings" ON public.risk_settings FOR SELECT TO authenticated USING (public.is_organization_member(organization_id, auth.uid()));
CREATE POLICY "Admins can create risk settings" ON public.risk_settings FOR INSERT TO authenticated WITH CHECK (updated_by = auth.uid() AND public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
CREATE POLICY "Admins can update risk settings" ON public.risk_settings FOR UPDATE TO authenticated USING (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[])) WITH CHECK (updated_by = auth.uid() AND public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));
CREATE POLICY "Admins can delete risk settings" ON public.risk_settings FOR DELETE TO authenticated USING (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));

CREATE POLICY "Members can view scans" ON public.skill_scans FOR SELECT TO authenticated USING (public.is_organization_member(organization_id, auth.uid()));
CREATE POLICY "Analysts can create scans" ON public.skill_scans FOR INSERT TO authenticated WITH CHECK (scanned_by = auth.uid() AND public.has_organization_role(organization_id, auth.uid(), ARRAY['admin','analyst']::public.organization_role[]));
CREATE POLICY "Admins can delete scans" ON public.skill_scans FOR DELETE TO authenticated USING (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));

CREATE POLICY "Members can view findings" ON public.scan_findings FOR SELECT TO authenticated USING (public.is_organization_member(organization_id, auth.uid()));
CREATE POLICY "Analysts can create findings" ON public.scan_findings FOR INSERT TO authenticated WITH CHECK (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin','analyst']::public.organization_role[]) AND EXISTS (SELECT 1 FROM public.skill_scans s WHERE s.id = scan_id AND s.organization_id = organization_id AND s.scanned_by = auth.uid()));
CREATE POLICY "Admins can delete findings" ON public.scan_findings FOR DELETE TO authenticated USING (public.has_organization_role(organization_id, auth.uid(), ARRAY['admin']::public.organization_role[]));

CREATE OR REPLACE FUNCTION public.create_organization_with_admin(_name text, _slug text)
RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE _org_id uuid;
BEGIN
  IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Authentication required'; END IF;
  INSERT INTO public.organizations(name, slug, created_by) VALUES (_name, _slug, auth.uid()) RETURNING id INTO _org_id;
  INSERT INTO public.organization_members(organization_id, user_id, role) VALUES (_org_id, auth.uid(), 'admin');
  INSERT INTO public.risk_settings(organization_id, updated_by) VALUES (_org_id, auth.uid());
  RETURN _org_id;
END;
$$;
GRANT EXECUTE ON FUNCTION public.create_organization_with_admin(text, text) TO authenticated;

CREATE OR REPLACE FUNCTION public.set_updated_at()
RETURNS trigger LANGUAGE plpgsql SET search_path = public AS $$ BEGIN NEW.updated_at = now(); RETURN NEW; END; $$;
CREATE TRIGGER organizations_updated_at BEFORE UPDATE ON public.organizations FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();
CREATE TRIGGER risk_settings_updated_at BEFORE UPDATE ON public.risk_settings FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

CREATE INDEX organization_members_user_idx ON public.organization_members(user_id);
CREATE INDEX skill_scans_org_date_idx ON public.skill_scans(organization_id, scanned_at DESC);
CREATE INDEX scan_findings_scan_idx ON public.scan_findings(scan_id);