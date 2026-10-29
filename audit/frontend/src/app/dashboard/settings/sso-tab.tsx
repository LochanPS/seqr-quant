"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, isStatus, type OIDCConfigIn, type SAMLConfigIn } from "@/lib/api";
import { errMsg } from "@/lib/utils";
import { ROLES } from "@/lib/domain";
import { Button } from "@/components/ui/button";
import { Field, Input, Select, Switch, Textarea } from "@/components/ui/field";
import { BlockSkeleton, ErrorState, Notice } from "@/components/ui/feedback";
import { Chip, StatusChip } from "@/components/ui/marks";
import { CopyButton } from "@/components/ui/code";
import { Segmented } from "@/components/ui/page";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";
import { IconPlus, IconTrash, IconExternal } from "@/components/icons";

export function SsoTab() {
  const [proto, setProto] = useState<"oidc" | "saml">("oidc");
  return (
    <div className="space-y-8">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <p className="max-w-xl text-sm text-ink-2">
          Let people sign in with your identity provider. Map IdP groups to SeQr roles, and optionally create accounts on first sign-in.
        </p>
        <Segmented
          label="Protocol"
          value={proto}
          onChange={setProto}
          options={[
            { value: "oidc", label: "OIDC" },
            { value: "saml", label: "SAML 2.0" },
          ]}
        />
      </div>
      {proto === "oidc" ? <OidcPanel /> : <SamlPanel />}
    </div>
  );
}

/** Editor for an IdP group to SeQr role map. */
function RoleMap({ value, onChange }: { value: Record<string, string>; onChange: (v: Record<string, string>) => void }) {
  const rows = Object.entries(value);
  return (
    <div>
      <p className="mb-1.5 text-[13px] font-medium text-ink-2">Group to role map</p>
      <div className="space-y-2">
        {rows.length === 0 && <p className="text-xs text-ink-3">No mappings. Everyone gets the default role.</p>}
        {rows.map(([g, r], i) => (
          <div key={i} className="flex gap-2">
            <Input
              aria-label="IdP group"
              value={g}
              placeholder="security-team"
              className="font-mono"
              onChange={(e) => {
                const next = [...rows];
                next[i] = [e.target.value, r];
                onChange(Object.fromEntries(next));
              }}
            />
            <Select
              aria-label="SeQr role"
              value={r}
              className="w-36"
              onChange={(e) => {
                const next = [...rows];
                next[i] = [g, e.target.value];
                onChange(Object.fromEntries(next));
              }}
            >
              {ROLES.map((x) => (
                <option key={x.value} value={x.value}>
                  {x.label}
                </option>
              ))}
            </Select>
            <Button type="button" variant="ghost" size="icon" aria-label="Remove mapping" onClick={() => onChange(Object.fromEntries(rows.filter((_, j) => j !== i)))}>
              <IconTrash size={16} />
            </Button>
          </div>
        ))}
        <Button type="button" variant="ghost" size="sm" onClick={() => onChange({ ...value, [`group-${rows.length + 1}`]: "viewer" })}>
          <IconPlus size={14} /> Add mapping
        </Button>
      </div>
    </div>
  );
}

function ReadOnlyRow({ label, value }: { label: string; value?: string | null }) {
  if (!value) return null;
  return (
    <div className="border-b border-rule py-3">
      <p className="eyebrow">{label}</p>
      <div className="mt-1 flex items-center gap-3">
        <code className="min-w-0 flex-1 break-all font-mono text-xs text-ink">{value}</code>
        <CopyButton text={value} compact />
      </div>
    </div>
  );
}

function OidcPanel() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const cfg = useQuery({ queryKey: ["sso-config"], queryFn: api.sso.get, retry: false });
  const [f, setF] = useState<OIDCConfigIn>({
    issuer: "",
    client_id: "",
    client_secret: "",
    display_name: "SSO",
    discovery_url: "",
    scopes: "openid email profile groups",
    groups_claim: "groups",
    group_role_map: {},
    default_role: "viewer",
    email_domain: "",
    auto_provision: true,
    enabled: true,
  });

  useEffect(() => {
    const d = cfg.data;
    if (d?.configured)
      setF((x) => ({
        ...x,
        issuer: d.issuer ?? "",
        client_id: d.client_id ?? "",
        client_secret: "",
        display_name: d.display_name ?? "SSO",
        discovery_url: d.discovery_url ?? "",
        scopes: d.scopes ?? x.scopes,
        groups_claim: d.groups_claim ?? "groups",
        group_role_map: d.group_role_map ?? {},
        default_role: d.default_role ?? "viewer",
        email_domain: d.email_domain ?? "",
        auto_provision: d.auto_provision ?? true,
        enabled: d.enabled ?? true,
      }));
  }, [cfg.data]);

  const save = useMutation({
    mutationFn: () =>
      api.sso.put({
        ...f,
        client_secret: f.client_secret || undefined,
        discovery_url: f.discovery_url || null,
        email_domain: f.email_domain || null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sso-config"] });
      toast({ title: "OIDC configuration saved", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not save OIDC", description: errMsg(e), tone: "error" }),
  });
  const remove = useMutation({
    mutationFn: api.sso.remove,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["sso-config"] });
      toast({ title: "OIDC removed", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not remove OIDC", description: errMsg(e), tone: "error" }),
  });

  if (cfg.isLoading) return <BlockSkeleton lines={8} className="max-w-2xl" />;
  if (cfg.isError)
    return isStatus(cfg.error, 403) ? (
      <Notice title="Admins only">Only organisation admins can configure single sign-on.</Notice>
    ) : (
      <ErrorState message={errMsg(cfg.error)} onRetry={() => cfg.refetch()} />
    );
  const d = cfg.data!;
  const set = <K extends keyof OIDCConfigIn>(k: K, v: OIDCConfigIn[K]) => setF((x) => ({ ...x, [k]: v }));
  const valid = f.issuer.trim() && f.client_id.trim() && (d.has_client_secret || f.client_secret);

  return (
    <div className="grid gap-12 lg:grid-cols-[1fr_340px]">
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) save.mutate();
        }}
      >
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="Issuer URL">{({ id }) => <Input id={id} value={f.issuer} onChange={(e) => set("issuer", e.target.value)} placeholder="https://login.company.com" className="font-mono" />}</Field>
          <Field label="Discovery URL" hint="Optional. Defaults to the issuer's well-known endpoint.">
            {({ id, describedBy }) => <Input id={id} value={f.discovery_url ?? ""} onChange={(e) => set("discovery_url", e.target.value)} className="font-mono" aria-describedby={describedBy} />}
          </Field>
          <Field label="Client ID">{({ id }) => <Input id={id} value={f.client_id} onChange={(e) => set("client_id", e.target.value)} className="font-mono" />}</Field>
          <Field label="Client secret" hint={d.has_client_secret ? "Stored. Leave empty to keep it." : "Write-only. Never shown again."}>
            {({ id, describedBy }) => (
              <Input id={id} type="password" autoComplete="off" value={f.client_secret ?? ""} onChange={(e) => set("client_secret", e.target.value)} aria-describedby={describedBy} />
            )}
          </Field>
          <Field label="Button label">{({ id }) => <Input id={id} value={f.display_name} onChange={(e) => set("display_name", e.target.value)} />}</Field>
          <Field label="Scopes">{({ id }) => <Input id={id} value={f.scopes} onChange={(e) => set("scopes", e.target.value)} className="font-mono" />}</Field>
          <Field label="Groups claim">{({ id }) => <Input id={id} value={f.groups_claim} onChange={(e) => set("groups_claim", e.target.value)} className="font-mono" />}</Field>
          <Field label="Allowed email domain" hint="Optional, for example company.com">
            {({ id, describedBy }) => <Input id={id} value={f.email_domain ?? ""} onChange={(e) => set("email_domain", e.target.value)} className="font-mono" aria-describedby={describedBy} />}
          </Field>
          <Field label="Default role">
            {({ id }) => (
              <Select id={id} value={f.default_role} onChange={(e) => set("default_role", e.target.value)}>
                {ROLES.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <RoleMap value={f.group_role_map} onChange={(v) => set("group_role_map", v)} />
        <div className="max-w-lg space-y-3 border-t border-rule pt-4">
          <Switch checked={f.auto_provision} onChange={(v) => set("auto_provision", v)} label="Create accounts on first sign-in" />
          <Switch checked={f.enabled} onChange={(v) => set("enabled", v)} label="Enabled" description="Turn off to keep the configuration without allowing sign-in." />
        </div>
        <div className="flex flex-wrap gap-2 border-t border-rule pt-5">
          <Button type="submit" pending={save.isPending} pendingLabel="Saving" disabled={!valid}>
            {d.configured ? "Save changes" : "Save OIDC"}
          </Button>
          {d.configured && (
            <Button
              type="button"
              variant="danger"
              pending={remove.isPending}
              pendingLabel="Removing"
              onClick={async () => {
                const ok = await confirm({ title: "Remove OIDC sign-in?", subject: d.issuer ?? "OIDC provider", body: "People who sign in through it lose that route until it is set up again.", confirmLabel: "Remove" });
                if (ok) remove.mutate();
              }}
            >
              Remove
            </Button>
          )}
        </div>
      </form>
      <aside className="border-t border-ink">
        <div className="flex items-center justify-between border-b border-rule py-3">
          <p className="eyebrow">Status</p>
          {d.configured ? <StatusChip value={d.enabled ? "enabled" : "disabled"} /> : <Chip>not configured</Chip>}
        </div>
        <ReadOnlyRow label="Redirect URI for your IdP" value={d.redirect_uri} />
        <ReadOnlyRow label="Sign-in URL" value={d.login_url} />
      </aside>
    </div>
  );
}

function SamlPanel() {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const cfg = useQuery({ queryKey: ["saml-config"], queryFn: api.saml.get, retry: false });
  const [f, setF] = useState<SAMLConfigIn>({
    idp_entity_id: "",
    idp_sso_url: "",
    idp_x509_cert: "",
    idp_slo_url: "",
    sp_entity_id: "",
    display_name: "SSO",
    want_assertions_signed: true,
    name_id_format: "",
    email_attribute: "",
    groups_attribute: "groups",
    group_role_map: {},
    default_role: "viewer",
    email_domain: "",
    auto_provision: true,
    enabled: true,
  });

  useEffect(() => {
    const d = cfg.data;
    if (d?.configured)
      setF((x) => ({
        ...x,
        ...Object.fromEntries(Object.entries(d).filter(([k, v]) => k in x && v != null)),
      }));
  }, [cfg.data]);

  const save = useMutation({
    mutationFn: () =>
      api.saml.put({
        ...f,
        idp_slo_url: f.idp_slo_url || null,
        sp_entity_id: f.sp_entity_id || null,
        name_id_format: f.name_id_format || null,
        email_attribute: f.email_attribute || null,
        email_domain: f.email_domain || null,
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["saml-config"] });
      toast({ title: "SAML configuration saved", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not save SAML", description: errMsg(e), tone: "error" }),
  });
  const remove = useMutation({
    mutationFn: api.saml.remove,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["saml-config"] });
      toast({ title: "SAML removed", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not remove SAML", description: errMsg(e), tone: "error" }),
  });

  if (cfg.isLoading) return <BlockSkeleton lines={8} className="max-w-2xl" />;
  if (cfg.isError)
    return isStatus(cfg.error, 403) ? (
      <Notice title="Admins only">Only organisation admins can configure single sign-on.</Notice>
    ) : (
      <ErrorState message={errMsg(cfg.error)} onRetry={() => cfg.refetch()} />
    );
  const d = cfg.data!;
  const set = <K extends keyof SAMLConfigIn>(k: K, v: SAMLConfigIn[K]) => setF((x) => ({ ...x, [k]: v }));
  const valid = f.idp_entity_id.trim() && f.idp_sso_url.trim() && f.idp_x509_cert.trim();

  return (
    <div className="grid gap-12 lg:grid-cols-[1fr_340px]">
      <form
        className="space-y-5"
        onSubmit={(e) => {
          e.preventDefault();
          if (valid) save.mutate();
        }}
      >
        <div className="grid gap-5 sm:grid-cols-2">
          <Field label="IdP entity ID">{({ id }) => <Input id={id} value={f.idp_entity_id} onChange={(e) => set("idp_entity_id", e.target.value)} className="font-mono" />}</Field>
          <Field label="IdP SSO URL">{({ id }) => <Input id={id} value={f.idp_sso_url} onChange={(e) => set("idp_sso_url", e.target.value)} className="font-mono" />}</Field>
          <Field label="IdP SLO URL" hint="Optional">
            {({ id, describedBy }) => <Input id={id} value={f.idp_slo_url ?? ""} onChange={(e) => set("idp_slo_url", e.target.value)} className="font-mono" aria-describedby={describedBy} />}
          </Field>
          <Field label="SP entity ID" hint="Optional. Defaults to the metadata URL.">
            {({ id, describedBy }) => <Input id={id} value={f.sp_entity_id ?? ""} onChange={(e) => set("sp_entity_id", e.target.value)} className="font-mono" aria-describedby={describedBy} />}
          </Field>
          <Field label="Button label">{({ id }) => <Input id={id} value={f.display_name} onChange={(e) => set("display_name", e.target.value)} />}</Field>
          <Field label="NameID format" hint="Optional">
            {({ id, describedBy }) => (
              <Input id={id} value={f.name_id_format ?? ""} onChange={(e) => set("name_id_format", e.target.value)} placeholder="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" className="font-mono" aria-describedby={describedBy} />
            )}
          </Field>
          <Field label="Email attribute" hint="Optional">
            {({ id, describedBy }) => <Input id={id} value={f.email_attribute ?? ""} onChange={(e) => set("email_attribute", e.target.value)} className="font-mono" aria-describedby={describedBy} />}
          </Field>
          <Field label="Groups attribute">{({ id }) => <Input id={id} value={f.groups_attribute} onChange={(e) => set("groups_attribute", e.target.value)} className="font-mono" />}</Field>
          <Field label="Allowed email domain" hint="Optional">
            {({ id, describedBy }) => <Input id={id} value={f.email_domain ?? ""} onChange={(e) => set("email_domain", e.target.value)} className="font-mono" aria-describedby={describedBy} />}
          </Field>
          <Field label="Default role">
            {({ id }) => (
              <Select id={id} value={f.default_role} onChange={(e) => set("default_role", e.target.value)}>
                {ROLES.map((r) => (
                  <option key={r.value} value={r.value}>
                    {r.label}
                  </option>
                ))}
              </Select>
            )}
          </Field>
        </div>
        <Field label="IdP x509 certificate" hint="PEM, including the BEGIN and END lines.">
          {({ id, describedBy }) => (
            <Textarea id={id} value={f.idp_x509_cert} onChange={(e) => set("idp_x509_cert", e.target.value)} className="min-h-[140px] font-mono text-xs" aria-describedby={describedBy} spellCheck={false} />
          )}
        </Field>
        <RoleMap value={f.group_role_map} onChange={(v) => set("group_role_map", v)} />
        <div className="max-w-lg space-y-3 border-t border-rule pt-4">
          <Switch checked={f.want_assertions_signed} onChange={(v) => set("want_assertions_signed", v)} label="Require signed assertions" />
          <Switch checked={f.auto_provision} onChange={(v) => set("auto_provision", v)} label="Create accounts on first sign-in" />
          <Switch checked={f.enabled} onChange={(v) => set("enabled", v)} label="Enabled" />
        </div>
        <div className="flex flex-wrap gap-2 border-t border-rule pt-5">
          <Button type="submit" pending={save.isPending} pendingLabel="Saving" disabled={!valid}>
            {d.configured ? "Save changes" : "Save SAML"}
          </Button>
          {d.configured && (
            <Button
              type="button"
              variant="danger"
              pending={remove.isPending}
              pendingLabel="Removing"
              onClick={async () => {
                const ok = await confirm({ title: "Remove SAML sign-in?", subject: d.idp_entity_id ?? "SAML provider", confirmLabel: "Remove" });
                if (ok) remove.mutate();
              }}
            >
              Remove
            </Button>
          )}
        </div>
      </form>
      <aside className="border-t border-ink">
        <div className="flex items-center justify-between border-b border-rule py-3">
          <p className="eyebrow">Status</p>
          {d.configured ? <StatusChip value={d.enabled ? "enabled" : "disabled"} /> : <Chip>not configured</Chip>}
        </div>
        <ReadOnlyRow label="ACS URL" value={d.acs_url} />
        <ReadOnlyRow label="Metadata URL" value={d.metadata_url ?? api.saml.metadataUrl(d.id)} />
        <div className="py-4">
          <Button asChild variant="secondary" size="sm">
            <a href={api.saml.metadataUrl(d.id)} target="_blank" rel="noopener noreferrer">
              <IconExternal size={14} /> Download SP metadata
            </a>
          </Button>
        </div>
      </aside>
    </div>
  );
}
