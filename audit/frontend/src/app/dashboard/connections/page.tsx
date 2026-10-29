"use client";

import { Suspense, useEffect, useState } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, API_BASE, type AgentCredentialCreated } from "@/lib/api";
import { errMsg, humanize } from "@/lib/utils";
import { PageHeader, RelTime, Section } from "@/components/ui/page";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Dialog, DialogContent, DialogFooter } from "@/components/ui/dialog";
import { EmptyState, ErrorState, ReadoutSkeleton, TableSkeleton } from "@/components/ui/feedback";
import { Chip, StatusChip } from "@/components/ui/marks";
import { CountUp, Readout, ReadoutStrip } from "@/components/ui/numbers";
import { CodeBlock } from "@/components/ui/code";
import { SecretOnce } from "@/components/ui/secret";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";
import { IconPlus } from "@/components/icons";

const KNOWN_PLUGINS = ["tls_kex", "tls_cert", "ssh_key", "cert_store", "proxy_conf", "pkcs11", "k8s", "cloud"];

function ConnectionsInner() {
  const params = useSearchParams();
  const router = useRouter();
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (params.get("new") === "1") {
      setOpen(true);
      router.replace("/dashboard/connections");
    }
  }, [params, router]);

  return (
    <div className="space-y-14">
      <PageHeader
        eyebrow="Discovery"
        title="Connections"
        description="On-prem discovery agents inventory what the internet cannot see: certificate stores, internal TLS listeners, proxies, HSMs and Kubernetes secrets. Their observations feed the graph."
        actions={
          <Button onClick={() => setOpen(true)}>
            <IconPlus size={16} /> Connect agent
          </Button>
        }
      />
      <Coverage />
      <Credentials onConnect={() => setOpen(true)} />
      <Setup />
      <ConnectDialog open={open} onOpenChange={setOpen} />
    </div>
  );
}

function Coverage() {
  const c = useQuery({ queryKey: ["agent-coverage"], queryFn: api.agent.coverage });
  if (c.isLoading) return <ReadoutSkeleton />;
  if (c.isError) return <ErrorState message={errMsg(c.error)} onRetry={() => c.refetch()} />;
  const d = c.data!;
  return (
    <Section index="01" title="Coverage" description="What the agent plane has reported so far.">
      <ReadoutStrip cols={4}>
        <Readout label="Agent" value={<span className="text-2xl">{d.agent ?? "none yet"}</span>} />
        <Readout label="Observations" value={<CountUp value={d.observations} />} />
        <Readout label="Assets covered" value={<CountUp value={d.assets_covered} />} />
        <Readout label="Last observed" value={<span className="text-2xl"><RelTime value={d.last_observed_at} /></span>} foot={d.last_event_at ? <>last event <RelTime value={d.last_event_at} /></> : undefined} />
      </ReadoutStrip>
      <div className="mt-5">
        <p className="eyebrow mb-2">Collectors</p>
        <div className="flex flex-wrap gap-2">
          {Array.from(new Set([...KNOWN_PLUGINS, ...d.plugin_coverage])).map((p) => (
            <Chip key={p} tone={d.plugin_coverage.includes(p) ? "safe" : "neutral"}>
              {humanize(p)} {d.plugin_coverage.includes(p) ? "reporting" : "idle"}
            </Chip>
          ))}
        </div>
      </div>
    </Section>
  );
}

function Credentials({ onConnect }: { onConnect: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const creds = useQuery({ queryKey: ["agent-credentials"], queryFn: api.agent.credentials.list });
  const revoke = useMutation({
    mutationFn: (id: string) => api.agent.credentials.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["agent-credentials"] });
      toast({ title: "Credential revoked", description: "The agent can no longer push observations.", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not revoke", description: errMsg(e), tone: "error" }),
  });

  return (
    <Section index="02" title="Agent credentials" description="Each agent signs in with its own key, scoped to pushing observations.">
      {creds.isLoading ? (
        <TableSkeleton cols={6} rows={3} />
      ) : creds.isError ? (
        <ErrorState message={errMsg(creds.error)} onRetry={() => creds.refetch()} />
      ) : !creds.data?.length ? (
        <EmptyState title="No agents connected" body="Mint a key for your first agent, then follow the setup below." action={{ label: "Connect agent", onClick: onConnect }} />
      ) : (
        <Table>
          <THead>
            <tr>
              <Th>Name</Th>
              <Th>Prefix</Th>
              <Th>Last seen</Th>
              <Th>Connected</Th>
              <Th>Expires</Th>
              <Th align="right">
                <span className="sr-only">Actions</span>
              </Th>
            </tr>
          </THead>
          <TBody>
            {creds.data.map((c) => (
              <Tr key={c.id}>
                <Td label="Name">{c.name}</Td>
                <Td label="Prefix" mono>
                  {c.key_prefix}
                </Td>
                <Td label="Last seen" className="text-ink-2">
                  <RelTime value={c.last_used_at} />
                </Td>
                <Td label="Connected">
                  <StatusChip value={c.last_used_at ? "active" : "pending"} />
                </Td>
                <Td label="Expires" className="text-ink-2">
                  {c.expires_at ? <RelTime value={c.expires_at} /> : "never"}
                </Td>
                <Td align="right">
                  <Button
                    variant="danger"
                    size="sm"
                    pending={revoke.isPending && revoke.variables === c.id}
                    pendingLabel="Revoking"
                    onClick={async () => {
                      const ok = await confirm({
                        title: "Revoke this agent credential?",
                        subject: `${c.name} · ${c.key_prefix}`,
                        body: "The agent using it stops reporting immediately. Observations already received stay in the graph.",
                        confirmLabel: "Revoke",
                      });
                      if (ok) revoke.mutate(c.id);
                    }}
                  >
                    Revoke
                  </Button>
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      )}
    </Section>
  );
}

function ConnectDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [expires, setExpires] = useState("");
  const [created, setCreated] = useState<AgentCredentialCreated | null>(null);

  useEffect(() => {
    if (!open) {
      setName("");
      setExpires("");
      setCreated(null);
    }
  }, [open]);

  const create = useMutation({
    mutationFn: () => api.agent.credentials.create(name.trim() || "discovery-agent", expires ? new Date(expires).toISOString() : null),
    onSuccess: (c) => {
      setCreated(c);
      qc.invalidateQueries({ queryKey: ["agent-credentials"] });
    },
    onError: (e) => toast({ title: "Could not create the credential", description: errMsg(e), tone: "error" }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={created ? "Agent key created" : "Connect an agent"} description={created ? undefined : "Mint a key for one discovery agent. Use one key per agent so you can revoke them separately."}>
        {created ? (
          <>
            <SecretOnce label={`Key for ${created.name}`} value={created.key} />
            <DialogFooter>
              <Button onClick={() => onOpenChange(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              create.mutate();
            }}
            className="space-y-5"
          >
            <Field label="Agent name">
              {({ id }) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} placeholder="dc-mumbai-agent" autoFocus />}
            </Field>
            <Field label="Expires" hint="Optional. Leave empty for a key that does not expire.">
              {({ id, describedBy }) => (
                <Input id={id} type="date" value={expires} min={new Date().toISOString().slice(0, 10)} onChange={(e) => setExpires(e.target.value)} aria-describedby={describedBy} className="w-48 font-mono" />
              )}
            </Field>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" pending={create.isPending} pendingLabel="Creating">
                Create key
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}

function Setup() {
  const yaml = `# agent.yaml for the on-prem SeQr discovery agent
api_url: ${API_BASE}
api_key: sq_live_...        # from "Connect agent"
mode: connected             # or air-gapped: writes a signed export file
plugins: [tls, cert_store, proxy_conf, pkcs11, ssh, k8s, cloud]
schedule: "0 * * * *"       # hourly`;

  const curl = `curl -X POST ${API_BASE}/agent/observations \\
  -H "Authorization: Bearer sq_live_..." \\
  -H "Content-Type: application/json" \\
  -d '{
    "agent": "dc-mumbai-agent",
    "observations": [
      {
        "asset_key": "lb-01.internal",
        "asset_type": "load_balancer",
        "location_type": "tls_kex",
        "algorithm": "X25519",
        "algorithm_family": "ECC",
        "quantum_status": "vulnerable"
      }
    ]
  }'`;

  const steps = [
    { t: "Mint a key", b: "Select Connect agent above. Copy the key; it is shown once." },
    { t: "Configure the agent", b: "Save this as agent.yaml next to the agent binary, with your key in place of the placeholder.", code: yaml, file: "agent.yaml" },
    { t: "Run it", b: "Start the agent with seqr-agent run. In air-gapped mode use seqr-agent export, then import the signed file from an admin session." },
    { t: "Or push directly", b: "Any system can post observations with the same key.", code: curl, file: "push-observation.sh" },
  ];

  return (
    <Section index="03" title="Setup" description="Four steps from nothing to a reporting agent.">
      <ol className="border-t border-ink">
        {steps.map((s, i) => (
          <li key={s.t} className="grid gap-4 border-b border-rule py-6 lg:grid-cols-[260px_1fr]">
            <div>
              <p className="font-mono text-xs text-ink-3">{String(i + 1).padStart(2, "0")}</p>
              <p className="mt-1 font-display text-xl text-ink">{s.t}</p>
              <p className="mt-1 text-sm text-ink-2">{s.b}</p>
            </div>
            {s.code && <CodeBlock code={s.code} filename={s.file} />}
          </li>
        ))}
      </ol>
    </Section>
  );
}

export default function ConnectionsPage() {
  return (
    <Suspense fallback={<ReadoutSkeleton />}>
      <ConnectionsInner />
    </Suspense>
  );
}
