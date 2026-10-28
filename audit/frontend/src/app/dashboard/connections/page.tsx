"use client";

import { useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  Activity,
  Check,
  Copy,
  Loader2,
  PlugZap,
  Plus,
  Radio,
  Server,
  Trash2,
} from "lucide-react";
import { api, API_BASE, type AgentCredential } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Dialog,
  DialogContent,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { formatDate } from "@/lib/utils";

export default function ConnectionsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Connections</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Connect on-prem discovery agents that inventory internal cryptography —
          cert stores, TLS listeners, internal PKI — and feed your posture graph.
        </p>
      </div>

      <CoverageCard />
      <AgentsCard />
    </div>
  );
}

function CoverageCard() {
  const coverage = useQuery({
    queryKey: ["agent-coverage"],
    queryFn: api.agent.coverage,
  });

  if (coverage.isLoading) return <Skeleton className="h-28 w-full" />;
  const c = coverage.data;
  if (!c || c.observations === 0) return null;

  const stats = [
    { icon: Activity, label: "Observations", value: c.observations },
    { icon: Server, label: "Assets covered", value: c.assets_covered },
    {
      icon: Radio,
      label: "Last seen",
      value: c.last_observed_at ? formatDate(c.last_observed_at) : "—",
    },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <Activity className="h-4 w-4 text-quantum" /> Agent coverage
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-3">
          {stats.map((s) => (
            <div
              key={s.label}
              className="rounded-xl border bg-card/40 p-4"
            >
              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                <s.icon className="h-3.5 w-3.5" /> {s.label}
              </div>
              <div className="mt-1 text-xl font-semibold">{s.value}</div>
            </div>
          ))}
        </div>
        {c.plugin_coverage.length > 0 && (
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-xs text-muted-foreground">Coverage:</span>
            {c.plugin_coverage.map((p) => (
              <Badge key={p} variant="secondary" className="font-mono text-xs">
                {p}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function AgentsCard() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const agents = useQuery({
    queryKey: ["agent-credentials"],
    queryFn: api.agent.credentials.list,
  });

  const [open, setOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const create = useMutation({
    mutationFn: () => api.agent.credentials.create(newName || "discovery-agent"),
    onSuccess: (res) => {
      setCreatedKey(res.key);
      setNewName("");
      qc.invalidateQueries({ queryKey: ["agent-credentials"] });
    },
    onError: (e) =>
      toast({
        title: "Could not connect agent",
        description: (e as Error).message,
        variant: "error",
      }),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.agent.credentials.revoke(id),
    onSuccess: () => {
      toast({ title: "Agent revoked", variant: "success" });
      qc.invalidateQueries({ queryKey: ["agent-credentials"] });
    },
    onError: (e) =>
      toast({
        title: "Revoke failed",
        description: (e as Error).message,
        variant: "error",
      }),
  });

  function copyKey() {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }

  const list = agents.data ?? [];

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle className="flex items-center gap-2 text-base">
          <PlugZap className="h-4 w-4 text-quantum" /> Discovery agents
        </CardTitle>
        <Button
          size="sm"
          onClick={() => {
            setCreatedKey(null);
            setOpen(true);
          }}
        >
          <Plus className="h-4 w-4" /> Connect agent
        </Button>
      </CardHeader>
      <CardContent>
        {agents.isLoading ? (
          <Skeleton className="h-40 w-full" />
        ) : list.length === 0 ? (
          <EmptyState />
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead>Connected</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {list.map((a: AgentCredential) => (
                <TableRow key={a.id}>
                  <TableCell className="font-medium">{a.name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {a.key_prefix}…
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {a.last_used_at ? formatDate(a.last_used_at) : "Never"}
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDate(a.created_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-8 w-8 text-vulnerable"
                      onClick={() => {
                        if (
                          confirm(
                            `Revoke agent "${a.name}"? It will no longer be able to upload. This cannot be undone.`
                          )
                        )
                          revoke.mutate(a.id);
                      }}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <PlugZap className="h-4 w-4 text-quantum" /> Connect discovery agent
            </DialogTitle>
          </DialogHeader>

          {createdKey ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Copy this agent key now — it grants upload access and will not be
                shown again. Put it in the agent&apos;s{" "}
                <code className="font-mono text-xs">agent.yaml</code>.
              </p>
              <div className="flex items-center gap-2 rounded-lg border border-quantum/40 bg-quantum/5 p-3">
                <code className="flex-1 break-all font-mono text-xs">
                  {createdKey}
                </code>
                <Button size="icon" variant="ghost" onClick={copyKey}>
                  {copied ? (
                    <Check className="h-4 w-4 text-safe" />
                  ) : (
                    <Copy className="h-4 w-4" />
                  )}
                </Button>
              </div>
              <p className="text-xs text-urgent">
                ⚠ Agent-scoped key. Store it in the agent host&apos;s secret store.
              </p>
              <DialogFooter>
                <Button onClick={() => setOpen(false)}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="agent-name">Agent name</Label>
                <Input
                  id="agent-name"
                  placeholder="dc-mumbai-agent"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
                <p className="text-xs text-muted-foreground">
                  A label for where this agent runs (a datacentre, a host, a segment).
                </p>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={() => create.mutate()} disabled={create.isPending}>
                  {create.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    "Connect"
                  )}
                </Button>
              </DialogFooter>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </Card>
  );
}

function EmptyState() {
  const [copied, setCopied] = useState<string | null>(null);

  const yaml = `# agent.yaml — on-prem SeQr discovery agent
api_url: ${API_BASE}
api_key: sq_live_...        # from "Connect agent" above
mode: connected             # or: air-gapped (writes a signed export file)
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

  function copy(id: string, text: string) {
    navigator.clipboard.writeText(text);
    setCopied(id);
    setTimeout(() => setCopied(null), 1500);
  }

  return (
    <div className="space-y-5 py-4">
      <div className="text-center">
        <div className="mx-auto flex h-12 w-12 items-center justify-center rounded-full bg-quantum/10">
          <PlugZap className="h-6 w-6 text-quantum" />
        </div>
        <h3 className="mt-3 text-sm font-semibold">
          Connect your first discovery agent
        </h3>
        <p className="mx-auto mt-1 max-w-md text-sm text-muted-foreground">
          Click <span className="font-medium">Connect agent</span> to mint a key,
          drop it into the agent config, and internal crypto posture starts flowing
          into your graph. No egress required — the agent can also export a signed
          file for air-gapped import.
        </p>
      </div>

      {[
        { id: "yaml", label: "agent.yaml", body: yaml },
        { id: "curl", label: "Or push directly", body: curl },
      ].map((s) => (
        <div key={s.id} className="space-y-1.5">
          <div className="flex items-center justify-between">
            <span className="text-xs font-medium text-muted-foreground">
              {s.label}
            </span>
            <Button
              size="sm"
              variant="ghost"
              className="h-7 gap-1.5 text-xs"
              onClick={() => copy(s.id, s.body)}
            >
              {copied === s.id ? (
                <Check className="h-3.5 w-3.5 text-safe" />
              ) : (
                <Copy className="h-3.5 w-3.5" />
              )}
              Copy
            </Button>
          </div>
          <pre className="overflow-x-auto rounded-lg border bg-muted/40 p-3 font-mono text-xs leading-relaxed">
            {s.body}
          </pre>
        </div>
      ))}
    </div>
  );
}
