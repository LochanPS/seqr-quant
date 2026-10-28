"use client";

import { useEffect, useState } from "react";
import { useTheme } from "next-themes";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Check, Copy, Loader2, Plus, Trash2, KeyRound } from "lucide-react";
import { api } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
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
import { cn } from "@/lib/utils";

export default function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="mt-1 text-sm text-muted-foreground">
          Manage your organisation, API access, and appearance.
        </p>
      </div>

      <Tabs defaultValue="org">
        <TabsList>
          <TabsTrigger value="org">Organisation</TabsTrigger>
          <TabsTrigger value="keys">API Keys</TabsTrigger>
          <TabsTrigger value="team">Team</TabsTrigger>
          <TabsTrigger value="appearance">Appearance</TabsTrigger>
        </TabsList>

        <TabsContent value="org">
          <OrgTab />
        </TabsContent>
        <TabsContent value="keys">
          <KeysTab />
        </TabsContent>
        <TabsContent value="team">
          <TeamTab />
        </TabsContent>
        <TabsContent value="appearance">
          <AppearanceTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function OrgTab() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const org = useQuery({ queryKey: ["org"], queryFn: api.org.get });
  const [name, setName] = useState("");
  const [sector, setSector] = useState("");

  useEffect(() => {
    if (org.data) {
      setName(org.data.name);
      setSector(org.data.sector || "");
    }
  }, [org.data]);

  const save = useMutation({
    mutationFn: () => api.org.update({ name, sector }),
    onSuccess: () => {
      toast({ title: "Organisation updated", variant: "success" });
      qc.invalidateQueries({ queryKey: ["org"] });
    },
    onError: (e) =>
      toast({ title: "Update failed", description: (e as Error).message, variant: "error" }),
  });

  if (org.isLoading) return <Skeleton className="h-64 w-full" />;

  return (
    <Card>
      <CardHeader>
        <CardTitle>Organisation</CardTitle>
      </CardHeader>
      <CardContent className="space-y-5">
        <div className="grid gap-5 sm:grid-cols-2">
          <div className="space-y-2">
            <Label htmlFor="org-name">Organisation name</Label>
            <Input
              id="org-name"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label htmlFor="org-sector">Sector</Label>
            <Input
              id="org-sector"
              placeholder="Fintech, Healthcare…"
              value={sector}
              onChange={(e) => setSector(e.target.value)}
            />
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="text-sm text-muted-foreground">Plan</span>
            <Badge variant="quantum" className="capitalize">
              {org.data?.plan || "trial"}
            </Badge>
          </div>
          <LicenseBadge expiry={org.data?.license_expires_at} />
        </div>

        <Button onClick={() => save.mutate()} disabled={save.isPending}>
          {save.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : "Save changes"}
        </Button>
      </CardContent>
    </Card>
  );
}

function LicenseBadge({ expiry }: { expiry?: string | null }) {
  if (!expiry) return null;
  const days = Math.round(
    (new Date(expiry).getTime() - Date.now()) / (1000 * 60 * 60 * 24)
  );
  const variant = days > 90 ? "safe" : days > 30 ? "urgent" : "vulnerable";
  return (
    <div className="flex items-center gap-2">
      <span className="text-sm text-muted-foreground">License</span>
      <Badge variant={variant as any}>{days} days left</Badge>
    </div>
  );
}

function KeysTab() {
  const qc = useQueryClient();
  const { toast } = useToast();
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: api.auth.apiKeys.list });
  const [open, setOpen] = useState(false);
  const [newName, setNewName] = useState("");
  const [createdKey, setCreatedKey] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const create = useMutation({
    mutationFn: () => api.auth.apiKeys.create(newName || "New key"),
    onSuccess: (res) => {
      setCreatedKey(res.key);
      setNewName("");
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (e) =>
      toast({ title: "Could not create key", description: (e as Error).message, variant: "error" }),
  });

  const revoke = useMutation({
    mutationFn: (id: string) => api.auth.apiKeys.revoke(id),
    onSuccess: () => {
      toast({ title: "Key revoked", variant: "success" });
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
  });

  function copyKey() {
    if (createdKey) {
      navigator.clipboard.writeText(createdKey);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    }
  }

  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>API Keys</CardTitle>
        <Button
          size="sm"
          onClick={() => {
            setCreatedKey(null);
            setOpen(true);
          }}
        >
          <Plus className="h-4 w-4" /> Create API key
        </Button>
      </CardHeader>
      <CardContent>
        {keys.isLoading ? (
          <Skeleton className="h-32 w-full" />
        ) : !keys.data || keys.data.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No API keys yet.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Name</TableHead>
                <TableHead>Prefix</TableHead>
                <TableHead>Created</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {keys.data.map((k) => (
                <TableRow key={k.id}>
                  <TableCell className="font-medium">{k.name}</TableCell>
                  <TableCell className="font-mono text-xs">
                    {k.key_prefix}…
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {formatDate(k.created_at)}
                  </TableCell>
                  <TableCell className="text-right">
                    <Button
                      size="icon"
                      variant="ghost"
                      className="h-8 w-8 text-vulnerable"
                      onClick={() => {
                        if (confirm(`Revoke API key "${k.name}"? This cannot be undone.`))
                          revoke.mutate(k.id);
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
              <KeyRound className="h-4 w-4 text-quantum" /> Create API key
            </DialogTitle>
          </DialogHeader>

          {createdKey ? (
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Copy your key now. You will not see it again.
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
                ⚠ This key grants full API access. Store it securely.
              </p>
              <DialogFooter>
                <Button onClick={() => setOpen(false)}>Done</Button>
              </DialogFooter>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="key-name">Key name</Label>
                <Input
                  id="key-name"
                  placeholder="CI pipeline"
                  value={newName}
                  onChange={(e) => setNewName(e.target.value)}
                />
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setOpen(false)}>
                  Cancel
                </Button>
                <Button onClick={() => create.mutate()} disabled={create.isPending}>
                  {create.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    "Create"
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

function TeamTab() {
  return (
    <Card>
      <CardHeader>
        <CardTitle>Team</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-sm text-muted-foreground">
          Invite teammates and manage roles. Member management is available to
          organisation admins via the API.
        </p>
      </CardContent>
    </Card>
  );
}

function AppearanceTab() {
  const { theme, setTheme } = useTheme();
  const [mounted, setMounted] = useState(false);
  useEffect(() => setMounted(true), []);

  const options = [
    { value: "light", label: "Light", bg: "#f8fafc", fg: "#0f172a" },
    { value: "dark", label: "Dark", bg: "#000000", fg: "#EDE7DC" },
    { value: "system", label: "System", bg: "linear-gradient(135deg,#f8fafc 50%,#000000 50%)", fg: "#8a857c" },
  ];

  return (
    <Card>
      <CardHeader>
        <CardTitle>Appearance</CardTitle>
      </CardHeader>
      <CardContent>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
          {options.map((o) => (
            <button
              key={o.value}
              onClick={() => setTheme(o.value)}
              className={cn(
                "rounded-xl border p-3 text-left transition-all",
                mounted && theme === o.value
                  ? "border-quantum ring-2 ring-quantum/40"
                  : "hover:border-foreground/30"
              )}
            >
              <div
                className="mb-3 h-20 w-full rounded-lg border"
                style={{ background: o.bg }}
              >
                <div className="flex h-full flex-col justify-end p-2">
                  <span
                    className="h-2 w-12 rounded-full"
                    style={{ background: o.fg, opacity: 0.6 }}
                  />
                  <span
                    className="mt-1 h-2 w-8 rounded-full"
                    style={{ background: o.fg, opacity: 0.3 }}
                  />
                </div>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium">{o.label}</span>
                {mounted && theme === o.value && (
                  <Check className="h-4 w-4 text-quantum" />
                )}
              </div>
            </button>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
