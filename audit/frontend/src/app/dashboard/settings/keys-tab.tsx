"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api } from "@/lib/api";
import type { ApiKeyCreated } from "@/lib/types";
import { errMsg } from "@/lib/utils";
import { Button } from "@/components/ui/button";
import { Field, Input } from "@/components/ui/field";
import { Dialog, DialogContent, DialogFooter } from "@/components/ui/dialog";
import { EmptyState, ErrorState, TableSkeleton } from "@/components/ui/feedback";
import { RelTime } from "@/components/ui/page";
import { SecretOnce } from "@/components/ui/secret";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";
import { IconPlus } from "@/components/icons";

export function KeysTab({ openNew, onConsumed }: { openNew?: boolean; onConsumed?: () => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const keys = useQuery({ queryKey: ["api-keys"], queryFn: api.auth.apiKeys.list });
  const [open, setOpen] = useState(false);

  useEffect(() => {
    if (openNew) {
      setOpen(true);
      onConsumed?.();
    }
  }, [openNew, onConsumed]);

  const revoke = useMutation({
    mutationFn: (id: string) => api.auth.apiKeys.revoke(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["api-keys"] });
      toast({ title: "Key revoked", tone: "success" });
    },
    onError: (e) => toast({ title: "Could not revoke the key", description: errMsg(e), tone: "error" }),
  });

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="font-display text-[1.45rem] text-ink">API keys</h2>
          <p className="mt-1 max-w-xl text-sm text-ink-2">For CI pipelines and scripts. Send as a bearer token. Each key acts with your organisation&apos;s permissions.</p>
        </div>
        <Button onClick={() => setOpen(true)}>
          <IconPlus size={16} /> Create key
        </Button>
      </div>

      {keys.isLoading ? (
        <TableSkeleton cols={4} rows={3} />
      ) : keys.isError ? (
        <ErrorState message={errMsg(keys.error)} onRetry={() => keys.refetch()} />
      ) : !keys.data?.length ? (
        <EmptyState title="No API keys" body="Create one for your CI pipeline to push findings." action={{ label: "Create key", onClick: () => setOpen(true) }} />
      ) : (
        <Table>
          <THead>
            <tr>
              <Th>Name</Th>
              <Th>Prefix</Th>
              <Th>Created</Th>
              <Th>Expires</Th>
              <Th align="right">
                <span className="sr-only">Actions</span>
              </Th>
            </tr>
          </THead>
          <TBody>
            {keys.data.map((k) => (
              <Tr key={k.id}>
                <Td label="Name">{k.name}</Td>
                <Td label="Prefix" mono>
                  {k.key_prefix}
                </Td>
                <Td label="Created" className="text-ink-2">
                  <RelTime value={k.created_at} />
                </Td>
                <Td label="Expires" className="text-ink-2">
                  {k.expires_at ? <RelTime value={k.expires_at} /> : "never"}
                </Td>
                <Td align="right">
                  <Button
                    variant="danger"
                    size="sm"
                    pending={revoke.isPending && revoke.variables === k.id}
                    pendingLabel="Revoking"
                    onClick={async () => {
                      const ok = await confirm({
                        title: "Revoke this API key?",
                        subject: `${k.name} · ${k.key_prefix}`,
                        body: "Anything using it starts failing with 401 straight away.",
                        confirmLabel: "Revoke key",
                      });
                      if (ok) revoke.mutate(k.id);
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
      <CreateKeyDialog open={open} onOpenChange={setOpen} />
    </div>
  );
}

function CreateKeyDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [name, setName] = useState("");
  const [created, setCreated] = useState<ApiKeyCreated | null>(null);

  useEffect(() => {
    if (!open) {
      setName("");
      setCreated(null);
    }
  }, [open]);

  const create = useMutation({
    mutationFn: () => api.auth.apiKeys.create(name.trim() || "New key"),
    onSuccess: (k) => {
      setCreated(k);
      qc.invalidateQueries({ queryKey: ["api-keys"] });
    },
    onError: (e) => toast({ title: "Could not create the key", description: errMsg(e), tone: "error" }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={created ? "Key created" : "Create an API key"}>
        {created ? (
          <>
            <SecretOnce label={created.name} value={created.key} />
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
            <Field label="Key name" hint="Name it after where it will live.">
              {({ id, describedBy }) => <Input id={id} value={name} onChange={(e) => setName(e.target.value)} placeholder="CI pipeline" autoFocus aria-describedby={describedBy} />}
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
