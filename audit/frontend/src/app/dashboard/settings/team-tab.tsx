"use client";

import { useEffect, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { api, isStatus, type InviteResult } from "@/lib/api";
import { errMsg } from "@/lib/utils";
import { ROLES, roleRank } from "@/lib/domain";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/field";
import { Dialog, DialogContent, DialogFooter } from "@/components/ui/dialog";
import { EmptyState, ErrorState, Notice, TableSkeleton } from "@/components/ui/feedback";
import { Chip, StatusChip } from "@/components/ui/marks";
import { RelTime } from "@/components/ui/page";
import { SecretOnce } from "@/components/ui/secret";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";
import { useToast } from "@/components/ui/toast";
import { useConfirm } from "@/components/ui/confirm";
import { IconPlus } from "@/components/icons";

export function TeamTab() {
  const users = useQuery({ queryKey: ["org-users"], queryFn: api.org.users, retry: false });
  const qc = useQueryClient();
  const toast = useToast();
  const confirm = useConfirm();
  const [inviteOpen, setInviteOpen] = useState(false);

  const setRole = useMutation({
    mutationFn: ({ id, role }: { id: string; role: string }) => api.org.setRole(id, role),
    onSuccess: (u) => {
      qc.invalidateQueries({ queryKey: ["org-users"] });
      toast({ title: "Role updated", description: `${u.email} is now ${u.role}.`, tone: "success" });
    },
    onError: (e) => {
      qc.invalidateQueries({ queryKey: ["org-users"] });
      toast({ title: "Could not change the role", description: errMsg(e), tone: "error" });
    },
  });

  if (users.isLoading) return <TableSkeleton cols={5} rows={3} />;
  if (users.isError)
    return isStatus(users.error, 403) ? (
      <Notice title="You can't see the member list">Your role does not include team access. Ask an organisation admin to invite people or change roles.</Notice>
    ) : (
      <ErrorState message={errMsg(users.error)} onRetry={() => users.refetch()} />
    );

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <h2 className="font-display text-[1.45rem] text-ink">Members</h2>
          <p className="mt-1 text-sm text-ink-2">{users.data?.length ?? 0} people in this workspace.</p>
        </div>
        <Button onClick={() => setInviteOpen(true)}>
          <IconPlus size={16} /> Invite member
        </Button>
      </div>

      {!users.data?.length ? (
        <EmptyState title="No members" action={{ label: "Invite member", onClick: () => setInviteOpen(true) }} />
      ) : (
        <Table>
          <THead>
            <tr>
              <Th>Person</Th>
              <Th>Role</Th>
              <Th>2FA</Th>
              <Th>Joined</Th>
            </tr>
          </THead>
          <TBody>
            {users.data.map((u) => (
              <Tr key={u.id}>
                <Td label="Person">
                  <span className="block text-ink">{u.name ?? u.email}</span>
                  {u.name && <span className="font-mono text-[11px] text-ink-3">{u.email}</span>}
                </Td>
                <Td label="Role">
                  <Select
                    aria-label={`Role for ${u.email}`}
                    value={u.role === "member" ? "analyst" : u.role}
                    disabled={setRole.isPending}
                    className="h-8 w-36"
                    onChange={async (e) => {
                      const role = e.target.value;
                      if (roleRank(role) < roleRank(u.role)) {
                        const ok = await confirm({
                          title: "Reduce this person's access?",
                          subject: `${u.email}: ${u.role} to ${role}`,
                          body: "They lose the permissions of their current role straight away.",
                          confirmLabel: "Change role",
                        });
                        if (!ok) {
                          e.target.value = u.role;
                          return;
                        }
                      }
                      setRole.mutate({ id: u.id, role });
                    }}
                  >
                    {ROLES.map((r) => (
                      <option key={r.value} value={r.value}>
                        {r.label}
                      </option>
                    ))}
                  </Select>
                </Td>
                <Td label="2FA">
                  <StatusChip value={u.mfa_enabled ? "enabled" : "off"} />
                </Td>
                <Td label="Joined" className="text-ink-2">
                  <RelTime value={u.created_at} />
                </Td>
              </Tr>
            ))}
          </TBody>
        </Table>
      )}

      <dl className="grid gap-px border-y border-rule bg-rule sm:grid-cols-2 lg:grid-cols-4 [&>div]:bg-bg">
        {ROLES.map((r) => (
          <div key={r.value} className="p-4">
            <dt>
              <Chip>{r.label}</Chip>
            </dt>
            <dd className="mt-2 text-xs text-ink-2">{r.note}</dd>
          </div>
        ))}
      </dl>

      <InviteDialog open={inviteOpen} onOpenChange={setInviteOpen} />
    </div>
  );
}

function InviteDialog({ open, onOpenChange }: { open: boolean; onOpenChange: (v: boolean) => void }) {
  const qc = useQueryClient();
  const toast = useToast();
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("analyst");
  const [result, setResult] = useState<InviteResult | null>(null);

  useEffect(() => {
    if (!open) {
      setEmail("");
      setRole("analyst");
      setResult(null);
    }
  }, [open]);

  const valid = /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
  const invite = useMutation({
    mutationFn: () => api.org.invite(email.trim(), role),
    onSuccess: (r) => {
      setResult(r);
      qc.invalidateQueries({ queryKey: ["org-users"] });
    },
    onError: (e) => toast({ title: "Invite failed", description: errMsg(e), tone: "error" }),
  });

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={result ? "Member invited" : "Invite a member"} description={result ? undefined : "They sign in with a temporary password and must change it on first login."}>
        {result ? (
          <>
            <p className="mb-4 text-sm text-ink-2">
              <span className="font-mono text-ink">{result.email}</span> joined as {result.role}. Share the password over a secure channel.
            </p>
            <SecretOnce label="Temporary password" value={result.temporary_password} note="Shown once. They must change it the first time they sign in." />
            <DialogFooter>
              <Button onClick={() => onOpenChange(false)}>Done</Button>
            </DialogFooter>
          </>
        ) : (
          <form
            onSubmit={(e) => {
              e.preventDefault();
              if (valid) invite.mutate();
            }}
            className="space-y-5"
          >
            <Field label="Work email">
              {({ id }) => <Input id={id} type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="colleague@company.com" autoFocus />}
            </Field>
            <Field label="Role" hint={ROLES.find((r) => r.value === role)?.note}>
              {({ id, describedBy }) => (
                <Select id={id} value={role} onChange={(e) => setRole(e.target.value)} aria-describedby={describedBy}>
                  {ROLES.map((r) => (
                    <option key={r.value} value={r.value}>
                      {r.label}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <DialogFooter>
              <Button type="button" variant="ghost" onClick={() => onOpenChange(false)}>
                Cancel
              </Button>
              <Button type="submit" pending={invite.isPending} pendingLabel="Inviting" disabled={!valid}>
                Send invite
              </Button>
            </DialogFooter>
          </form>
        )}
      </DialogContent>
    </Dialog>
  );
}
