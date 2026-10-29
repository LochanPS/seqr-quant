"use client";

import { useState } from "react";
import { useInfiniteQuery } from "@tanstack/react-query";
import { api, isStatus } from "@/lib/api";
import { errMsg, shortId } from "@/lib/utils";
import { useDebounced } from "@/lib/hooks";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/field";
import { EmptyState, ErrorState, Notice, TableSkeleton } from "@/components/ui/feedback";
import { Chip, toneFor } from "@/components/ui/marks";
import { RelTime } from "@/components/ui/page";
import { TBody, THead, Table, Td, Th, Tr } from "@/components/ui/table";

const PAGE = 50;

export function AuditTab() {
  const [actor, setActor] = useState("");
  const [action, setAction] = useState("");
  const [since, setSince] = useState("");
  const [until, setUntil] = useState("");
  const filters = useDebounced({ actor, action, since, until }, 300);

  const q = useInfiniteQuery({
    queryKey: ["audit", filters],
    queryFn: ({ pageParam }) =>
      api.audit.list({
        actor: filters.actor || undefined,
        action: filters.action || undefined,
        since: filters.since ? new Date(filters.since).toISOString() : undefined,
        until: filters.until ? new Date(filters.until + "T23:59:59").toISOString() : undefined,
        limit: PAGE,
        offset: pageParam,
      }),
    initialPageParam: 0,
    getNextPageParam: (last, all) => (last.length === PAGE ? all.length * PAGE : undefined),
    retry: false,
  });

  const rows = q.data?.pages.flat() ?? [];
  const anyFilter = actor || action || since || until;

  if (q.isError && isStatus(q.error, 403))
    return <Notice title="Admins and auditors only">The audit log is available to the admin and auditor roles.</Notice>;

  return (
    <div className="space-y-6">
      <div>
        <h2 className="font-display text-[1.45rem] text-ink">Audit log</h2>
        <p className="mt-1 text-sm text-ink-2">Every authenticated request that changed something, plus sign-ins. Newest first.</p>
      </div>
      <div className="flex flex-wrap items-end gap-3 border-y border-rule py-3">
        <label className="block">
          <span className="eyebrow mb-1 block">Actor</span>
          <Input value={actor} onChange={(e) => setActor(e.target.value)} placeholder="user id or system" className="h-9 w-56 font-mono text-xs" />
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">Action contains</span>
          <Input value={action} onChange={(e) => setAction(e.target.value)} placeholder="auth.login" className="h-9 w-48 font-mono text-xs" />
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">Since</span>
          <Input type="date" value={since} onChange={(e) => setSince(e.target.value)} className="h-9 w-40 font-mono text-xs" />
        </label>
        <label className="block">
          <span className="eyebrow mb-1 block">Until</span>
          <Input type="date" value={until} onChange={(e) => setUntil(e.target.value)} className="h-9 w-40 font-mono text-xs" />
        </label>
        {anyFilter && (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => {
              setActor("");
              setAction("");
              setSince("");
              setUntil("");
            }}
          >
            Reset
          </Button>
        )}
      </div>

      {q.isLoading ? (
        <TableSkeleton cols={6} />
      ) : q.isError ? (
        <ErrorState message={errMsg(q.error)} onRetry={() => q.refetch()} />
      ) : !rows.length ? (
        <EmptyState title={anyFilter ? "No events match" : "No events yet"} />
      ) : (
        <>
          <Table>
            <THead>
              <tr>
                <Th>Time</Th>
                <Th>Actor</Th>
                <Th>Action</Th>
                <Th>Request</Th>
                <Th align="right">Status</Th>
              </tr>
            </THead>
            <TBody>
              {rows.map((e) => (
                <Tr key={e.id}>
                  <Td label="Time" className="text-ink-2">
                    <RelTime value={e.at} />
                  </Td>
                  <Td label="Actor" mono>
                    <button className="link-underline" onClick={() => setActor(e.actor ?? "")} title="Filter by this actor">
                      {e.actor ? (e.actor.length > 20 ? shortId(e.actor) : e.actor) : "anonymous"}
                    </button>{" "}
                    <span className="text-ink-3">{e.actor_type}</span>
                  </Td>
                  <Td label="Action" mono>
                    {e.action}
                  </Td>
                  <Td label="Request" mono className="max-w-[340px] text-ink-2">
                    <span className="block truncate">
                      {e.method} {e.path}
                    </span>
                  </Td>
                  <Td label="Status" align="right">
                    {e.status_code != null ? (
                      <Chip tone={e.status_code >= 400 ? toneFor("fail") : "neutral"}>{e.status_code}</Chip>
                    ) : (
                      <span className="font-mono text-xs text-ink-3">n/a</span>
                    )}
                  </Td>
                </Tr>
              ))}
            </TBody>
          </Table>
          {q.hasNextPage && (
            <Button variant="secondary" onClick={() => q.fetchNextPage()} pending={q.isFetchingNextPage} pendingLabel="Loading">
              Load more
            </Button>
          )}
        </>
      )}
    </div>
  );
}
