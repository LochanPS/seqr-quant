"use client";

import Link from "next/link";
import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Dialog, DialogTrigger, SheetContent } from "@/components/ui/dialog";
import { api, type EventRow } from "@/lib/api";
import { cn, humanize } from "@/lib/utils";
import { useStoredState } from "@/lib/hooks";
import { RelTime } from "@/components/ui/page";
import { BlockSkeleton, ErrorState } from "@/components/ui/feedback";
import { Chip, toneFor } from "@/components/ui/marks";
import { IconBell } from "@/components/icons";

function eventHref(e: EventRow) {
  if (e.asset_id) return `/dashboard/assets/${e.asset_id}`;
  if (e.type.includes("attest")) return "/dashboard/posture#sec-attest";
  if (e.type.includes("plan") || e.type.includes("bundle") || e.type.includes("verif")) return "/dashboard/posture#sec-actions";
  return "/dashboard/posture#sec-events";
}

export function Notifications() {
  const [open, setOpen] = useState(false);
  const [seen, setSeen] = useStoredState<string>("seqr_notif_seen", "1970-01-01T00:00:00Z");
  const events = useQuery({ queryKey: ["graph-events"], queryFn: api.graph.events, refetchInterval: 60_000 });
  const violations = useQuery({ queryKey: ["violations-current"], queryFn: api.graph.currentViolations });

  const list = (events.data ?? []).slice().sort((a, b) => b.at.localeCompare(a.at)).slice(0, 30);
  const unread = list.filter((e) => e.at > seen).length;
  const bySev = (violations.data ?? []).reduce<Record<string, number>>((m, v) => {
    m[v.severity] = (m[v.severity] ?? 0) + 1;
    return m;
  }, {});

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <button
          aria-label={unread ? `Notifications, ${unread} unread` : "Notifications"}
          className="relative inline-flex h-10 w-10 items-center justify-center text-ink-2 transition-colors duration-micro hover:text-ink"
        >
          <IconBell size={18} />
          {unread > 0 && (
            <span className="absolute right-1.5 top-1.5 inline-flex h-4 min-w-4 items-center justify-center bg-immediate px-1 font-mono text-[9px] text-bg tabular">
              {unread > 9 ? "9+" : unread}
            </span>
          )}
        </button>
      </DialogTrigger>
      <SheetContent title="Notifications">
        <div className="flex items-center justify-between border-b border-rule px-5 py-3">
          <p className="text-sm text-ink-2">{unread ? `${unread} unread` : "All caught up"}</p>
          <button
            disabled={!unread}
            onClick={() => setSeen(list[0]?.at ?? new Date().toISOString())}
            className="text-sm text-ink link-underline disabled:opacity-40"
          >
            Mark all read
          </button>
        </div>

        <div className="border-b border-rule px-5 py-4">
          <p className="eyebrow mb-3">Open violations</p>
          {violations.isLoading ? (
            <BlockSkeleton lines={2} />
          ) : violations.isError ? (
            <ErrorState message={(violations.error as Error).message} onRetry={() => violations.refetch()} />
          ) : (violations.data ?? []).length === 0 ? (
            <p className="text-sm text-ink-2">No open policy violations.</p>
          ) : (
            <Link
              href="/dashboard/posture#sec-violations"
              onClick={() => setOpen(false)}
              className="flex flex-wrap items-center gap-2 text-sm text-ink link-underline"
            >
              {violations.data!.length} open
              {["immediate", "urgent", "planned"].map(
                (s) =>
                  bySev[s] && (
                    <Chip key={s} tone={toneFor(s)}>
                      {bySev[s]} {s}
                    </Chip>
                  )
              )}
            </Link>
          )}
        </div>

        <p className="eyebrow px-5 pb-1 pt-4">Activity</p>
        {events.isLoading ? (
          <div className="p-5">
            <BlockSkeleton lines={6} />
          </div>
        ) : events.isError ? (
          <div className="p-5">
            <ErrorState message={(events.error as Error).message} onRetry={() => events.refetch()} />
          </div>
        ) : list.length === 0 ? (
          <p className="px-5 py-6 text-sm text-ink-2">No activity recorded yet.</p>
        ) : (
          <ul>
            {list.map((e) => {
              const isNew = e.at > seen;
              return (
                <li key={e.id}>
                  <Link
                    href={eventHref(e)}
                    onClick={() => setOpen(false)}
                    className="flex items-start gap-3 border-b border-rule px-5 py-3 transition-colors duration-micro hover:bg-surface"
                  >
                    <span aria-hidden className={cn("mt-1.5 h-1.5 w-1.5 shrink-0", isNew ? "bg-accent" : "bg-rule")} />
                    <span className="min-w-0 flex-1">
                      <span className="block text-sm capitalize text-ink">{humanize(e.type)}</span>
                      <span className="mt-0.5 block font-mono text-[11px] text-ink-3">
                        {e.actor === "system" ? "system" : e.actor ? `user ${e.actor.slice(0, 8)}` : "unknown actor"}
                      </span>
                    </span>
                    <RelTime value={e.at} className="font-mono text-[11px] text-ink-3" />
                  </Link>
                </li>
              );
            })}
          </ul>
        )}
      </SheetContent>
    </Dialog>
  );
}
