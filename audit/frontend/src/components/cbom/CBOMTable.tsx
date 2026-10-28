"use client";

import { AnimatePresence, motion } from "framer-motion";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { Check, XCircle } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  QuantumStatusBadge,
  TimelineBadge,
  HndlBadge,
} from "@/components/shared/StatusBadges";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useToast } from "@/components/ui/toast";
import { api } from "@/lib/api";
import { truncateMiddle } from "@/lib/utils";
import type { Component } from "@/lib/types";

export function CBOMTable({ items }: { items: Component[] }) {
  const qc = useQueryClient();
  const { toast } = useToast();

  const patch = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) =>
      api.cbom.patch(id, status),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["cbom"] });
      toast({ title: "Component updated", variant: "success" });
    },
    onError: (e) =>
      toast({
        title: "Update failed",
        description: (e as Error).message,
        variant: "error",
      }),
  });

  return (
    <Table>
      <TableHeader>
        <TableRow>
          <TableHead>Location</TableHead>
          <TableHead>Algorithm</TableHead>
          <TableHead>Status</TableHead>
          <TableHead>HNDL</TableHead>
          <TableHead>Timeline</TableHead>
          <TableHead className="text-right">Priority</TableHead>
          <TableHead>Migration</TableHead>
          <TableHead className="text-right">Actions</TableHead>
        </TableRow>
      </TableHeader>
      <TableBody>
        <AnimatePresence initial={false}>
          {items.map((c, i) => (
            <motion.tr
              key={c.id}
              layout
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0 }}
              transition={{ delay: Math.min(i * 0.02, 0.3) }}
              className="border-b transition-colors hover:bg-muted/40"
            >
              <TableCell className="max-w-[220px]">
                <Tooltip>
                  <TooltipTrigger asChild>
                    <span className="block truncate font-mono text-xs">
                      {truncateMiddle(c.location_detail, 40)}
                    </span>
                  </TooltipTrigger>
                  <TooltipContent className="max-w-md break-all">
                    {c.location_detail}
                  </TooltipContent>
                </Tooltip>
              </TableCell>
              <TableCell className="font-mono text-xs">
                {c.algorithm}
                {c.key_size ? (
                  <span className="text-muted-foreground"> · {c.key_size}</span>
                ) : null}
              </TableCell>
              <TableCell>
                <QuantumStatusBadge status={c.quantum_status} />
              </TableCell>
              <TableCell>
                <HndlBadge exposure={c.estimated_hndl_exposure} />
              </TableCell>
              <TableCell>
                <TimelineBadge timeline={c.threat_timeline} />
              </TableCell>
              <TableCell className="text-right tabular-nums">
                {c.pqc_migration_priority?.toFixed(1) ?? "—"}
              </TableCell>
              <TableCell>
                <Badge variant="muted" className="capitalize">
                  {(c.migration_status || "not_started").replace(/_/g, " ")}
                </Badge>
              </TableCell>
              <TableCell className="text-right">
                <div className="flex justify-end gap-1">
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-safe"
                        onClick={() =>
                          patch.mutate({ id: c.id, status: "done" })
                        }
                      >
                        <Check className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Mark done</TooltipContent>
                  </Tooltip>
                  <Tooltip>
                    <TooltipTrigger asChild>
                      <Button
                        size="icon"
                        variant="ghost"
                        className="h-8 w-8 text-muted-foreground"
                        onClick={() =>
                          patch.mutate({ id: c.id, status: "false_positive" })
                        }
                      >
                        <XCircle className="h-4 w-4" />
                      </Button>
                    </TooltipTrigger>
                    <TooltipContent>Mark false positive</TooltipContent>
                  </Tooltip>
                </div>
              </TableCell>
            </motion.tr>
          ))}
        </AnimatePresence>
      </TableBody>
    </Table>
  );
}
