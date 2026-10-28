"use client";

import Link from "next/link";
import { motion } from "framer-motion";
import { AlertTriangle, ArrowRight } from "lucide-react";

export function HNDLAlert({ count }: { count: number }) {
  if (count <= 0) return null;
  return (
    <motion.div
      initial={{ opacity: 0, y: 12 }}
      animate={{ opacity: 1, y: 0 }}
      className="relative overflow-hidden rounded-xl p-[1px]"
      style={{
        background:
          "linear-gradient(120deg, #f59e0b, #f43f5e, #f59e0b)",
      }}
    >
      <div className="flex flex-col items-start justify-between gap-4 rounded-[11px] bg-card p-5 sm:flex-row sm:items-center">
        <div className="flex items-start gap-4">
          <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-full bg-urgent/15 text-urgent">
            <AlertTriangle className="h-5 w-5" />
          </div>
          <div>
            <p className="font-semibold">
              Harvest-Now, Decrypt-Later risk detected
            </p>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">
              <span className="font-medium text-foreground">{count}</span>{" "}
              component{count === 1 ? "" : "s"} handling long-lived sensitive
              data use quantum-vulnerable key exchange. Adversaries may be
              collecting this traffic today.
            </p>
          </div>
        </div>
        <Link
          href="/dashboard/cbom?quantum_status=vulnerable"
          className="inline-flex shrink-0 items-center gap-1.5 rounded-lg bg-urgent/15 px-4 py-2 text-sm font-medium text-urgent transition-colors hover:bg-urgent/25"
        >
          View HNDL components <ArrowRight className="h-4 w-4" />
        </Link>
      </div>
    </motion.div>
  );
}
