"use client";

import { CopyButton } from "./code";
import { IconWarning } from "@/components/icons";

/** A secret shown exactly once, with copy and a plain warning. */
export function SecretOnce({ label, value, note }: { label: string; value: string; note?: string }) {
  return (
    <div className="space-y-3">
      <p className="flex items-start gap-2 border border-urgent/60 bg-urgent/10 px-3 py-2 text-sm text-ink">
        <IconWarning size={16} className="mt-0.5 shrink-0 text-urgent" />
        {note ?? "Copy this now. SeQr shows it once and stores only a hash."}
      </p>
      <div>
        <p className="eyebrow mb-1.5">{label}</p>
        <div className="flex items-center gap-3 border border-ink bg-surface px-3 py-2.5">
          <code className="min-w-0 flex-1 break-all font-mono text-sm text-ink">{value}</code>
          <CopyButton text={value} />
        </div>
      </div>
    </div>
  );
}
