"use client";

import { motion } from "framer-motion";
import { Card } from "@/components/ui/card";
import { ComplianceBadge } from "@/components/shared/StatusBadges";
import type { ComplianceMap } from "@/lib/types";

const FRAMEWORKS: { key: string; name: string }[] = [
  { key: "PCI_DSS_12_3_3", name: "PCI DSS" },
  { key: "NIST_FIPS", name: "NIST FIPS" },
  { key: "DST_TASK_FORCE_2026", name: "DST 2026" },
  { key: "RBI_IT_FRAMEWORK", name: "RBI" },
  { key: "CERT_IN", name: "CERT-In" },
];

export function ComplianceCards({ data }: { data: ComplianceMap }) {
  return (
    <div className="grid grid-cols-2 gap-4 md:grid-cols-3 lg:grid-cols-5">
      {FRAMEWORKS.map((f, i) => {
        const entry = data[f.key];
        return (
          <motion.div
            key={f.key}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.06 }}
            whileHover={{ scale: 1.02, y: -2 }}
          >
            <Card className="flex h-full flex-col p-4 transition-shadow hover:shadow-lg">
              <div className="flex items-center justify-between">
                <span className="text-sm font-semibold">{f.name}</span>
                <span className="flex h-7 w-7 items-center justify-center rounded-md bg-muted text-[10px] font-bold text-muted-foreground">
                  {f.name.slice(0, 2).toUpperCase()}
                </span>
              </div>
              <div className="mt-3">
                <ComplianceBadge status={entry?.status || "MONITOR"} />
              </div>
              <p className="mt-2 line-clamp-3 text-xs text-muted-foreground">
                {entry?.message || "Awaiting first scan."}
              </p>
            </Card>
          </motion.div>
        );
      })}
    </div>
  );
}
