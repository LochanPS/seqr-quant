"use client";

import * as T from "@radix-ui/react-tabs";
import { motion } from "motion/react";
import { useId } from "react";
import { cn } from "@/lib/utils";

export const Tabs = T.Root;
export const TabsContent = ({ className, ...p }: T.TabsContentProps) => (
  <T.Content className={cn("pt-8 focus-visible:outline-none", className)} {...p} />
);

/** Tab rail with a sliding ink rule under the active tab. */
export function TabsList({
  items,
  value,
  className,
}: {
  items: { value: string; label: React.ReactNode }[];
  value: string;
  className?: string;
}) {
  const layoutId = useId();
  return (
    <T.List className={cn("flex gap-6 overflow-x-auto border-b border-rule", className)}>
      {items.map((it) => (
        <T.Trigger
          key={it.value}
          value={it.value}
          className={cn(
            "relative shrink-0 pb-3 pt-1 text-sm font-medium transition-colors duration-micro",
            value === it.value ? "text-ink" : "text-ink-3 hover:text-ink"
          )}
        >
          {it.label}
          {value === it.value && (
            <motion.span
              layoutId={layoutId}
              className="absolute inset-x-0 -bottom-px h-[2px] bg-ink"
              transition={{ type: "spring", stiffness: 500, damping: 40 }}
            />
          )}
        </T.Trigger>
      ))}
    </T.List>
  );
}
