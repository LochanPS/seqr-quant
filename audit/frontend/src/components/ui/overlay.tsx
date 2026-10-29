"use client";

// Tooltip and dropdown menu, restyled Radix primitives.
import * as T from "@radix-ui/react-tooltip";
import * as M from "@radix-ui/react-dropdown-menu";
import { cn } from "@/lib/utils";

export function Tip({
  label,
  children,
  side = "top",
}: {
  label: React.ReactNode;
  children: React.ReactNode;
  side?: "top" | "right" | "bottom" | "left";
}) {
  return (
    <T.Root>
      <T.Trigger asChild>{children}</T.Trigger>
      <T.Portal>
        <T.Content
          side={side}
          sideOffset={6}
          className="popover z-[70] max-w-xs bg-ink px-2.5 py-1.5 font-mono text-[11px] leading-snug text-bg"
        >
          {label}
        </T.Content>
      </T.Portal>
    </T.Root>
  );
}

export const Menu = M.Root;
export const MenuTrigger = M.Trigger;

export function MenuContent({
  children,
  align = "end",
  className,
}: {
  children: React.ReactNode;
  align?: "start" | "end" | "center";
  className?: string;
}) {
  return (
    <M.Portal>
      <M.Content
        align={align}
        sideOffset={6}
        className={cn("popover z-[70] min-w-[220px] border border-ink bg-bg py-1", className)}
      >
        {children}
      </M.Content>
    </M.Portal>
  );
}

export function MenuItem({
  children,
  onSelect,
  danger,
  asChild,
}: {
  children: React.ReactNode;
  onSelect?: () => void;
  danger?: boolean;
  asChild?: boolean;
}) {
  return (
    <M.Item
      asChild={asChild}
      onSelect={onSelect}
      className={cn(
        "flex cursor-pointer select-none items-center gap-2.5 px-3 py-2 text-sm outline-none transition-colors duration-micro",
        danger ? "text-immediate data-[highlighted]:bg-immediate data-[highlighted]:text-bg" : "text-ink data-[highlighted]:bg-ink data-[highlighted]:text-bg"
      )}
    >
      {children}
    </M.Item>
  );
}

export function MenuLabel({ children }: { children: React.ReactNode }) {
  return <M.Label className="px-3 py-2">{children}</M.Label>;
}

export function MenuSeparator() {
  return <M.Separator className="my-1 h-px bg-rule" />;
}
