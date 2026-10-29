"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { AnimatePresence, motion } from "motion/react";
import { cn } from "@/lib/utils";
import { logout, useIsOperator, useOrg } from "@/lib/hooks";
import { Monogram, Wordmark } from "@/components/brand";
import { Tip } from "@/components/ui/overlay";
import { IconBuilding, IconCollapse, IconExpand, IconLogout } from "@/components/icons";
import { NAV, type NavItem } from "./nav";

export function NavList({ collapsed, onNavigate }: { collapsed: boolean; onNavigate?: () => void }) {
  const pathname = usePathname();
  const { isOperator } = useIsOperator();
  const items: NavItem[] = isOperator
    ? [...NAV, { href: "/admin", label: "Operator console", icon: IconBuilding }]
    : NAV;

  return (
    <nav aria-label="Primary" className="flex flex-col gap-px px-3">
      {items.map((item, i) => {
        const active = pathname === item.href || pathname.startsWith(item.href + "/");
        const Icon = item.icon;
        const link = (
          <Link
            href={item.href}
            onClick={onNavigate}
            aria-current={active ? "page" : undefined}
            className={cn(
              "relative flex h-10 items-center gap-3 px-3 text-sm transition-colors duration-micro",
              collapsed && "justify-center px-0",
              active ? "text-bg" : "text-ink-2 hover:text-ink",
              item.href === "/admin" && "mt-4"
            )}
          >
            {active && (
              <motion.span
                layoutId="nav-active"
                className="absolute inset-0 bg-ink"
                transition={{ type: "spring", stiffness: 480, damping: 40 }}
              />
            )}
            <Icon size={18} className="relative shrink-0" />
            {!collapsed && (
              <span className="relative flex min-w-0 flex-1 items-center justify-between gap-2">
                <span className="truncate">{item.label}</span>
                {item.tag && (
                  <span className={cn("font-mono text-[10px] uppercase tracking-[0.08em]", active ? "text-bg/70" : "text-ink-3")}>
                    {item.tag}
                  </span>
                )}
              </span>
            )}
            {!collapsed && (
              <span className={cn("relative font-mono text-[10px] tabular", active ? "text-bg/60" : "text-ink-3/70")}>
                {String(i + 1).padStart(2, "0")}
              </span>
            )}
          </Link>
        );
        return collapsed ? (
          <Tip key={item.href} label={item.label} side="right">
            {link}
          </Tip>
        ) : (
          <div key={item.href}>{link}</div>
        );
      })}
    </nav>
  );
}

export function OrgFooter({ collapsed }: { collapsed: boolean }) {
  const { data: org } = useOrg();
  const initials = (org?.name || "SeQr")
    .split(/\s+/)
    .map((w) => w[0])
    .join("")
    .slice(0, 2);
  return (
    <div className={cn("flex items-center gap-3 border-t border-rule p-3", collapsed && "flex-col")}>
      <Monogram text={initials} />
      {!collapsed && (
        <div className="min-w-0 flex-1">
          <p className="truncate text-sm font-medium text-ink">{org?.name ?? "Workspace"}</p>
          <p className="truncate font-mono text-[11px] uppercase tracking-[0.06em] text-ink-3">{org?.plan ?? "trial"} plan</p>
        </div>
      )}
      <Tip label="Log out" side={collapsed ? "right" : "top"}>
        <button
          onClick={() => logout()}
          aria-label="Log out"
          className="inline-flex h-8 w-8 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-immediate"
        >
          <IconLogout size={18} />
        </button>
      </Tip>
    </div>
  );
}

export function Sidebar({ collapsed, onToggle }: { collapsed: boolean; onToggle: () => void }) {
  return (
    <motion.aside
      animate={{ width: collapsed ? 72 : 248 }}
      transition={{ type: "spring", stiffness: 340, damping: 36 }}
      className="sticky top-0 z-30 hidden h-dvh shrink-0 flex-col border-r border-ink bg-bg lg:flex"
    >
      <div className={cn("flex h-16 items-center border-b border-rule px-5", collapsed ? "justify-center px-0" : "justify-between")}>
        <AnimatePresence initial={false} mode="wait">
          {collapsed ? (
            <motion.span key="m" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <Link href="/" aria-label="SeQr home">
                <Wordmark className="text-[22px]" />
              </Link>
            </motion.span>
          ) : (
            <motion.span key="w" initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
              <Link href="/" aria-label="SeQr home">
                <Wordmark className="text-[24px]" labs />
              </Link>
            </motion.span>
          )}
        </AnimatePresence>
        {!collapsed && (
          <button
            onClick={onToggle}
            aria-label="Collapse sidebar"
            className="inline-flex h-8 w-8 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-ink"
          >
            <IconCollapse size={18} />
          </button>
        )}
      </div>
      {collapsed && (
        <button
          onClick={onToggle}
          aria-label="Expand sidebar"
          className="mx-auto mt-3 inline-flex h-8 w-8 items-center justify-center text-ink-3 transition-colors duration-micro hover:text-ink"
        >
          <IconExpand size={18} />
        </button>
      )}
      {!collapsed && <p className="eyebrow px-6 pb-2 pt-6">Workspace</p>}
      <div className={cn("min-h-0 flex-1 overflow-y-auto", collapsed && "pt-3")}>
        <NavList collapsed={collapsed} />
      </div>
      <OrgFooter collapsed={collapsed} />
    </motion.aside>
  );
}
