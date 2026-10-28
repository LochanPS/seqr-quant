"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import {
  LayoutDashboard,
  Boxes,
  Share2,
  ScanLine,
  FileText,
  Settings,
  PlugZap,
  PanelLeftClose,
  PanelLeftOpen,
  LogOut,
} from "lucide-react";
import { Logo, LogoMark } from "@/components/Logo";
import { cn } from "@/lib/utils";
import { logout, useOrg } from "@/lib/hooks";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";

// Navigation is scoped to surfaces that are coherent with the graph-based architecture.
//   - Overview (Posture): graph + migration spine — the product home.
//   - Assets: the org's asset inventory.
//   - CBOM: still reads the retired scan-era `/cbom` plane (parallel to the graph's
//       component-state). It renders + exports today, so it stays visible but is badged
//       "Preview" until it is rebuilt on the graph. Not the graph-native inventory yet.
//   - Settings: architecture-neutral.
//   - Reports: HIDDEN. The report generator reads the scan pipeline, which is empty for
//       graph-seeded orgs — nothing to show in a demo. Route + code are preserved (see
//       app/dashboard/reports), just unlinked, pending a graph-native rebuild.
type NavItem = {
  href: string;
  label: string;
  icon: typeof LayoutDashboard;
  badge?: string;
  hidden?: boolean;
};

const NAV: NavItem[] = [
  { href: "/dashboard/posture", label: "Overview", icon: LayoutDashboard },
  { href: "/dashboard/assets", label: "Assets", icon: Boxes },
  { href: "/dashboard/graph", label: "Graph", icon: Share2 },
  { href: "/dashboard/cbom", label: "CBOM", icon: ScanLine, badge: "Preview" },
  { href: "/dashboard/connections", label: "Connections", icon: PlugZap },
  { href: "/dashboard/reports", label: "Reports", icon: FileText, hidden: true },
  { href: "/dashboard/settings", label: "Settings", icon: Settings },
].filter((item) => !item.hidden);

export function Sidebar({
  collapsed,
  onToggle,
}: {
  collapsed: boolean;
  onToggle: () => void;
}) {
  const pathname = usePathname();
  const { data: org } = useOrg();

  return (
    <motion.aside
      animate={{ width: collapsed ? 72 : 240 }}
      transition={{ type: "spring", stiffness: 300, damping: 32 }}
      className="sticky top-0 z-30 flex h-screen flex-col border-r bg-card/40 backdrop-blur"
    >
      {/* Top: logo + collapse */}
      <div className="flex h-16 items-center justify-between px-4">
        <Link href="/" className="overflow-hidden">
          {collapsed ? <LogoMark /> : <Logo />}
        </Link>
        {!collapsed && (
          <button
            onClick={onToggle}
            className="text-muted-foreground transition-colors hover:text-foreground"
            aria-label="Collapse sidebar"
          >
            <PanelLeftClose className="h-5 w-5" />
          </button>
        )}
      </div>

      {collapsed && (
        <button
          onClick={onToggle}
          className="mx-auto mb-2 text-muted-foreground transition-colors hover:text-foreground"
          aria-label="Expand sidebar"
        >
          <PanelLeftOpen className="h-5 w-5" />
        </button>
      )}

      {/* Nav */}
      <nav className="flex flex-1 flex-col gap-1 px-3 py-2">
        {NAV.map((item) => {
          const active =
            item.href === "/dashboard"
              ? pathname === "/dashboard"
              : pathname.startsWith(item.href);
          const Icon = item.icon;
          const link = (
            <Link
              href={item.href}
              className={cn(
                "group relative flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors",
                active
                  ? "bg-accent text-foreground"
                  : "text-muted-foreground hover:bg-accent/60 hover:text-foreground",
                collapsed && "justify-center px-0"
              )}
            >
              {active && (
                <motion.span
                  layoutId="sidebar-active"
                  className="absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r-full bg-quantum"
                  transition={{ type: "spring", stiffness: 400, damping: 30 }}
                />
              )}
              <Icon
                className={cn(
                  "h-5 w-5 shrink-0",
                  active && "text-quantum"
                )}
              />
              <AnimatePresence initial={false}>
                {!collapsed && (
                  <motion.span
                    initial={{ opacity: 0, width: 0 }}
                    animate={{ opacity: 1, width: "auto" }}
                    exit={{ opacity: 0, width: 0 }}
                    className="flex items-center gap-2 overflow-hidden whitespace-nowrap"
                  >
                    {item.label}
                    {item.badge && (
                      <span className="rounded-full border border-quantum/40 bg-quantum/10 px-1.5 py-0.5 text-[0.6rem] font-medium uppercase tracking-wide text-quantum">
                        {item.badge}
                      </span>
                    )}
                  </motion.span>
                )}
              </AnimatePresence>
            </Link>
          );

          return collapsed ? (
            <Tooltip key={item.href}>
              <TooltipTrigger asChild>{link}</TooltipTrigger>
              <TooltipContent side="right">{item.label}</TooltipContent>
            </Tooltip>
          ) : (
            <div key={item.href}>{link}</div>
          );
        })}
      </nav>

      {/* Bottom: user / org / logout */}
      <div className="border-t p-3">
        <div
          className={cn(
            "flex items-center gap-3",
            collapsed && "justify-center"
          )}
        >
          <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-full bg-gradient-to-br from-quantum to-planned text-xs font-semibold text-white">
            {(org?.name || "S").slice(0, 2).toUpperCase()}
          </div>
          {!collapsed && (
            <div className="min-w-0 flex-1">
              <p className="truncate text-sm font-medium">
                {org?.name || "Workspace"}
              </p>
              <p className="truncate text-xs capitalize text-muted-foreground">
                {org?.plan || "trial"} plan
              </p>
            </div>
          )}
          {!collapsed && (
            <button
              onClick={logout}
              aria-label="Log out"
              className="text-muted-foreground transition-colors hover:text-vulnerable"
            >
              <LogOut className="h-4 w-4" />
            </button>
          )}
        </div>
      </div>
    </motion.aside>
  );
}
