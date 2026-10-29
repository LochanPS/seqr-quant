"use client";

import Link from "next/link";
import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { cn, shortId } from "@/lib/utils";
import { logout, useIsOperator, useOrg, useThemeSwitch } from "@/lib/hooks";
import { Monogram, Wordmark } from "@/components/brand";
import { Menu, MenuContent, MenuItem, MenuLabel, MenuSeparator, MenuTrigger } from "@/components/ui/overlay";
import { Dialog, DialogTrigger, SheetContent } from "@/components/ui/dialog";
import { Tip } from "@/components/ui/overlay";
import { IconChevronRight, IconMenu, IconSearch, IconTheme } from "@/components/icons";
import { CommandPalette } from "./command-palette";
import { Notifications } from "./notifications";
import { NavList, OrgFooter } from "./sidebar";
import { SEGMENT_LABELS } from "./nav";

const UUIDISH = /^[0-9a-f]{8}-[0-9a-f]{4}-/i;

function Breadcrumb() {
  const pathname = usePathname();
  const parts = pathname.split("/").filter(Boolean);
  const crumbs: { label: string; href: string; mono: boolean }[] = [];
  let acc = "";
  parts.forEach((p, i) => {
    acc += `/${p}`;
    // /dashboard alone redirects to the overview, so its crumb points there.
    const href = acc === "/dashboard" ? "/dashboard/posture" : acc;
    if (p === "dashboard" && parts[i + 1] === "posture") return;
    const isId = UUIDISH.test(p);
    // "scans" has no index page; link it to Assets, where scans start.
    const fixedHref = p === "scans" ? "/dashboard/assets" : href;
    crumbs.push({ label: isId ? shortId(p) : SEGMENT_LABELS[p] ?? p, href: fixedHref, mono: isId });
  });
  return (
    <nav aria-label="Breadcrumb" className="min-w-0">
      <ol className="flex min-w-0 items-center gap-1.5 text-sm">
        {crumbs.map((c, i) => {
          const last = i === crumbs.length - 1;
          return (
            <li key={c.href + i} className="flex min-w-0 items-center gap-1.5">
              {i > 0 && <IconChevronRight size={12} className="shrink-0 text-ink-3" />}
              {last ? (
                <span aria-current="page" className={cn("truncate font-medium text-ink", c.mono && "font-mono text-[13px]")}>
                  {c.label}
                </span>
              ) : (
                <Link href={c.href} className={cn("truncate text-ink-3 transition-colors duration-micro hover:text-ink", c.mono && "font-mono text-[13px]")}>
                  {c.label}
                </Link>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}

export function Header() {
  const { data: org } = useOrg();
  const { isOperator } = useIsOperator();
  const { toggle, resolvedTheme } = useThemeSwitch();
  const [palette, setPalette] = useState(false);
  const [drawer, setDrawer] = useState(false);
  const pathname = usePathname();

  useEffect(() => setDrawer(false), [pathname]);
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const initials = (org?.name || "SeQr")
    .split(/\s+/)
    .map((w) => w[0])
    .join("")
    .slice(0, 2);

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center gap-3 border-b border-rule bg-bg px-4 sm:px-6">
      <Dialog open={drawer} onOpenChange={setDrawer}>
        <DialogTrigger asChild>
          <button aria-label="Open navigation" className="inline-flex h-10 w-10 items-center justify-center text-ink lg:hidden">
            <IconMenu size={20} />
          </button>
        </DialogTrigger>
        <SheetContent side="left" title="Navigation">
          <div className="flex h-full flex-col">
            <div className="px-6 py-5">
              <Wordmark className="text-[24px]" labs />
            </div>
            <div className="flex-1">
              <NavList collapsed={false} onNavigate={() => setDrawer(false)} />
            </div>
            <OrgFooter collapsed={false} />
          </div>
        </SheetContent>
      </Dialog>

      <div className="min-w-0 flex-1">
        <Breadcrumb />
      </div>

      <button
        onClick={() => setPalette(true)}
        className="hidden h-9 items-center gap-3 border border-rule px-3 text-sm text-ink-3 transition-colors duration-micro hover:border-ink hover:text-ink md:inline-flex"
      >
        <IconSearch size={16} />
        <span>Search</span>
        <kbd className="ml-6 font-mono text-[10px] tracking-[0.08em]">CTRL K</kbd>
      </button>
      <button
        onClick={() => setPalette(true)}
        aria-label="Search"
        className="inline-flex h-10 w-10 items-center justify-center text-ink-2 md:hidden"
      >
        <IconSearch size={18} />
      </button>

      <Notifications />

      <Tip label={resolvedTheme === "dark" ? "Switch to light" : "Switch to dark"}>
        <button
          onClick={toggle}
          aria-label="Toggle colour theme"
          className="inline-flex h-10 w-10 items-center justify-center text-ink-2 transition-colors duration-micro hover:text-ink"
        >
          <IconTheme size={18} />
        </button>
      </Tip>

      <Menu>
        <MenuTrigger asChild>
          <button aria-label="Account menu" className="ml-1">
            <Monogram text={initials} className="h-8 w-8 text-[11px]" />
          </button>
        </MenuTrigger>
        <MenuContent>
          <MenuLabel>
            <span className="block truncate text-sm font-medium text-ink">{org?.name ?? "Workspace"}</span>
            <span className="block font-mono text-[11px] uppercase tracking-[0.06em] text-ink-3">{org?.plan ?? "trial"} plan</span>
          </MenuLabel>
          <MenuSeparator />
          <MenuItem asChild>
            <Link href="/dashboard/settings">Settings</Link>
          </MenuItem>
          <MenuItem asChild>
            <Link href="/dashboard/settings?tab=security">Security</Link>
          </MenuItem>
          {isOperator && (
            <MenuItem asChild>
              <Link href="/admin">Operator console</Link>
            </MenuItem>
          )}
          <MenuSeparator />
          <MenuItem danger onSelect={() => logout()}>
            Log out
          </MenuItem>
        </MenuContent>
      </Menu>

      <CommandPalette open={palette} onOpenChange={setPalette} />
    </header>
  );
}
