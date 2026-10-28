"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import { Bell, Search, ChevronRight } from "lucide-react";
import { ThemeToggle } from "./ThemeToggle";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
  SheetTrigger,
} from "@/components/ui/sheet";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { logout, useOrg } from "@/lib/hooks";

const LABELS: Record<string, string> = {
  dashboard: "Dashboard",
  assets: "Assets",
  graph: "Graph",
  cbom: "CBOM",
  reports: "Reports",
  settings: "Settings",
  scans: "Scans",
};

function Breadcrumb() {
  const pathname = usePathname();
  const parts = pathname.split("/").filter(Boolean);
  const crumbs: { label: string; href: string }[] = [];
  let acc = "";
  for (const p of parts) {
    acc += `/${p}`;
    crumbs.push({ label: LABELS[p] || p, href: acc });
  }
  if (crumbs.length === 0) crumbs.push({ label: "Dashboard", href: "/dashboard" });
  return (
    <nav className="flex items-center gap-1.5 text-sm">
      {crumbs.map((c, i) => (
        <span key={c.href} className="flex items-center gap-1.5">
          {i > 0 && <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
          <Link
            href={c.href}
            className={
              i === crumbs.length - 1
                ? "font-medium text-foreground"
                : "text-muted-foreground hover:text-foreground"
            }
          >
            {c.label}
          </Link>
        </span>
      ))}
    </nav>
  );
}

export function Header() {
  const { data: org } = useOrg();
  const [searchOpen, setSearchOpen] = useState(false);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  return (
    <header className="sticky top-0 z-20 flex h-16 items-center justify-between gap-4 border-b bg-background/70 px-6 backdrop-blur">
      <Breadcrumb />

      <div className="flex items-center gap-2">
        <button
          onClick={() => setSearchOpen(true)}
          className="hidden items-center gap-2 rounded-lg border bg-muted/40 px-3 py-1.5 text-sm text-muted-foreground transition-colors hover:bg-muted md:flex"
        >
          <Search className="h-4 w-4" />
          Search
          <kbd className="ml-6 rounded border bg-background px-1.5 font-mono text-[10px]">
            ⌘K
          </kbd>
        </button>

        {/* notifications */}
        <Sheet>
          <SheetTrigger asChild>
            <Button variant="ghost" size="icon" className="relative">
              <Bell className="h-5 w-5" />
              <span className="absolute right-1.5 top-1.5 h-2 w-2 rounded-full bg-vulnerable ring-2 ring-background" />
            </Button>
          </SheetTrigger>
          <SheetContent side="right">
            <SheetHeader>
              <SheetTitle>Notifications</SheetTitle>
            </SheetHeader>
            <div className="mt-6 space-y-3 text-sm">
              <div className="rounded-lg border p-3">
                <p className="font-medium">HNDL risk detected</p>
                <p className="mt-1 text-muted-foreground">
                  Long-lived sensitive data is protected by quantum-vulnerable
                  key exchange.
                </p>
              </div>
              <div className="rounded-lg border p-3">
                <p className="font-medium">Policy re-evaluated</p>
                <p className="mt-1 text-muted-foreground">
                  Component states refreshed from the latest graph observations.
                </p>
              </div>
            </div>
          </SheetContent>
        </Sheet>

        <ThemeToggle />

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button className="flex h-9 w-9 items-center justify-center rounded-full bg-gradient-to-br from-quantum to-planned text-xs font-semibold text-white">
              {(org?.name || "S").slice(0, 2).toUpperCase()}
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="w-56">
            <DropdownMenuLabel>
              <div className="flex flex-col">
                <span>{org?.name || "Workspace"}</span>
                <span className="text-xs font-normal capitalize text-muted-foreground">
                  {org?.plan || "trial"} plan
                </span>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem asChild>
              <Link href="/dashboard/settings">Settings</Link>
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={logout}
              className="text-vulnerable focus:text-vulnerable"
            >
              Log out
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* search command sheet */}
      <Sheet open={searchOpen} onOpenChange={setSearchOpen}>
        <SheetContent side="top" className="mx-auto max-w-2xl">
          <SheetHeader>
            <SheetTitle className="flex items-center gap-2">
              <Search className="h-4 w-4" /> Search
            </SheetTitle>
          </SheetHeader>
          <input
            autoFocus
            placeholder="Search assets, components, reports…"
            className="mt-4 w-full rounded-lg border bg-background px-4 py-3 text-sm outline-none focus:ring-2 focus:ring-ring"
          />
          <div className="mt-3 flex flex-wrap gap-2">
            {["Overview", "Assets", "CBOM", "Settings"].map((q) => (
              <Badge key={q} variant="muted">
                {q}
              </Badge>
            ))}
          </div>
          <p className="mt-4 text-xs text-muted-foreground">
            Global search is a preview. Use the sidebar to navigate.
          </p>
        </SheetContent>
      </Sheet>
    </header>
  );
}
