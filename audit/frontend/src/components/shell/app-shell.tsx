"use client";

import { usePathname } from "next/navigation";
import { motion } from "motion/react";
import { useRequireAuth, useStoredState } from "@/lib/hooks";
import { Skeleton } from "@/components/ui/feedback";
import { Sidebar } from "./sidebar";
import { Header } from "./header";

/** Authenticated application frame shared by /dashboard and /admin. */
export function AppShell({ children }: { children: React.ReactNode }) {
  const authed = useRequireAuth();
  const [collapsed, setCollapsed] = useStoredState("seqr_sidebar_collapsed", false);
  const pathname = usePathname();

  if (!authed) {
    return (
      <div className="flex min-h-dvh" role="status" aria-label="Checking your session">
        <div className="hidden w-[248px] border-r border-ink lg:block" />
        <div className="flex-1 space-y-6 p-8">
          <Skeleton className="h-3 w-40" />
          <Skeleton className="h-10 w-80" />
          <Skeleton className="h-40 w-full" />
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-dvh w-full bg-bg">
      <a
        href="#main"
        className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-[80] focus:bg-ink focus:px-3 focus:py-2 focus:text-bg"
      >
        Skip to content
      </a>
      <Sidebar collapsed={collapsed} onToggle={() => setCollapsed(!collapsed)} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Header />
        <main id="main" className="flex-1 px-4 pb-24 pt-8 sm:px-8 lg:px-10">
          <motion.div
            key={pathname}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4, ease: [0.2, 0, 0, 1] }}
            className="mx-auto w-full max-w-page"
          >
            {children}
          </motion.div>
        </main>
      </div>
    </div>
  );
}
