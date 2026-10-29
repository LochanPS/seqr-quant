"use client";

import { Suspense } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { PageHeader } from "@/components/ui/page";
import { Tabs, TabsContent, TabsList } from "@/components/ui/tabs";
import { TableSkeleton } from "@/components/ui/feedback";
import { OrgTab } from "./org-tab";
import { TeamTab } from "./team-tab";
import { SecurityTab } from "./security-tab";
import { SsoTab } from "./sso-tab";
import { KeysTab } from "./keys-tab";
import { AuditTab } from "./audit-tab";
import { AppearanceTab } from "./appearance-tab";

const TABS = [
  { value: "org", label: "Organisation" },
  { value: "team", label: "Team" },
  { value: "security", label: "Security" },
  { value: "sso", label: "Single sign-on" },
  { value: "keys", label: "API keys" },
  { value: "audit", label: "Audit log" },
  { value: "appearance", label: "Appearance" },
];

function SettingsInner() {
  const params = useSearchParams();
  const router = useRouter();
  const pathname = usePathname();
  const raw = params.get("tab") ?? "org";
  const tab = TABS.some((t) => t.value === raw) ? raw : "org";
  const openNewKey = tab === "keys" && params.get("new") === "1";

  return (
    <div className="space-y-8">
      <PageHeader eyebrow="Workspace" title="Settings" description="Organisation details, people and roles, sign-in security, keys, the audit trail and how SeQr looks." />
      <Tabs value={tab} onValueChange={(v) => router.replace(v === "org" ? pathname : `${pathname}?tab=${v}`, { scroll: false })}>
        <TabsList value={tab} items={TABS} />
        <TabsContent value="org">
          <OrgTab />
        </TabsContent>
        <TabsContent value="team">
          <TeamTab />
        </TabsContent>
        <TabsContent value="security">
          <SecurityTab />
        </TabsContent>
        <TabsContent value="sso">
          <SsoTab />
        </TabsContent>
        <TabsContent value="keys">
          <KeysTab openNew={openNewKey} onConsumed={() => router.replace(`${pathname}?tab=keys`, { scroll: false })} />
        </TabsContent>
        <TabsContent value="audit">
          <AuditTab />
        </TabsContent>
        <TabsContent value="appearance">
          <AppearanceTab />
        </TabsContent>
      </Tabs>
    </div>
  );
}

export default function SettingsPage() {
  return (
    <Suspense fallback={<TableSkeleton />}>
      <SettingsInner />
    </Suspense>
  );
}
