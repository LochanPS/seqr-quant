import {
  IconAssets,
  IconCbom,
  IconConnections,
  IconGraph,
  IconOverview,
  IconRemediation,
  IconReports,
  IconSettings,
  type IconProps,
} from "@/components/icons";

export type NavItem = {
  href: string;
  label: string;
  icon: (p: IconProps) => JSX.Element;
  tag?: string;
  keywords?: string;
};

export const NAV: NavItem[] = [
  { href: "/dashboard/posture", label: "Overview", icon: IconOverview, keywords: "posture home migration attestation" },
  { href: "/dashboard/assets", label: "Assets", icon: IconAssets, keywords: "inventory hosts domains scan" },
  { href: "/dashboard/graph", label: "Graph", icon: IconGraph, keywords: "topology edges explorer" },
  { href: "/dashboard/cbom", label: "CBOM", icon: IconCbom, tag: "Preview", keywords: "bill of materials cyclonedx components export" },
  { href: "/dashboard/remediation", label: "Remediation", icon: IconRemediation, keywords: "planner budget qaoa qpiai" },
  { href: "/dashboard/connections", label: "Connections", icon: IconConnections, keywords: "agent discovery credentials" },
  { href: "/dashboard/reports", label: "Reports", icon: IconReports, keywords: "pdf executive technical ci" },
  { href: "/dashboard/settings", label: "Settings", icon: IconSettings, keywords: "organisation team security sso api keys audit appearance" },
];

export const SEGMENT_LABELS: Record<string, string> = {
  dashboard: "Dashboard",
  posture: "Overview",
  assets: "Assets",
  graph: "Graph",
  cbom: "CBOM",
  remediation: "Remediation",
  connections: "Connections",
  reports: "Reports",
  settings: "Settings",
  scans: "Scans",
  admin: "Operator console",
  blog: "Blog",
};
