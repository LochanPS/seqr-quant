import type { Metadata } from "next";
import { LegalPage } from "@/components/legal/legal-page";
import { PRIVACY } from "@/components/legal/content";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description: "How SeQr Labs collects, uses and protects your data.",
};

export default function PrivacyPage() {
  return <LegalPage doc={PRIVACY} other={{ label: "Terms of Service", href: "/terms" }} />;
}
