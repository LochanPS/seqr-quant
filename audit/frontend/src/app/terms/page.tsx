import type { Metadata } from "next";
import { LegalPage } from "@/components/legal/legal-page";
import { TERMS } from "@/components/legal/content";

export const metadata: Metadata = {
  title: "Terms of Service",
  description: "The terms that govern use of SeQr.",
};

export default function TermsPage() {
  return <LegalPage doc={TERMS} other={{ label: "Privacy Policy", href: "/privacy" }} />;
}
